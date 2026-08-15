#!/usr/bin/env python3
"""Derive Stage 1 sigma floors from the sensor's own window log.

The floors exist to stop a boundary collapsing onto the mean when the learned
standard deviation is smaller than the traffic really warrants. The right value
is a property of the network, so it can only come from measurement. This reads
the per window debug lines out of the journal, keeps the windows the sensor
itself treated as ordinary, and derives floors that sit just outside the
observed normal spread.

Sample per target defaults to 1000 windows, which is roughly 8 to 17 minutes
of traffic. Nothing is written unless --apply is passed.

Usage:
    sudo python3 scripts/calibrate.py                  # measure and report
    sudo python3 scripts/calibrate.py --apply          # measure, write, restart
    sudo python3 scripts/calibrate.py --since -6h      # reuse existing history
    sudo python3 scripts/calibrate.py --reset          # back to sensor defaults
"""

import argparse
import math
import os
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime, timedelta

SERVICE = "ddos-stage1.service"
UNIT_PATH = "/etc/systemd/system/ddos-stage1.service"
TUNING_DIR = "/etc/ddos_stage1"
TUNING_FILE = os.path.join(TUNING_DIR, "tuning.env")
TUNING_VAR = "FLOD_TUNING"
DEBUG_DROPIN_DIR = "/etc/systemd/system/ddos-stage1.service.d"
DEBUG_DROPIN = os.path.join(DEBUG_DROPIN_DIR, "10-calibration-debug.conf")
BASELINE_PATH = "/var/lib/ddos_stage1/baselines.json"

# Mirrors the sensor's own default. Only emitted when the derived floor would
# otherwise exceed it.
SENSOR_ENTROPY_SIGMA_CEILING = 0.15

# env_logger is configured with WriteStyle::Always, so journal lines carry
# colour escapes.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Emitted once per window at debug level, after warm up and after the
# boundaries are computed. See the log::debug! call in analysis.rs.
WINDOW_RE = re.compile(
    r"Window #(?P<id>\d+)\[victim=(?P<ip>[^\]]+)\]: "
    r"r=(?P<r>[-\d.]+) pps \| h=(?P<h>[-\d.]+) bits \| "
    r"μ_r=(?P<mean_r>[-\d.]+) σ_r=(?P<sigma_r>[-\d.]+) \(active=(?P<active_r>[-\d.]+)\) \| "
    r"μ_h=(?P<mean_h>[-\d.]+) σ_h=(?P<sigma_h>[-\d.]+) \(active=(?P<active_h>[-\d.]+)\) \| "
    r"cooldown=(?P<cooldown>\d+)"
)

# The startup banner carries the k actually in force.
K_RE = re.compile(r"Analysis: thread started \|.*\| k=(?P<k>[-\d.]+)")


class Window:
    __slots__ = ("wid", "r", "h", "mean_r", "sigma_r", "mean_h", "sigma_h", "cooldown")

    def __init__(self, wid, r, h, mean_r, sigma_r, mean_h, sigma_h, cooldown):
        self.wid = wid
        self.r = r
        self.h = h
        self.mean_r = mean_r
        self.sigma_r = sigma_r
        self.mean_h = mean_h
        self.sigma_h = sigma_h
        self.cooldown = cooldown


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(1)


def run(cmd, check=True):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        die("`%s` failed: %s" % (" ".join(cmd), res.stderr.strip()))
    return res


def need_root(action):
    if os.geteuid() != 0:
        die("%s needs root. Re-run with sudo." % action)


def percentile(values, q):
    """Linear interpolation between order statistics."""
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    pos = (len(s) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return s[int(pos)]
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def robust_sigma(values):
    """Median absolute deviation, scaled to a standard deviation.

    Used instead of the plain standard deviation so a handful of odd windows
    that slipped past the clean filter cannot inflate the floor.
    """
    if len(values) < 2:
        return 0.0
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values])
    if mad > 0.0:
        return mad * 1.4826
    return statistics.pstdev(values)


def journal_since(spec):
    """Turn a relative spec into an absolute one journalctl always accepts."""
    m = re.fullmatch(r"-(\d+)([smhd])", spec.strip())
    if not m:
        return spec
    n = int(m.group(1))
    unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
    when = datetime.now() - timedelta(**{unit: n})
    return when.strftime("%Y-%m-%d %H:%M:%S")


def read_journal(since):
    res = run(["journalctl", "-u", SERVICE, "--no-pager", "-o", "cat", "--since", since])
    return ANSI_RE.sub("", res.stdout)


def parse_windows(text):
    """Group per window samples by protected host, newest run's k alongside."""
    by_ip = {}
    k = None
    for line in text.splitlines():
        km = K_RE.search(line)
        if km:
            k = float(km.group("k"))
            continue
        m = WINDOW_RE.search(line)
        if not m:
            continue
        by_ip.setdefault(m.group("ip"), []).append(
            Window(
                int(m.group("id")),
                float(m.group("r")),
                float(m.group("h")),
                float(m.group("mean_r")),
                float(m.group("sigma_r")),
                float(m.group("mean_h")),
                float(m.group("sigma_h")),
                int(m.group("cooldown")),
            )
        )
    return by_ip, k


def recommend(windows, k, margin):
    """Derive floors for one protected host from its clean windows.

    A window with a live cooldown is either the anomaly itself or one of the
    windows following it, so those are dropped: the floors describe ordinary
    traffic, and folding an incident back in would raise them until the same
    incident no longer registers.
    """
    clean = [w for w in windows if w.cooldown == 0]
    if len(clean) < 2:
        return None

    rates = [w.r for w in clean]
    entropies = [w.h for w in clean]

    mu_r = statistics.fmean(rates)
    mu_h = statistics.fmean(entropies)
    # Trimmed rather than the raw extremes, so one freak window does not set
    # the floor on its own. The margin below covers what the trim removes.
    peak_r = percentile(rates, 0.995)
    trough_h = percentile(entropies, 0.005)

    spread_r = robust_sigma(rates)
    spread_h = robust_sigma(entropies)

    # The boundary is mean + k * sigma for the rate and mean - k * sigma for
    # entropy, so this is the sigma that puts it just past ordinary traffic.
    tail_r = max(0.0, (peak_r * (1.0 + margin) - mu_r) / k)
    tail_h = max(0.0, (mu_h - trough_h * (1.0 - margin)) / k)

    return {
        "windows_total": len(windows),
        "windows_clean": len(clean),
        "flagged_share": 1.0 - (len(clean) / len(windows)),
        "mu_r": mu_r,
        "peak_r": peak_r,
        "spread_r": spread_r,
        "tail_r": tail_r,
        "rate_floor": max(spread_r, tail_r, 1.0),
        "mu_h": mu_h,
        "trough_h": trough_h,
        "spread_h": spread_h,
        "tail_h": tail_h,
        "entropy_floor": max(spread_h, tail_h, 0.001),
        # What the sensor itself currently believes, for the drift check below.
        "learned_mean_r": statistics.fmean([w.mean_r for w in clean]),
        "learned_sigma_r": statistics.fmean([w.sigma_r for w in clean]),
        "learned_sigma_h": statistics.fmean([w.sigma_h for w in clean]),
    }


def report(results, k, margin):
    print()
    print("Per target, from clean windows only (k=%.2f, margin=%d%%)" % (k, margin * 100))
    print()
    header = "%-18s %8s %8s %10s %10s %10s %10s" % (
        "target", "windows", "flagged", "mean pps", "peak pps", "rate flr", "entr flr")
    print(header)
    print("-" * len(header))
    for ip in sorted(results):
        d = results[ip]
        print("%-18s %8d %7.1f%% %10.1f %10.1f %10.1f %10.4f" % (
            ip, d["windows_clean"], d["flagged_share"] * 100.0,
            d["mu_r"], d["peak_r"], d["rate_floor"], d["entropy_floor"]))
    print()

    for ip in sorted(results):
        d = results[ip]
        if d["flagged_share"] > 0.25:
            print("warning: %s spent %.0f%% of the sample flagged or in cooldown. "
                  "That is not peacetime traffic, and floors derived from it will be "
                  "biased. Investigate the flags before trusting these numbers."
                  % (ip, d["flagged_share"] * 100.0))
        if d["learned_mean_r"] > 0 and d["mu_r"] > d["learned_mean_r"] * 1.3:
            print("warning: %s is running at %.0f pps while the sensor's learned mean is "
                  "%.0f pps. The baseline is behind the traffic and, because every "
                  "flagged window freezes it, cannot catch up on its own. Apply with "
                  "--clear-baseline so it relearns."
                  % (ip, d["mu_r"], d["learned_mean_r"]))
        if d["rate_floor"] > d["spread_r"] * 4.0 and d["spread_r"] > 0:
            print("note: %s has a long rate tail. Its typical spread is %.1f pps but "
                  "ordinary peaks reach %.1f pps, so the floor is set by the peak, not "
                  "the spread." % (ip, d["spread_r"], d["peak_r"]))


def reconcile(results):
    """One set of floors covers every target, so the widest target wins.

    Erring high costs sensitivity on the quietest host and erring low flags the
    busiest one continuously, which also freezes its baseline. The first
    failure is recoverable, the second is not.
    """
    rate = max(d["rate_floor"] for d in results.values())
    entropy = max(d["entropy_floor"] for d in results.values())

    rate_lo = min(d["rate_floor"] for d in results.values())
    if len(results) > 1 and rate_lo > 0 and rate / rate_lo > 4.0:
        print("warning: the per target rate floors span %.1f to %.1f pps. One global "
              "value cannot fit both, and the quiet target will be much harder to "
              "trip. Consider running a separate sensor per host if that matters."
              % (rate_lo, rate))
    return rate, entropy


def build_flags(rate_floor, entropy_floor):
    """Only values that were measured. Anything omitted keeps the sensor's own
    default, so a later release can improve it."""
    flags = [
        "--rate-sigma-floor %s" % round(rate_floor, 1),
        "--entropy-sigma-floor %s" % round(entropy_floor, 4),
    ]
    if entropy_floor * 2.0 > SENSOR_ENTROPY_SIGMA_CEILING:
        ceiling = min(0.9, round(entropy_floor * 3.0, 4))
        flags.append("--entropy-sigma-ceiling %s" % ceiling)
    return " ".join(flags)


def ensure_unit_reads_tuning():
    """Add the environment file and its expansion to the unit if absent.

    Kept as one variable appended to the end of ExecStart rather than a drop in
    that restates the whole command: the sensor's parser takes the last value
    for a flag, so this overrides whatever the installer chose without needing
    to know the interface, the targets, or the capture mode.
    """
    if not os.path.exists(UNIT_PATH):
        die("%s not found. Install the service first." % UNIT_PATH)

    with open(UNIT_PATH) as f:
        lines = f.readlines()

    has_envfile = any(l.strip().startswith("EnvironmentFile=") and TUNING_FILE in l for l in lines)
    exec_idx = next((i for i, l in enumerate(lines) if l.startswith("ExecStart=")), None)
    if exec_idx is None:
        die("no ExecStart= line in %s" % UNIT_PATH)

    changed = False
    if "$" + TUNING_VAR not in lines[exec_idx]:
        lines[exec_idx] = lines[exec_idx].rstrip("\n") + " $" + TUNING_VAR + "\n"
        changed = True
    if not has_envfile:
        # The leading dash makes the file optional, so removing it falls back
        # to the values the installer wrote.
        lines.insert(exec_idx, "EnvironmentFile=-%s\n" % TUNING_FILE)
        changed = True

    if changed:
        with open(UNIT_PATH, "w") as f:
            f.writelines(lines)
        print("patched %s to read %s" % (UNIT_PATH, TUNING_FILE))
    return changed


def write_tuning(flags, sample_size):
    os.makedirs(TUNING_DIR, mode=0o755, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    body = (
        "# Stage 1 detection tuning, generated by scripts/calibrate.py on %s\n"
        "# Derived from %d clean windows per protected host.\n"
        "# Delete this file and restart to fall back to the sensor's defaults.\n"
        "%s=%s\n" % (stamp, sample_size, TUNING_VAR, flags)
    )
    with open(TUNING_FILE, "w") as f:
        f.write(body)
    os.chmod(TUNING_FILE, 0o644)
    print("wrote %s" % TUNING_FILE)


def set_debug_logging(enabled):
    if enabled:
        os.makedirs(DEBUG_DROPIN_DIR, mode=0o755, exist_ok=True)
        with open(DEBUG_DROPIN, "w") as f:
            f.write(
                "# Temporary, written by scripts/calibrate.py. The per window\n"
                "# samples it reads are only logged at debug level.\n"
                "[Service]\n"
                'Environment="RUST_LOG=debug"\n'
            )
        print("enabled debug logging via %s" % DEBUG_DROPIN)
    else:
        if not os.path.exists(DEBUG_DROPIN):
            return False
        os.remove(DEBUG_DROPIN)
        print("removed %s" % DEBUG_DROPIN)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "restart", SERVICE])
    return True


def do_reset(args):
    need_root("--reset")
    removed = False
    if os.path.exists(TUNING_FILE):
        os.remove(TUNING_FILE)
        print("removed %s" % TUNING_FILE)
        removed = True
    else:
        print("%s does not exist, nothing to reset" % TUNING_FILE)
    if removed and not args.no_restart:
        run(["systemctl", "restart", SERVICE])
        print("restarted %s, sensor defaults are back in force" % SERVICE)
    return 0


def collect(args):
    """Poll the journal until every target has enough windows, or time runs out."""
    since = journal_since(args.since)
    deadline = time.monotonic() + args.timeout * 60
    last_line = ""

    while True:
        by_ip, k = parse_windows(read_journal(since))

        if not by_ip:
            if time.monotonic() >= deadline:
                die("no per window samples in the journal since %s. The sensor logs "
                    "them at debug level only. Re-run with --auto-debug, or set "
                    "RUST_LOG=debug on the unit yourself." % since)
            print("\rwaiting for the first window...", end="", flush=True)
            time.sleep(args.poll)
            continue

        counts = {ip: len([w for w in ws if w.cooldown == 0]) for ip, ws in by_ip.items()}
        if all(n >= args.windows for n in counts.values()):
            print("\r" + " " * len(last_line) + "\r", end="")
            return by_ip, k

        if time.monotonic() >= deadline:
            print("\r" + " " * len(last_line) + "\r", end="")
            short = {ip: n for ip, n in counts.items() if n < args.windows}
            if args.partial:
                print("timed out after %d minutes with %s short of %d windows. "
                      "Continuing on the partial sample."
                      % (args.timeout, ", ".join(sorted(short)), args.windows))
                return by_ip, k
            die("timed out after %d minutes. Short of %d clean windows: %s. Give it "
                "longer with --timeout, lower the target with --windows, or accept "
                "the partial sample with --partial."
                % (args.timeout, args.windows,
                   ", ".join("%s=%d" % (ip, n) for ip, n in sorted(short.items()))))

        last_line = "collecting: " + "  ".join(
            "%s %d/%d" % (ip, n, args.windows) for ip, n in sorted(counts.items()))
        print("\r" + last_line, end="", flush=True)
        time.sleep(args.poll)


def main():
    p = argparse.ArgumentParser(
        description="Derive Stage 1 sigma floors from observed traffic.")
    p.add_argument("--windows", type=int, default=1000,
                   help="clean windows required per protected host (default: 1000)")
    p.add_argument("--since", default="now",
                   help="journal start point, absolute or relative like -6h (default: now)")
    p.add_argument("--timeout", type=int, default=60,
                   help="minutes to wait for the sample (default: 60)")
    p.add_argument("--poll", type=int, default=15,
                   help="seconds between journal reads while collecting (default: 15)")
    p.add_argument("--partial", action="store_true",
                   help="calibrate on whatever was collected when the timeout hits")
    p.add_argument("--k", type=float, default=None,
                   help="anomaly multiplier, if it cannot be read from the journal")
    p.add_argument("--margin", type=float, default=0.10,
                   help="headroom above the observed peak, as a fraction (default: 0.10)")
    p.add_argument("--apply", action="store_true",
                   help="write the values to %s and restart the sensor" % TUNING_FILE)
    p.add_argument("--clear-baseline", action="store_true",
                   help="with --apply, delete %s so the baseline relearns" % BASELINE_PATH)
    p.add_argument("--auto-debug", action="store_true",
                   help="turn on debug logging for the run, then turn it back off")
    p.add_argument("--no-restart", action="store_true",
                   help="write the values but leave restarting to the operator")
    p.add_argument("--reset", action="store_true",
                   help="remove the calibration and return to the sensor defaults")
    args = p.parse_args()

    if args.reset:
        return do_reset(args)
    if args.apply or args.auto_debug:
        need_root("--apply and --auto-debug")
    if args.windows < 2:
        die("--windows needs at least 2")

    debug_enabled_here = False
    if args.auto_debug:
        set_debug_logging(True)
        debug_enabled_here = True
        # The restart resets warm up, so the first samples are 200 windows out.
        args.since = journal_since("-1m")

    try:
        by_ip, journal_k = collect(args)
    finally:
        if debug_enabled_here:
            set_debug_logging(False)

    k = args.k or journal_k
    if k is None:
        die("could not read k from the journal. Pass it with --k.")

    results = {}
    for ip, windows in by_ip.items():
        d = recommend(windows, k, args.margin)
        if d is None:
            print("skipping %s: only %d windows" % (ip, len(windows)))
            continue
        results[ip] = d
    if not results:
        die("no target had enough clean windows to calibrate.")

    report(results, k, args.margin)
    rate_floor, entropy_floor = reconcile(results)
    flags = build_flags(rate_floor, entropy_floor)

    print()
    print("Recommended, covering every target:")
    print("  %s" % flags)
    print()

    if not args.apply:
        print("Nothing was written. Re-run with --apply to save these and restart, "
              "and add --clear-baseline if a warning above asked for it.")
        return 0

    sample = min(d["windows_clean"] for d in results.values())
    ensure_unit_reads_tuning()
    write_tuning(flags, sample)
    run(["systemctl", "daemon-reload"])

    if args.clear_baseline and os.path.exists(BASELINE_PATH):
        os.remove(BASELINE_PATH)
        print("removed %s, the baseline will relearn from scratch" % BASELINE_PATH)

    if args.no_restart:
        print("not restarting. The values take effect on the next start of %s." % SERVICE)
    else:
        run(["systemctl", "restart", SERVICE])
        print("restarted %s. Warm up takes 200 windows before detection resumes."
              % SERVICE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
