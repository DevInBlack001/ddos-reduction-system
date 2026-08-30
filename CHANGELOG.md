# Changelog

Notable changes to the FLOD System, starting from this file's introduction at
1.1.1. Earlier releases are not backfilled here; see the git tags and
`docs/roadmap.md` for that history. Versioning and tagging follow the rules
in this repository's own contribution conventions: a patch bump is a fix, a
minor bump adds a feature, milestones are numbered separately from tags.

## 1.2.0, 2026-08-30

### Added

- Three evasion-resistant features: source port entropy, TTL variance, and
  TCP SYN fingerprint diversity, computed from per-window histograms keyed
  by the field value rather than by source address, so a randomized source
  flood cannot fill them the way it fills `SOURCES`. Close the detection
  blind spot on randomized source spoofing, though safe enforcement
  against a spoofed flood remains open.
- A second model, an Isolation Forest, trained unsupervised on the same
  feature set and running alongside the RandomForest on every window.
  Surfaces a new `Anomalous` classification state for traffic unlike
  anything either model has learned; does not drive enforcement on its
  own.
- `--exclude-ips`, excluding specific addresses from monitoring without
  removing them from a protected subnet.
- `--max-baseline-freeze-windows` (default 400), bounding how long a
  target's rate baseline may stay frozen under sustained legitimate
  traffic growth before the current traffic is accepted as the new
  baseline.
- `anomalous_capture.csv`, appended to whenever the Isolation Forest
  flags a window, for human review; never fed back into training
  automatically.
- `scripts/benchmark_fixed_threshold.py`, comparing both trained models
  against a fixed rate threshold under genuine Leave-One-Session-Out
  evaluation, with real training time, prediction latency, and system
  resource measurements alongside the detection numbers.
- `scripts/train.sh`, an interactive selector for training one or both
  models against a chosen CSV.
- `scripts/build-stage1.sh`, building Stage 1 and its eBPF backend as the
  invoking user rather than as root.
- `docs/explainer.md`, `docs/lessons-learned.md`, `docs/benchmark-results.md`,
  and real dashboard and architecture screenshots throughout the README
  and docs.

### Fixed

- Sustained legitimate traffic growth could freeze a target's rate
  baseline permanently: once traffic crossed a boundary learned from an
  earlier, lower-rate baseline, every subsequent window flagged too,
  keeping cooldown re-armed and the baseline from ever catching up.
  `--max-baseline-freeze-windows` bounds it; a second, corrective fix was
  needed after the first version compiled and passed its own tests but
  changed nothing in practice, because a separate outlier check was
  independently rejecting the same sample the freeze escape had just
  forced through.
- `--train-csv` wrote warm-up windows with unclamped `sigma_r`/`sigma_h`
  into the training CSV, with no column distinguishing them from
  converged, post-warm-up rows.
- A warm-up enforcement bypass: the fix gating classifier calls on
  warm-up traffic also gated the deterministic safety-override
  enforcement rules on the same check, leaving a freshly restarted or
  newly added target completely unenforced for its first ~200 windows.
  `apply_safety_overrides()` no longer takes a warm-up parameter at all.
- Stage 2 ran as root directly out of the checkout: code, virtual
  environment, trained models, configuration, and database all in a
  directory the account that ran `git clone` could still write to. Now
  runs from a root-owned install at `/opt/flod/stage2`, with state in
  `/var/lib/flod`, migrated automatically from an existing checkout
  rooted install on upgrade.
- Stage 1 and its eBPF backend were built as root during install and
  update, so `cargo build`'s build scripts and proc macros ran with root
  privileges against a checkout a lower-privileged account could still
  write to. Now built as the invoking user, root only installs the
  result.
- Symlinks in the Stage 2 code-copy loop were followed during install
  and update, auto-trusting checkout-owned model files into the runtime
  state directory a compromised or careless checkout could have planted.
  Now rejected.
- File ownership left over in the checkout from a previous root-owned
  build was not reclaimed before building as the invoking user, which
  could leave root-owned build artifacts a later non-root build could
  not clean up.
- A cosmetic sklearn/joblib warning during training and benchmark runs,
  from `n_jobs=-1` fits triggering a config-propagation check that does
  not apply since nothing in these scripts touches sklearn's global
  configuration.

### Changed

- The training dataset was recaptured with jittered generator timing
  (randomised inter-request and inter-packet delays, varying active
  source counts, no unpaced flood mode) after the original capture's
  mechanically regular timing was found to collapse `sigma_r` to its
  configured floor for an entire session regardless of real traffic
  volume, teaching the model "this traffic is mechanically regular"
  rather than the intended class signature.
- A ramp-gap mislabeling pitfall in automated capture orchestration was
  found and fixed in the corrected training set: a script that starts
  traffic and only sets the new label after a ramp period lets real
  traffic land in the CSV still stamped with the previous phase's label
  for a few seconds at every transition. Documented in
  `docs/training.md`'s Clean Rule as a concrete failure mode to check
  for, not just a theoretical one.

## 1.1.1, 2026-08-25

### Fixed

- The `0.0.0.0` sentinel Stage 1 writes for a window with no attributable
  dominant source was being logged into `logs.src_ip` as if it were a real
  address. It could account for a large share of an incident log's "sources"
  during idle or low-traffic periods. Stage 2 now skips the incident-log
  write entirely for a window with no attributable source, instead of
  logging a placeholder.
- The PDF incident report rendered in landscape with an unpainted page
  margin, which made every report look like a screenshot pasted onto a
  blank sheet. Switched to portrait and gave the page an explicit
  background matching the report's own theme.

## 1.1.0, 2026-08-23

### Changed

- PDF incident report generation moved to server side rendering.
  `report_data.py` and `report_pdf.py` build the report from the database
  and render it with WeasyPrint, replacing the client supplied chart data
  the dashboard used to hand the server for the same purpose.

The version strings in `stage1/Cargo.toml`, `stage1-common/Cargo.toml`,
`stage1-ebpf/Cargo.toml`, and `stage2/config.py` were not updated in the
commit this tag points to, and still read `1.0.2` there. Corrected as part
of the 1.1.1 bump; noted here since this entry is otherwise the only public
record that 1.1.0 exists.
