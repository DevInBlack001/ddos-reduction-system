# Changelog

Notable changes to the FLOD System, starting from this file's introduction at
1.1.1. Earlier releases are not backfilled here; see the git tags and
`docs/roadmap.md` for that history. Versioning and tagging follow the rules
in this repository's own contribution conventions: a patch bump is a fix, a
minor bump adds a feature, milestones are numbered separately from tags.

## Unreleased

### Added

- Stage 2 logs a `Latency: summary` line every 30 seconds
  (`LATENCY_LOG_INTERVAL_SECS`, 0 turns it off) with the count, mean, p95, and
  maximum for four figures per window: handoff from the sensor, inference,
  the enforcement call, and window close to rule applied.
- `scripts/benchmark_live.sh` runs the seven phase set against each capture
  backend in `CAPTURE_MODES` (kernel, then libpcap, by default) in one
  session. It switches the sensor's backend through `tuning.env`, gives each
  run its own baseline file, empties both ipsets and restarts Stage 2 before
  each run, times the downtime of each switch, then restores the original
  configuration and times the rollback. An exit trap performs the same
  rollback if the script is interrupted.
- The benchmark sampler records context switches per service and system wide,
  system wide CPU including softirq, and interface packet, byte, drop, and
  error counters. A helper on the gateway (`benchmark_mode_switch.sh`) also
  snapshots the ddos iptables drop counters at every phase boundary.
- `scripts/analyze_live_benchmark.py` reports per phase throughput, drops,
  CPU, context switches, latency, time from attack to first detection and
  first block, and detection consistency, then compares the backends
  side by side, including whether they agree on each phase. Given a
  session directory it also writes `results.json`. It still reads a single
  run directory in the older format.
- `docs/benchmark-backends.md` describes the backend comparison, and
  `docs/roadmap.md` gains V14, kernel space inference and enforcement, with a
  user space Random Forest fallback if the in-kernel program fails.

- The live benchmark varies its traffic. Normal, Flash Crowd and the attack
  each take named variants (`NORMAL_VARIANTS`, `FLASHCROWD_VARIANTS`,
  `ATTACK_VARIANTS`) that rotate every time the class starts, offset by the run
  number. With `ATTACK_SWEEP_SECS` set, every attack type also runs alone and
  then with Normal traffic after the seven phases, with traffic stopped, both
  ipsets emptied and Stage 2 restarted before each type. The report shows which
  variant every phase ran and compares the backends on each attack type.
- The benchmark checks the attacker's source address count against a
  configured range (30 to 40 by default) and records it, and reports for each
  phase which signal flagged the anomaly windows (rate, entropy, or both) with
  the mean entropy and dominant source share.

- The live benchmark can run `scripts/calibrate.py` during each run's warm-up
  stage (`CALIBRATE=measure` or `apply`, off by default). It measures only,
  and with `apply` the derived sigma floors are added to the sensor's tuning
  line by the gateway helper, which restarts the sensor under timing and waits
  for the baseline again, so the capture mode and baseline path the run
  depends on are kept. The warm-up stage is now its own phase (`warmup`), so
  the `normal` phase holds only steady state. The report shows each run's
  calibration and compares the floors between backends.

- `scripts/label_from_benchmark.py` labels captured windows from the traffic a
  benchmark recorded for each phase, for training on shapes the corpus lacks
  (the concentrated Flash Crowd read as DDoS in both backend sessions).
- Stage 2 records how long it spends handling each window (`busy` in the latency
  summary) and logs a warning for any window that takes a second or more.

### Changed

- `train.py` picks the tree depth that clears the auto-labeling confidence
  threshold most often among the depths that tie on accuracy, so the gate is no
  longer close to arbitrary (depth 6 on the current corpus, where depth 3 was
  chosen before).

### Fixed

- Stage 2 no longer waits on a capture file's lock in its receive loop.
  `auto_label.py` held that lock through a whole read, score and rewrite pass and
  scored one row at a time, so windows queued behind it and handoff reached tens of
  seconds. The job now locks only to read and to swap in the result with any rows
  appended meanwhile, and scores in batches (2.0 s for 50,000 rows, about 18
  minutes before on the gateway). Rows waiting for the lock are held in a bounded
  buffer. A row with the wrong number of columns is dropped and a row with a
  non-finite value stays out of the models.
- Enforcement used every flow in the sensor's snapshot, whatever host it targeted
  and however old the snapshot was. It now keeps only flows to the window's host
  and ignores a snapshot older than 30 seconds.
- The benchmark refuses to start when the gateway's egress interface has no IPv4
  address, and the report warns about any phase where more than 20% of the
  sample intervals had incoming traffic and no egress traffic. A gateway whose
  egress interface had dropped out would otherwise have every phase measure that
  failure (found on 2026-09-19).
- `scripts/analyze_live_benchmark.py` mixed the two libpcap capture threads. With
  an egress interface the sensor logs a `Capture: status` line per interface and
  the lines interleave, so the cumulative counters were read as one series and a
  phase's captured packet count came out wrong. The status lines are now kept
  apart by interface. A cumulative total taken across a gap in the status lines
  (libpcap logs only when a packet arrives) is no longer credited to the wrong
  phase, and the detection agreement table now shows enforcement actions
  beside DDoS verdicts, since the block and rate limit tiers do most of the
  mitigating. Found while checking the first backend comparison session against
  its raw files.
- Model files are loaded through `storage.load_trusted_model`, which refuses a
  symlink, and a file or directory that another account could have written
  (root owned with no group or other write bit under a root run service, owned
  by the operator with no world write bit otherwise), checked on the open
  descriptor. `joblib.load` unpickles, so this closes a code execution path for
  a replaced model. A refused model leaves Stage 2 in its passive mode.
- `install.sh` and `update.sh` validate the values they write into root run
  systemd units: the `--training-csv` path (safe characters only), and in
  `install.sh` the interface, address lists and tuning numbers, after the flags
  and after the prompts.
- The benchmark helper checks the tuning path itself (directory ownership and
  mode, no symlinks among the files it replaces), and the driver refuses a
  config file owned by another account or writable by everyone.
- The benchmark scripts now validate every config value that reaches a command
  line on the gateway, delete only `flod_benchmark_*.json` files in one named
  directory instead of expanding a glob, keep their helper and output files in
  a root only directory instead of `/tmp`, and refuse to write through a
  symlink. Raised by an independent security review. A wait deadline that lost
  precision, which could let a missing log line hold the helper for hours, was
  also fixed.

### Changed

- Documentation describes results as coming from the simulated lab
  environment throughout.

## 1.6.0, 2026-09-18

### Added

- The Auto Label review page now pages through the staged rows, 500 at
  a time, with Previous and Next buttons and a "Rows 1 to 500 of N"
  line. `/api/auto-label/review` takes `offset` and `limit` (limit
  capped at 500, a negative offset is refused). Previously only the
  first 500 rows of a larger queue could be seen.

### Fixed

- `scripts/analyze_live_benchmark.py` read the kernel backend's
  `Kernel: status` ingress and egress as running totals and reported the
  difference between two samples, which produced negative packet counts.
  Stage 1 resets those counters after every status line, so each one is
  that interval's own count. The kernel backend now sums the samples
  inside a phase, and the pcap backend, whose line is cumulative, keeps
  the difference. Checked against an independent sum of the raw log.

### Documentation

- `docs/benchmark-live-v1.3.0.md` and the benchmark report no longer call the
  Isolation Forest labeling nearly every live window `Anomalous` correct
  operation. Most of it comes from the training corpus and the deployed sensor
  running different sigma floors, which changes two of the Isolation Forest's
  inputs. Scored against 3,000 gateway rows it flagged 100% as they stand and
  27.3% (Normal) and 0.0% (Flash Crowd) with just those two columns swapped.
- New sections in `docs/training.md`: capturing under the tuning you deploy,
  how tree depth sets what the auto-label confidence gate means, and where
  Merge writes (the same file the retrain timer trains on, and `update.sh`
  drops it when `--training-csv` is not passed).
- `docs/benchmark-live-v1.3.0.md` records the 2026-09-18 reruns and why they
  cannot be compared for escalation.
- `docs/roadmap.md`: V7 and V8, both shipped, moved from Planned to Completed.
  New Known Gaps for the tuning mismatch, the depth and confidence gate, and
  benchmark hygiene. A dashboard visual redesign is now listed as planned.
- `docs/lessons-learned.md` gains four entries, `docs/testing.md` has the
  current test counts (75 Rust, 315 Python), and `README.md` describes the
  capture and review loop.
- `SECURITY.md` lists 1.5.x and later as the supported line. `CONTRIBUTING.md`
  documents the version and release title conventions.

## 1.5.0, 2026-09-18

### Added

- Confidence gated automatic labeling now has a real path to new DDoS
  training examples. A window the RandomForest already confidently
  calls DDoS is captured to a new `stage2/ddos_capture.csv`, and
  `auto_label.py` re-scores it exactly like the other two capture
  files, same dual-model agreement, same confidence threshold, same
  freshness check. Previously the pipeline only ever grew the Normal
  and Flash Crowd share of the training corpus.

## 1.4.1, 2026-09-18

### Fixed

- `train.py`'s `max_depth` sweep and `train_second_model.py`'s
  `max_leaf_nodes` sweep both picked whichever candidate scored the
  strict-highest LOSO accuracy, with no penalty for complexity, the
  same failure shape already fixed once for the entropy floor and again
  for the Isolation Forest's `contamination` sweep. Both now select the
  simplest candidate within a new `ACCURACY_TOLERANCE` (0.005) of the
  best accuracy actually seen, so a fraction of a point of difference,
  often noise from a small held-out session, no longer selects a
  needlessly complex model.

## 1.4.0, 2026-09-18

### Added

- A dashboard page for reviewing `auto_label.py`'s staged output:
  timestamped alerts for each completed run with rows to review (a
  matching badge on every page's sidebar), a table of the staged rows,
  and Merge or Discard buttons, so reviewing and resolving a run no
  longer needs the terminal. Merge appends into `TRAINING_CSV_PATH`, a
  new environment variable `install.sh`/`update.sh`'s existing
  `--training-csv` flag also sets on the running service; Discard clears
  the staged file without merging. Both act on the whole queue at once,
  the same file every pending alert points at. Confirmed with a
  merge in the simulated lab environment: 9,538 staged rows appended into the
  training CSV from the dashboard.
- `scripts/benchmark_live.sh` now records system health alongside
  detection outcomes: a new `scripts/benchmark_system_sampler.sh` polls
  both services' CPU time and memory on the gateway for the whole
  session, and `analyze_live_benchmark.py` reports packet
  throughput and drop counts per phase, parsed from the capture
  backend's own existing periodic log line, no new instrumentation
  needed there.

## 1.3.0, 2026-09-15

### Added

- Confidence gated automatic labeling: `stage2/auto_label.py`, run
  periodically by `ddos-stage2-auto-label.timer`, auto-labels a captured
  window into `stage2/auto_labeled_capture.csv` only when the RandomForest
  and a newly introduced second model (`stage2/train_second_model.py`, a
  `HistGradientBoostingClassifier`) agree on the class, are both confident,
  and were both trained after the row was captured. Covers both
  `anomalous_capture.csv` (Isolation Forest flagged windows) and the new
  `pretraining_capture.csv` (windows captured before any RandomForest
  existed on a deployment). Staged rows still require an operator to merge
  them into `training.csv`, never automatic.
- `ddos-stage2-retrain.timer`, an opt-in periodic job (`--training-csv` on
  `install.sh`/`update.sh`, no default) that retrains all three models,
  the RandomForest, the Isolation Forest, and the second model, together.
  The RF and second model retrain so the freshness safeguard above does
  not become a permanent block once a model stops changing; the
  Isolation Forest retrains so its contamination boundary does not go
  stale against live traffic, found in the simulated lab environment scoring
  benign generated traffic as `Anomalous` on effectively every window.
- `is_row_degenerate()`, refusing to auto-label a zero-traffic window
  (every one of `entropy`, `proto_ratio`, `dominant_ip_ratio`,
  `source_port_entropy`, `ttl_variance`, and `fingerprint_diversity`
  reading exactly `0.0`) regardless of model agreement or confidence.
  Found in a simulated lab run: this pattern occurs across all three labels in
  the training corpus, so agreement on it reflects a shared blind spot.
- `--auto-label-interval` and `--retrain-interval` flags on
  `install.sh`/`update.sh`, both operator configurable.
- `scripts/benchmark_live.sh` extended from four phases to the full seven:
  Normal, Flash Crowd, Attacker, then every pairwise mix, then all three
  together, redesigned around one start/stop command pair per traffic
  type so a generator already running into a mixed phase stays running.
  Confirmed end to end in the simulated lab environment against a freshly
  calibrated, freshly retrained deployment: 0% of Flash Crowd traffic escalated to
  DDoS, 100% escalation once all three traffic types combined.

### Security

- File locking (`fcntl.flock`) between `ipc_receiver.py`'s live appends
  and `auto_label.py`'s periodic rewrites of the same capture files,
  closing a race that could silently drop a written row.
- Both capture files bounded, by row count (`AUTO_LABEL_MAX_QUEUE_ROWS`)
  and by file size (`PRETRAINING_MAX_BYTES`), so an unbounded deployment
  cannot grow either file without limit.
- `ddos-stage2-auto-label.timer` and `ddos-stage2-retrain.timer` both run
  at low priority (`Nice=10`, `CPUWeight=20`, `IOSchedulingClass=idle`),
  so neither can contend with live enforcement during a flood.
- `uninstall.sh` now stops, disables, and removes both new timers and
  their oneshot services.

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
  evaluation, with training time, prediction latency, and system
  resource measurements alongside the detection numbers.
- `scripts/train.sh`, an interactive selector for training one or both
  models against a chosen CSV.
- `scripts/build-stage1.sh`, building Stage 1 and its eBPF backend as the
  invoking user rather than as root.
- `docs/explainer.md`, `docs/lessons-learned.md`, `docs/benchmark-results.md`,
  and dashboard and architecture screenshots throughout the README
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
  configured floor for an entire session regardless of the traffic
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
