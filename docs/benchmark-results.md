# Benchmark Results

Full output of `scripts/benchmark_fixed_threshold.py`, run against the
corrected, merged V7 training set (60,891 rows, 21 sessions across Normal,
Flash Crowd, and DDoS). See [Roadmap](roadmap.md#benchmark-flod-vs-fixed-threshold)
for the summary and the methodology decisions behind this script.

## Environment

Everything below ran on the sensor VM this project deploys and verifies
against, not a laptop and not a shared CI runner. The numbers are only
meaningful relative to this specific machine.

| | |
|-|-|
| CPU | Intel(R) Core(TM) i7-8650U @ 1.90GHz, 4 vCPUs, 1 thread per core |
| Memory | 3.8 GiB total |
| Disk | 15 GB root filesystem, 4.4 GB free at the time of this run |
| OS | Fedora Linux 44 (Server Edition), kernel 6.19.10 |
| Virtualization | VMware guest |
| Python | 3.14, scikit-learn 1.9.0, joblib 1.5.3 (the exact pins in `stage2/requirements.txt`, run from the deployed venv at `/opt/flod/stage2/venv`, not an ad hoc one) |

A 4 vCPU, 3.8 GiB VM is a modest machine by design: FLOD's stated job is
running on the gateway alongside the traffic it inspects, not on
dedicated training hardware. The performance numbers below describe what
that machine can do, not a best case.

## Dataset

60,891 rows after merging the original 35,442 row capture with a fresh
25,449 row recapture using jittered traffic generators. 59,489 rows survive
the same cleaning `stage2/train.py` applies (duplicate rows, warm-up-rate
Flash Crowd rows, idle-rate DDoS rows). 21 independent sessions: 9 Normal,
7 Flash Crowd, 5 DDoS by session count (rows per session vary; see
`train.py`'s own session table for the per-session breakdown).

## RandomForest: Leave-One-Session-Out

Every prediction below comes from a model that never saw its own row's
session during training.

```
max_depth=1:    LOSO accuracy=0.980
max_depth=2:    LOSO accuracy=0.986
max_depth=3:    LOSO accuracy=0.997
max_depth=4:    LOSO accuracy=0.997
max_depth=5:    LOSO accuracy=0.997   <- selected
max_depth=6:    LOSO accuracy=0.995
max_depth=7:    LOSO accuracy=0.995
max_depth=8:    LOSO accuracy=0.995
max_depth=9:    LOSO accuracy=0.993
max_depth=10:   LOSO accuracy=0.993
max_depth=None: LOSO accuracy=0.992
```

Full 3-class report at the selected depth:

```
                 precision    recall  f1-score   support

     Normal (0)       0.99      1.00      1.00     20079
Flash Crowd (1)       1.00      1.00      1.00     22157
       DDoS (2)       1.00      0.99      0.99     17253

       accuracy                           1.00     59489

Confusion matrix:
[[20039     1    39]
 [    0 22148     9]
 [  122    19 17112]]
```

## Isolation Forest: Leave-One-Session-Out

`stage2/train_isolation_forest.py`'s own reported outlier rate is measured
on the same data it fit on, since the model is unsupervised and has no
held-out label to score against in production. This benchmark holds it to
the RandomForest's own standard instead: contamination is picked once
against the full dataset (matching the production script exactly), and
only the resulting single value is then evaluated under genuine LOSO.

```
contamination=0.01:  DDoS outlier rate=2.4%,  benign outlier rate=0.4%,  separation=+0.019
contamination=0.02:  DDoS outlier rate=5.3%,  benign outlier rate=0.7%,  separation=+0.046
contamination=0.05:  DDoS outlier rate=12.9%, benign outlier rate=1.8%,  separation=+0.112
contamination=0.075: DDoS outlier rate=19.8%, benign outlier rate=2.5%,  separation=+0.173
contamination=0.1:   DDoS outlier rate=26.9%, benign outlier rate=3.1%,  separation=+0.238  <- selected
contamination=0.15:  DDoS outlier rate=38.6%, benign outlier rate=5.3%,  separation=+0.333  (over the 5% benign cap)
contamination=0.2:   DDoS outlier rate=54.4%, benign outlier rate=5.9%,  separation=+0.485  (over the cap)
contamination=0.25:  DDoS outlier rate=70.9%, benign outlier rate=6.2%,  separation=+0.647  (over the cap)
```

Held-out outlier rate by scenario at `contamination=0.1`:

```
Normal       7.7% of 20079 rows flagged as outliers
Flash Crowd  0.0% of 22157 rows flagged as outliers
DDoS        51.1% of 17253 rows flagged as outliers
```

**A note on reproducibility worth stating plainly.** The Isolation Forest
model this project actually deploys, `ddos_if_model.joblib`, is trained by
`train_isolation_forest.py`, which selected `contamination=0.15` on this
same dataset, not the `0.1` this benchmark selected. Both scripts share
identical filtering and feature logic, but `train_isolation_forest.py`
does not sort rows by timestamp first and this benchmark's shared
`load_and_prepare()` does; `IsolationForest`'s random sampling draws from
array position, not row identity, so a different row order can select a
different contamination candidate even with the same `random_state`. Not
a bug in either script, a real sensitivity of the algorithm to input
order that happens to matter here because the separation-vs-cap
selection criterion sits close to a boundary between candidates. The
numbers above describe the Isolation Forest's general held-out behaviour
faithfully; they are not a byte-for-byte description of the specific
`ddos_if_model.joblib` this project ships. Worth unifying (add the same
timestamp sort to `train_isolation_forest.py`) as a small follow-up, not
done as part of this benchmark.

## Detection comparison

RandomForest and Isolation Forest as evaluated above, against a fixed
threshold at 3x the observed Normal mean rate (62.95 pps), chosen once
before scoring, per [Roadmap](roadmap.md#benchmark-flod-vs-fixed-threshold)'s
stated methodology.

```
Scenario          Rows   RandomForest   Isolation Forest      Fixed
Normal           20079           0.2%               7.7%       0.0%
Flash Crowd      22157           0.0%               0.0%     100.0%
DDoS             17253          99.2%              51.1%      98.9%
```

For Normal and Flash Crowd, the figure is a false-positive rate (lower is
better). For DDoS, it is recall or outlier rate (higher is better).

```
RandomForest (trained classifier, held-out)
  precision=99.7%  recall=99.2%  f1=99.5%  fpr=0.1%  fnr=0.8%

Isolation Forest (held-out, outlier-as-DDoS-vote, a narrower question than
what it is actually for; see the reproducibility note above)
  precision=85.1%  recall=51.1%  f1=63.8%  fpr=3.6%  fnr=48.9%

Fixed threshold
  precision=43.5%  recall=98.9%  f1=60.4%  fpr=52.5%  fnr=1.1%
```

Flash Crowd traffic correctly left alone, the operational number this
benchmark exists to surface, since a fixed threshold cannot structurally
tell a legitimate surge from an attack the way the trained models can:

```
RandomForest:      100.0%
Isolation Forest:  100.0%
Fixed threshold:     0.0%
```

## Performance

Training and prediction cost of a production-shaped fit on the full
dataset, not the LOSO sweeps above (those exist to pick a hyperparameter
and measure generalisation, not real-world cost). Packets/sec, Gbps, and
Stage 1 overhead need a live traffic phase and are out of reach of a CSV
replay by construction; they belong to a later benchmark phase once the
XDP rate limiter comparison arm exists.

```
RandomForest:
  fit:      1.70s on 66,471 rows (balanced training set)
  predict:  0.100s on 59,489 rows (596,564 rows/sec, 0.002 ms/row)
  model size on disk: 420.9 KB

Isolation Forest:
  fit:      0.61s on 59,489 rows
  predict:  0.209s on 59,489 rows (284,372 rows/sec, 0.004 ms/row)
  model size on disk: 1022.1 KB
```

Both models predict fast enough, on this modest 4 vCPU VM, to classify
every window Stage 1 could plausibly produce with room to spare; window
cadence is measured in seconds, prediction here is measured in
milliseconds per tens of thousands of rows.

Evaluation-only costs, not representative of real deployment (a single
production fit, above, is): the RandomForest's 11-depth LOSO sweep took
403.8s; the Isolation Forest's single-contamination LOSO evaluation took
12.0s.

## System resource usage

Measured from this process's own CPU accounting (the standard library
`resource` module), not an external sampler polling over SSH, since an
earlier attempt at SSH-based sampling for this same exercise proved
unreliable and is not repeated here.

```
Phase                              Wall       CPU   Cores~   Peak RSS
load and prepare                   0.2s      2.7s      n/a    184 MB
RandomForest LOSO sweep          403.8s   1406.9s      3.5    283 MB
Isolation Forest contamination     5.9s      6.0s      1.0    283 MB
Isolation Forest LOSO             12.0s     12.2s      1.0    283 MB
production-shaped fit and predict  2.8s      7.4s      2.7    283 MB
total                            424.6s   1435.3s      3.4    283 MB
```

Peak RSS is a whole-process high-water mark, not an isolated reading per
phase: each row is the peak up to and including that phase. 283 MB peak
against 3.8 GiB available is comfortable headroom on this VM; disk usage
changed by under 25 KB over the entire run, this workload's footprint is
the two model files, nothing more.

The RandomForest LOSO sweep is the only phase that meaningfully uses more
than one core (3.5 of 4 on average), because `n_estimators=100,
n_jobs=-1` parallelises tree construction within a single fit; the
Isolation Forest phases run closer to one core, since each of their fits
is individually smaller and the loop between sessions is sequential.

## Reproducing this

```bash
python3 scripts/benchmark_fixed_threshold.py <path-to-training-csv>
```

Needs at least two independent sessions per label for LOSO to run at all.
Wall time scales with session count and dataset size; on this VM, the
21-session, 60,891-row run above took just over seven minutes end to end.
