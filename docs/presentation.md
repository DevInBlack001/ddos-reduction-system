# Presentation

`scripts/present.py` walks through the FLOD pipeline in the terminal, one stage at
a time. Each section shows a title, a short description, and the numbered steps of
that stage. The content lives in `docs/presentation/stages.json`.

```bash
python3 scripts/present.py                   # step through with Enter
python3 scripts/present.py --auto 4          # advance every 4 seconds
python3 scripts/present.py --stage baseline  # start at one stage
python3 scripts/present.py --run             # also run each step's demo command
python3 scripts/present.py --list            # list the stages
python3 scripts/present.py --check           # validate the stages file
```

## Stages

| Id | Stage |
|-|-|
| `capture` | Stage 1: Packet capture |
| `windows` | Stage 1: Windows and features |
| `baseline` | Stage 1: Adaptive baseline |
| `handoff` | The handoff between stages |
| `classification` | Stage 2: Classification |
| `enforcement` | Stage 2: Enforcement |
| `dashboard` | Dashboard, alerts and reports |
| `learning` | The learning loop |
| `benchmark` | Benchmarking the gateway |

## Demo commands

A step can carry a `command`, a list of strings. With `--run` the presenter runs it
without a shell, waits at most 15 seconds, and shows up to 20 lines of output.
The shipped commands only read state (`journalctl`, `ls`, `ipset list -terse`, `curl`
against the local dashboard), so run the presenter on the gateway for live output.
A program that is not installed or a path that does not exist is reported on the
slide and the presentation continues.

## Adding or changing a stage

Edit `docs/presentation/stages.json`. A stage has an `id`, a `title`, a `description`
and a list of `steps`, each a string or an object with `text` and an optional
`command`. Keep one stage per piece of the pipeline, describe what it does and not how
the code is arranged, and update the stage in the same change that alters the
behavior. Run `python3 scripts/present.py --check` before committing.
