# Playbooks

**Files:** `stage2/playbooks.py`, `stage2/playbooks_api.py`,
`stage2/static/playbooks.html`, `stage2/schema.py`

Design spec: [docs/specs/2026-09-13-playbooks-design.md](specs/2026-09-13-playbooks-design.md).
V10 roadmap entry: [docs/roadmap.md](roadmap.md).

## What a playbook is, and what it is not

A playbook is a second, optional layer on top of the four enforcement
tiers documented in [Enforcement](enforcement.md#the-four-tiers). **The
four tiers keep running automatically and unconditionally on every
window, exactly as they do with zero playbooks configured.** A playbook
never replaces, gates, delays, or overrides that path. Writing a new
playbook does not change how any existing traffic is already being
enforced against; it only adds a second, separately-triggered sequence
of actions on top.

What a playbook adds that the tiers alone cannot do:

- **Escalate a target over time**, without an operator watching and
  acting by hand: "if this host is still under attack five windows from
  now, take it to the next tier."
- **Fire an external alert as a scripted step**, timed however an
  operator wants, rather than only the one baseline notification the
  system already sends on a DDoS verdict.
- **Generate an incident report the moment the trigger fires**, instead
  of waiting for an operator to pull one later from the Incident
  Response page.

A playbook belongs to an operator, not to this codebase: it is
configured data, not code, and different deployments are expected to
want different sequences.

**Non-goals**, deliberately out of scope: branching (stages are a
linear, ordered sequence, never conditional), widening a block to a
subnet (escalation stays scoped to the same source or host the tier
system already attributes traffic to), and a new firewall backend (a
playbook's escalate stage calls the exact same `enforcement.py`
functions the tiers already call).

## Triggers

A playbook has one or more triggers and a `trigger_mode` (`any` or
`all`) saying how they combine. Evaluated once per window per protected
host, immediately after that window's tier decision is made, since
`tier_reached` needs to read the tier the window was just classified
into.

| Trigger type | Field | Fires when |
|-|-|-|
| `tier_reached` | `min_tier` (default 1) | The window's enforcement reached at least this tier (1 highest severity, 4 lowest; see [Enforcement](enforcement.md#the-four-tiers)) |
| `persistence` | `consecutive_windows` (default 1) | This host has been classified as under attack for at least this many consecutive windows |
| `scale` | `min_hosts_simultaneously` (default 1) | At least this many protected hosts are under attack in the same window |

A playbook is not required to use all three; they are building blocks,
combinable per playbook however an operator chooses.

At most one `running` run exists per `(playbook, host)` pair at a time.
While a run is already in progress for a host, that playbook's trigger
is not re-evaluated for that host, a still-firing trigger cannot spawn a
second, duplicate run.

## Stages

Once a run starts, its stages fire in order, each after its own
`delay_seconds` has elapsed since the previous stage (or since the run
started, for the first one). `delay_seconds: 0` fires immediately, on
the same window the run starts. A run with no stages left is marked
`completed`.

Three stage types, a closed set the engine interprets, not arbitrary
operator-supplied logic:

| Stage type | Fields | Action |
|-|-|-|
| `escalate` | `target_tier` (default 1) | Tier 1 or 2: blocks the run's attributed source. Tier 3 or 4: rate-limits it. Calls the exact same `enforcement.py` functions the tiers themselves call; this stage only changes *when* an existing action happens, never *what* the action is. |
| `notify` | `channel` (default `all`) | Sends the existing Discord/SMTP alert as a scripted step, in addition to the baseline alert the system already fires on a DDoS verdict, not a replacement for it. |
| `report` | none | Generates the incident report immediately (reusing the existing 6 hour report window) and writes it under `config.PLAYBOOK_REPORTS_DIR`, instead of waiting for an operator to pull one by hand from Incident Response. |

If a run's attributed source is unknown at escalate time (no single
source could be attributed, e.g. `Unknown`, `0.0.0.0`, `::`), the
escalate stage records that it was skipped rather than escalating
nobody.

## Target scope

A playbook is scoped to `host` (one protected IP address),
`subnet` (a CIDR range), or `all` (every protected host). Set once,
validated server-side (`host` must parse as a real address, `subnet` as
a real CIDR).

## Definition document

Both editing surfaces (the form builder and the JSON/YAML text editor)
read and write the same one JSON document, so a hand-edited definition
can never express anything the form couldn't have produced; both are
validated server-side against the closed trigger/stage type lists
above.

```json
{
  "triggers": [
    { "type": "tier_reached", "min_tier": 1 }
  ],
  "trigger_mode": "any",
  "stages": [
    { "type": "notify", "delay_seconds": 0, "channel": "all" },
    { "type": "escalate", "delay_seconds": 60, "target_tier": 2 }
  ]
}
```

The same document as YAML, exactly as the text editor tab accepts it
(normalized to the JSON above server-side on save):

```yaml
triggers:
  - type: tier_reached
    min_tier: 1
trigger_mode: any
stages:
  - type: notify
    delay_seconds: 0
    channel: all
  - type: escalate
    delay_seconds: 60
    target_tier: 2
```

## Example playbooks to test with

Three ready-to-use definitions, each exercising a different trigger
type, for pasting straight into the JSON/YAML tab on `/playbooks.html`
(scope each to a real protected host or subnet before saving):

**Notify immediately, escalate a minute later** (the walkthrough in
`STATUS.md`'s Antigravity checklist):

```json
{
  "triggers": [{ "type": "tier_reached", "min_tier": 1 }],
  "trigger_mode": "any",
  "stages": [
    { "type": "notify", "delay_seconds": 0, "channel": "all" },
    { "type": "escalate", "delay_seconds": 60, "target_tier": 2 }
  ]
}
```

**Only act once an attack has actually persisted**, rather than on the
first flagged window:

```json
{
  "triggers": [{ "type": "persistence", "consecutive_windows": 5 }],
  "trigger_mode": "any",
  "stages": [
    { "type": "report", "delay_seconds": 0 },
    { "type": "notify", "delay_seconds": 0, "channel": "all" }
  ]
}
```

**React to a coordinated event across the whole network**, several
hosts under attack at once, not just one:

```json
{
  "triggers": [{ "type": "scale", "min_hosts_simultaneously": 3 }],
  "trigger_mode": "any",
  "stages": [
    { "type": "notify", "delay_seconds": 0, "channel": "all" },
    { "type": "report", "delay_seconds": 30 }
  ]
}
```

## Run history and reporting

`/playbooks.html` shows run history (`running`/`completed`/`cancelled`,
which stage it's on, why it started) with each run's own event list
expandable inline, and the reports a `report` stage has generated so
far.

The incident report (`/ir.html`, and any report a `report` stage
generates) gains two sections from this milestone: a **timeline** of
which stage fired when and against which source or host, and a
**per-source detail table** (first seen, last seen, peak rate, current
enforcement status) for the incident's duration. Both are additive to
the report's existing content.

## API reference

| Method | Path | Purpose |
|-|-|-|
| GET | `/api/playbooks` | List all playbooks |
| POST | `/api/playbooks` | Create a playbook |
| GET | `/api/playbooks/{id}` | Get one playbook |
| PUT | `/api/playbooks/{id}` | Replace a playbook's name/scope/definition |
| POST | `/api/playbooks/{id}/toggle` | Body `{"enabled": bool}`, flips enable state without resending the definition |
| DELETE | `/api/playbooks/{id}` | Delete a playbook and cascade its run/event history |
| POST | `/api/playbooks/validate` | Check a definition without saving it |
| POST | `/api/playbooks/parse-yaml` | Body `{"yaml": "<text>"}`, normalizes YAML to the same JSON shape |
| GET | `/api/playbooks/runs` | Recent run history (`?limit=`, default 50, max 200) |
| GET | `/api/playbooks/runs/{run_id}/events` | One run's stage-by-stage event log |
| GET | `/api/playbooks/reports` | Files a `report` stage has written |
| GET | `/api/playbooks/reports/{filename}` | Download one report (filename only, no path segments accepted) |

Every literal-path GET route above (`/runs`, `/reports`, etc.) is
registered before the generic `GET /api/playbooks/{id}` in
`playbooks_api.py`, deliberately: FastAPI matches by path shape before
validating a path parameter's type, so the generic route registered
first would have tried to parse `"runs"` as an integer and 422 instead
of ever reaching the intended handler.

## Testing

`stage2/tests/test_playbooks.py` covers each trigger type independently,
both `trigger_mode` settings, run lifecycle (start on trigger, no
duplicate run while one is already running, stage advancement respecting
`delay_seconds`, completion after the last stage), and each stage type's
action with `enforcement.py`/`alerts.py`/`report_pdf.py` calls mocked.
`stage2/tests/test_playbooks_api.py` covers the HTTP surface: CRUD,
scope validation, definition validation, run history, and report listing
including path-traversal and symlink-refusal cases.

## Open questions

Carried over from the design spec, not yet resolved:

- Whether `scale`'s "hosts under attack simultaneously" trigger should
  read as a raw count or a fraction of currently-tracked hosts. A raw
  count of 3 reads very differently depending on whether there are 4
  protected hosts or 40. Currently a raw count with a documented,
  non-authoritative default, pending a real multi-host capture to size
  it sensibly.
- Whether a `report` stage firing mid-incident, before the incident has
  resolved, needs different framing in the PDF (an explicit "still in
  progress" marker) rather than reusing the after-the-fact template as
  though the reported window had already closed.
