# V9: Operator-Defined Playbooks and Granular Incident Reporting

Design spec. Corresponds to the V9 roadmap entry in `docs/roadmap.md`.

## Goal

Today, enforcement is a single automatic pass per window: four fixed tiers,
evaluated in order, self-healing on expiry. Nothing sequences a response
over time, and nothing lets an operator script "if this keeps happening,
also do that." This milestone adds a second, optional layer on top: a
playbook that starts when a trigger condition fires and runs a sequence of
stages over time. The four tiers keep running exactly as they do today,
unconditionally, on every window, regardless of whether any playbook is
configured. A playbook adds to that behaviour; it never replaces or gates
it.

## Non-goals

Explicitly out of scope for this milestone, recorded so they don't get
re-added by accident partway through:

- **Branching.** Stages are a linear, ordered sequence. Nothing described
  for this milestone needs a conditional stage graph, and a graph is a
  materially bigger and harder to secure thing to build (an operator
  authoring conditions is closer to authoring logic, which is exactly the
  kind of exposure the closed stage-type list below exists to avoid).
- **Widening block scope to a subnet.** Considered and deliberately left
  out; escalation stays scoped to the same source or host the tier system
  already attributes traffic to.
- **A new firewall backend.** Separate milestone (V10). A playbook's
  escalate stage calls the same `enforcement.py` functions the tiers
  already call; it does not know or care which backend is enforcing the
  result underneath.

## Data Model

Three new tables in `stage2.db`, following `schema.py`'s existing
single-definition convention.

**`playbooks`**: `id`, `name`, `target_scope_type` (`host` | `subnet` |
`all`), `target_scope_value`, `enabled`, `definition` (JSON, see below),
`created_at`, `updated_at`.

`definition` is the single canonical document both editing surfaces read
and write, one JSON object per playbook with two arrays: `triggers` and
`stages`. Storing the whole thing as one JSON column rather than a
normalized `playbook_triggers`/`playbook_stages` join table is a
deliberate simplification: a playbook is authored and edited as one
document by one operator, not queried or joined against by anything else
in the system, so a relational breakdown would add schema complexity
nothing here needs.

```json
{
  "triggers": [
    {"type": "tier_reached", "min_tier": 1},
    {"type": "persistence", "consecutive_windows": 5},
    {"type": "scale", "min_hosts_simultaneously": 3}
  ],
  "trigger_mode": "any",
  "stages": [
    {"type": "escalate", "delay_seconds": 300, "target_tier": 1},
    {"type": "notify", "delay_seconds": 0, "channel": "discord"},
    {"type": "report", "delay_seconds": 60, "format": "pdf"}
  ]
}
```

`trigger_mode` is `any` or `all` across whichever trigger entries the
operator included; a playbook is not required to use all three trigger
types, they are the available building blocks, combinable per playbook as
the operator chooses, per the earlier decision that all three should
exist rather than picking one.

**`playbook_runs`**: `id`, `playbook_id`, `target_host`, `target_source`
(nullable, the attributed source if the trigger was source-specific),
`current_stage_index`, `status` (`running` | `completed` | `cancelled`),
`trigger_reason`, `started_at`, `updated_at`. One row per active or
completed execution. A playbook can have many runs over time, but at most
one `running` row per `(playbook_id, target_host)` pair, checked before
starting a new one so a still-firing trigger doesn't spawn duplicate runs.

**`playbook_events`**: `id`, `run_id`, `stage_index`, `stage_type`,
`fired_at`, `target_source`, `detail` (free text, e.g. which tier was
escalated to, which alert channel fired, which report file was written).
This is what backs the new reporting requirement: a timeline of which
stage fired when, and against which source, distinct from the existing
window-by-window classification log in `logs`.

## Trigger Evaluation

Evaluated once per window per protected host, in `ipc_receiver.py`,
immediately after the existing `apply_safety_overrides()` call (that
ordering matters: a playbook's trigger check reads the tier the window
was just classified into, so it has to run after that decision is made,
never before).

For each enabled playbook whose `target_scope` matches the current host:

1. If a `running` run already exists for this `(playbook, host)`, skip
   trigger evaluation entirely and go to stage advancement below.
2. Otherwise, evaluate each configured trigger against this window and
   this host's existing rolling state (the same per-target counters the
   tier system already keeps for hysteresis and cooldown; `scale` reads
   across all currently tracked hosts, not just this one). Combine per
   `trigger_mode`. If the result is true, insert a new `playbook_runs`
   row at `current_stage_index = 0` with `started_at = now`.

No new counters are introduced for `tier_reached` or `persistence`; both
read state the tier system already maintains. `scale` is the one genuinely
new piece of shared state: a count of hosts currently classified as under
attack in the same window, computed once per window cycle and read by
every playbook's trigger check rather than recomputed per playbook.

## Stage Execution and Advancement

Also once per window, for every `running` playbook_run: if
`now - stage_started_at >= stages[current_stage_index].delay_seconds`,
execute that stage, write a `playbook_events` row, and advance
`current_stage_index`. A run whose stages are exhausted is marked
`completed`. `delay_seconds: 0` fires immediately on the same window the
run started, which is what makes a "notify right away, escalate later"
sequence expressible without any special-casing in the engine.

Three stage types, a closed set the engine interprets rather than
arbitrary operator-supplied logic:

- **`escalate`**: calls the same `enforcement.py` block/throttle functions
  the tiers already call, against the run's `target_source` (or, for a
  `scale`-triggered run with no single attributable source, every source
  the aggregate fallback tier is already throttling for that host).
  `target_tier` says which tier's action to invoke; there is no new
  enforcement primitive here, this stage only changes *when* an existing
  action happens, not *what* the action is.
- **`notify`**: calls the existing Discord/SMTP alert functions in
  `alerts.py` as a scripted step. Additive to whatever baseline alerting
  already fires on a DDoS verdict; a playbook's notify stage is a second,
  deliberately timed notification, not a replacement for the existing
  one.
- **`report`**: calls `report_data.py`/`report_pdf.py` for the ongoing
  incident immediately, writing the result somewhere the dashboard
  surfaces, rather than waiting for an operator to pull one later from the
  Incident Response page.

## Editing Surfaces

One stored `definition` document, two ways to edit it, both round-tripping
to the same JSON:

- **Form builder**: add/remove/reorder trigger and stage rows, each with a
  type dropdown and type-specific fields, following the same pattern the
  dashboard's existing settings pages (Firewall, Alerts) already use.
- **Text editor**: the same `definition` document as raw JSON or YAML
  (YAML normalized to JSON server-side on save). Validated server-side
  against a strict schema restricted to the closed trigger/stage type
  lists above; an operator can hand-edit a definition, but cannot express
  anything the form builder couldn't have produced, which is what keeps
  this from becoming an arbitrary-logic surface.

Switching surfaces mid-edit re-renders from whichever was last saved; there
is no live two-way sync while typing, only on save.

## Reporting Integration

Two additions to the existing incident report (`report_data.py`,
`report_pdf.py`, `ir.html`/`reports.py`):

- A **timeline** section, one row per `playbook_events` entry in the
  report's time window: stage type, when it fired, and against which
  source or host, distinct from the existing window-by-window
  classification table.
- A **per-source breakdown** within a single incident: the existing report
  gives aggregate volume and concentration per window; this adds a
  per-source table for the incident's duration, so an operator can see
  which individual sources were escalated against, not only the aggregate
  picture.

Both are additive to the existing report structure.

## Testing Plan

New `stage2/tests/test_playbooks.py`:

- Each trigger type independently (`tier_reached`, `persistence`,
  `scale`), and `trigger_mode` combination (`any`/`all`).
- Run lifecycle: start on trigger, no duplicate run while one is already
  `running`, stage advancement respecting `delay_seconds`, completion
  after the last stage.
- Each stage type's action, with `enforcement.py`/`alerts.py`/
  `report_pdf.py` calls mocked, asserting the correct function is called
  with the correct target rather than exercising real iptables or a real
  alert delivery.
- The two editing surfaces: a form-built definition and a hand-written
  JSON/YAML definition describing the same playbook produce identical
  stored documents; the schema validator rejects a stage or trigger type
  outside the closed lists.

No Rust changes. This milestone is entirely Stage 2 and dashboard work,
which is also why it carries none of the kernel-level verifier risk the
firewall backend milestone (V10) does, per the roadmap's difficulty
ordering.

## Open Questions

- Whether `scale`'s "hosts under attack simultaneously" count should be a
  raw count or a fraction of currently-tracked hosts (a raw count of 3 out
  of 4 protected hosts reads very differently from 3 out of 40). Leaning
  toward a raw count with a documented, non-authoritative default, per
  this project's own convention that a threshold like this is a starting
  point, not a proven value, but this needs a real multi-host capture to
  size sensibly.
- Whether a `report` stage firing mid-incident, before the incident has
  fully resolved, needs any different framing in the PDF than the existing
  after-the-fact report (e.g. an explicit "still in progress" marker on
  the cover page) rather than reusing the existing template as though the
  window being reported on had already closed.
