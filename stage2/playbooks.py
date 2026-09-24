"""
playbooks.py: operator-defined playbooks, V10.

A playbook is a second, optional layer on top of the four enforcement
tiers, which keep running automatically and unconditionally on every
window exactly as they do today, regardless of whether any playbook is
configured. A playbook adds to that behaviour; it never replaces or gates
it. It starts when a trigger condition fires and runs a linear, ordered
sequence of stages over time: escalate, notify, report. Stages are
linear, no branching, per this milestone's own non-goals.

See docs/specs/2026-09-13-playbooks-design.md for the full design.
"""

import json
import logging
import os
import time

import alerts
import config
import db
import enforcement

TRIGGER_TYPES = {"tier_reached", "persistence", "scale"}
STAGE_TYPES = {"escalate", "notify", "report"}
TRIGGER_MODES = {"any", "all"}


class DefinitionError(ValueError):
    """A playbook definition used a trigger or stage type outside the
    closed lists above, or was otherwise malformed. Raised on both editing
    paths (the form builder's own output and a hand-edited JSON/YAML
    document), so a hand-edited definition can never express anything the
    form builder couldn't have produced."""


def validate_definition(definition):
    """Raise DefinitionError on anything outside the closed trigger/stage
    type lists, or a malformed shape. Returns `definition` unchanged so it
    can be used inline: `stored = validate_definition(parsed)`."""
    if not isinstance(definition, dict):
        raise DefinitionError("definition must be a JSON object")

    triggers = definition.get("triggers")
    stages = definition.get("stages")
    trigger_mode = definition.get("trigger_mode", "any")

    if not isinstance(triggers, list) or not triggers:
        raise DefinitionError("definition needs at least one trigger")
    if not isinstance(stages, list) or not stages:
        raise DefinitionError("definition needs at least one stage")
    if trigger_mode not in TRIGGER_MODES:
        raise DefinitionError(f"trigger_mode must be one of {sorted(TRIGGER_MODES)}")

    for t in triggers:
        if not isinstance(t, dict) or t.get("type") not in TRIGGER_TYPES:
            raise DefinitionError(f"trigger type must be one of {sorted(TRIGGER_TYPES)}")

    for s in stages:
        if not isinstance(s, dict) or s.get("type") not in STAGE_TYPES:
            raise DefinitionError(f"stage type must be one of {sorted(STAGE_TYPES)}")
        delay = s.get("delay_seconds", 0)
        if not isinstance(delay, (int, float)) or isinstance(delay, bool) or delay < 0:
            raise DefinitionError("stage delay_seconds must be a non-negative number")

    return definition


def _trigger_fires(trigger, tier_reached, consecutive_windows, hosts_under_attack):
    ttype = trigger.get("type")
    if ttype == "tier_reached":
        return tier_reached >= trigger.get("min_tier", 1)
    if ttype == "persistence":
        return consecutive_windows >= trigger.get("consecutive_windows", 1)
    if ttype == "scale":
        return hosts_under_attack >= trigger.get("min_hosts_simultaneously", 1)
    return False


def evaluate_triggers(definition, tier_reached, consecutive_windows, hosts_under_attack):
    """Whether this window's state fires this playbook's trigger, combined
    across however many trigger entries the operator configured, per
    `trigger_mode`. A playbook is not required to use all three trigger
    types; they are the available building blocks, combinable as the
    operator chooses."""
    results = [
        _trigger_fires(t, tier_reached, consecutive_windows, hosts_under_attack)
        for t in definition["triggers"]
    ]
    mode = definition.get("trigger_mode", "any")
    return all(results) if mode == "all" else any(results)


def check_and_start_runs(victim_ip, tier_reached, consecutive_windows, hosts_under_attack,
                          target_source, now=None):
    """Evaluated once per window per protected host, immediately after
    apply_safety_overrides(): a playbook's trigger check reads the tier the
    window was just classified into, so it has to run after that decision
    is made, never before.

    For each enabled playbook whose target_scope matches this host: if a
    running run already exists for this (playbook, host), skip trigger
    evaluation entirely, that running run's own stage advancement, a
    separate once-per-window pass across every running run in
    advance_runs(), is what moves it forward. Otherwise evaluate the
    trigger and start a new run if it fires."""
    now = now if now is not None else time.time()
    for playbook_id, definition_json in db.get_enabled_playbooks_for_host(victim_ip):
        if db.get_active_playbook_run(playbook_id, victim_ip) is not None:
            continue
        try:
            definition = validate_definition(json.loads(definition_json))
        except (DefinitionError, json.JSONDecodeError) as e:
            logging.error(f"[-] Playbook {playbook_id} has an invalid stored definition: {e}")
            continue
        if evaluate_triggers(definition, tier_reached, consecutive_windows, hosts_under_attack):
            reason = (
                f"tier={tier_reached} consecutive={consecutive_windows} "
                f"hosts_under_attack={hosts_under_attack}"
            )
            run_id = db.start_playbook_run(playbook_id, victim_ip, target_source, reason, now)
            logging.info(f"[+] Playbook {playbook_id} run {run_id} started for {victim_ip} ({reason})")


def advance_runs(now=None):
    """Once per window: for every running playbook_run, execute the current
    stage once its delay has elapsed, then advance. A run whose stages are
    exhausted is marked completed.

    `stage_started_at` from the design spec is `updated_at` here: a run's
    `updated_at` is set to `started_at` when it is created and to `now`
    every time a stage advances, so it always holds when the current stage
    began. `delay_seconds: 0` therefore fires immediately on the same pass
    the run started, since `now - updated_at` is 0 at that point, which is
    what makes a "notify right away, escalate later" sequence expressible
    without any special-casing here."""
    now = now if now is not None else time.time()
    for run in db.get_running_playbook_runs():
        run_id, playbook_id, target_host, target_source, stage_index, started_at, updated_at = run
        definition_json = db.get_playbook_definition(playbook_id)
        if definition_json is None:
            continue
        try:
            definition = validate_definition(json.loads(definition_json))
        except (DefinitionError, json.JSONDecodeError):
            continue

        stages = definition["stages"]
        if stage_index >= len(stages):
            db.advance_playbook_run(run_id, None, now)
            continue

        stage = stages[stage_index]
        if now - updated_at < stage.get("delay_seconds", 0):
            continue

        detail = execute_stage(stage, target_host, target_source)
        db.record_playbook_event(run_id, stage_index, stage["type"], target_source, detail, now)
        next_index = stage_index + 1
        db.advance_playbook_run(run_id, next_index if next_index < len(stages) else None, now)


def execute_stage(stage, target_host, target_source):
    """Run one stage's action, returning a short human-readable detail
    string for the run's event log. A closed set of three stage types the
    engine interprets, not arbitrary operator-supplied logic."""
    stage_type = stage["type"]
    if stage_type == "escalate":
        return _execute_escalate(stage, target_host, target_source)
    if stage_type == "notify":
        return _execute_notify(stage, target_host, target_source)
    if stage_type == "report":
        return _execute_report(target_host)
    return f"unknown stage type {stage_type!r}"


def _execute_escalate(stage, target_host, target_source):
    """Calls the same enforcement.py block/throttle functions the tiers
    already call, against the run's target_source. There is no new
    enforcement primitive here: target_tier only changes when an existing
    action happens, not what the action is. Tiers 1 and 2 block, 3 and 4
    rate-limit, matching the tier numbering in docs/detection.md."""
    if not target_source or target_source in ("Unknown", "0.0.0.0", "::"):
        return "no attributable source, escalate stage skipped"
    tier = stage.get("target_tier", 1)
    cfg = config.get_enforcement_config()
    if tier <= 2:
        enforcement.block_ip(target_source, duration=cfg["block_duration_seconds"], victim_ip=target_host)
        return f"blocked {target_source} (tier {tier})"
    enforcement.ratelimit_ip(target_source, duration=cfg["ratelimit_duration_seconds"], victim_ip=target_host)
    return f"rate-limited {target_source} (tier {tier})"


def _execute_notify(stage, target_host, target_source):
    """Calls the existing alert functions as a scripted step. Additive to
    whatever baseline alerting already fires on a DDoS classification
    transition; a playbook's notify stage is a second, deliberately timed
    notification, not a replacement for that one."""
    channel = stage.get("channel", "all")
    subject = f"FLOD System: playbook escalation for {target_host}"
    message = f"Playbook stage fired against {target_host}"
    if target_source:
        message += f", source {target_source}"
    message += "."
    alerts.dispatch_alert(subject, message)
    return f"notified ({channel})"


def _execute_report(target_host):
    """Generates the incident report immediately rather than waiting for an
    operator to pull one later from the Incident Response page, and writes
    it under config.PLAYBOOK_REPORTS_DIR. Reuses report_data.py's existing
    6 hour default window; a playbook-specific window, and dashboard
    surfacing of this directory, are both open questions in the design
    spec, not built yet.

    Imported locally rather than at module load: report_pdf.py pulls in
    WeasyPrint, no reason to pay that import cost for every playbook
    evaluation when most stages are escalate or notify."""
    import report_data
    import report_pdf

    try:
        ctx = report_data.build_context(hours=6.0)
        pdf_bytes = report_pdf.render_pdf(ctx)
    except Exception as e:
        logging.error(f"[-] Playbook report stage failed to render: {e}")
        return f"report generation failed: {e}"

    os.makedirs(config.PLAYBOOK_REPORTS_DIR, exist_ok=True)
    filename = f"playbook_report_{target_host}_{int(time.time())}.pdf"
    path = os.path.join(config.PLAYBOOK_REPORTS_DIR, filename)
    _atomic_write_bytes(path, pdf_bytes)
    return path


def _atomic_write_bytes(path, data):
    """Same shape as storage.py's _atomic_write: a temp file in the same
    directory via O_CREAT|O_EXCL (refuses to follow a symlink planted at
    the temp name), then an atomic rename over the target, so a reader
    never sees a partial PDF. Binary rather than storage.py's text mode,
    which is why this is its own small helper rather than a shared one."""
    tmp = f"{path}.tmp{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
