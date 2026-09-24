"""
playbooks_api.py: the dashboard's two playbook editing surfaces (form
builder, JSON/YAML text editor) and the run history / generated report
list they share.

Both editing surfaces round-trip through the same PlaybookPayload and the
same playbooks.validate_definition() call, so a hand-edited JSON or YAML
document can never express anything the form builder couldn't have
produced. See docs/specs/2026-09-13-playbooks-design.md.

Route order matters here and is deliberate: FastAPI matches by path shape
first, then validates the path parameter's type, so a generic
"/{playbook_id}" route registered before a specific literal path like
"/runs" or "/reports" would catch that request first and 422 on the
non-integer segment instead of ever reaching the intended handler. Every
GET route with a literal path segment (/runs, /runs/{id}/events, /reports,
/reports/{filename}) is registered before the generic "/{playbook_id}" GET,
for exactly that reason.
"""

import ipaddress
import json
import logging
import os
import time

import yaml
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

import config
import db
import playbooks
from models import PlaybookPayload

router = APIRouter()


def _validate_scope(target_scope_type, target_scope_value):
    """Cross-field check pydantic's own per-field validators can't do:
    'host' needs a real host address, 'subnet' needs a real network,
    'all' carries no value at all (stored as None, whatever the caller
    sent is discarded rather than silently kept around unused)."""
    if target_scope_type == "host":
        if not target_scope_value:
            raise HTTPException(status_code=400, detail="target_scope_value is required for scope type 'host'.")
        try:
            ipaddress.ip_address(target_scope_value)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"'{target_scope_value}' is not a valid host address.")
        return target_scope_value
    if target_scope_type == "subnet":
        if not target_scope_value:
            raise HTTPException(status_code=400, detail="target_scope_value is required for scope type 'subnet'.")
        try:
            ipaddress.ip_network(target_scope_value, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"'{target_scope_value}' is not a valid subnet (CIDR).")
        return target_scope_value
    return None  # 'all'


def _validate_definition_or_400(definition):
    try:
        return playbooks.validate_definition(definition)
    except playbooks.DefinitionError as e:
        raise HTTPException(status_code=400, detail=str(e))


def _row_to_dict(row):
    playbook_id, name, scope_type, scope_value, enabled, definition_json, created_at, updated_at = row
    return {
        "id": playbook_id,
        "name": name,
        "target_scope_type": scope_type,
        "target_scope_value": scope_value,
        "enabled": bool(enabled),
        "definition": json.loads(definition_json),
        "created_at": created_at,
        "updated_at": updated_at,
    }


@router.get("/api/playbooks")
def list_playbooks():
    return {"playbooks": [_row_to_dict(r) for r in db.get_all_playbooks()]}


@router.post("/api/playbooks")
def create_playbook(payload: PlaybookPayload):
    scope_value = _validate_scope(payload.target_scope_type, payload.target_scope_value)
    definition = _validate_definition_or_400(payload.definition)
    now = time.time()
    playbook_id = db.create_playbook(
        payload.name, payload.target_scope_type, scope_value, payload.enabled,
        json.dumps(definition), now,
    )
    if playbook_id is None:
        raise HTTPException(status_code=500, detail="Failed to create playbook.")
    logging.info(f"[+] Playbook {playbook_id} ({payload.name!r}) created.")
    return _row_to_dict(db.get_playbook(playbook_id))


@router.post("/api/playbooks/validate")
def validate_definition_only(payload: dict):
    """Lets either editing surface check a definition before saving,
    without creating or overwriting anything. Takes the raw definition
    object directly (not a PlaybookPayload), since the text editor may
    be validating a document that isn't attached to a name or scope
    yet."""
    try:
        validated = playbooks.validate_definition(payload)
    except playbooks.DefinitionError as e:
        return {"valid": False, "error": str(e)}
    return {"valid": True, "definition": validated}


@router.post("/api/playbooks/parse-yaml")
def parse_yaml_definition(payload: dict):
    """The text editor's YAML path: normalizes YAML to the same JSON
    object the form builder produces, server-side, so validation and
    storage only ever deal with one shape. Body: {"yaml": "<text>"}."""
    text = payload.get("yaml", "")
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="Top level YAML document must be an object.")
    return {"definition": parsed}


@router.get("/api/playbooks/runs")
def list_runs(limit: int = 50):
    limit = max(1, min(limit, 200))
    rows = db.get_recent_playbook_runs(limit)
    return {
        "runs": [
            {
                "id": r[0], "playbook_id": r[1], "playbook_name": r[2],
                "target_host": r[3], "target_source": r[4],
                "current_stage_index": r[5], "status": r[6],
                "trigger_reason": r[7], "started_at": r[8], "updated_at": r[9],
            }
            for r in rows
        ]
    }


@router.get("/api/playbooks/runs/{run_id}/events")
def list_run_events(run_id: int):
    rows = db.get_playbook_events(run_id)
    return {
        "events": [
            {
                "stage_index": r[0], "stage_type": r[1], "fired_at": r[2],
                "target_source": r[3], "detail": r[4],
            }
            for r in rows
        ]
    }


@router.get("/api/playbooks/reports")
def list_reports():
    """Files a report stage has written under config.PLAYBOOK_REPORTS_DIR.
    The directory not existing yet (no report stage has ever fired) is
    not an error, it just means an empty list."""
    directory = config.PLAYBOOK_REPORTS_DIR
    if not os.path.isdir(directory):
        return {"reports": []}
    entries = []
    for name in os.listdir(directory):
        if not name.endswith(".pdf"):
            continue
        path = os.path.join(directory, name)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        stat = os.stat(path)
        entries.append({"filename": name, "size_bytes": stat.st_size, "modified_at": stat.st_mtime})
    entries.sort(key=lambda e: e["modified_at"], reverse=True)
    return {"reports": entries}


@router.get("/api/playbooks/reports/{filename}")
def download_report(filename: str):
    """Serves one file from config.PLAYBOOK_REPORTS_DIR by name only, no
    path segments accepted, so a caller cannot walk outside the reports
    directory. Refuses a symlink at the resolved path rather than
    following it."""
    if "/" in filename or "\\" in filename or filename in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename.")
    directory = os.path.realpath(config.PLAYBOOK_REPORTS_DIR)
    path = os.path.join(directory, filename)
    if os.path.islink(path):
        raise HTTPException(status_code=404, detail="Report not found.")
    real_path = os.path.realpath(path)
    if os.path.dirname(real_path) != directory or not os.path.isfile(real_path):
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(real_path, media_type="application/pdf", filename=filename)


@router.get("/api/playbooks/{playbook_id}")
def get_playbook(playbook_id: int):
    row = db.get_playbook(playbook_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found.")
    return _row_to_dict(row)


@router.put("/api/playbooks/{playbook_id}")
def update_playbook(playbook_id: int, payload: PlaybookPayload):
    if db.get_playbook(playbook_id) is None:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found.")
    scope_value = _validate_scope(payload.target_scope_type, payload.target_scope_value)
    definition = _validate_definition_or_400(payload.definition)
    now = time.time()
    ok = db.update_playbook(
        playbook_id, payload.name, payload.target_scope_type, scope_value,
        payload.enabled, json.dumps(definition), now,
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to update playbook.")
    logging.info(f"[+] Playbook {playbook_id} updated.")
    return _row_to_dict(db.get_playbook(playbook_id))


@router.post("/api/playbooks/{playbook_id}/toggle")
def toggle_playbook(playbook_id: int, payload: dict):
    """Body: {"enabled": bool}. A separate endpoint from the full update
    so the dashboard's enable/disable switch doesn't have to resend the
    whole definition just to flip one flag."""
    if "enabled" not in payload or not isinstance(payload["enabled"], bool):
        raise HTTPException(status_code=400, detail="Body must be {\"enabled\": true|false}.")
    if db.get_playbook(playbook_id) is None:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found.")
    ok = db.set_playbook_enabled(playbook_id, payload["enabled"], time.time())
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to toggle playbook.")
    return _row_to_dict(db.get_playbook(playbook_id))


@router.delete("/api/playbooks/{playbook_id}")
def delete_playbook(playbook_id: int):
    if db.get_playbook(playbook_id) is None:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found.")
    ok = db.delete_playbook(playbook_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to delete playbook.")
    logging.info(f"[+] Playbook {playbook_id} deleted.")
    return {"deleted": playbook_id}
