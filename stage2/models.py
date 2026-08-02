"""
models.py — Pydantic request payloads and the shared IP-address validator.

Deliberately leaf-level: only needs the stdlib and fastapi/pydantic, so
every route module can import from here without risking a cycle.
"""

import ipaddress
from typing import List, Optional

from fastapi import HTTPException
from pydantic import BaseModel, field_validator


def _validate_host_ip(ip: str) -> str:
    """Reject anything that isn't a single valid IPv4/IPv6 host address --
    no CIDR ranges, no garbage strings. Without this, an unvalidated value
    reaches ipset (a hash:ip set, which accepts CIDR shorthand and expands
    it to every host in the range) or gets rendered back into the
    dashboard, so this is both a correctness and an XSS-defense-in-depth
    gate. Raises plain ValueError so pydantic field_validators can call it
    directly; query-param endpoints go through _validate_host_ip_or_400.
    """
    ipaddress.ip_address(ip)  # raises ValueError on anything invalid
    return ip


def _validate_host_ip_or_400(ip: str) -> str:
    try:
        return _validate_host_ip(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{ip}' is not a valid IP address.")


class IpPayload(BaseModel):
    ip: str
    victim_ip: Optional[str] = None

    @field_validator("ip")
    @classmethod
    def _check_ip(cls, v):
        return _validate_host_ip(v)

    @field_validator("victim_ip")
    @classmethod
    def _check_victim_ip(cls, v):
        return _validate_host_ip(v) if v else v


class VictimPayload(BaseModel):
    ip: str
    description: str

    @field_validator("ip")
    @classmethod
    def _check_ip(cls, v):
        return _validate_host_ip(v)

    @field_validator("description")
    @classmethod
    def _check_description(cls, v):
        if len(v) > 200:
            raise ValueError("Description too long (max 200 characters).")
        return v


class EnforcementConfigPayload(BaseModel):
    dominant_ip_ratio_block_threshold: Optional[float] = None
    dominant_ip_ratio_extreme_threshold: Optional[float] = None
    block_rate_floor_pps: Optional[float] = None
    ratelimit_rate_floor_pps: Optional[float] = None
    block_sigma_multiplier: Optional[float] = None
    block_hysteresis_windows: Optional[int] = None
    block_duration_seconds: Optional[int] = None
    ratelimit_duration_seconds: Optional[int] = None
    ratelimit_hashlimit_pps: Optional[int] = None


class PdfReportPayload(BaseModel):
    rate_chart_base64: str
    entropy_chart_base64: str
    # Network/traffic diagrams are drawn server-side now (see reports.py),
    # not accepted as a client-supplied image.


def _check_username(v: str) -> str:
    if not (1 <= len(v) <= 64):
        raise ValueError("Username must be 1-64 characters.")
    return v

def _check_password_strength(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters.")
    return v


class DeleteUserPayload(BaseModel):
    username: str
    admin_password: str

    @field_validator("username")
    @classmethod
    def _v_username(cls, v):
        return _check_username(v)


class CreateUserPayload(BaseModel):
    username: str
    password: str
    # The caller's own current password, re-checked server-side. No length
    # validator here -- it's checked against an existing bcrypt hash, not a
    # new password, so it must accept whatever that account's password
    # already is.
    admin_password: str

    @field_validator("username")
    @classmethod
    def _v_username(cls, v):
        return _check_username(v)

    @field_validator("password")
    @classmethod
    def _v_password(cls, v):
        return _check_password_strength(v)


class SetPasswordPayload(BaseModel):
    username: str
    new_password: str
    admin_password: str

    @field_validator("username")
    @classmethod
    def _v_username(cls, v):
        return _check_username(v)

    @field_validator("new_password")
    @classmethod
    def _v_password(cls, v):
        return _check_password_strength(v)


class AlertsConfigPayload(BaseModel):
    discord_enabled: Optional[bool] = None
    discord_webhook_url: Optional[str] = None
    email_enabled: Optional[bool] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_username: Optional[str] = None
    smtp_app_password: Optional[str] = None
    email_recipients: Optional[List[str]] = None
