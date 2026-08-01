"""Scope & authorization gate.

Nothing else in this project should run before this module confirms the
requested action is inside a signed, time-bounded engagement scope.
Every module calls check_module() / check_target() before doing anything
that touches a live system.
"""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

DEFAULT_PROTOCOL_LIMITS = {"seconds_between_passwords": 300, "tasks": 1}


class ScopeViolation(Exception):
    """Raised when an action would fall outside the authorized scope."""


@dataclass
class Scope:
    engagement_id: str
    client_name: str
    authorized_by: str
    start_date: date
    end_date: date
    targets: list
    allowed_modules: list
    max_requests_per_minute: int
    confirm_online_testing: bool
    source_path: Path
    source_sha256: str
    target_groups: dict = field(default_factory=dict)
    protocol_limits: dict = field(default_factory=dict)
    emergency_contact: str = ""

    @classmethod
    def load(cls, path) -> "Scope":
        path = Path(path)
        if not path.exists():
            raise ScopeViolation(f"Scope file not found: {path}")

        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        data = yaml.safe_load(raw)

        required = [
            "engagement_id", "client_name", "authorized_by",
            "start_date", "end_date", "targets", "allowed_modules",
        ]
        missing = [k for k in required if k not in data]
        if missing:
            raise ScopeViolation(f"Scope file is missing required fields: {missing}")

        scope = cls(
            engagement_id=data["engagement_id"],
            client_name=data["client_name"],
            authorized_by=data["authorized_by"],
            start_date=data["start_date"],
            end_date=data["end_date"],
            targets=data["targets"],
            allowed_modules=data["allowed_modules"],
            max_requests_per_minute=data.get("max_requests_per_minute", 30),
            confirm_online_testing=data.get("confirm_online_testing", False),
            source_path=path,
            source_sha256=digest,
            target_groups=data.get("target_groups", {}) or {},
            protocol_limits=data.get("protocol_limits", {}) or {},
            emergency_contact=data.get("emergency_contact", ""),
        )
        scope._validate_dates()
        scope._validate_target_groups()
        return scope

    def _validate_dates(self) -> None:
        today = date.today()
        if not (self.start_date <= today <= self.end_date):
            raise ScopeViolation(
                f"Engagement '{self.engagement_id}' is not active today "
                f"(window: {self.start_date} to {self.end_date}). Refusing to run."
            )

    def _validate_target_groups(self) -> None:
        """A named group can organize targets, but it can never expand
        scope -- every host in every group must already be covered by the
        flat top-level targets list, checked the same way check_target
        checks anything else (CIDR-aware)."""
        for group_name, members in self.target_groups.items():
            for host in members:
                try:
                    self.check_target(host)
                except ScopeViolation:
                    raise ScopeViolation(
                        f"target_groups.{group_name} contains '{host}', which is "
                        f"not covered by the top-level targets list. Groups can "
                        f"only organize existing scope, not extend it."
                    )

    def check_target(self, host: str) -> None:
        """Raise ScopeViolation if host is not explicitly covered by scope."""
        for entry in self.targets:
            if "/" in entry:
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                        return
                except ValueError:
                    continue
            elif entry == host:
                return
        raise ScopeViolation(
            f"Target '{host}' is not listed in scope file {self.source_path}"
        )

    def check_module(self, module_name: str) -> None:
        if module_name not in self.allowed_modules:
            raise ScopeViolation(
                f"Module '{module_name}' is not in allowed_modules for "
                f"engagement '{self.engagement_id}'."
            )

    def resolve_group(self, group_name: str) -> list:
        """Return the target list for a named group. Every member is
        already guaranteed (at load time) to be within the flat targets
        list -- this is purely an organizational convenience."""
        if group_name not in self.target_groups:
            available = ", ".join(sorted(self.target_groups)) or "(none defined)"
            raise ScopeViolation(
                f"target_group '{group_name}' is not defined in this scope file. "
                f"Available groups: {available}"
            )
        return list(self.target_groups[group_name])

    def get_protocol_limits(self, protocol: str) -> dict:
        """Per-protocol pacing, falling back to sane defaults. Lets a
        scope file say 'RDP lockouts after 3 tries, SSH after 10' instead
        of one global number for every protocol."""
        overrides = self.protocol_limits.get(protocol, {})
        return {**DEFAULT_PROTOCOL_LIMITS, **overrides}

    def require_interactive_confirmation(self, module_name: str) -> None:
        """Extra manual gate for anything that touches live credentials."""
        if module_name != "online":
            return
        if self.confirm_online_testing:
            return  # pre-approved, e.g. for a CI run

        answer = input(
            f"\nAbout to run LIVE credential testing against: "
            f"{', '.join(self.targets)}\n"
            f"Engagement: {self.engagement_id} | Authorized by: {self.authorized_by}\n"
            f"Type the engagement id to confirm you are authorized to proceed: "
        )
        if answer.strip() != self.engagement_id:
            raise ScopeViolation("Confirmation did not match engagement id. Aborting.")
