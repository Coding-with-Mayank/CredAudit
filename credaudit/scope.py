"""Scope & authorization gate.

Nothing else in this project should run before this module confirms the
requested action is inside an authorized, time-bounded engagement scope.
Every module calls check_target() / check_module() (and, where it
applies, check_protocol()) before doing anything that touches a live
system.

Authorization model, in increasing order of assurance:
  1. Free-text `authorized_by` + a required, checked `targets` /
     `allowed_modules` / date-window gate. This is what the project has
     always enforced -- it stops any module from touching an
     out-of-scope target, an unlisted module, or running outside the
     engagement window, regardless of what a free-text field claims.
  2. Optional cryptographic signature (`signature` + `require_signature`
     in the scope file, verified by `core.authorization`). This adds
     real proof that the scope file's *content* hasn't changed since
     someone holding a specific private key approved it -- see
     `core/authorization.py` for exactly what this does and does not
     prove, and why an externally-supplied trusted key (not one
     embedded in the scope file itself) is the only mode that provides
     real assurance rather than mere self-consistency.

Fail-closed discipline: any ambiguity in scope (an unlisted target, an
unlisted module, an expired window, a signature that doesn't verify, a
signature that's present but unverifiable) raises ScopeViolation. There
is no code path in this module that treats "couldn't verify" as "assume
it's fine".

Documented limitation: this module can guarantee that *credaudit's own
Python code* won't act outside scope. It cannot guarantee that an
external binary it invokes (hydra, hashcat, nuclei, ...) will never, by
some bug or flag misuse, touch something outside that boundary --
scope-checking every target before every subprocess call is the
strongest control credaudit can offer from the outside of someone
else's compiled tool, not an absolute guarantee about that tool's own
behavior.
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
    """Raised when an action would fall outside the authorized scope,
    or when authorization cannot be verified and the scope file
    requires that it be."""


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
    allowed_protocols: dict = field(default_factory=dict)
    require_signature: bool = False
    cryptographically_verified: bool = False
    verification_trust_level: str = "unsigned"  # "unsigned" | "embedded_key_self_signed" | "external_trusted_key"

    @classmethod
    def load(cls, path, trusted_public_key: bytes = None) -> "Scope":
        """Load and validate a scope file.

        trusted_public_key: an Ed25519 public key (PEM bytes) from a
        source *outside* the scope file itself -- e.g. read from a
        separate file in your own controlled repo, or a CI secret. If
        the scope file carries a `signature`, pass this to get real
        cryptographic assurance rather than the weaker
        embedded-key/self-consistency check (see module docstring).
        """
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
            allowed_protocols=data.get("allowed_protocols", {}) or {},
            require_signature=data.get("require_signature", False),
        )
        scope._validate_dates()
        scope._validate_target_groups()
        scope._verify_authorization(data, trusted_public_key)
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
        checks anything else (CIDR/wildcard-aware)."""
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

    def _verify_authorization(self, raw_data: dict, trusted_public_key: bytes = None) -> None:
        """Verify the scope file's optional cryptographic signature.
        See module docstring for the two trust levels this can reach.
        Fails closed: a signature that's present but unverifiable, or
        that doesn't verify, always raises -- it never falls back to
        "treat it as unsigned"."""
        signature = raw_data.get("signature")

        if not signature:
            if self.require_signature:
                raise ScopeViolation(
                    f"Engagement '{self.engagement_id}' sets require_signature: true "
                    "but no 'signature' field is present in the scope file. Fail "
                    "closed: refusing to run an engagement whose authorization "
                    "cannot be cryptographically verified."
                )
            self.cryptographically_verified = False
            self.verification_trust_level = "unsigned"
            return

        from .core import authorization

        payload = {k: v for k, v in raw_data.items() if k != "signature"}

        if trusted_public_key:
            key_to_use = trusted_public_key
            trust_level = "external_trusted_key"
        else:
            embedded = raw_data.get("signer_public_key")
            if not embedded:
                raise ScopeViolation(
                    "A 'signature' is present in this scope file but no public key "
                    "is available to verify it (no trusted_public_key was supplied, "
                    "and no 'signer_public_key' is embedded in the file). Fail "
                    "closed: refusing to treat an unverifiable signature as valid."
                )
            key_to_use = embedded.encode() if isinstance(embedded, str) else embedded
            trust_level = "embedded_key_self_signed"

        try:
            valid = authorization.verify_scope_data(payload, signature, key_to_use)
        except authorization.AuthorizationError as e:
            raise ScopeViolation(f"Signature verification failed: {e}") from e

        if not valid:
            raise ScopeViolation(
                f"Engagement '{self.engagement_id}' has a 'signature' field that "
                "does not verify against the available public key. Fail closed: "
                "refusing to run -- the scope file may have been altered after "
                "signing, or signed with an untrusted key."
            )

        self.cryptographically_verified = True
        self.verification_trust_level = trust_level

    def check_target(self, host: str) -> None:
        """Raise ScopeViolation if host is not explicitly covered by
        scope. Supports exact hostnames/IPs, CIDR ranges (`10.0.0.0/24`),
        and wildcard subdomains (`*.acme-test-range.example`)."""
        for entry in self.targets:
            if "/" in entry:
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                        return
                except ValueError:
                    continue
            elif entry.startswith("*."):
                suffix = entry[1:]  # e.g. ".acme-test-range.example"
                if host == entry[2:] or host.endswith(suffix):
                    return
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

    def check_protocol(self, module_name: str, protocol: str) -> None:
        """Optional, finer-grained module-level permission: if a scope
        file defines `allowed_protocols.<module_name>`, the requested
        protocol must be in that list. A module with no entry in
        allowed_protocols has no additional restriction beyond
        check_module -- this is an opt-in tightening, not a new default
        restriction that would break scope files written before this
        field existed."""
        allowed = self.allowed_protocols.get(module_name)
        if allowed is not None and protocol not in allowed:
            raise ScopeViolation(
                f"Protocol '{protocol}' is not in allowed_protocols.{module_name} "
                f"for engagement '{self.engagement_id}'. Allowed: {sorted(allowed)}"
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
