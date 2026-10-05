"""Alias module: the actual tamper-evident audit log implementation
lives in `credaudit/audit_log.py` (kept there for backward compatibility
-- existing code and tests import `credaudit.audit_log` directly). This
module re-exports it so `credaudit.core.audit` also works, matching the
project's `core/{scope,authorization,evidence,risk,correlation,audit}`
layout.
"""
from ..audit_log import AuditLog, verify_manifest  # noqa: F401

__all__ = ["AuditLog", "verify_manifest"]
