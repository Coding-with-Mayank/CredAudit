"""Alias module: the actual Scope/authorization-gate implementation
lives in `credaudit/scope.py` (kept there for backward compatibility --
existing code and tests import `credaudit.scope` directly). This module
re-exports it so `credaudit.core.scope` also works, matching the
project's `core/{scope,authorization,evidence,risk,correlation,audit}`
layout.
"""
from ..scope import DEFAULT_PROTOCOL_LIMITS, Scope, ScopeViolation  # noqa: F401

__all__ = ["Scope", "ScopeViolation", "DEFAULT_PROTOCOL_LIMITS"]
