"""Reporting layer.

The actual report-building code lives in `credaudit/report.py` (kept at
that path for backward compatibility -- it predates this restructuring
and existing imports/tests depend on it staying there). This package is
a thin, documented alias so the package layout matches the rest of the
platform's `core/analyzers/integrations/attack_paths/dashboard/reporting`
structure; import from `credaudit.report` directly if you prefer.
"""
from ..report import build_html_report, build_report  # noqa: F401

__all__ = ["build_report", "build_html_report"]
