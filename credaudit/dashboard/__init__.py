"""Lightweight, self-contained HTML dashboard. Uses the project's
existing technology (plain Python string templating + inline SVG, no
JS framework, no network dependency) rather than introducing a new
frontend stack -- see `builder.py`.
"""
from .builder import build_dashboard

__all__ = ["build_dashboard"]
