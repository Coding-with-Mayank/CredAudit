"""Evidence-driven attack-path modeling. See `graph.py` -- this builds
directly on `core.correlation` output, so every path is traceable back
to the specific findings that support it. This complements (does not
replace) `modules/attack_graph.py`, which models a narrower hypothetical
escalation path specifically from recon risk assessments + JS-intel
secrets; that module is unchanged and still used for that path.
"""
