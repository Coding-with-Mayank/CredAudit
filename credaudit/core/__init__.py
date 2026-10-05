"""Core platform layer: evidence schema, risk engine, correlation engine,
authorization/signature verification, and the pipeline that wires them
together. This is what makes credaudit an assessment/intelligence
platform rather than a thin wrapper around Hydra/Hashcat/Nuclei -- those
tools remain evidence *sources* (see `credaudit.integrations`); the
interpretation happens here.
"""
