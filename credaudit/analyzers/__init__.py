"""Native analysis modules: credential intelligence, secret detection,
and vulnerability/service-exposure interpretation. These are what turn
raw tool output (a cracked password, a JS file, a nuclei finding) into
unified `core.evidence.Evidence` objects with an explainable risk score
attached -- this is CredAudit's own analysis, not a pass-through of
whatever the underlying tool printed.
"""
