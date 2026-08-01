"""Hash-mode presets for the offline module.

Every mode number here was checked against hashcat's own reference table
(https://hashcat.net/wiki/doku.php?id=example_hashes) at the time this
was written -- not guessed, not remembered. Hashcat adds new modes over
time; if you need something not listed here, use the raw hashcat -m
number directly with --hash-mode, or check the wiki link above.
"""
from __future__ import annotations

PRESETS = {
    "md5": {"mode": "0", "name": "MD5", "note": "generic MD5"},
    "sha1": {"mode": "100", "name": "SHA1", "note": "generic SHA1"},
    "sha256": {"mode": "1400", "name": "SHA2-256", "note": "generic SHA-256"},
    "sha512": {"mode": "1700", "name": "SHA2-512", "note": "generic SHA-512"},

    "ntlm": {"mode": "1000", "name": "NTLM", "note": "Windows/AD NTLM hash, e.g. from an NTDS export"},
    "lm": {"mode": "3000", "name": "LM", "note": "legacy Windows LM hash"},
    "netntlmv1": {"mode": "5500", "name": "NetNTLMv1", "note": "captured NetNTLMv1 challenge/response"},
    "netntlmv2": {"mode": "5600", "name": "NetNTLMv2", "note": "captured NetNTLMv2 challenge/response, e.g. via Responder"},
    "dcc": {"mode": "1100", "name": "DCC (MS Cache)", "note": "Windows cached domain credentials"},
    "dcc2": {"mode": "2100", "name": "DCC2 (MS Cache 2)", "note": "Windows cached domain credentials v2"},

    "md5crypt": {"mode": "500", "name": "md5crypt ($1$)", "note": "older Unix/Linux shadow hash"},
    "sha256crypt": {"mode": "7400", "name": "sha256crypt ($5$)", "note": "Unix/Linux shadow hash"},
    "sha512crypt": {"mode": "1800", "name": "sha512crypt ($6$)", "note": "modern Unix/Linux shadow hash, most common on current distros"},
    "bcrypt": {"mode": "3200", "name": "bcrypt ($2*$)", "note": "common for web app user tables"},

    "phpass": {"mode": "400", "name": "phpass / WordPress / phpBB3", "note": "common CMS password hash"},
    "django": {"mode": "10000", "name": "Django PBKDF2-SHA256", "note": "Django's default password hasher"},

    "kerberoast": {"mode": "13100", "name": "Kerberos 5 TGS-REP etype 23", "note": "classic Kerberoasting (RC4)"},
    "kerberoast-aes128": {"mode": "19600", "name": "Kerberos 5 TGS-REP etype 17 (AES128)", "note": "Kerberoasting, AES-enabled SPNs"},
    "kerberoast-aes256": {"mode": "19700", "name": "Kerberos 5 TGS-REP etype 18 (AES256)", "note": "Kerberoasting, AES-enabled SPNs"},
    "asreproast": {"mode": "18200", "name": "Kerberos 5 AS-REP etype 23", "note": "accounts with Kerberos pre-auth disabled"},
}


def resolve_hash_mode(value: str) -> str:
    """Accepts either a preset key (e.g. 'ntlm') or a raw hashcat -m
    number (e.g. '1000') and returns the numeric mode string hashcat
    expects. Raw numbers pass through untouched, so this never narrows
    what you can already do with hashcat directly."""
    if value is None:
        raise ValueError("No hash type given. Use --hash-mode <preset-or-number>.")

    key = value.strip().lower()
    if key in PRESETS:
        return PRESETS[key]["mode"]
    if value.strip().isdigit():
        return value.strip()

    available = ", ".join(sorted(PRESETS))
    raise ValueError(
        f"Unknown hash type '{value}'. Use a preset ({available}) or a raw "
        f"hashcat -m number. Run `python -m credaudit.cli hash-types` to see details."
    )


def format_preset_table() -> str:
    lines = [f"{'preset':<20} {'mode':<6} {'name':<40} note", "-" * 100]
    for key, info in sorted(PRESETS.items()):
        lines.append(f"{key:<20} {info['mode']:<6} {info['name']:<40} {info['note']}")
    lines.append("")
    lines.append("Any raw hashcat -m number also works directly with --hash-mode.")
    return "\n".join(lines)
