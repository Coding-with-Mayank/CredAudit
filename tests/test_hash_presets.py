import pytest

from credaudit.modules.hash_presets import PRESETS, format_preset_table, resolve_hash_mode


def test_resolve_known_preset():
    assert resolve_hash_mode("ntlm") == "1000"


def test_resolve_preset_case_insensitive():
    assert resolve_hash_mode("NTLM") == "1000"
    assert resolve_hash_mode("  ntlm  ") == "1000"


def test_resolve_raw_number_passthrough():
    assert resolve_hash_mode("99999") == "99999"


def test_resolve_unknown_raises_with_helpful_message():
    with pytest.raises(ValueError, match="Unknown hash type"):
        resolve_hash_mode("not-a-real-hash-type")


def test_resolve_none_raises():
    with pytest.raises(ValueError):
        resolve_hash_mode(None)


def test_all_presets_have_required_fields():
    for key, info in PRESETS.items():
        assert "mode" in info and info["mode"].isdigit()
        assert "name" in info and info["name"]
        assert "note" in info and info["note"]


def test_format_preset_table_includes_all_presets():
    table = format_preset_table()
    for key in PRESETS:
        assert key in table
