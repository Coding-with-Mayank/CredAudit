import sys

from credaudit.cli import main


def test_hash_types_command_prints_presets(capsys):
    sys.argv = ["credaudit", "hash-types"]
    main()
    out = capsys.readouterr().out
    assert "ntlm" in out
    assert "1000" in out


def test_generate_wordlist_command_creates_file(tmp_path, capsys):
    out_path = tmp_path / "custom.txt"
    sys.argv = [
        "credaudit", "generate-wordlist",
        "--seed", "AcmeCorp", "--seed", "Widget",
        "--out", str(out_path), "--max", "50",
    ]
    main()
    assert out_path.exists()
    lines = [l for l in out_path.read_text().splitlines() if l.strip()]
    assert 0 < len(lines) <= 50
    out = capsys.readouterr().out
    assert "Wrote" in out
