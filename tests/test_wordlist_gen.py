from credaudit.modules import wordlist_gen


def test_generates_case_variants():
    candidates = wordlist_gen.generate_candidates(["Acme"], include_years=False, include_leet=False)
    assert "Acme" in candidates
    assert "acme" in candidates
    assert "ACME" in candidates


def test_generates_suffixes():
    candidates = wordlist_gen.generate_candidates(["acme"], include_years=False, include_leet=False)
    assert "acme123" in candidates
    assert "acme!" in candidates


def test_generates_year_variants():
    candidates = wordlist_gen.generate_candidates(["acme"], include_years=True, include_leet=False)
    assert any("2026" in c for c in candidates)


def test_generates_leet_variants():
    candidates = wordlist_gen.generate_candidates(["acme"], include_years=False, include_leet=True)
    assert any("4" in c or "3" in c for c in candidates)


def test_ignores_blank_seed_words():
    candidates = wordlist_gen.generate_candidates(["", "  ", "acme"], include_years=False, include_leet=False)
    assert "" not in candidates
    assert "acme" in candidates


def test_respects_max_candidates():
    candidates = wordlist_gen.generate_candidates(
        ["acme", "widget", "corp"], max_candidates=5
    )
    assert len(candidates) <= 5


def test_write_candidates_creates_file(tmp_path):
    out_path = tmp_path / "custom.txt"
    count = wordlist_gen.write_candidates(["acme"], out_path, include_years=False, include_leet=False)
    assert out_path.exists()
    lines = out_path.read_text().splitlines()
    assert len(lines) == count
    assert count > 0
