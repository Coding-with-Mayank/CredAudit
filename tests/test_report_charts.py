from credaudit.report import _stat_bar, recon_severity_buckets


def test_stat_bar_zero_total_returns_note():
    result = _stat_bar([(0, "var(--flag)", "x")], total=0)
    assert "No data" in result


def test_stat_bar_renders_svg_with_correct_rect_count():
    result = _stat_bar(
        [(3, "var(--flag)", "Weak"), (7, "var(--clear)", "Safe")], total=10
    )
    assert result.count("<rect") == 3  # 1 background + 2 segments
    assert "Weak: 3 (30%)" in result
    assert "Safe: 7 (70%)" in result


def test_stat_bar_skips_zero_width_segment():
    result = _stat_bar(
        [(0, "var(--flag)", "Weak"), (10, "var(--clear)", "Safe")], total=10
    )
    # background rect + only the non-zero segment rect
    assert result.count("<rect") == 2


def test_recon_severity_buckets_nuclei_shape():
    findings = [
        {"info": {"severity": "critical"}},
        {"info": {"severity": "high"}},
        {"info": {"severity": "info"}},
        {"info": {"severity": "low"}},
    ]
    buckets = recon_severity_buckets(findings)
    assert buckets["needs_attention"] == 2
    assert buckets["informational"] == 2


def test_recon_severity_buckets_missing_severity_is_informational():
    findings = [{"template": "x"}]
    buckets = recon_severity_buckets(findings)
    assert buckets == {"needs_attention": 0, "informational": 1}


def test_recon_severity_buckets_empty_findings():
    assert recon_severity_buckets([]) == {"needs_attention": 0, "informational": 0}
