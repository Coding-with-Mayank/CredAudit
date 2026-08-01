from unittest.mock import patch, MagicMock

from credaudit.modules import breach_check


def _fake_response(suffix_to_count: dict):
    resp = MagicMock()
    resp.raise_for_status = lambda: None
    resp.text = "\n".join(f"{suffix}:{count}" for suffix, count in suffix_to_count.items())
    return resp


def test_breached_password_detected():
    import hashlib
    sha1 = hashlib.sha1(b"password123").hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    with patch("requests.get", return_value=_fake_response({suffix: "5000"})):
        result = breach_check.check_password("password123")

    assert result.is_breached is True
    assert result.times_seen == 5000
    assert result.password_masked == "p**********"


def test_clean_password_not_in_range_response():
    with patch("requests.get", return_value=_fake_response({"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF": "1"})):
        result = breach_check.check_password("a-genuinely-unique-passphrase-2026")

    assert result.is_breached is False
    assert result.times_seen == 0


def test_check_many_returns_one_result_per_password():
    with patch("requests.get", return_value=_fake_response({})):
        results = breach_check.check_many(["a", "b", "c"])
    assert len(results) == 3
