import pytest

from credaudit.core import authorization as auth


def test_keypair_generation_produces_pem():
    priv, pub = auth.generate_keypair()
    assert b"PRIVATE KEY" in priv
    assert b"PUBLIC KEY" in pub


def test_sign_and_verify_roundtrip():
    priv, pub = auth.generate_keypair()
    data = {"engagement_id": "E1", "targets": ["10.0.0.1"]}
    sig = auth.sign_scope_data(data, priv)
    assert auth.verify_scope_data(data, sig, pub) is True


def test_tampered_data_fails_verification():
    priv, pub = auth.generate_keypair()
    data = {"engagement_id": "E1", "targets": ["10.0.0.1"]}
    sig = auth.sign_scope_data(data, priv)
    tampered = dict(data, targets=["10.0.0.2"])
    assert auth.verify_scope_data(tampered, sig, pub) is False


def test_wrong_key_fails_verification():
    priv, _ = auth.generate_keypair()
    _, other_pub = auth.generate_keypair()
    data = {"a": 1}
    sig = auth.sign_scope_data(data, priv)
    assert auth.verify_scope_data(data, sig, other_pub) is False


def test_garbage_signature_does_not_raise():
    _, pub = auth.generate_keypair()
    assert auth.verify_scope_data({"a": 1}, "not-valid-base64!!", pub) is False


def test_canonical_bytes_ignores_key_order_and_dates():
    import datetime
    a = {"x": 1, "y": datetime.date(2026, 1, 1)}
    b = {"y": datetime.date(2026, 1, 1), "x": 1}
    assert auth.canonical_bytes(a) == auth.canonical_bytes(b)


def test_sign_bytes_and_verify_bytes_roundtrip():
    priv, pub = auth.generate_keypair()
    sig = auth.sign_bytes(b"hello world", priv)
    assert auth.verify_bytes(b"hello world", sig, pub) is True
    assert auth.verify_bytes(b"goodbye", sig, pub) is False


def test_non_ed25519_key_rejected_for_signing():
    with pytest.raises(auth.AuthorizationError):
        auth.sign_scope_data({"a": 1}, b"not a real key")
