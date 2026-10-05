from datetime import date, timedelta

import pytest
import yaml

from credaudit.core import authorization
from credaudit.scope import Scope, ScopeViolation


def write_scope(tmp_path, **overrides):
    data = {
        "engagement_id": "TEST-001",
        "client_name": "Test Client",
        "authorized_by": "Tester",
        "start_date": date.today() - timedelta(days=1),
        "end_date": date.today() + timedelta(days=1),
        "targets": ["10.0.0.1", "10.0.1.0/24"],
        "allowed_modules": ["recon"],
    }
    data.update(overrides)
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.dump(data))
    return path, data


# --- wildcard subdomain matching -------------------------------------------

def test_wildcard_domain_matches_subdomain(tmp_path):
    path, _ = write_scope(tmp_path, targets=["*.acme-test.example"])
    scope = Scope.load(path)
    scope.check_target("www.acme-test.example")
    scope.check_target("acme-test.example")  # bare domain also matches


def test_wildcard_domain_rejects_unrelated_host(tmp_path):
    path, _ = write_scope(tmp_path, targets=["*.acme-test.example"])
    scope = Scope.load(path)
    with pytest.raises(ScopeViolation):
        scope.check_target("evil.example")
    with pytest.raises(ScopeViolation):
        scope.check_target("notacme-test.example")  # substring, not a subdomain


# --- target_groups can't expand scope ---------------------------------------

def test_target_group_cannot_extend_scope(tmp_path):
    path, _ = write_scope(
        tmp_path,
        targets=["10.0.0.1"],
        target_groups={"prod": ["10.0.0.1", "10.0.0.99"]},  # .99 not in targets
    )
    with pytest.raises(ScopeViolation):
        Scope.load(path)


def test_target_group_resolves_when_valid(tmp_path):
    path, _ = write_scope(
        tmp_path,
        targets=["10.0.0.1", "10.0.0.2"],
        target_groups={"prod": ["10.0.0.1", "10.0.0.2"]},
    )
    scope = Scope.load(path)
    assert scope.resolve_group("prod") == ["10.0.0.1", "10.0.0.2"]


def test_resolve_unknown_group_raises(tmp_path):
    path, _ = write_scope(tmp_path)
    scope = Scope.load(path)
    with pytest.raises(ScopeViolation):
        scope.resolve_group("does-not-exist")


# --- module-level protocol permissions --------------------------------------

def test_check_protocol_allows_listed_protocol(tmp_path):
    path, _ = write_scope(
        tmp_path,
        allowed_modules=["online"],
        allowed_protocols={"online": ["ssh", "rdp"]},
    )
    scope = Scope.load(path)
    scope.check_protocol("online", "ssh")


def test_check_protocol_rejects_unlisted_protocol(tmp_path):
    path, _ = write_scope(
        tmp_path,
        allowed_modules=["online"],
        allowed_protocols={"online": ["ssh"]},
    )
    scope = Scope.load(path)
    with pytest.raises(ScopeViolation):
        scope.check_protocol("online", "ftp")


def test_check_protocol_is_opt_in(tmp_path):
    """A module with no entry in allowed_protocols has no additional
    restriction -- old scope files without this field keep working."""
    path, _ = write_scope(tmp_path, allowed_modules=["online"])
    scope = Scope.load(path)
    scope.check_protocol("online", "anything-goes")


# --- cryptographic signature verification -----------------------------------

def test_unsigned_scope_loads_fine_by_default(tmp_path):
    path, _ = write_scope(tmp_path)
    scope = Scope.load(path)
    assert scope.cryptographically_verified is False
    assert scope.verification_trust_level == "unsigned"


def test_require_signature_fails_closed_without_signature(tmp_path):
    path, _ = write_scope(tmp_path, require_signature=True)
    with pytest.raises(ScopeViolation):
        Scope.load(path)


def test_signed_scope_verifies_with_embedded_key(tmp_path):
    private_pem, public_pem = authorization.generate_keypair()
    path, data = write_scope(tmp_path)
    data["signer_public_key"] = public_pem.decode()
    signature = authorization.sign_scope_data(data, private_pem)
    data["signature"] = signature
    path.write_text(yaml.dump(data))

    scope = Scope.load(path)
    assert scope.cryptographically_verified is True
    assert scope.verification_trust_level == "embedded_key_self_signed"


def test_signed_scope_verifies_with_external_trusted_key(tmp_path):
    private_pem, public_pem = authorization.generate_keypair()
    path, data = write_scope(tmp_path)
    signature = authorization.sign_scope_data(data, private_pem)
    data["signature"] = signature
    path.write_text(yaml.dump(data))

    scope = Scope.load(path, trusted_public_key=public_pem)
    assert scope.cryptographically_verified is True
    assert scope.verification_trust_level == "external_trusted_key"


def test_tampered_scope_fails_signature_verification(tmp_path):
    private_pem, public_pem = authorization.generate_keypair()
    path, data = write_scope(tmp_path)
    signature = authorization.sign_scope_data(data, private_pem)
    data["signature"] = signature
    data["targets"] = ["10.0.0.1", "10.0.1.0/24", "8.8.8.8"]  # tampered after signing
    path.write_text(yaml.dump(data))

    with pytest.raises(ScopeViolation):
        Scope.load(path, trusted_public_key=public_pem)


def test_signature_present_but_no_key_available_fails_closed(tmp_path):
    private_pem, _ = authorization.generate_keypair()
    path, data = write_scope(tmp_path)
    signature = authorization.sign_scope_data(data, private_pem)
    data["signature"] = signature  # no signer_public_key embedded, no trusted_public_key passed
    path.write_text(yaml.dump(data))

    with pytest.raises(ScopeViolation):
        Scope.load(path)


def test_wrong_trusted_key_fails_closed(tmp_path):
    private_pem, _ = authorization.generate_keypair()
    _, other_public_pem = authorization.generate_keypair()
    path, data = write_scope(tmp_path)
    signature = authorization.sign_scope_data(data, private_pem)
    data["signature"] = signature
    path.write_text(yaml.dump(data))

    with pytest.raises(ScopeViolation):
        Scope.load(path, trusted_public_key=other_public_pem)
