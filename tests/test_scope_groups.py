from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from credaudit.scope import Scope, ScopeViolation


def write_scope(tmp_path, **overrides):
    data = {
        "engagement_id": "TEST-001",
        "client_name": "Test Client",
        "authorized_by": "Tester",
        "start_date": date.today() - timedelta(days=1),
        "end_date": date.today() + timedelta(days=1),
        "targets": ["10.0.0.1", "10.0.0.2", "10.0.1.0/24"],
        "allowed_modules": ["recon", "online"],
    }
    data.update(overrides)
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.dump(data))
    return path


def test_target_groups_valid_subset(tmp_path):
    scope = Scope.load(write_scope(tmp_path, target_groups={"prod": ["10.0.0.1"]}))
    assert scope.resolve_group("prod") == ["10.0.0.1"]


def test_target_groups_can_use_cidr_coverage(tmp_path):
    # 10.0.1.55 isn't listed literally but falls inside the 10.0.1.0/24 CIDR
    scope = Scope.load(write_scope(tmp_path, target_groups={"prod": ["10.0.1.55"]}))
    assert scope.resolve_group("prod") == ["10.0.1.55"]


def test_target_group_cannot_expand_scope(tmp_path):
    path = write_scope(tmp_path, target_groups={"prod": ["8.8.8.8"]})
    with pytest.raises(ScopeViolation, match="not covered by the top-level targets"):
        Scope.load(path)


def test_resolve_unknown_group_raises(tmp_path):
    scope = Scope.load(write_scope(tmp_path, target_groups={"prod": ["10.0.0.1"]}))
    with pytest.raises(ScopeViolation, match="not defined"):
        scope.resolve_group("staging")


def test_protocol_limits_override(tmp_path):
    scope = Scope.load(write_scope(
        tmp_path,
        protocol_limits={"rdp": {"seconds_between_passwords": 900, "tasks": 2}},
    ))
    limits = scope.get_protocol_limits("rdp")
    assert limits["seconds_between_passwords"] == 900
    assert limits["tasks"] == 2


def test_protocol_limits_fallback_to_default(tmp_path):
    scope = Scope.load(write_scope(tmp_path))
    limits = scope.get_protocol_limits("ssh")  # not configured
    assert limits["seconds_between_passwords"] == 300
    assert limits["tasks"] == 1


def test_scope_without_optional_fields_still_loads(tmp_path):
    scope = Scope.load(write_scope(tmp_path))
    assert scope.target_groups == {}
    assert scope.protocol_limits == {}
    assert scope.emergency_contact == ""
