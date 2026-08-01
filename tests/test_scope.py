from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from credaudit.scope import Scope, ScopeViolation


def write_scope(tmp_path, **overrides) -> Path:
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
    return path


def test_loads_valid_scope(tmp_path):
    scope = Scope.load(write_scope(tmp_path))
    assert scope.engagement_id == "TEST-001"


def test_rejects_expired_engagement(tmp_path):
    path = write_scope(
        tmp_path,
        start_date=date.today() - timedelta(days=10),
        end_date=date.today() - timedelta(days=1),
    )
    with pytest.raises(ScopeViolation):
        Scope.load(path)


def test_rejects_out_of_scope_target(tmp_path):
    scope = Scope.load(write_scope(tmp_path))
    with pytest.raises(ScopeViolation):
        scope.check_target("8.8.8.8")


def test_allows_cidr_target(tmp_path):
    scope = Scope.load(write_scope(tmp_path))
    scope.check_target("10.0.1.55")  # inside 10.0.1.0/24


def test_rejects_disallowed_module(tmp_path):
    scope = Scope.load(write_scope(tmp_path))
    with pytest.raises(ScopeViolation):
        scope.check_module("online")


def test_missing_scope_file(tmp_path):
    with pytest.raises(ScopeViolation):
        Scope.load(tmp_path / "does-not-exist.yaml")
