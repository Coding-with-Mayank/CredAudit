from credaudit.analyzers import credentials as ca


def rec(account, password, **kw):
    return ca.CredentialRecord(account=account, password=password, **kw)


def test_strength_classification():
    assert ca.classify_strength("short", False) == "Weak"
    assert ca.classify_strength("password", True) == "Weak"
    assert ca.classify_strength("alllowercaseletters", False) == "Weak"  # one class
    assert ca.classify_strength("Abcdefgh1!xy", False) == "Medium"
    assert ca.classify_strength("Abcdefgh1!xyzQ9#", False) == "Strong"


def test_default_credential_detected():
    f = ca.analyze_credentials([rec("admin", "admin")])[0]
    assert f.default_credential is True
    assert f.strength == "Weak"
    assert f.privileged is True


def test_reuse_detected_across_accounts():
    findings = ca.analyze_credentials([rec("alice", "Sh4red!Pass#2024x"), rec("bob", "Sh4red!Pass#2024x"), rec("carol", "Un1que!Pass#9876y")])
    by = {f.account: f for f in findings}
    assert by["alice"].reused_with == ["bob"]
    assert by["bob"].reused_with == ["alice"]
    assert by["carol"].reused_with == []


def test_privileged_inference_and_override():
    f = ca.analyze_credentials([rec("svc_backup", "x"), rec("root", "x"), rec("jdoe", "x", privileged=True)])
    by = {x.account: x for x in f}
    assert by["svc_backup"].privileged is False
    assert by["root"].privileged is True
    assert by["jdoe"].privileged is True


def test_plaintext_never_stored_on_finding():
    pw = "Sup3r!Secret#Value99"
    f = ca.analyze_credentials([rec("jdoe", pw)])[0]
    assert pw not in repr(f)
    assert pw not in repr(f.risk)
    e = ca.finding_to_evidence(f, "ENG-1", "dc01")
    assert pw not in repr(e.to_dict())


def test_breach_checker_true_false_and_unchecked():
    f = ca.analyze_credentials([rec("a", "pw1")], breach_checker=lambda p: True)[0]
    assert f.breach_exposure is True
    f = ca.analyze_credentials([rec("a", "pw1")], breach_checker=lambda p: False)[0]
    assert f.breach_exposure is False
    f = ca.analyze_credentials([rec("a", "pw1")])[0]
    assert f.breach_exposure is None  # not checked != clean


def test_breach_checker_failure_becomes_unknown_not_clean():
    def boom(_):
        raise RuntimeError("network down")
    f = ca.analyze_credentials([rec("a", "pw1")], breach_checker=boom)[0]
    assert f.breach_exposure is None
    assert f.risk.confidence < 1.0  # discounted for unknown


def test_worked_example_admin_is_critical():
    recs = [rec("admin", "admin"), rec("svc", "admin")]
    f = ca.analyze_credentials(recs, breach_checker=lambda p: True, internet_facing=True)[0]
    assert f.risk.severity == "Critical"


def test_internet_facing_raises_score():
    ext = ca.analyze_credentials([rec("jdoe", "weak")], internet_facing=True)[0]
    internal = ca.analyze_credentials([rec("jdoe", "weak")], internet_facing=False)[0]
    assert ext.risk.score > internal.risk.score


def test_custom_common_password_list():
    f = ca.analyze_credentials([rec("a", "Zebra-Crossing-77!")], common_passwords={"zebra-crossing-77!"})[0]
    assert f.common_password is True and f.strength == "Weak"


def test_evidence_shape():
    f = ca.analyze_credentials([rec("admin", "admin")])[0]
    e = ca.finding_to_evidence(f, "ENG-1", "dc01")
    assert e.category == "Credential Exposure"
    assert e.status == "detected"
    assert e.severity == f.risk.severity
    assert "unknown (not checked)" in e.evidence
