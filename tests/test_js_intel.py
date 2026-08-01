from credaudit.modules.js_intel import analyze_js


SAMPLE_JS = '''
const config = {
  apiKey: "sk-abcdef0123456789abcdef01",
  awsKey: "AKIAABCDEFGHIJKLMNOP",
};

fetch("/api/v2/admin/users").then(r => r.json());
axios.get("/api/internal/debug/config");

const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

// graphql endpoint
fetch("/graphql");
'''


def test_extracts_endpoints():
    result = analyze_js(SAMPLE_JS, source="main.js")
    paths = [p for p, score in result.endpoints]
    assert "/api/v2/admin/users" in paths
    assert "/api/internal/debug/config" in paths


def test_ranks_admin_and_debug_endpoints_higher():
    result = analyze_js(SAMPLE_JS, source="main.js")
    scores = dict(result.endpoints)
    assert scores["/api/internal/debug/config"] > scores.get("/graphql", 0)


def test_detects_aws_key():
    result = analyze_js(SAMPLE_JS, source="main.js")
    kinds = [s.kind for s in result.secrets]
    assert "aws_access_key" in kinds


def test_detects_generic_api_key():
    result = analyze_js(SAMPLE_JS, source="main.js")
    kinds = [s.kind for s in result.secrets]
    assert "generic_api_key" in kinds


def test_detects_jwt():
    result = analyze_js(SAMPLE_JS, source="main.js")
    kinds = [s.kind for s in result.secrets]
    assert "jwt" in kinds


def test_secrets_are_masked():
    result = analyze_js(SAMPLE_JS, source="main.js")
    for secret in result.secrets:
        assert secret.masked != secret.value
        assert "*" in secret.masked


def test_detects_graphql_hint():
    result = analyze_js(SAMPLE_JS, source="main.js")
    assert result.has_graphql is True


def test_no_false_positive_on_clean_js():
    clean = 'function add(a, b) { return a + b; }'
    result = analyze_js(clean, source="clean.js")
    assert result.secrets == []
    assert result.has_graphql is False


def test_source_is_recorded():
    result = analyze_js(SAMPLE_JS, source="https://acme.example/static/main.js")
    assert result.source == "https://acme.example/static/main.js"


def test_to_dict_from_dict_round_trip():
    from credaudit.modules.js_intel import to_dict, from_dict

    original = analyze_js(SAMPLE_JS, source="main.js")
    restored = from_dict(to_dict(original))

    assert restored.source == original.source
    assert restored.endpoints == original.endpoints
    assert restored.has_graphql == original.has_graphql
    assert [s.kind for s in restored.secrets] == [s.kind for s in original.secrets]
    assert [s.value for s in restored.secrets] == [s.value for s in original.secrets]
