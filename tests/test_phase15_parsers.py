"""Phase 15: the modern parser catalogue.

Each parser is exercised against a fragment shaped like the tool's real output,
not against a fixture invented to match the implementation. The assertions are
about the three things a parser can get wrong in a way that silently corrupts a
vulnerability programme:

1. **Dropping records.** Counts are asserted explicitly.
2. **Misgrading severity.** A tool's own scale must map onto the VEYRS ladder,
   and where a tool has no severity the parser must say `None` rather than
   invent one - `test_pip_audit_does_not_invent_a_severity`.
3. **Losing the dimension that makes the finding deduplicable.** A SAST record
   with no file/line, or an SCA record with no package, dedupes into its
   neighbours.

Secrets are also checked to be *absent*: a scanner that finds a credential must
not have VEYRS store a second copy of it.
"""
from __future__ import annotations

import json

import pytest

from veyrs.services.importers import ParserError, parsers
from veyrs.services.importers.parsers_modern import detect_modern_format


def _records(name: str, payload: bytes):
    return [r.normalise() for r in parsers.get_parser(name)(payload)]


def _j(obj) -> bytes:
    return json.dumps(obj).encode()


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------
SARIF = _j({
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [{
            "id": "js/sql-injection",
            "shortDescription": {"text": "Database query built from user input"},
            "fullDescription": {"text": "Untrusted input flows into a SQL query."},
            "help": {"text": "Use parameterised queries."},
            "properties": {"security-severity": "9.8",
                           "tags": ["security", "external/cwe/cwe-089"]},
        }]}},
        "results": [{
            "ruleId": "js/sql-injection",
            "level": "error",
            "message": {"text": "This query depends on a user-provided value."},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/db/query.js"},
                "region": {"startLine": 42, "snippet": {"text": "db.query(sql)"}},
            }}],
            "partialFingerprints": {"primaryLocationLineHash": "9f8e7d"},
        }],
    }],
})


def test_sarif_maps_security_severity_and_location():
    records = _records("sarif", SARIF)
    assert len(records) == 1
    record = records[0]
    assert record.title == "Database query built from user input"
    assert record.plugin_id == "js/sql-injection"
    assert record.severity == "critical"          # 9.8, not "error" -> high
    assert record.cvss_score == 9.8
    assert record.cwe == "CWE-89"
    assert record.file_path == "src/db/query.js"
    assert record.line == 42
    assert record.unique_id == "js/sql-injection:9f8e7d"
    assert record.solution == "Use parameterised queries."


def test_sarif_falls_back_to_level_when_no_security_severity():
    payload = json.loads(SARIF)
    del payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    records = _records("sarif", _j(payload))
    assert records[0].severity == "high"          # level "error"


def test_sarif_rejects_a_non_sarif_document():
    with pytest.raises(ParserError, match="SARIF"):
        _records("sarif", _j({"results": []}))


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------
TRIVY = _j({
    "ArtifactName": "registry.internal/api:2.4.1",
    "ArtifactType": "container_image",
    "Results": [{
        "Target": "registry.internal/api:2.4.1 (debian 12.5)",
        "Class": "os-pkgs", "Type": "debian",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-0001",
            "PkgName": "openssl", "InstalledVersion": "3.0.11-1",
            "FixedVersion": "3.0.13-1", "Severity": "HIGH",
            "Title": "openssl: denial of service via malformed certificate",
            "Description": "A malformed certificate can crash the parser.",
            "CVSS": {"nvd": {"V3Score": 7.5,
                             "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
        }],
        "Misconfigurations": [{
            "ID": "DS002", "Title": "Image user should not be root",
            "Severity": "HIGH", "Description": "Running as root.",
            "Resolution": "Add a USER directive.",
            "CauseMetadata": {"StartLine": 3},
        }],
        "Secrets": [{
            "RuleID": "aws-access-key-id", "Category": "AWS",
            "Severity": "CRITICAL", "Title": "AWS Access Key ID",
            "StartLine": 7, "Match": "AKIAIOSFODNN7EXAMPLE",
            "Code": {"Lines": [{"Content": "AKIAIOSFODNN7EXAMPLE"}]},
        }],
    }],
})


def test_trivy_reads_vulnerabilities_misconfigurations_and_secrets():
    records = _records("trivy", TRIVY)
    assert len(records) == 3

    vuln = records[0]
    assert vuln.hostname == "registry.internal/api:2.4.1"
    assert vuln.cve_ids == ["CVE-2026-0001"]
    assert vuln.severity == "high"
    assert vuln.cvss_score == 7.5
    assert vuln.cvss_vector.startswith("CVSS:3.1/")
    assert vuln.component_name == "openssl"
    assert vuln.component_version == "3.0.11-1"
    assert "3.0.13-1" in vuln.solution

    misconfig = records[1]
    assert misconfig.plugin_id == "DS002"
    assert misconfig.line == 3

    secret = records[2]
    assert secret.severity == "critical"
    assert "Exposed secret" in secret.title


def test_trivy_never_stores_the_secret_it_found():
    """VEYRS must not become a second place the credential is leaked from."""
    secret = _records("trivy", TRIVY)[2]
    blob = json.dumps({"evidence": secret.evidence, "raw": secret.raw,
                       "description": secret.description})
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


# ---------------------------------------------------------------------------
# Grype
# ---------------------------------------------------------------------------
GRYPE = _j({
    "matches": [{
        "vulnerability": {
            "id": "CVE-2026-0002", "severity": "Critical",
            "description": "Remote code execution in the XML parser.",
            "cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                      "metrics": {"baseScore": 9.8}}],
            "fix": {"versions": ["2.9.14"], "state": "fixed"},
        },
        "artifact": {"name": "libxml2", "version": "2.9.13", "type": "deb",
                     "locations": [{"path": "/usr/lib/libxml2.so"}]},
    }],
    "source": {"type": "image", "target": {"userInput": "acme/web:1.0"}},
})


def test_grype_reads_package_identity_and_fix():
    record = _records("grype", GRYPE)[0]
    assert record.hostname == "acme/web:1.0"
    assert record.cve_ids == ["CVE-2026-0002"]
    assert record.severity == "critical"
    assert record.cvss_score == 9.8
    assert record.component_name == "libxml2"
    assert record.component_version == "2.9.13"
    assert "2.9.14" in record.solution


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------
SEMGREP = _j({"results": [{
    "check_id": "python.django.security.audit.raw-query",
    "path": "app/views.py",
    "start": {"line": 88}, "end": {"line": 88},
    "extra": {
        "message": "Detected raw SQL built from user input.",
        "severity": "ERROR",
        "fingerprint": "d41d8cd98f00",
        "metadata": {"cwe": ["CWE-89: Improper Neutralization of Special Elements"],
                     "impact": "HIGH", "confidence": "HIGH", "category": "security",
                     "owasp": ["A03:2021 - Injection"]},
    },
}]})


def test_semgrep_keeps_file_line_and_rule_identity():
    record = _records("semgrep", SEMGREP)[0]
    assert record.plugin_id == "python.django.security.audit.raw-query"
    assert record.unique_id.endswith("d41d8cd98f00")
    assert record.severity == "high"
    assert record.cwe == "CWE-89"
    assert record.file_path == "app/views.py"
    assert record.line == 88


# ---------------------------------------------------------------------------
# Bandit / Gitleaks / Checkov
# ---------------------------------------------------------------------------
BANDIT = _j({"results": [{
    "filename": "scripts/deploy.py", "line_number": 17,
    "issue_severity": "HIGH", "issue_confidence": "HIGH",
    "issue_text": "subprocess call with shell=True identified.",
    "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true",
    "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
    "code": "subprocess.Popen(cmd, shell=True)",
}], "metrics": {"_totals": {}}})


def test_bandit_reads_test_id_cwe_and_line():
    record = _records("bandit", BANDIT)[0]
    assert record.plugin_id == "B602"
    assert record.severity == "high"
    assert record.cwe == "CWE-78"
    assert record.file_path == "scripts/deploy.py"
    assert record.line == 17


GITLEAKS = _j([{
    "Description": "AWS Access Key", "File": "config/settings.py", "StartLine": 3,
    "RuleID": "aws-access-token", "Secret": "AKIAIOSFODNN7EXAMPLE",
    "Match": "key = AKIAIOSFODNN7EXAMPLE",
    "Fingerprint": "config/settings.py:aws-access-token:3",
    "Commit": "9c1e2f", "Author": "someone",
}])


def test_gitleaks_is_always_high_and_never_stores_the_secret():
    record = _records("gitleaks", GITLEAKS)[0]
    assert record.severity == "high"
    assert record.unique_id == "config/settings.py:aws-access-token:3"
    assert record.line == 3
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(
        {"e": record.evidence, "r": record.raw, "d": record.description})


CHECKOV = _j({"check_type": "terraform", "results": {"failed_checks": [{
    "check_id": "CKV_AWS_18",
    "check_name": "Ensure the S3 bucket has access logging enabled",
    "file_path": "/modules/storage/main.tf", "file_line_range": [12, 20],
    "resource": "aws_s3_bucket.artifacts", "severity": None,
    "guideline": "https://docs.example/CKV_AWS_18",
    "code_block": [[12, "resource \"aws_s3_bucket\" \"artifacts\" {"]],
}], "passed_checks": []}})


def test_checkov_defaults_ungraded_checks_to_medium():
    """Community Checkov leaves severity null; treating it as critical would
    drown the real criticals, and as informational would hide it."""
    record = _records("checkov", CHECKOV)[0]
    assert record.severity == "medium"
    assert record.plugin_id == "CKV_AWS_18"
    assert record.file_path == "/modules/storage/main.tf"
    assert record.line == 12
    assert record.evidence["resource"] == "aws_s3_bucket.artifacts"


# ---------------------------------------------------------------------------
# Nuclei / ZAP
# ---------------------------------------------------------------------------
NUCLEI = (
    json.dumps({
        "template-id": "CVE-2021-44228",
        "info": {"name": "Apache Log4j2 RCE", "severity": "critical",
                 "tags": ["cve", "rce"],
                 "classification": {"cve-id": ["CVE-2021-44228"], "cwe-id": ["CWE-502"],
                                    "cvss-score": 10.0,
                                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
        "host": "https://app.example.com", "matched-at": "https://app.example.com/api/v1",
        "type": "http", "matcher-name": "jndi",
    }) + "\n" + json.dumps({
        "template-id": "tech-detect", "info": {"name": "Nginx", "severity": "info"},
        "host": "https://app.example.com", "matched-at": "https://app.example.com/",
        "type": "http",
    })
).encode()


def test_nuclei_reads_jsonl_and_keeps_the_url():
    records = _records("nuclei", NUCLEI)
    assert len(records) == 2
    critical = records[0]
    assert critical.url == "https://app.example.com/api/v1"
    assert critical.severity == "critical"
    assert critical.cve_ids == ["CVE-2021-44228"]
    assert critical.cwe == "CWE-502"
    assert critical.cvss_score == 10.0
    assert critical.unique_id == "CVE-2021-44228:jndi:https://app.example.com/api/v1"
    assert records[1].severity == "informational"


def test_nuclei_also_accepts_a_json_array():
    array = _j([json.loads(line) for line in NUCLEI.decode().splitlines()])
    assert len(_records("nuclei", array)) == 2


ZAP = _j({"site": [{
    "@name": "https://app.example.com", "@host": "app.example.com",
    "@port": "443", "@ssl": "true",
    "alerts": [{
        "pluginid": "40018", "alert": "SQL Injection", "riskcode": "3",
        "confidence": "2", "cweid": "89", "wascid": "19",
        "desc": "<p>SQL injection may be possible.</p>",
        "solution": "<p>Use prepared statements.</p>",
        "instances": [
            {"uri": "https://app.example.com/search", "method": "GET",
             "param": "q", "evidence": "syntax error", "attack": "' OR 1=1--"},
            {"uri": "https://app.example.com/report", "method": "POST", "param": "id"},
        ],
    }],
}]})


def test_zap_yields_one_record_per_alert_with_every_instance_attached():
    """One alert is one thing to triage; its instances are places to fix.

    Splitting per instance would make an analyst triage "SQL Injection" once
    per affected URL, which is the failure mode the endpoint model exists to
    avoid.
    """
    records = _records("zap", ZAP)
    assert len(records) == 1
    record = records[0]
    assert record.url == "https://app.example.com/search"
    assert [e["url"] for e in record.endpoints] == ["https://app.example.com/report"]
    assert record.evidence["instance_count"] == 2
    assert record.severity == "high"               # riskcode 3
    assert record.cwe == "CWE-89"
    assert record.method == "GET"
    assert record.params == "q"
    assert record.description == "SQL injection may be possible."   # no <p>
    assert record.solution == "Use prepared statements."


def test_zap_and_nuclei_dedupe_at_the_granularity_each_tool_reports():
    """ZAP aggregates, Nuclei does not - and the configs must match, or one of
    them forks a finding per URL while the other merges two real issues."""
    from veyrs.services import dedupe

    assert "endpoint" not in dedupe.config_for("zap").fields
    assert "endpoint" in dedupe.config_for("nuclei").fields


# ---------------------------------------------------------------------------
# SCA: npm audit / pip-audit / Dependabot
# ---------------------------------------------------------------------------
NPM_AUDIT = _j({"vulnerabilities": {
    "lodash": {
        "name": "lodash", "severity": "high", "range": "<4.17.21",
        "fixAvailable": {"name": "lodash", "version": "4.17.21"},
        "via": [{"source": 1065, "name": "lodash", "title": "Prototype Pollution",
                 "url": "https://github.com/advisories/GHSA-p6mc",
                 "severity": "high", "cwe": ["CWE-1321"],
                 "cvss": {"score": 7.4, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"},
                 "range": "<4.17.21", "cve": "CVE-2020-8203"}],
    },
    "async": {"name": "async", "severity": "high", "via": ["lodash"], "range": "*"},
}})


def test_npm_audit_reads_advisories_and_skips_transitive_parents():
    """`via: ["lodash"]` names the parent, not an advisory. Emitting it too
    would double-count the same underlying vulnerability."""
    records = _records("npm_audit", NPM_AUDIT)
    assert len(records) == 1
    record = records[0]
    assert record.component_name == "lodash"
    assert record.severity == "high"
    assert record.cvss_score == 7.4
    assert record.cwe == "CWE-1321"
    assert record.cve_ids == ["CVE-2020-8203"]


PIP_AUDIT = _j({"dependencies": [
    {"name": "flask", "version": "1.0", "vulns": [
        {"id": "PYSEC-2019-179", "fix_versions": ["1.0.1"],
         "aliases": ["CVE-2019-1010083"],
         "description": "Denial of service via unbounded memory use."}]},
    {"name": "requests", "version": "2.31.0", "vulns": []},
]})


def test_pip_audit_does_not_invent_a_severity():
    """pip-audit reports none. A guess here would be a fabricated risk score."""
    records = _records("pip_audit", PIP_AUDIT)
    assert len(records) == 1
    record = records[0]
    assert record.severity is None
    assert record.cve_ids == ["CVE-2019-1010083"]
    assert record.component_name == "flask"
    assert "1.0.1" in record.solution


DEPENDABOT = _j([
    {"number": 7, "state": "open",
     "dependency": {"package": {"ecosystem": "pip", "name": "django"},
                    "manifest_path": "requirements.txt"},
     "security_advisory": {"ghsa_id": "GHSA-abcd", "cve_id": "CVE-2026-0003",
                           "severity": "high", "summary": "SQL injection in QuerySet",
                           "description": "Long form.",
                           "cvss": {"score": 8.8, "vector_string": "CVSS:3.1/AV:N"},
                           "cwes": [{"cwe_id": "CWE-89"}]},
     "security_vulnerability": {"vulnerable_version_range": "< 4.2.11",
                                "first_patched_version": {"identifier": "4.2.11"}},
     "html_url": "https://github.com/acme/app/security/dependabot/7"},
    {"number": 8, "state": "fixed",
     "dependency": {"package": {"ecosystem": "npm", "name": "left-pad"}},
     "security_advisory": {"ghsa_id": "GHSA-efgh", "severity": "low",
                           "summary": "Already fixed"},
     "security_vulnerability": {}},
])


def test_dependabot_ignores_alerts_somebody_already_closed():
    records = _records("dependabot", DEPENDABOT)
    assert len(records) == 1
    record = records[0]
    assert record.plugin_id == "GHSA-abcd"
    assert record.cve_ids == ["CVE-2026-0003"]
    assert record.severity == "high"
    assert record.cvss_score == 8.8
    assert record.cwe == "CWE-89"
    assert record.file_path == "requirements.txt"
    assert "4.2.11" in record.solution


# ---------------------------------------------------------------------------
# Prowler
# ---------------------------------------------------------------------------
PROWLER = _j([
    {"check_id": "s3_bucket_public_access", "check_title": "S3 bucket is public",
     "status_code": "FAIL", "severity": "critical",
     "status_detail": "Bucket acme-artifacts allows public reads.",
     "resource_uid": "arn:aws:s3:::acme-artifacts", "account_uid": "111122223333",
     "region": "eu-central-1", "service_name": "s3",
     "remediation": {"desc": "Enable Block Public Access."},
     "finding_info": {"title": "S3 bucket is public"}},
    {"check_id": "iam_root_mfa", "check_title": "Root account has MFA",
     "status_code": "PASS", "severity": "high", "resource_uid": "root",
     "account_uid": "111122223333", "finding_info": {"title": "Root MFA"}},
])


def test_prowler_imports_failures_and_drops_passes():
    """A PASS is evidence of compliance. Importing it as a finding would make
    a healthy account look catastrophic and bury the real failure."""
    records = _records("prowler", PROWLER)
    assert len(records) == 1
    record = records[0]
    assert record.severity == "critical"
    assert record.plugin_id == "s3_bucket_public_access"
    assert record.hostname == "arn:aws:s3:::acme-artifacts"
    assert record.unique_id == "s3_bucket_public_access:arn:aws:s3:::acme-artifacts"
    assert "Block Public Access" in record.solution


# ---------------------------------------------------------------------------
# Detection and registry
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name, payload", [
    ("sarif", SARIF), ("trivy", TRIVY), ("grype", GRYPE), ("semgrep", SEMGREP),
    ("bandit", BANDIT), ("gitleaks", GITLEAKS), ("checkov", CHECKOV),
    ("nuclei", NUCLEI), ("zap", ZAP), ("npm_audit", NPM_AUDIT),
    ("pip_audit", PIP_AUDIT), ("dependabot", DEPENDABOT), ("prowler", PROWLER),
])
def test_every_format_is_detected_from_its_own_payload(name, payload):
    assert parsers.detect_format(payload, "") == name


def test_unrecognised_json_still_falls_back_to_the_generic_parser():
    assert parsers.detect_format(_j({"anything": [1, 2, 3]}), "") == "json"
    assert detect_modern_format(_j({"anything": []}), "") is None


def test_filename_hints_win_over_content_sniffing():
    """A named tool beats sniffing, and the alias keeps its own scanner label.

    `codeql-results.sarif` resolves to the `codeql` scanner, not to `sarif`:
    both use the same parser, but the label is what lands on the finding and
    what `dedupe.config_for()` looks up, so the alias needs to stay distinct.
    """
    from veyrs.services.importers.parsers_modern import parse_sarif

    detected = parsers.detect_format(_j({"anything": []}), "codeql-results.sarif")
    assert detected == "codeql"
    assert parsers.get_parser(detected) is parse_sarif
    assert parsers.detect_format(_j({"anything": []}), "report.sarif") == "sarif"


@pytest.mark.parametrize("name", sorted([
    "sarif", "trivy", "grype", "semgrep", "bandit", "gitleaks", "checkov",
    "nuclei", "zap", "npm_audit", "pip_audit", "dependabot", "prowler",
]))
def test_every_parser_refuses_garbage_rather_than_yielding_nonsense(name):
    with pytest.raises(ParserError):
        _records(name, b"this is not json at all")


@pytest.mark.parametrize("name", sorted([
    "sarif", "trivy", "grype", "semgrep", "bandit", "gitleaks", "checkov",
    "nuclei", "zap", "npm_audit", "pip_audit", "dependabot", "prowler",
]))
def test_every_parser_refuses_a_report_from_a_different_tool(name):
    """Silently returning zero records from the wrong parser is how an import
    'succeeds' having ingested nothing."""
    with pytest.raises(ParserError):
        _records(name, _j({"totally": "unrelated", "shape": [1, 2]}))


def test_every_registered_parser_has_a_dedupe_config():
    """A parser with no registered config falls back to `legacy`, which is the
    algorithm that collapses SAST findings. Catch it here, not in production."""
    from veyrs.services import dedupe

    code_and_web = {"sarif", "codeql", "semgrep", "bandit", "gitleaks", "checkov",
                    "nuclei", "zap", "trivy", "grype", "npm_audit", "pip_audit",
                    "dependabot", "prowler"}
    for name in code_and_web:
        config = dedupe.config_for(name)
        assert config.algorithm != dedupe.LEGACY, f"{name} would dedupe on port/path"
        assert config.fields, f"{name} has an empty hash field list"
