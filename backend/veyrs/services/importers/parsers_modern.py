"""Parsers for the modern toolchain: SAST, SCA, DAST, IaC and cloud posture.

VEYRS shipped with five parsers, all of them network-scanner shaped
(host, port, plugin id). That covers infrastructure scanning and nothing else,
which is why every code, container and cloud finding had to be imported as
generic CSV and lost its structure on the way in.

The formats here are the ones that actually carry the market. Ordered by how
much each unlocks:

* **SARIF** - an OASIS standard, not a vendor format. CodeQL, ESLint, Clippy,
  Coverity, PMD, SpotBugs, Snyk Code, Trivy and dozens of others all emit it.
  One parser, a long tail of tools.
* **Trivy / Grype / npm audit / pip-audit / Dependabot** - SCA. The finding is
  a package at a version, not a port.
* **Semgrep / Bandit / Gitleaks / Checkov** - SAST, secrets and IaC. The
  finding is a file at a line.
* **Nuclei / ZAP** - DAST. The finding is a URL, which is what makes the
  endpoint model earn its keep.
* **Prowler** - cloud posture. The finding is a cloud resource.

**Licensing.** These parsers were written against each tool's *documented output
schema* (and, for SARIF, the published specification). No code was copied from
DefectDojo, Faraday or any other project. DefectDojo is BSD-3 and copying with
attribution would have been permissible; Faraday is GPL-3.0 and copying from it
would have forced VEYRS to become GPL. Reimplementing from the schema keeps the
question moot.

Every parser obeys the same contract as the originals: pure `bytes ->
Iterator[ScanRecord]`, no database, no network, and a malformed file raises
`ParserError` rather than yielding nonsense.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterator

from .base import CVE_RE, ParserError, ScanRecord

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
#: Where a numeric score lands on the VEYRS ladder. Matches the CVSS v3 bands so
#: a tool that reports 7.5 gets the same severity as the CVE would.
def severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "informational"


WORD_SEVERITY = {
    "critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
    "low": "low", "negligible": "low", "info": "informational",
    "informational": "informational", "unknown": None, "none": "informational",
    "error": "high", "warning": "medium", "note": "low",
}


def severity_from_word(word: Any) -> str | None:
    if word is None:
        return None
    return WORD_SEVERITY.get(str(word).strip().lower())


def _load_json(payload: bytes) -> Any:
    try:
        return json.loads(payload.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise ParserError("file is not UTF-8 text") from exc
    except json.JSONDecodeError as exc:
        raise ParserError(f"invalid JSON: {exc}") from exc


def _load_jsonl(payload: bytes) -> list[dict]:
    """JSON Lines, tolerating a plain JSON array (tools emit both)."""
    text = payload.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise ParserError("empty file")
    if text.startswith("["):
        data = _load_json(payload)
        if not isinstance(data, list):
            raise ParserError("expected a JSON array")
        return [row for row in data if isinstance(row, dict)]
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ParserError(f"invalid JSON Lines input: {exc}") from exc
        if isinstance(row, dict):
            rows.append(row)
    if not rows:
        raise ParserError("no JSON objects found")
    return rows


def _cves(*values: Any) -> list[str]:
    """Pull CVE ids out of anything: a string, a list, a nested structure."""
    found: list[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            found.extend(_cves(*value))
        elif isinstance(value, dict):
            found.extend(_cves(*value.values()))
        else:
            found.extend(CVE_RE.findall(str(value)))
    return sorted({c.upper() for c in found})


def _cwe(value: Any) -> str | None:
    """Normalise anything CWE-shaped to `CWE-79`."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        for item in value:
            found = _cwe(item)
            if found:
                return found
        return None
    if isinstance(value, dict):
        return _cwe(value.get("cwe_id") or value.get("id") or value.get("cweId"))
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"(\d{1,5})", text)
    if not match:
        return None
    # `int()` strips leading zeros. SARIF writes the tag `external/cwe/cwe-089`
    # and MITRE calls it CWE-89; keeping the zero would make the two spellings
    # different CWEs to every consumer downstream.
    return f"CWE-{int(match.group(1))}"


def _text(value: Any) -> str | None:
    """SARIF and friends wrap human strings in `{"text": ...}` objects."""
    if value is None:
        return None
    if isinstance(value, dict):
        return _text(value.get("text") or value.get("markdown"))
    text = str(value).strip()
    return text or None


def _require(data: Any, *keys: str) -> None:
    """Assert the payload has at least one of `keys`, or it is not this format."""
    if not isinstance(data, dict) or not any(k in data for k in keys):
        raise ParserError(
            f"payload does not look like this format (expected one of: {', '.join(keys)})"
        )


# ---------------------------------------------------------------------------
# SARIF 2.1.0 (OASIS) - CodeQL, Snyk Code, ESLint, Clippy, Coverity, ...
# ---------------------------------------------------------------------------
SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "informational"}


def parse_sarif(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    if not isinstance(data, dict) or "runs" not in data:
        raise ParserError("not a SARIF document (no 'runs' array)")

    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool_name = driver.get("name") or "sarif"
        # Rule metadata lives once in the driver, and every result points at it
        # by id. Resolving it here is what turns a bare rule id into a title,
        # a CWE and a severity.
        rules: dict[str, dict] = {}
        for rule in (driver.get("rules") or []):
            if isinstance(rule, dict) and rule.get("id"):
                rules[str(rule["id"])] = rule

        for result in (run.get("results") or []):
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "")
            rule = rules.get(rule_id, {})
            properties = rule.get("properties") or {}

            # `security-severity` is a CVSS-like 0-10 float and is more precise
            # than the three-valued `level`, so it wins when present.
            score = None
            raw_score = properties.get("security-severity")
            if raw_score is not None:
                try:
                    score = float(raw_score)
                except (TypeError, ValueError):
                    score = None
            severity = (
                severity_from_score(score)
                or SARIF_LEVEL.get(str(result.get("level") or "").lower())
                or SARIF_LEVEL.get(str(rule.get("defaultConfiguration", {})
                                       .get("level") or "").lower())
                or "medium"
            )

            location = ((result.get("locations") or [{}])[0] or {})
            physical = location.get("physicalLocation") or {}
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            file_path = artifact.get("uri")
            line = region.get("startLine")

            title = (
                _text(rule.get("shortDescription"))
                or _text(result.get("message"))
                or rule_id
                or "SARIF result"
            )
            # Fingerprints are the tool's own stable identity; SARIF even says
            # so. Preferring them is the difference between a result surviving a
            # refactor and being reported as new every run.
            fingerprints = result.get("fingerprints") or result.get("partialFingerprints") or {}
            unique_id = None
            if isinstance(fingerprints, dict) and fingerprints:
                key = sorted(fingerprints)[0]
                unique_id = f"{rule_id}:{fingerprints[key]}"

            yield ScanRecord(
                title=title[:500],
                plugin_id=rule_id or None,
                unique_id=unique_id,
                severity=severity,
                cvss_score=score,
                description=_text(result.get("message")) or _text(rule.get("fullDescription")),
                solution=_text(rule.get("help")),
                cwe=_cwe(properties.get("tags") or properties.get("cwe")),
                cve_ids=_cves(rule_id, properties.get("tags"), _text(result.get("message"))),
                file_path=file_path,
                line=int(line) if isinstance(line, int) else None,
                evidence={
                    "tool": tool_name,
                    "snippet": _text(region.get("snippet")),
                    "level": result.get("level"),
                },
                raw=result,
            )


# ---------------------------------------------------------------------------
# Trivy (containers, filesystems, IaC, secrets)
# ---------------------------------------------------------------------------
def parse_trivy(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    if isinstance(data, list):          # older `trivy -f json` emitted a bare array
        data = {"Results": data}
    _require(data, "Results", "results")
    artifact = data.get("ArtifactName") or data.get("artifactName")

    for result in (data.get("Results") or data.get("results") or []):
        if not isinstance(result, dict):
            continue
        target = result.get("Target") or artifact

        for vuln in (result.get("Vulnerabilities") or []):
            if not isinstance(vuln, dict):
                continue
            cvss = vuln.get("CVSS") or {}
            score = vector = None
            # Trivy carries several vendors' scores; NVD first, then whatever
            # else is there, rather than picking one arbitrarily.
            for source in ("nvd", "redhat", "ghsa", "bitnami"):
                entry = cvss.get(source) or {}
                score = entry.get("V3Score") or entry.get("V2Score") or score
                vector = entry.get("V3Vector") or entry.get("V2Vector") or vector
            if score is None:
                for entry in cvss.values():
                    if isinstance(entry, dict):
                        score = entry.get("V3Score") or entry.get("V2Score")
                        vector = entry.get("V3Vector") or vector
                        if score:
                            break

            fixed = vuln.get("FixedVersion")
            yield ScanRecord(
                hostname=artifact,
                host_is_artifact=True,
                title=(vuln.get("Title") or vuln.get("VulnerabilityID") or "")[:500],
                cve_ids=_cves(vuln.get("VulnerabilityID"), vuln.get("References")),
                plugin_id=vuln.get("VulnerabilityID"),
                severity=severity_from_word(vuln.get("Severity")),
                cvss_score=float(score) if score else None,
                cvss_vector=vector,
                description=vuln.get("Description"),
                solution=(f"Upgrade {vuln.get('PkgName')} to {fixed}" if fixed else None),
                component_name=vuln.get("PkgName"),
                component_version=vuln.get("InstalledVersion"),
                file_path=vuln.get("PkgPath") or target,
                evidence={"target": target, "class": result.get("Class"),
                          "type": result.get("Type"), "fixed_version": fixed},
                raw=vuln,
            )

        for misconfig in (result.get("Misconfigurations") or []):
            if not isinstance(misconfig, dict):
                continue
            lines = (misconfig.get("CauseMetadata") or {}).get("StartLine")
            yield ScanRecord(
                hostname=artifact,
                host_is_artifact=True,
                title=(misconfig.get("Title") or misconfig.get("ID") or "")[:500],
                plugin_id=misconfig.get("ID") or misconfig.get("AVDID"),
                unique_id=f"{misconfig.get('ID')}:{target}:{lines}" if misconfig.get("ID") else None,
                severity=severity_from_word(misconfig.get("Severity")),
                description=misconfig.get("Description"),
                solution=misconfig.get("Resolution"),
                file_path=target,
                line=lines if isinstance(lines, int) else None,
                evidence={"type": misconfig.get("Type"), "message": misconfig.get("Message")},
                raw=misconfig,
            )

        for secret in (result.get("Secrets") or []):
            if not isinstance(secret, dict):
                continue
            yield ScanRecord(
                hostname=artifact,
                host_is_artifact=True,
                title=f"Exposed secret: {secret.get('Title') or secret.get('RuleID')}"[:500],
                plugin_id=secret.get("RuleID"),
                severity=severity_from_word(secret.get("Severity")) or "high",
                file_path=target,
                line=secret.get("StartLine") if isinstance(secret.get("StartLine"), int) else None,
                description=(
                    "A credential was found in the artifact. Rotate it: anything "
                    "committed must be treated as disclosed."
                ),
                # The matched secret itself is deliberately NOT stored.
                evidence={"category": secret.get("Category"), "rule": secret.get("RuleID")},
                raw={k: v for k, v in secret.items() if k not in ("Match", "Code")},
            )


# ---------------------------------------------------------------------------
# Grype (Anchore)
# ---------------------------------------------------------------------------
def parse_grype(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    _require(data, "matches")
    source = ((data.get("source") or {}).get("target") or {})
    artifact = (
        source.get("userInput") if isinstance(source, dict) else None
    ) or (source if isinstance(source, str) else None)

    for match in (data.get("matches") or []):
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability") or {}
        package = match.get("artifact") or {}
        score = vector = None
        for entry in (vuln.get("cvss") or []):
            if not isinstance(entry, dict):
                continue
            score = (entry.get("metrics") or {}).get("baseScore") or score
            vector = entry.get("vector") or vector
        fix_versions = (vuln.get("fix") or {}).get("versions") or []

        yield ScanRecord(
            hostname=artifact,
            host_is_artifact=True,
            title=f"{vuln.get('id')} in {package.get('name')}"[:500],
            cve_ids=_cves(vuln.get("id"), vuln.get("urls")),
            plugin_id=vuln.get("id"),
            severity=severity_from_word(vuln.get("severity")),
            cvss_score=float(score) if score else None,
            cvss_vector=vector,
            description=vuln.get("description"),
            solution=(f"Upgrade {package.get('name')} to {', '.join(fix_versions)}"
                      if fix_versions else None),
            component_name=package.get("name"),
            component_version=package.get("version"),
            file_path=(package.get("locations") or [{}])[0].get("path")
            if package.get("locations") else None,
            evidence={"type": package.get("type"), "fix_state": (vuln.get("fix") or {}).get("state")},
            raw=match,
        )


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------
SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def parse_semgrep(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    _require(data, "results")

    for result in (data.get("results") or []):
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        check_id = result.get("check_id")
        line = (result.get("start") or {}).get("line")
        # Semgrep grades impact separately from rule severity; impact is the
        # better signal because it is about the finding, not the rule's noise.
        severity = (
            severity_from_word(metadata.get("impact"))
            or SEMGREP_SEVERITY.get(str(extra.get("severity") or "").upper())
            or "medium"
        )
        fingerprint = extra.get("fingerprint")

        yield ScanRecord(
            title=(_text(metadata.get("shortDescription"))
                   or (str(check_id).split(".")[-1] if check_id else None)
                   or _text(extra.get("message"))
                   or "Semgrep finding")[:500],
            plugin_id=str(check_id) if check_id else None,
            unique_id=f"{check_id}:{fingerprint}" if fingerprint else None,
            severity=severity,
            description=_text(extra.get("message")),
            solution=_text(extra.get("fix")) or _text(metadata.get("references")),
            cwe=_cwe(metadata.get("cwe")),
            cve_ids=_cves(metadata.get("cve"), metadata.get("references")),
            file_path=result.get("path"),
            line=int(line) if isinstance(line, int) else None,
            evidence={"confidence": metadata.get("confidence"),
                      "category": metadata.get("category"),
                      "owasp": metadata.get("owasp")},
            raw=result,
        )


# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------
def parse_bandit(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    _require(data, "results", "metrics")

    for result in (data.get("results") or []):
        if not isinstance(result, dict):
            continue
        line = result.get("line_number")
        yield ScanRecord(
            title=(result.get("test_name") or result.get("test_id") or "")[:500],
            plugin_id=result.get("test_id"),
            severity=severity_from_word(result.get("issue_severity")),
            description=result.get("issue_text"),
            cwe=_cwe(result.get("issue_cwe")),
            file_path=result.get("filename"),
            line=int(line) if isinstance(line, int) else None,
            evidence={"confidence": result.get("issue_confidence"),
                      "code": (result.get("code") or "")[:2000]},
            raw={k: v for k, v in result.items() if k != "code"},
        )


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------
def parse_gitleaks(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    if isinstance(data, dict):
        # Gitleaks emits a bare array; some wrappers nest it. A dict with
        # neither key is somebody else's report, and returning zero records
        # would let the import "succeed" having ingested nothing.
        if "findings" not in data and "Findings" not in data:
            raise ParserError("not a Gitleaks report (no findings array)")
        data = data.get("findings") or data.get("Findings") or []
    if not isinstance(data, list):
        raise ParserError("not a Gitleaks report (expected an array of findings)")
    if data and not any(
        isinstance(item, dict) and (item.get("RuleID") or item.get("ruleID"))
        for item in data
    ):
        raise ParserError("not a Gitleaks report (no RuleID on any finding)")

    for item in data:
        if not isinstance(item, dict):
            continue
        line = item.get("StartLine") or item.get("startLine")
        rule = item.get("RuleID") or item.get("ruleID")
        yield ScanRecord(
            title=f"Exposed secret: {item.get('Description') or rule}"[:500],
            plugin_id=rule,
            #: Gitleaks' fingerprint is `file:rule:line` and is already stable.
            unique_id=item.get("Fingerprint") or item.get("fingerprint"),
            severity="high",   # a committed credential has no low-severity form
            description=(
                "A credential was committed to the repository. Treat it as "
                "disclosed and rotate it; removing the commit does not undo "
                "disclosure."
            ),
            file_path=item.get("File") or item.get("file"),
            line=int(line) if isinstance(line, int) else None,
            # The secret value itself is never carried into VEYRS.
            evidence={"commit": item.get("Commit"), "author": item.get("Author"),
                      "rule": rule, "entropy": item.get("Entropy")},
            raw={k: v for k, v in item.items() if k not in ("Secret", "Match", "secret", "match")},
        )


# ---------------------------------------------------------------------------
# Checkov (IaC)
# ---------------------------------------------------------------------------
def parse_checkov(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    blocks = data if isinstance(data, list) else [data]

    seen_any = False
    for block in blocks:
        if not isinstance(block, dict) or "results" not in block:
            continue
        seen_any = True
        check_type = block.get("check_type")
        for check in ((block.get("results") or {}).get("failed_checks") or []):
            if not isinstance(check, dict):
                continue
            line_range = check.get("file_line_range") or []
            line = line_range[0] if line_range else None
            resource = check.get("resource")
            yield ScanRecord(
                title=(check.get("check_name") or check.get("check_id") or "")[:500],
                plugin_id=check.get("check_id"),
                unique_id=(f"{check.get('check_id')}:{check.get('file_path')}:{resource}"
                           if check.get("check_id") else None),
                #: Checkov leaves severity null on the community rule set. A
                #: misconfiguration with no grading is medium, not critical:
                #: inflating it would drown the real criticals.
                severity=severity_from_word(check.get("severity")) or "medium",
                description=check.get("guideline") or check.get("check_name"),
                solution=check.get("guideline"),
                file_path=check.get("file_path"),
                line=int(line) if isinstance(line, int) else None,
                evidence={"resource": resource, "check_type": check_type,
                          "code_block": str(check.get("code_block"))[:2000]},
                raw={k: v for k, v in check.items() if k != "code_block"},
            )
    if not seen_any:
        raise ParserError("not a Checkov report (no 'results' block)")


# ---------------------------------------------------------------------------
# Nuclei (DAST)
# ---------------------------------------------------------------------------
def parse_nuclei(payload: bytes) -> Iterator[ScanRecord]:
    rows = _load_jsonl(payload)
    # `rows and` matters: an empty result set means the scan found nothing,
    # NOT that the file is some other tool's format.
    if rows and not any(("template-id" in r or "templateID" in r) for r in rows):
        raise ParserError("not a Nuclei report (no template-id in any record)")

    for row in rows:
        info = row.get("info") or {}
        classification = info.get("classification") or {}
        template_id = row.get("template-id") or row.get("templateID")
        matched = row.get("matched-at") or row.get("matched") or row.get("host")
        matcher = row.get("matcher-name") or ""
        score = classification.get("cvss-score")

        yield ScanRecord(
            url=matched if isinstance(matched, str) and "://" in matched else None,
            hostname=None if (isinstance(matched, str) and "://" in matched) else matched,
            title=(info.get("name") or template_id or "")[:500],
            plugin_id=template_id,
            #: template + matcher + location is Nuclei's natural identity, and
            #: it survives the template being re-run against the same target.
            unique_id=f"{template_id}:{matcher}:{matched}" if template_id else None,
            severity=severity_from_word(info.get("severity")),
            cvss_score=float(score) if isinstance(score, (int, float)) else None,
            cvss_vector=classification.get("cvss-metrics"),
            cve_ids=_cves(classification.get("cve-id"), template_id, info.get("reference")),
            cwe=_cwe(classification.get("cwe-id")),
            description=info.get("description"),
            solution=info.get("remediation"),
            method=row.get("type", "").upper() if row.get("type") in ("http",) else None,
            request=row.get("request"),
            response=(row.get("response") or "")[:20000] or None,
            evidence={"template": template_id, "matcher": matcher,
                      "extracted": row.get("extracted-results"),
                      "tags": info.get("tags")},
            raw={k: v for k, v in row.items() if k not in ("request", "response")},
        )


# ---------------------------------------------------------------------------
# OWASP ZAP (JSON report)
# ---------------------------------------------------------------------------
ZAP_RISK = {"0": "informational", "1": "low", "2": "medium", "3": "high"}


def parse_zap(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    sites = data.get("site") if isinstance(data, dict) else None
    if sites is None:
        raise ParserError("not a ZAP JSON report (no 'site' array)")
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        if not isinstance(site, dict):
            continue
        host = site.get("@host") or site.get("host")
        port = site.get("@port") or site.get("port")
        ssl = str(site.get("@ssl") or site.get("ssl") or "").lower() in ("true", "1")

        for alert in (site.get("alerts") or []):
            if not isinstance(alert, dict):
                continue
            risk = str(alert.get("riskcode") or alert.get("riskdesc") or "")
            severity = ZAP_RISK.get(risk.strip()[:1]) or severity_from_word(
                risk.split()[0] if risk else None)
            instances = [i for i in (alert.get("instances") or []) if isinstance(i, dict)]
            # ZAP reports one ALERT with N instances. That is one thing to
            # triage and N places to fix, so it becomes one record carrying N
            # endpoints - not N records. Splitting it would make an analyst
            # triage "SQL Injection" once per affected URL.
            endpoints = [
                {"url": instance.get("uri"),
                 "method": instance.get("method"),
                 "params": instance.get("param") or None,
                 "param_location": "query" if instance.get("param") else None,
                 "request": instance.get("requestheader"),
                 "response": instance.get("responseheader")}
                for instance in instances if instance.get("uri")
            ]
            first = instances[0] if instances else {}

            yield ScanRecord(
                url=first.get("uri"),
                endpoints=endpoints[1:],   # the first is carried on the record
                hostname=host,
                port=int(port) if str(port or "").isdigit() else None,
                protocol="https" if ssl else "http",
                title=(alert.get("alert") or alert.get("name") or "")[:500],
                plugin_id=str(alert.get("pluginid") or "") or None,
                severity=severity,
                description=_strip_html(alert.get("desc")),
                solution=_strip_html(alert.get("solution")),
                cwe=_cwe(alert.get("cweid")),
                method=first.get("method"),
                params=first.get("param") or None,
                param_location="query" if first.get("param") else None,
                evidence={"instance_count": len(instances),
                          "evidence": first.get("evidence"),
                          "attack": first.get("attack"),
                          "confidence": alert.get("confidence"),
                          "wasc": alert.get("wascid")},
                raw=alert,
            )


_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(value: Any) -> str | None:
    """ZAP wraps its prose in <p> tags. Storing markup would leak into reports."""
    if not value:
        return None
    return " ".join(_TAG_RE.sub(" ", str(value)).split()) or None


# ---------------------------------------------------------------------------
# npm audit (v2 schema, npm >= 7)
# ---------------------------------------------------------------------------
def parse_npm_audit(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    _require(data, "vulnerabilities", "advisories")

    # npm 6 used a flat `advisories` map; npm 7+ nests `via` chains.
    if "advisories" in data and "vulnerabilities" not in data:
        for advisory in (data.get("advisories") or {}).values():
            if not isinstance(advisory, dict):
                continue
            yield ScanRecord(
                title=(advisory.get("title") or "")[:500],
                cve_ids=_cves(advisory.get("cves"), advisory.get("url")),
                plugin_id=str(advisory.get("id") or "") or None,
                severity=severity_from_word(advisory.get("severity")),
                description=advisory.get("overview"),
                solution=advisory.get("recommendation"),
                cwe=_cwe(advisory.get("cwe")),
                component_name=advisory.get("module_name"),
                component_version=advisory.get("findings", [{}])[0].get("version")
                if advisory.get("findings") else None,
                evidence={"vulnerable_versions": advisory.get("vulnerable_versions")},
                raw=advisory,
            )
        return

    for name, entry in (data.get("vulnerabilities") or {}).items():
        if not isinstance(entry, dict):
            continue
        advisories = [v for v in (entry.get("via") or []) if isinstance(v, dict)]
        if not advisories:
            # A purely transitive entry: npm names the parent, not an advisory.
            # Reporting it as its own finding would double-count the real one.
            continue
        for advisory in advisories:
            cvss = advisory.get("cvss") or {}
            yield ScanRecord(
                title=(advisory.get("title") or f"Vulnerable dependency: {name}")[:500],
                cve_ids=_cves(advisory.get("cve"), advisory.get("url")),
                plugin_id=str(advisory.get("source") or "") or None,
                severity=severity_from_word(advisory.get("severity")
                                            or entry.get("severity")),
                cvss_score=cvss.get("score"),
                cvss_vector=cvss.get("vectorString"),
                description=advisory.get("title"),
                solution=(f"Upgrade {name} outside {advisory.get('range')}"
                          if advisory.get("range") else None),
                cwe=_cwe(advisory.get("cwe")),
                component_name=advisory.get("name") or name,
                component_version=None,
                file_path="package.json",
                evidence={"range": advisory.get("range"),
                          "fix_available": bool(entry.get("fixAvailable")),
                          "url": advisory.get("url")},
                raw=advisory,
            )


# ---------------------------------------------------------------------------
# pip-audit
# ---------------------------------------------------------------------------
def parse_pip_audit(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    dependencies = data.get("dependencies") if isinstance(data, dict) else data
    if not isinstance(dependencies, list):
        raise ParserError("not a pip-audit report (expected a dependency array)")

    saw_vuln_key = False
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        if "vulns" in dependency or "vulnerabilities" in dependency:
            saw_vuln_key = True
        name = dependency.get("name")
        version = dependency.get("version")
        for vuln in (dependency.get("vulns") or dependency.get("vulnerabilities") or []):
            if not isinstance(vuln, dict):
                continue
            fix_versions = vuln.get("fix_versions") or []
            advisory_id = vuln.get("id")
            yield ScanRecord(
                title=f"{advisory_id} in {name} {version}"[:500],
                cve_ids=_cves(advisory_id, vuln.get("aliases")),
                plugin_id=advisory_id,
                #: pip-audit reports no severity at all. Guessing one would be
                #: an invention; leaving it None lets the CVE enrichment supply
                #: the authoritative value once NVD is synced.
                severity=None,
                description=vuln.get("description"),
                solution=(f"Upgrade {name} to {', '.join(fix_versions)}"
                          if fix_versions else None),
                component_name=name,
                component_version=version,
                file_path="requirements.txt",
                evidence={"aliases": vuln.get("aliases"), "fix_versions": fix_versions},
                raw=vuln,
            )
    if not saw_vuln_key:
        raise ParserError("not a pip-audit report (no 'vulns' on any dependency)")


# ---------------------------------------------------------------------------
# GitHub Dependabot alerts (REST API)
# ---------------------------------------------------------------------------
def parse_dependabot(payload: bytes) -> Iterator[ScanRecord]:
    data = _load_json(payload)
    if isinstance(data, dict):
        data = data.get("alerts") or [data]
    if not isinstance(data, list) or not data:
        raise ParserError("not a Dependabot alert list")
    if data and not any(isinstance(a, dict) and "security_advisory" in a for a in data):
        raise ParserError("not a Dependabot alert list (no security_advisory)")

    for alert in data:
        if not isinstance(alert, dict):
            continue
        advisory = alert.get("security_advisory") or {}
        vulnerability = alert.get("security_vulnerability") or {}
        dependency = alert.get("dependency") or {}
        package = dependency.get("package") or vulnerability.get("package") or {}
        cvss = advisory.get("cvss") or {}
        patched = (vulnerability.get("first_patched_version") or {}).get("identifier")

        # A dismissed or fixed alert is history, not work. Importing it as open
        # would resurrect decisions somebody already made on GitHub.
        if str(alert.get("state") or "open").lower() not in ("open", "auto_dismissed"):
            continue

        yield ScanRecord(
            title=(advisory.get("summary") or advisory.get("ghsa_id") or "")[:500],
            cve_ids=_cves(advisory.get("cve_id"), advisory.get("identifiers")),
            plugin_id=advisory.get("ghsa_id"),
            unique_id=f"dependabot:{alert.get('number')}" if alert.get("number") else None,
            severity=severity_from_word(advisory.get("severity")),
            cvss_score=cvss.get("score"),
            cvss_vector=cvss.get("vector_string"),
            description=advisory.get("description"),
            solution=(f"Upgrade {package.get('name')} to {patched}" if patched else None),
            cwe=_cwe(advisory.get("cwes")),
            component_name=package.get("name"),
            component_version=None,
            file_path=dependency.get("manifest_path"),
            evidence={"ecosystem": package.get("ecosystem"),
                      "vulnerable_range": vulnerability.get("vulnerable_version_range"),
                      "url": alert.get("html_url")},
            raw=alert,
        )


# ---------------------------------------------------------------------------
# Prowler (cloud posture)
# ---------------------------------------------------------------------------
def parse_prowler(payload: bytes) -> Iterator[ScanRecord]:
    rows = _load_jsonl(payload)
    if rows and not any(_looks_like_prowler(r) for r in rows):
        raise ParserError("not a Prowler report")

    for row in rows:
        if not _looks_like_prowler(row):
            continue
        status = str(
            row.get("status_code") or row.get("Status") or row.get("status") or ""
        ).upper()
        # PASS rows are evidence of compliance, not findings. Importing them
        # would make the estate look catastrophically vulnerable at first sight
        # and bury the failures.
        if status not in ("FAIL", "FAILED", "MANUAL"):
            continue

        check_id = (row.get("check_id") or row.get("CheckID")
                    or (row.get("metadata") or {}).get("event_code"))
        resource = (
            row.get("resource_uid") or row.get("ResourceId") or row.get("resource_id")
            or ((row.get("resources") or [{}])[0].get("uid")
                if isinstance(row.get("resources"), list) else None)
        )
        account = (row.get("account_uid") or row.get("AccountId")
                   or (row.get("cloud") or {}).get("account", {}).get("uid"))
        region = row.get("region") or row.get("Region")

        yield ScanRecord(
            hostname=resource or account,
            host_is_artifact=True,
            title=(row.get("check_title") or row.get("CheckTitle")
                   or row.get("finding_info", {}).get("title") or check_id or "")[:500],
            plugin_id=check_id,
            unique_id=f"{check_id}:{resource}" if check_id and resource else None,
            severity=severity_from_word(row.get("severity") or row.get("Severity")),
            description=(row.get("status_detail") or row.get("StatusExtended")
                         or row.get("description")),
            solution=((row.get("remediation") or {}).get("desc")
                      if isinstance(row.get("remediation"), dict)
                      else row.get("Remediation")),
            evidence={"account": account, "region": region, "resource": resource,
                      "service": row.get("service_name") or row.get("ServiceName"),
                      "compliance": row.get("compliance")},
            raw=row,
        )


def _looks_like_prowler(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    return bool(
        row.get("check_id") or row.get("CheckID")
        or (row.get("finding_info") and row.get("status_code"))
    )


# ---------------------------------------------------------------------------
# Registry + detection
# ---------------------------------------------------------------------------
MODERN_PARSERS = {
    "sarif": parse_sarif,
    "codeql": parse_sarif,          # CodeQL's native export IS SARIF
    "trivy": parse_trivy,
    "grype": parse_grype,
    "semgrep": parse_semgrep,
    "bandit": parse_bandit,
    "gitleaks": parse_gitleaks,
    "checkov": parse_checkov,
    "nuclei": parse_nuclei,
    "zap": parse_zap,
    "npm_audit": parse_npm_audit,
    "pip_audit": parse_pip_audit,
    "dependabot": parse_dependabot,
    "prowler": parse_prowler,
}

#: Detection table. Each format lists one or more ALTERNATIVE signatures; a
#: signature is a group of markers that must ALL appear.
#:
#:     ("nuclei", (("template-id",), ("templateID",)))
#:              -> either spelling identifies it
#:     ("semgrep", (("check_id", "extra"),))
#:              -> both, because `check_id` alone is also Prowler's
#:
#: The alternatives/conjunction distinction is not decoration: writing the two
#: Nuclei spellings as a single conjunctive group meant a real Nuclei report
#: matched nothing and fell through to the generic JSON parser.
#:
#: Order still matters where two formats share a signature, so the more
#: specific format is listed first.
_JSON_MARKERS: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...] = (
    ("sarif", (("$schema\": \"https://json.schemastore.org/sarif",), ("\"runs\":", "\"tool\":"))),
    ("trivy", (("\"ArtifactName\":",), ("\"Results\":", "\"Vulnerabilities\":"))),
    ("grype", (("\"matches\":", "\"vulnerability\":"),)),
    ("zap", (("\"site\":", "\"alerts\":"),)),
    ("checkov", (("\"check_type\":", "\"failed_checks\":"),)),
    ("bandit", (("\"issue_severity\":",),)),
    ("gitleaks", (("\"RuleID\":", "\"Fingerprint\":"), ("\"RuleID\":", "\"StartLine\":"))),
    ("dependabot", (("\"security_advisory\":",),)),
    ("npm_audit", (("\"vulnerabilities\":", "\"via\":"),)),
    ("pip_audit", (("\"vulns\":", "\"dependencies\":"),)),
    ("nuclei", (("\"template-id\":",), ("\"templateID\":",))),
    # Prowler before Semgrep: both use `check_id`, so each is disambiguated by
    # a second marker and the more specific one is tried first regardless.
    ("prowler", (("\"check_id\":", "\"status_code\":"), ("\"CheckID\":",),
                 ("\"check_id\":", "\"finding_info\":"))),
    ("semgrep", (("\"check_id\":", "\"extra\":"),)),
)


def detect_modern_format(payload: bytes, filename: str = "") -> str | None:
    """Identify a JSON report, or None to let the caller keep guessing.

    Returns None rather than raising: this runs *before* the original
    `detect_format`, and a JSON file it does not recognise must still be allowed
    to fall through to the generic JSON parser.
    """
    name = (filename or "").lower()
    for key in MODERN_PARSERS:
        if name.startswith(key) or f"-{key}" in name or f"_{key}" in name:
            return key
    if name.endswith(".sarif") or name.endswith(".sarif.json"):
        return "sarif"

    window = payload[:200_000].decode("utf-8", errors="replace")
    for parser_name, signatures in _JSON_MARKERS:
        for signature in signatures:
            if all(marker in window for marker in signature):
                return parser_name
    return None
