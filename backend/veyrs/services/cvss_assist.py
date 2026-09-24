"""Turn a pasted security bulletin into a filled-in CVSS calculator.

The calculator asks eight questions in a vocabulary (AV, AC, PR, UI, S, C, I, A)
that a bulletin answers in prose, in a different order, usually without naming
the metrics. Somebody who has read the advisory still has to translate it, and
the translation is where the vector goes wrong -- almost always in the
optimistic direction, because "authenticated" reads as PR:H when the account
in question is a default one.

So the assistant does three separate things, and it is worth being precise
about which is which, because they have very different trust levels:

1. **Extraction (deterministic).** CVE identifiers and any CVSS vector the
   bulletin PRINTS are pulled out by regex. This is not a guess: an advisory
   that already carries `CVSS:3.1/AV:N/...` has told us the answer, and no
   model gets a vote on it.
2. **Inventory (deterministic).** Extracted CVEs are looked up in the tenant's
   own findings, and product/version mentions against `asset_products`. This is
   the part that answers "does this apply to me", and it is a database query,
   never a model.
3. **Proposal (model).** Only for the metrics nothing above could settle. The
   model reads the bulletin and proposes values WITH a per-metric rationale.

**Three refusals that make the difference between a helper and a liar:**

* **The score is never taken from the model.** Whatever vector comes out, it is
  scored by `engines.cvss`, the same code path validated against the official
  corpora. A model that says "9.8" and a vector that computes to 7.5 is a
  number an analyst would have put in a report.
* **Every proposed metric value is validated against the official catalogue and
  DROPPED if unknown.** A model that answers `AV:Q` must not reach a form that
  then 422s at the user, and must certainly not reach a stored vector.
* **Nothing is applied.** The result pre-fills a form the analyst confirms. The
  provenance of each metric (`bulletin`, `model`) travels with it precisely so
  a reviewer can see which half they are actually reviewing.

The bulletin text is third-party content and goes into `AiRequest.untrusted`,
which the gateway fences -- an advisory that contains "ignore previous
instructions" is a prompt-injection attempt, and it is exactly the kind of file
this feature is fed.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..engines import cvss
from ..models import (
    Asset, AssetProduct, Cve, Finding, OPEN_STATES, Product, Vendor, Vulnerability,
)
from ..security import scope as team_scope
from .ai.gateway import AiRequest, invoke
from .versions import normalize_name

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

#: A printed vector, with or without the `CVSS:x.y/` prefix. The v2 form has no
#: prefix at all, which is why the second alternative exists.
VECTOR_RE = re.compile(
    r"(CVSS:[234](?:\.\d)?/[A-Za-z:/\-\.]+)"
    r"|((?:AV:[LANP]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]))"
)

#: Cap on what is sent to a model. A 400-page PDF pasted into the box is a
#: bill, not an advisory; the useful part of a bulletin is its first pages.
MAX_TEXT_CHARS = 20000

#: Product mentions are matched against the tenant's inventory by name. Very
#: short tokens ("go", "vi", "R") match half an estate, so they are skipped
#: rather than reported -- a false "you are affected" is worse than a miss
#: here, because it is the one the analyst will act on.
MIN_PRODUCT_TOKEN = 4


def extract_cves(text: str) -> list[str]:
    seen: list[str] = []
    for match in CVE_RE.findall(text or ""):
        upper = match.upper()
        if upper not in seen:
            seen.append(upper)
    return seen


def extract_vectors(text: str) -> list[dict[str, Any]]:
    """Vectors the bulletin prints, each validated before it is offered.

    An invalid vector is REPORTED as invalid rather than dropped: a typo in a
    vendor advisory is a fact the analyst wants to see, and silently ignoring
    it looks like the bulletin never carried one.
    """
    out: list[dict[str, Any]] = []
    for prefixed, bare in VECTOR_RE.findall(text or ""):
        raw = (prefixed or bare).strip().rstrip("./,;)")
        if any(v["vector"] == raw for v in out):
            continue
        version = "2.0"
        if raw.upper().startswith("CVSS:"):
            version = raw.split("/", 1)[0].split(":", 1)[1]
            if version in ("3", "4"):
                version = f"{version}.1" if version == "3" else "4.0"
        ok, error = cvss.validate(raw, version)
        entry: dict[str, Any] = {"vector": raw, "version": version, "valid": ok, "error": error}
        if ok:
            entry["score"] = cvss.score(raw, version).as_dict()
        out.append(entry)
    return out


def _catalogue(version: str) -> dict[str, set[str]]:
    """abbrev -> allowed values, straight from the engine's own definitions."""
    catalogue: dict[str, set[str]] = {}
    for group in cvss.metric_catalogue(version).get("groups", []):
        for metric in group.get("metrics", []):
            catalogue[metric["abbrev"]] = {v["value"] for v in metric.get("values", [])}
    return catalogue


def sanitize_metrics(metrics: dict[str, Any], version: str) -> tuple[dict[str, str], list[str]]:
    """Keep only metric/value pairs the specification actually defines.

    Returns the survivors and the names of what was thrown away. The rejects
    are reported rather than swallowed: a model that keeps proposing an
    invented metric is a prompt problem, and a silent filter hides it forever.
    """
    catalogue = _catalogue(version)
    kept: dict[str, str] = {}
    rejected: list[str] = []
    for key, value in (metrics or {}).items():
        abbrev = str(key).strip().upper()
        candidate = str(value).strip().upper()
        allowed = catalogue.get(abbrev)
        if allowed is None:
            rejected.append(f"{key}: unknown metric")
            continue
        if candidate not in allowed:
            rejected.append(f"{abbrev}: {value!r} is not one of {'/'.join(sorted(allowed))}")
            continue
        kept[abbrev] = candidate
    return kept, rejected


def inventory_context(
    session: Session, organization_id: uuid.UUID, cve_ids: list[str], text: str,
    *, scope: team_scope.TeamScope = team_scope.UNRESTRICTED,
) -> dict[str, Any]:
    """What THIS tenant has, for the CVEs and products the bulletin names.

    Every number here is a query. The whole point of doing this next to the
    calculator is that "CVSS 9.8" and "CVSS 9.8 on four internet-facing hosts
    you own" are different sentences, and only the second one is actionable.

    **Narrowed by team scope**, which is why the `cvss` tag had to leave
    `EXEMPT_TAGS`: that set asserts its routes carry no asset- or
    finding-level rows, and this one now does. Serving it unfiltered would let
    a team-restricted analyst count the whole estate's exposure from a
    calculator -- the same read leak phase 28 found under `policies`.
    """
    known: list[dict[str, Any]] = []
    for cve_id in cve_ids:
        cve = session.get(Cve, cve_id)
        entry: dict[str, Any] = {"cve_id": cve_id, "in_catalogue": cve is not None}
        if cve is not None:
            entry.update({
                "cvss_score": cve.best_cvss_score,
                "cvss_vector": cve.cvss4_vector or cve.cvss3_vector or cve.cvss2_vector,
                "epss_score": cve.epss_score,
                "kev": bool(cve.kev),
            })
            vulnerability = session.execute(
                select(Vulnerability).where(
                    Vulnerability.organization_id == organization_id,
                    Vulnerability.cve_id == cve.id,
                )
            ).scalars().first()
            if vulnerability is not None:
                open_findings = session.execute(team_scope.findings(
                    select(Finding).where(
                        Finding.organization_id == organization_id,
                        Finding.vulnerability_id == vulnerability.id,
                        Finding.state.in_(tuple(OPEN_STATES)),
                    ), scope,
                )).scalars().all()
                entry["open_findings"] = len(open_findings)
                entry["internet_exposed"] = sum(
                    1 for f in open_findings
                    if (a := session.get(Asset, f.asset_id)) is not None
                    and a.exposure == "internet"
                )
                entry["max_risk_score"] = max(
                    (f.risk_score for f in open_findings if f.risk_score is not None),
                    default=None,
                )
            else:
                entry["open_findings"] = 0
        known.append(entry)

    return {
        "cves": known,
        "products": matched_products(session, organization_id, text, scope=scope),
        "estate_assets": session.execute(
            select(func.count()).select_from(team_scope.assets(
                select(Asset).where(
                    Asset.organization_id == organization_id, Asset.deleted_at.is_(None)
                ), scope,
            ).subquery())
        ).scalar_one(),
        # Said out loud rather than implied: "0 affected" and "0 affected that
        # you can see" are different answers under the same heading.
        "scope_restricted": scope.restricted,
    }


def matched_products(
    session: Session, organization_id: uuid.UUID, text: str, *, limit: int = 25,
    scope: team_scope.TeamScope = team_scope.UNRESTRICTED,
) -> list[dict[str, Any]]:
    """Which products in the tenant's inventory the bulletin actually names.

    It walks the INVENTORY and asks "is this name in the text", not the other
    way round. Extracting candidate product names from prose and then looking
    each up would invent products the tenant does not own and then fail to find
    them, which reads as "not affected" for the wrong reason.
    """
    stmt = (
        select(AssetProduct, Product, Vendor)
        .join(Product, Product.id == AssetProduct.product_id)
        .join(Vendor, Vendor.id == Product.vendor_id, isouter=True)
        .join(Asset, Asset.id == AssetProduct.asset_id)
        .where(AssetProduct.organization_id == organization_id,
               Asset.deleted_at.is_(None))
    )
    rows = session.execute(team_scope.assets(stmt, scope)).all()

    # Sentinel-wrapped so the match is on whole normalised tokens. A plain
    # substring test reports the estate's `nginx` as named by a bulletin that
    # only ever says `nginx-plus`, and the analyst acts on the wrong host.
    haystack = f"_{normalize_name(text or '')}_"
    hits: dict[str, dict[str, Any]] = {}
    for installation, product, vendor in rows:
        name = normalize_name(product.name or "")
        if len(name) < MIN_PRODUCT_TOKEN or f"_{name}_" not in haystack:
            continue
        key = f"{vendor.name if vendor else '?'}:{product.name}"
        entry = hits.setdefault(key, {
            "vendor": vendor.name if vendor else None,
            "product": product.name,
            "installations": 0,
            "versions": [],
        })
        entry["installations"] += 1
        if installation.version and installation.version not in entry["versions"]:
            entry["versions"].append(installation.version)
    return sorted(
        hits.values(), key=lambda e: e["installations"], reverse=True
    )[:limit]


PROMPT = """\
You are helping an analyst fill in a CVSS {version} base vector from a security
bulletin. Answer with a single JSON object and nothing else:

{{"metrics": {{"AV": "N", ...}}, "rationale": {{"AV": "one sentence", ...}},
  "summary": "two sentences", "confidence": "high|medium|low",
  "affected_products": ["vendor product version", ...]}}

Rules you must not break:
- Use ONLY the metric abbreviations and values of CVSS {version}. If the
  bulletin does not say, OMIT the metric rather than guessing a value.
- Do not output a score or a severity word. The score is computed by the
  platform from the vector, not by you.
- Every entry in "rationale" must quote or paraphrase the bulletin. If you
  cannot point at the text, omit the metric.
"""


def _parse_model_json(text: str) -> dict[str, Any]:
    """Pull the JSON object out of a completion that may be wrapped in prose.

    A model that adds "Here is the JSON:" is not an error worth failing the
    whole request over; a model that produces no object at all is, and that is
    what the empty dict signals to the caller.
    """
    candidate = (text or "").strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        candidate = candidate.split("\n", 1)[-1] if "\n" in candidate else candidate
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end <= start:
        return {}
    try:
        parsed = json.loads(candidate[start:end + 1])
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def assist(
    session: Session,
    *,
    organization_id: uuid.UUID,
    text: str,
    version: str = "3.1",
    permissions: frozenset[str] | set[str] = frozenset(),
    is_superuser: bool = False,
    user_id: uuid.UUID | None = None,
    locale: str = "en",
    use_ai: bool = True,
    scope: team_scope.TeamScope = team_scope.UNRESTRICTED,
) -> dict[str, Any]:
    """The whole pipeline. Returns a prefilled vector plus its provenance."""
    if version not in cvss.SUPPORTED_VERSIONS:
        raise cvss.CVSSError(f"unsupported CVSS version {version!r}")
    text = (text or "").strip()
    if not text:
        raise ValueError("paste the bulletin text first")
    excerpt = text[:MAX_TEXT_CHARS]

    cve_ids = extract_cves(text)
    printed = extract_vectors(text)
    context = inventory_context(session, organization_id, cve_ids, text, scope=scope)

    # A vector the bulletin printed for the requested version wins outright.
    # The model is not asked to second-guess a number the vendor published.
    authoritative = next(
        (v for v in printed if v["valid"] and v["version"] == version), None
    )
    metrics: dict[str, str] = {}
    source: dict[str, str] = {}
    if authoritative is not None:
        metrics, _ = sanitize_metrics(
            dict(
                part.split(":", 1) for part in authoritative["vector"].split("/")
                if ":" in part and not part.upper().startswith("CVSS")
            ),
            version,
        )
        source = {k: "bulletin" for k in metrics}

    ai: dict[str, Any] = {"used": False, "decision": "skipped", "rejected": []}
    if use_ai and authoritative is None:
        facts = _facts_block(context, cve_ids, printed)
        result = invoke(
            session,
            organization_id=organization_id,
            request=AiRequest(
                capability="advisory_analysis",
                prompt=PROMPT.format(version=version),
                facts=facts,
                # Third-party text. The gateway fences it; an advisory carrying
                # "ignore previous instructions" is exactly the input this
                # feature exists to accept.
                untrusted=excerpt,
                classification="internal",
                locale=locale,
            ),
            permissions=permissions,
            is_superuser=is_superuser,
            user_id=user_id,
        )
        ai = {
            "used": True,
            "decision": result.decision,
            "allowed": result.allowed,
            "provider": result.provider,
            "model": result.model,
            "external": result.external,
            "block_reason": result.block_reason,
            "degraded": result.degraded,
            "rejected": [],
        }
        if result.allowed:
            parsed = _parse_model_json(result.text)
            proposed, rejected = sanitize_metrics(parsed.get("metrics") or {}, version)
            ai["rejected"] = rejected
            ai["rationale"] = {
                k: v for k, v in (parsed.get("rationale") or {}).items()
                if k.upper() in proposed
            }
            ai["summary"] = parsed.get("summary")
            ai["confidence"] = parsed.get("confidence")
            ai["affected_products"] = parsed.get("affected_products") or []
            for key, value in proposed.items():
                # The bulletin's own values were set first and are not
                # overwritten -- `setdefault` is the whole precedence rule.
                if metrics.setdefault(key, value) == value:
                    source.setdefault(key, "model")

    vector: str | None = None
    score: dict[str, Any] | None = None
    incomplete: list[str] = []
    try:
        vector = cvss.generate(metrics, version)
        score = cvss.score(vector, version).as_dict()
    except (cvss.CVSSError, KeyError) as exc:
        # A partial answer is the normal outcome, not a failure: a bulletin
        # that never says whether privileges are required leaves PR unset, and
        # the honest response is a half-filled form plus the list of what the
        # analyst still has to decide.
        vector, score = None, None
        incomplete = _missing_mandatory(metrics, version)
        if not incomplete:
            incomplete = [str(exc)]

    return {
        "version": version,
        "metrics": metrics,
        "metric_source": source,
        "vector": vector,
        "score": score,
        "needs_decision": incomplete,
        "cve_ids": cve_ids,
        "printed_vectors": printed,
        "inventory": context,
        "ai": ai,
        "chars_analysed": len(excerpt),
        "truncated": len(text) > MAX_TEXT_CHARS,
    }


def _missing_mandatory(metrics: dict[str, str], version: str) -> list[str]:
    missing = []
    for group in cvss.metric_catalogue(version).get("groups", []):
        for metric in group.get("metrics", []):
            if metric.get("mandatory") and metric["abbrev"] not in metrics:
                missing.append(f"{metric['abbrev']} ({metric['name']})")
    return missing


def _facts_block(context: dict[str, Any], cve_ids: list[str], printed: list[dict]) -> str:
    """VEYRS-computed facts, so the model narrates them instead of inventing them."""
    lines = [f"- assets in this organization's inventory: {context['estate_assets']}"]
    for entry in context["cves"]:
        if entry["in_catalogue"]:
            lines.append(
                f"- {entry['cve_id']}: known to VEYRS, CVSS {entry.get('cvss_score')}, "
                f"EPSS {entry.get('epss_score')}, KEV {entry.get('kev')}, "
                f"{entry.get('open_findings', 0)} open finding(s) in this organization"
            )
        else:
            lines.append(f"- {entry['cve_id']}: not in the VEYRS CVE catalogue")
    for product in context["products"]:
        lines.append(
            f"- inventory match: {product['vendor']} {product['product']} "
            f"on {product['installations']} installation(s), versions "
            f"{', '.join(product['versions']) or 'unknown'}"
        )
    for entry in printed:
        lines.append(
            f"- vector printed in the bulletin: {entry['vector']} "
            f"({'valid' if entry['valid'] else 'INVALID: ' + str(entry['error'])})"
        )
    return "\n".join(lines)
