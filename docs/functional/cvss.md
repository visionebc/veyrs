---
title: CVSS scoring and the bulletin assistant
purpose: Document the CVSS v2/v3.x/v4.0 calculator API and the assistant that pre-fills a vector from a pasted bulletin.
scope: The `/api/v1/cvss/*` routes, the scoring engine under engines/cvss and services/cvss_assist.py; how stored CVE scores are ingested is in threat-intelligence.md.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/api/v1/cvss.py, backend/veyrs/engines/cvss/__init__.py, backend/veyrs/engines/cvss/v2.py, backend/veyrs/engines/cvss/v3.py, backend/veyrs/engines/cvss/v4.py, backend/veyrs/services/cvss_assist.py]
related: [api/reference/cvss.md, functional/threat-intelligence.md, functional/ai.md, functional/risk-engine.md]
---

# CVSS scoring and the bulletin assistant

All nine routes are tagged `cvss` and require `vulnerability:read` (`api/v1/cvss.py:21`). Reference: [../api/reference/cvss.md](../api/reference/cvss.md).

## Engine

`veyrs.engines.cvss` is a single facade over three calculators (`engines/cvss/__init__.py`):

| Version | Module | Notes |
|---|---|---|
| 2.0 | `v2.py` | 3-band severity (Low/Medium/High). |
| 3.0 / 3.1 | `v3.py` | Shared weights; 3.1 uses integer Roundup, differing Modified Impact for Scope:Changed (`v3.py:1-12`). |
| 4.0 | `v4.py`, `v4_tables.py` | MacroVector (EQ1-EQ6) lookup in the 270-entry official table plus severity-distance interpolation; port of the FIRST reference implementation. |

Every calculator returns a `CVSSResult` (`common.py`) with `base_score`, `temporal_score`, `environmental_score`, `score` (the most specific available), `severity`, `nomenclature` (v4: `CVSS-B`, `CVSS-BT`, ...), a `metrics` list and `intermediates`. Severity bands: v2 Low <4.0, Medium <7.0, High; v3/v4 None 0, Low <4.0, Medium <7.0, High <9.0, Critical (`common.py:77-97`). `SUPPORTED_VERSIONS = ("2.0","3.0","3.1","4.0")`. The module docstring in `api/v1/cvss.py:3` states the engine is validated against the official corpora (729 v2, 2 592 v3, 1 058 v4 vectors) in `tests/test_cvss_official.py`.

### Worked example (computed locally, not via the API)

The engine was imported from the source tree with a stub package so no database or secrets were needed, and run read-only:

| Vector | Result |
|---|---|
| `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | base 7.5 High (the HTTP/2 Rapid Reset vector; the stored score of `CVE-2023-44487` on environment A is the same 7.5) |
| `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` | 9.3 Critical, `CVSS-B`, macro vector `000200` |
| `AV:N/AC:L/Au:N/C:P/I:P/A:P` (v2) | 7.5 High |
| `CVSS:3.1/AV:X` | `validate` returns `false`, `CVSS v3.1 base metric AC is mandatory` |

`GET /cvss/severity?score=9.3&version=4.0` on environment A returned `{"score":9.3,"version":"4.0","severity":"Critical"}`.

## Features

### Versions and metric catalogue

| Item | Detail |
|---|---|
| What | `GET /cvss/versions`; `GET /cvss/metrics/{version}`. |
| How it works | `metric_catalogue` (`engines/cvss/__init__.py:37`) returns groups (Base, Temporal, Environmental; v4: Base, Threat, Environmental, Supplemental), each metric with abbreviation, label, allowed values and a `mandatory` flag, plus the severity bands. The console builds the calculator from it so it cannot drift from the engine. |
| Errors | 404 `unsupported version` for an unknown `{version}` (`api/v1/cvss.py:32`). |
| Status | Verified (`/cvss/versions` observed live) |

### Score, explain, validate

| Item | Detail |
|---|---|
| What | `POST /cvss/score`, `/cvss/explain`, `/cvss/validate`. Body `{vector, version?}`; `version` pattern `2.0\|3.0\|3.1\|4.0`, vector 3-400 chars. |
| How it works | `cvss.score` auto-detects the version from the vector when `version` is omitted (`detect_version`, `common.py:149`). `explain` adds `drivers` (plain-language factors such as "Remotely reachable over the network (AV:N)") and a `summary` sentence. `validate` never raises: it returns `{valid, error}`, converting any parser exception into an error string. |
| Errors | 422 `CVSSError` message from `score` and `explain` (for example missing mandatory metric, unknown value). `validate` returns 200 with `valid:false`. 422 also from body validation. |
| Status | Verified (`tests/test_cvss_official.py`, `tests/test_phase2_core.py`) |

### Generate a vector from metrics

| Item | Detail |
|---|---|
| What | `POST /cvss/generate` body `{version, metrics:{AV:"N",...}}`. |
| How it works | `cvss.generate` (`engines/cvss/__init__.py:105`) emits metrics in canonical order, skipping `X`/`ND`/empty, prefixes `CVSS:<version>/` (not for 2.0), then scores the result to validate it. The response is `{vector, ...score fields}`. |
| Errors | 422 `cannot build vector: ...` on `CVSSError` or `KeyError` (a missing mandatory metric). |
| Status | Verified (the 3.1 example above round-trips to its canonical vector) |

### Compare vectors

| Item | Detail |
|---|---|
| What | `POST /cvss/compare` body `{vectors:[...]}` (1-12). |
| How it works | `cvss.compare` scores each vector independently; invalid ones return `{vector, error}` instead of failing the whole call; adds `max_score`, `min_score`, `spread` (only when at least two valid). Mixed versions are allowed. |
| Status | Implemented |

### Severity for a score

| Item | Detail |
|---|---|
| What | `GET /cvss/severity?score=&version=` (score 0-10; version default `3.1`). |
| Exceptional | `version` is not validated: any string not starting with `2` uses the 5-band scale (`common.py:84`). |
| Status | Verified (observed live) |

### Bulletin assistant

| Item | Detail |
|---|---|
| What | `POST /cvss/assist` body `{text (20-200000 chars), version="3.1", use_ai=true}`. Pre-fills a calculator from a pasted advisory and cross-checks it against the tenant's inventory. |
| Why | Analysts translate prose into AV/AC/PR/... by hand and the error is usually optimistic. |
| How it works | `cvss_assist.assist` (`services/cvss_assist.py:302`): (1) deterministic extraction of CVE ids and printed vectors (`extract_cves`, `extract_vectors`, `:80`, `:89`); an invalid printed vector is reported, not dropped; (2) `inventory_context` (`:147`) counts the tenant's open findings, internet-exposed ones and matches products named in the text against `asset_products`, narrowed by team scope; (3) if the bulletin printed a valid vector for the requested version it wins and no model is called; otherwise, when `use_ai` is true, `gateway.invoke` runs capability `advisory_analysis` with the bulletin as fenced untrusted text; (4) model metrics pass `sanitize_metrics` (`:123`) and unknown names or values are dropped and reported; bulletin values take precedence (`setdefault`); (5) the vector is generated and scored by the engine, never by the model. |
| Response | `metrics`, `metric_source` (`bulletin`/`model` per metric), `vector`, `score`, `needs_decision` (mandatory metrics still missing), `printed_vectors`, `inventory`, `ai` (decision, provider, model, external, block reason, rejected), `chars_analysed`, `truncated` (text cut at 20 000 chars). |
| Permissions | `vulnerability:read`. The AI leg additionally requires `intel:read` (checked inside the gateway); without it the deterministic half still answers with `ai.decision = "blocked"`. |
| Team scope | The `cvss` tag is in `SCOPED_TAGS` (`security/scope.py:67`) because `inventory_context` reads findings and assets; a restricted caller gets a narrowed count and `scope_restricted: true`. |
| Errors | 422 for unsupported `version`, empty text, or `CVSSError`/`ValueError` from the pipeline. |
| Exceptional | An incomplete vector is a normal 200 with `vector: null` and `needs_decision`. Nothing is stored; the output only fills a form. |
| Dependencies | [ai.md](ai.md) gateway and guardrails. |
| Status | Implemented (`tests/test_phase35_operability.py` references the route; no live POST performed) |

## Console

Intelligence > CVSS Calculator (`route('cvss')`, `frontend/console/app.js:3236`); the assist call is at `app.js:3416`.
