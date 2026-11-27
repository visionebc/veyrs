---
title: Risk register
purpose: Document the enterprise risk register module: records, RACI, links, scoring matrix and the on/off switch.
scope: The `/risks` API and service; finding-level scoring is in risk-engine.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/risk_register.py, backend/veyrs/services/risk_register.py, backend/veyrs/services/risk_register_mode.py, backend/veyrs/models/risk_register.py]
related: [functional/risk-engine.md, functional/administration-platform.md, api/reference/risk-register.md]
---

# Risk register

A register of organisational risks (as opposed to per-asset findings) with treatment, owner and RACI. Tests: `test_phase46_risk_register`, `test_phase47_risk_matrix` (names read only).

## Rules

- Code format `RISK-%06d`, allocated from the shared `ticket_counter`.
- Status and treatment vocabularies: `models/risk_register.py:76-82`.
- Score is a 5x5 matrix; bands at >= 15, >= 10, >= 5.
- Closing a risk requires `closure_note`.
- Exactly one Accountable, which must be a person, not a team. RACI is replaced as a whole matrix.
- Soft delete.
- Module switch: `organizations.settings["risk_register"]` (default on), toggled with `GET/PUT /risk-register` (`settings:read` / `settings:admin`, `api/v1/admin.py:228,243`). When off, writes return 409 and reads stay open.
- Team-scoped principals can read only risks on which they hold a seat and every write is refused.

## Endpoints

| Feature | Endpoint | Permission | Source | Status |
|---|---|---|---|---|
| Metadata (vocabularies, matrix) | `GET /risks/meta` | `riskregister:read` | `risk_register.py:186` | Verified |
| Summary | `GET /risks/summary` | `riskregister:read` | `:214` | Verified |
| List | `GET /risks` | `riskregister:read` | `:227` | Implemented |
| Detail | `GET /risks/{risk_id}` | `riskregister:read` | `:299` | Implemented |
| Create | `POST /risks` | `riskregister:write` | `:312` | Implemented |
| Update | `PATCH /risks/{risk_id}` | `riskregister:write` | `:338` | Implemented |
| Replace RACI | `PUT /risks/{risk_id}/raci` | `riskregister:write` | `:361` | Implemented |
| Add link | `POST /risks/{risk_id}/links` | `riskregister:write` | `:392` | Implemented |
| Remove link | `DELETE /risks/{risk_id}/links/{link_id}` | `riskregister:write` | `:420` | Implemented |
| Delete | `DELETE /risks/{risk_id}` | `riskregister:delete` | `:445` | Implemented |

Links connect a risk to findings, assets, tickets or controls (see `models/risk_register.py`). Data: `risks`, risk RACI and link tables.

## Errors and exceptional conditions

409 module disabled, or write by a team-scoped principal; 404 unknown or invisible risk; 422 missing `closure_note`, no or multiple Accountable, a team as Accountable.

Live observation: `/risks/summary` returned 0 risks with the module enabled.

Debt: `GET /risks` loads every row and filters and paginates in memory (`risk_register.py:227-298`); `accepted_until` has no expiry handling in this module.
