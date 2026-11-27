# backend

The `veyrs` Python package: the FastAPI app (`main.py`, `api/`), the CLI (`cli.py`, `python -m veyrs`), database access (`db.py`, `models/`), and the business logic.

- `engines/` — risk scoring and the CVSS v2/v3/v4 calculators.
- `security/` — authentication, MFA, LDAP/OIDC, scopes, rate limiting, secret vault.
- `services/` — reporting, scanning and importers, ticketing and ITSM, SLA, threat intel, AI gateway.
- `intel/` and `data/` — threat-intelligence feed handling and bundled reference data.

See `docs/ARCHITECTURE.md` for how these fit together.
