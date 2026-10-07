# Architecture Decision Records

Each ADR records a decision that was not obvious, the alternatives that were
rejected, and what would make us revisit it.

| # | Decision |
|---|---|
| [0001](/adr/0001-postgres-rls.html) | PostgreSQL RLS as a second tenant barrier |
| [0002](/adr/0002-cvss-from-spec.html) | Implement CVSS from the published algorithms |
| [0003](/adr/0003-ai-gateway.html) | One gateway, no provider access anywhere else |
| [0004](/adr/0004-closed-query-grammar.html) | AI emits validated JSON, never SQL |
| [0005](/adr/0005-partial-catalogues.html) | Ship compliance catalogues partial and say so |
| [0006](/adr/0006-no-autoclose-on-absence.html) | Never close a finding because a scan omitted it |
| [0007](/adr/0007-stateless-app-nodes.html) | Split the state out; make the app nodes disposable |
