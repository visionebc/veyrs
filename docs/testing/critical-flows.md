---
title: Critical flows and the tests that pin them
purpose: Map each business-critical VEYRS flow to the exact test cases that guard it and name the gaps visible in the test code.
scope: Eight flows (login and MFA, tenant isolation, import and closure, risk scoring, SLA escalation, agent job lifecycle, AI policy gate, exports and release signing); it lists tests by name and does not describe the features themselves.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [tests/test_phase2_core.py, tests/test_phase24_mfa.py, tests/test_phase54_mfa_methods.py, tests/test_phase58_oidc.py, tests/test_audit_rls.py, tests/test_phase15_unified_ingest.py, tests/test_phase18_hardening.py, tests/test_phase3_risk.py, tests/test_phase3_intel.py, tests/test_phase16_agents.py, tests/test_phase6_ai.py, tests/test_phase9_reporting.py, tests/test_phase52_release_signing.py]
related: [testing/strategy.md, testing/coverage-matrix.md, testing/known-issues.md, THREAT_MODEL.md, AI_SECURITY.md]
---

# Critical flows and the tests that pin them

Test names are `file::function`, relative to `tests/`. Every name below was read in the code; the suite was **not run**, so "pinned" means a test of that name asserts the behaviour, not that it was observed green. Gaps are limited to what the test code itself shows.

## 1. Login, refresh and MFA

Fixtures create an org-admin per test (`conftest.py::_make_org`), so every one of these runs against a fresh tenant.

| Guarantee | Test |
|---|---|
| Wrong password is indistinguishable from unknown user | `test_phase2_core.py::test_wrong_password_is_indistinguishable_from_unknown_user` |
| No/garbage credentials are 401 | `test_phase2_core.py::test_no_credentials_is_401`, `::test_garbage_token_is_401` |
| Refresh rotates; re-using a refresh token kills the family | `test_phase2_core.py::test_refresh_rotates_and_reuse_kills_the_family` |
| Logout revokes refresh tokens; password change invalidates sessions | `::test_logout_revokes_refresh_tokens`, `::test_password_change_invalidates_sessions` |
| Expired/forged tokens and unknown API keys are rejected | `test_phase10_hardening.py::test_expired_or_forged_tokens_are_rejected`, `::test_unknown_api_key_is_rejected` |
| Auth endpoints have a stricter rate budget; probes are exempt; limiter fails open if its backend errors | `test_phase10_hardening.py::test_auth_endpoints_have_a_stricter_budget`, `::test_probes_are_never_rate_limited`, `::test_limiter_fails_open_when_the_backend_errors` |
| Login error message does not leak which factor failed | `test_login_error_message.py` (7 tests) |
| TOTP: RFC 6238 vector, one-step skew, replay refused, wrong/missing code | `test_phase24_mfa.py::test_rfc6238_reference_vector`, `::test_skew_window_is_one_step_each_way`, `::test_a_code_cannot_be_replayed`, `::test_wrong_code_is_refused` |
| A missing code challenges without spending the lockout budget; wrong codes **do** consume it | `test_phase24_mfa.py::test_missing_code_challenges_without_spending_the_lockout_budget`, `::test_bad_codes_share_the_password_lockout_budget` |
| Enabled-but-unusable secret fails closed; secret encrypted at rest | `::test_enabled_but_unusable_secret_fails_closed`, `::test_secret_is_encrypted_at_rest` |
| Email/Telegram codes: single use, burned after five wrong guesses, not sent before the password is proved, delivery failure fails closed, sending is throttled | `test_phase54_mfa_methods.py::test_email_lifecycle_login_and_single_use`, `::test_five_wrong_guesses_burn_the_code`, `::test_no_code_is_sent_before_the_password_is_proved`, `::test_delivery_failure_fails_closed_and_says_why`, `::test_sending_is_throttled` |
| Recovery codes hashed and single-use; can disable MFA | `::test_recovery_codes_are_hashed_and_single_use`, `::test_disable_with_a_recovery_code` |
| OIDC: off by default, single-use sign-in, untrustworthy ID tokens refused, no superuser via SSO, required MFA claim | `test_phase58_oidc.py::test_off_by_default`, `::test_full_sign_in_and_single_use`, `::test_untrustworthy_id_tokens_are_refused`, `::test_no_superuser_through_sso`, `::test_required_mfa_claim` |
| LDAP/RADIUS: identifier handling, unencrypted bind refused, secrets never bound unreadable | `test_phase41_directory_auth.py`, `test_phase57_radius.py`, `test_phase48_secret_vault.py::test_ldap_never_binds_with_an_unreadable_stored_password` |

**Gaps.**

- The password-only lockout (`failed_logins >= MAX_FAILED` → `locked_until`, `backend/veyrs/api/v1/auth.py:111-113`) is asserted only indirectly: through MFA guessing (`test_bad_codes_share_the_password_lockout_budget`) and in the RADIUS/MFA-method files. A test that locks an account with bad passwords alone, and that the lock expires, was not found.
- `POST /api/v1/auth/mfa/send-code` has no path reference in any test (see [coverage matrix](coverage-matrix.md#routes-with-no-test-reference-of-any-kind-36)); the email/Telegram lifecycle tests drive `/auth/mfa/enroll` and `/auth/mfa/activate`.
- Real mail relays, Telegram, RADIUS servers and identity providers are always stubbed (`outbox`, `idp` fixtures); no test talks to a real one.

## 2. Tenant isolation

Isolation has two layers — application scoping and PostgreSQL RLS — and tests exist for both.

| Layer | Guarantee | Test |
|---|---|---|
| RLS | Suite is not connected as a role that bypasses RLS (precondition; otherwise every isolation test is vacuous) | `test_audit_rls.py::test_the_suite_is_not_running_as_a_role_that_bypasses_rls` |
| RLS | `audit_log` and `ai_audit_log` carry a forced tenant policy; rows invisible to another tenant | `test_audit_rls.py::test_audit_tables_are_forced_with_the_tenant_policy`, `::test_audit_rows_are_invisible_to_another_tenant` |
| RLS | The tenant binding survives `commit()` (it was transaction-local once) | `test_phase2_core.py::test_tenant_binding_survives_commit` |
| RLS | Directory first-login writes its grants and audit row inside the tenant | `test_audit_rls.py::test_directory_first_login_writes_its_grants_and_audit_row` |
| API | Lists never cross tenants; another tenant's object by UUID is 404; invisible teams | `test_phase2_core.py::test_user_list_never_crosses_tenants`, `::test_cannot_read_another_tenants_object_by_uuid`, `::test_team_of_another_tenant_is_invisible` |
| API | A token from tenant A cannot read tenant B | `test_phase10_hardening.py::test_a_token_from_one_tenant_cannot_read_another` |
| API | Audit trail is tenant-scoped and never leaks secrets | `test_phase2_core.py::test_audit_is_tenant_scoped`, `::test_audit_never_leaks_secrets` |
| API | Exports, analytics, AI search, agents are tenant-isolated | `test_phase9_reporting.py::test_exports_never_contain_another_tenants_rows`, `::test_analytics_are_tenant_isolated`; `test_phase6_ai.py::test_nl_search_across_tenants_returns_nothing`, `::test_compiled_query_is_always_tenant_scoped`; `test_phase16_agents.py::test_agents_and_jobs_are_invisible_across_tenants`, `::test_an_agent_cannot_touch_another_tenants_job` |
| Team scope | A team-scoped identity sees only its teams: 404 (not 403) outside scope, no transition of invisible findings, bulk transition silently skips them | `test_phase26_scope.py::test_assets_outside_the_scope_are_not_listed`, `::test_an_asset_outside_the_scope_answers_404_not_403`, `::test_a_finding_outside_the_scope_cannot_be_transitioned`, `::test_bulk_transition_silently_skips_what_it_cannot_see` |
| Team scope | Scope also governs SLA events, sweep and policy edits; no policies route reads findings without a scope | `test_phase28_sla_scope.py::test_the_sweep_touches_only_the_scoped_findings`, `::test_no_route_in_the_policies_router_reads_findings_without_a_scope` |
| Team scope | New tables are tenant-isolated | `test_phase15_unified_ingest.py::test_tenant_isolation_holds_for_the_new_tables` |

**Gaps.**

- Only `audit_log` and `ai_audit_log` get a direct catalog-level RLS assertion (`RLS_TABLES_STRICT_NULLABLE`, 2 tables). For the other tenant-owned tables the policy is applied by `init-db` and verified only through behaviour (cross-tenant API calls), not by a test that enumerates all tables for `FORCE ROW LEVEL SECURITY`.
- RLS correctness depends on the application role being `NOBYPASSRLS`; the precondition test checks the role the suite uses, not the role production uses.
- The 336-route walk in `test_every_route_is_protected` proves *authorization*, not that each list route scopes by tenant.

## 3. Import, dedupe and closure

| Guarantee | Test |
|---|---|
| Re-importing does not close findings outside its own scope | `test_phase15_unified_ingest.py::test_reimport_does_not_close_findings_outside_its_own_scope` |
| Re-import closes what its own test stopped reporting; one absence on a scheduled sweep does not; reappearance resets the counter | `::test_reimport_closes_what_its_own_test_stopped_reporting`, `::test_a_single_absence_does_not_close_on_a_scheduled_sweep`, `::test_a_reappearing_finding_resets_its_absence_counter` |
| Dedupe algorithms: hash code stable across cosmetic differences, field names hashed so values cannot cross fields, unique-id fallback, legacy key equals the original formula | `::test_hash_code_separates_them`, `::test_hash_code_is_stable_across_cosmetic_differences`, `::test_field_names_are_hashed_so_values_cannot_cross_fields`, `::test_unique_id_algorithm_falls_back_when_the_tool_supplies_none`, `::test_legacy_key_matches_the_original_correlation_formula` |
| Re-importing the same SAST report creates nothing new | `::test_reimporting_the_same_sast_report_creates_nothing_new` |
| A record whose asset cannot be identified is rejected, not attached to a neighbour | `::test_a_report_with_no_host_and_no_target_asset_is_rejected`, `::test_a_url_only_record_still_resolves_its_asset` |
| Endpoint (DAST) lifecycle: canonicalisation, partial fix visible, reappearing endpoint reopens only itself | `::test_endpoint_canonicalisation`, `::test_partially_fixing_a_web_finding_is_visible`, `::test_a_reappearing_endpoint_reopens_only_that_endpoint` |
| A crashed scanner with no/partial output closes nothing; a successful empty scan does | `test_phase18_hardening.py::test_a_crashed_scanner_with_no_output_is_not_reconciled`, `::test_a_crashed_scanner_with_partial_output_imports_but_closes_nothing`, `::test_a_successful_empty_scan_still_closes_what_was_fixed` |
| Risk acceptance: requester cannot approve own; pending does not silence; expiry restores and does not launder an overdue SLA; `expire_due` idempotent | `::test_the_requester_cannot_approve_their_own_acceptance`, `::test_a_pending_acceptance_does_not_silence_the_finding`, `::test_approval_accepts_the_finding_and_expiry_puts_it_back`, `::test_expiry_does_not_launder_an_overdue_sla`, `::test_expire_due_is_idempotent` |
| Parsers per scanner format; connector sync skips identical exports; Jira/Confluence/ITSM inbound | `test_phase15_parsers.py` (24 fn), `test_phase33_scanner_connectors.py::test_an_identical_export_is_skipped_and_force_overrides`, `test_phase17_itsm_inbound.py`, `test_phase43_jira.py`, `test_phase44_confluence.py` |
| Disposition (stale candidates are not closures) | `test_phase36_disposition.py` (43 fn) |
| NVD rejected records / EPSS retention | `test_nvd_rejects.py`, `test_epss_retention.py`, `test_phase3_intel.py::test_ingest_epss_skips_unknown_cves` |

**Gaps.** The parsers are tested with synthetic report snippets inside the test files, not with vendor-produced files (`tests/fixtures/` holds only the CVSS corpora). `POST /api/v1/assets/inventory/import`, `.../inventory/resolve` and `POST /api/v1/teams/import/assign-assets` have no path reference. Concurrent imports of the same report are not exercised.

## 4. Risk scoring

| Guarantee | Test |
|---|---|
| Same CVSS, different context → different risk; lower CVSS can outrank higher | `test_phase3_risk.py::test_same_cvss_different_context_produces_different_risk`, `::test_lower_cvss_can_outrank_higher_cvss` |
| KEV and active-exploitation floors; zero CVSS with KEV is not silenced; missing CVSS defaults to medium | `::test_kev_floor_applies`, `::test_internet_kev_floor_is_higher_than_kev_floor`, `::test_active_exploitation_floor`, `::test_zero_cvss_with_kev_is_not_silenced`, `::test_missing_cvss_defaults_to_medium_not_zero` |
| EPSS sqrt scaling; control credit capped and unknown controls ignored; age penalty doubles after SLA breach and is capped | `::test_epss_is_sqrt_scaled_so_low_values_still_register`, `::test_control_credit_is_capped`, `::test_unknown_control_is_ignored_not_credited`, `::test_age_penalty_grows_and_doubles_after_sla_breach` |
| Score bounded; levels map to documented bands; explanation lists every factor and pre/post-floor score | `::test_score_is_always_bounded`, `::test_levels_map_to_the_documented_bands`, `::test_explanation_lists_every_contributing_factor` |
| Every built-in profile scores | `::test_every_builtin_profile_scores_without_error` (parametrized over `risk.BUILTIN_PROFILES`) |
| CVSS v2/v3/v4 base scores against 4,379 official vectors; v4 rounding is half-up | `test_cvss_official.py::test_v2_official`, `::test_v3_official`, `::test_v4_official` |
| A correlated finding is scored and gets an SLA | `test_phase3_intel.py::test_correlated_finding_is_scored_and_has_sla` |
| Risk register and matrix | `test_phase46_risk_register.py` (24 fn), `test_phase47_risk_matrix.py` (7 fn) |

**Gaps.** `POST /api/v1/risk/simulate` and `POST /api/v1/findings/{finding_id}/rescore` have no path reference. `services/risk.py` is called by many tests through helpers rather than directly (see the coverage matrix notes). Nothing in the suite compares the scoring weights to documented values beyond the explanation tests.

## 5. SLA clocks and escalation

| Guarantee | Test |
|---|---|
| Sweep breaches and escalates; sweep is idempotent | `test_phase3_intel.py::test_sla_sweep_breaches_and_escalates`, `::test_sla_sweep_is_idempotent` |
| Business-hours deadline skips the weekend | `test_phase3_intel.py::test_business_hours_deadline_skips_the_weekend` |
| Numeric gate ignores unscored findings | `test_phase3_intel.py::test_sla_policy_numeric_gate_ignores_unscored_findings` |
| Scope on the SLA summary, events and sweep; the two SLA surfaces agree | `test_phase28_sla_scope.py` (23 fn), notably `::test_the_two_sla_surfaces_agree_under_the_same_filter`, `::test_a_scoped_identity_cannot_edit_the_estate_wide_sla_policy` |
| Expired risk acceptance does not reset an overdue SLA | `test_phase15_unified_ingest.py::test_expiry_does_not_launder_an_overdue_sla` |
| Digest and notifications | `test_phase36_disposition.py` (digest recipients), `test_phase35_operability.py` |
| The CLI entry `run-sla` and the `veyrs-digest` timer | `test_docs_are_current.py::test_every_cli_command_appears_in_the_manual`, `::test_every_shipped_unit_can_actually_start` (documentation/unit guards, not behaviour) |

**Gaps.** Time is controlled by constructing dates, never by freezing a clock; no test runs the sweep across a DST change or time-zone boundary. The scheduler itself (systemd timers) is verified only at the unit-file level.

## 6. Agent job lifecycle

All in `test_phase16_agents.py` unless noted.

| Stage | Test |
|---|---|
| Enrol: a fresh agent can run nothing; a declared tool is not an authorised tool | `test_a_freshly_enrolled_agent_can_run_nothing`, `test_a_declared_tool_is_not_an_authorised_tool` |
| Queue: a job needs a reason; unrunnable tool refused at queue time; unknown parser refused | `test_a_job_needs_a_reason`, `test_an_unrunnable_tool_is_refused_at_queue_time`, `test_an_unknown_parser_is_refused_not_guessed` |
| Target policy: reserved ranges refused, explicit allow, deny beats allow, register as boundary, name targets never match network rules | `test_reserved_ranges_are_refused` … `test_unregistered_hosts_are_refused_when_the_register_is_the_boundary` |
| Claim and lease: concurrency respected; unpinned job re-authorised; only the lease holder writes | `test_claim_leases_a_job_and_respects_concurrency`, `test_an_unpinned_job_is_re_authorised_against_the_claiming_agent`, `test_only_the_lease_holder_may_write_to_a_job` |
| Progress: events stream incrementally, `seq` is server-assigned | `test_events_stream_incrementally_and_seq_is_server_assigned` |
| Result: becomes findings; empty result closes what was fixed; non-zero exit fails the job; oversized result refused with no partial import | `test_a_result_becomes_findings_in_the_jobs_engagement`, `test_an_empty_result_is_a_clean_scan_and_closes_what_was_fixed`, `test_a_nonzero_exit_code_fails_the_job_even_with_parsable_output`, `test_an_oversized_result_is_refused_without_a_partial_import` |
| Failure, retry, expiry, liveness | `test_a_failed_job_requeues_until_attempts_run_out`, `test_an_expired_lease_is_requeued_then_expired_not_failed`, `test_a_silent_agent_is_marked_offline` |
| Credential boundary | `test_agent_token_is_not_a_principal`, `test_a_disabled_agent_is_told_why`, `test_deleting_an_agent_with_live_work_is_refused` |
| End to end over HTTP | `test_enrol_queue_claim_and_submit_over_http` |
| Failure detail / crash recorded | `test_phase18_hardening.py::test_a_failed_job_reports_why_and_not_just_the_exit_code`, `::test_a_crashed_job_still_records_its_output_hash` |
| Runner and agent script | `test_phase16_runner.py` (7 fn, 15 expanded), `test_phase19_coverage.py` |

**Gaps.** Routes `POST /api/v1/agents/self/jobs/{job_id}/lease`, `.../fail`, `POST /api/v1/agents/self/inventory`, `POST /api/v1/agents/maintenance/reap` and `POST /api/v1/agents/{agent_id}/rotate-token` have no strict path reference: lease/fail/reap behaviour is tested at service level, so the HTTP contract of those routes (status codes, auth header handling) is not directly pinned. `test_phase19_coverage.py` loads the agent script from the hard-coded path `/opt/veyrs/integrations/veyrs-agent/veyrs_agent.py` ([known issue](known-issues.md#tests-bound-to-optveyrs)).

## 7. AI policy gate

The gateway is the single choke point; tests target its refusals.

| Guarantee | Test (`test_phase6_ai.py`) |
|---|---|
| Default policy forbids external providers; confidential data cannot reach an external provider; public data may reach an *allowed* one | `test_default_policy_forbids_external_providers`, `test_confidential_data_cannot_reach_an_external_provider`, `test_public_data_may_reach_an_allowed_external_provider` |
| A hosted vendor cannot be relabelled "internal"; model allow-list is authoritative | `test_hosted_vendor_cannot_be_relabelled_internal`, `test_model_allow_list_is_authoritative` |
| Capability needs the caller's own permission; unknown capability is a programming error; disabled capability refused; daily limit blocks | `test_capability_requires_the_callers_own_permission`, `test_unknown_capability_is_a_programming_error`, `test_disabled_capability_is_refused`, `test_daily_call_limit_blocks_further_calls` |
| Secrets/PII redacted before the prompt; echoed secrets scanned in output; injection blocks and is audited | `test_secrets_never_reach_the_prompt_that_is_sent`, `test_model_output_is_scanned_for_echoed_secrets`, `test_injection_in_untrusted_content_blocks_and_is_audited`, `test_untrusted_content_cannot_close_its_own_fence` |
| Degradation instead of failure when no provider/provider errors | `test_no_provider_degrades_instead_of_failing`, `test_provider_failure_degrades_and_records_the_error` |
| NL search is a closed grammar compiled to a tenant-scoped query | `test_grammar_rejects_anything_outside_the_allow_list`, `test_every_grammar_field_resolves_to_a_real_column`, `test_compiled_query_is_always_tenant_scoped` |
| Hallucinated team suggestion rejected; CVE facts computed not generated | `test_hallucinated_team_suggestion_is_rejected`, `test_cve_facts_are_computed_not_generated` |
| Provider key never returned in clear; policy API; AI routes require authentication | `test_provider_api_key_is_never_returned_in_clear`, `test_policy_roundtrip_over_http`, `test_ai_routes_require_authentication` |

**Gaps.** No test uses a real model: providers are stubbed, so prompt quality and real-provider failure modes are untested. The HTTP routes for `explain`, `remediation`, `ticket-draft`, `suggest-team`, `threat-summary` and `cve/{cve_id}/analysis` have no strict path reference (gateway-level tests cover the logic). `DELETE /api/v1/ai/providers/{provider_id}` is weakly referenced only.

## 8. Exports, update path and release signing

| Guarantee | Test |
|---|---|
| Exports carry provenance; CSV neutralises formulas; XLSX stores formulas as text; sheet names sanitised; exports audited; each report enforces its own permission | `test_phase9_reporting.py::test_provenance_names_the_organization_and_the_moment`, `test_phase50_report_builder.py::test_csv_export_neutralises_formulas_and_carries_provenance`, `::test_xlsx_export_stores_formulas_as_text`, `test_phase9_reporting.py::test_xlsx_sheet_names_are_sanitised`, `::test_export_is_audited`, `::test_each_report_enforces_its_own_permission` |
| A shared report runs under the reader's scope | `test_phase26_scope.py::test_a_shared_report_runs_under_the_readers_scope`, `::test_the_export_is_scoped_as_well` |
| `verify-release.sh` accepts a correctly signed release; rejects tampered asset (hash mismatch), tampered sums (bad signature), foreign key, no signature, placeholder key | `test_phase52_release_signing.py::test_sign_and_verify_round_trip`, `::test_a_tampered_asset_is_a_hash_mismatch`, `::test_a_tampered_sums_file_is_a_bad_signature`, `::test_a_signature_by_another_key_is_a_bad_signature`, `::test_no_signature_is_unsigned_not_ok`, `::test_the_placeholder_key_means_cannot_verify_never_success` |
| Traversing or malformed sums lines refused even when signed; unlisted files reported | `::test_a_malformed_or_traversing_sums_line_is_refused_even_when_signed`, `::test_an_unlisted_file_is_reported_not_silently_trusted` |
| Installer embeds the same key as `release/allowed_signers`; setup refuses tampered/unsigned releases even with `--allow-unsigned` | `::test_the_key_embedded_in_veyrs_setup_equals_release_allowed_signers`, `::test_setup_refuses_a_tampered_tarball_and_a_bad_signature_even_with_allow_unsigned` |
| Publishing refuses without a signing key or with a key other accounts can read; unsigned must be asked for by name | `::test_publish_release_refuses_without_a_signing_key_before_any_network_call`, `::test_publish_release_refuses_a_key_other_accounts_can_read`, `::test_publish_unsigned_must_be_asked_for_by_name` |
| Self-updater refuses unsigned, bad hash, foreign signature, placeholder key, git checkout, no backup, non-newer target | `test_phase52_updates.py::test_updater_refuses_an_unsigned_release` … `::test_updater_refuses_a_target_that_is_not_newer_and_a_malformed_request` |
| Update API is platform-admin only; uploads are platform-admin only; a request carries a keyword, never a path; symlinks in local copies refused | `test_phase52_updates.py::test_the_api_is_platform_admin_only`, `test_phase55_local_update.py::test_uploads_are_platform_admin_only`, `::test_the_request_carries_a_keyword_never_a_path`, `::test_updater_refuses_a_symlink_in_a_local_copy` |
| Version in `pyproject.toml` equals `Settings.version` | `test_phase24_dependencies.py::test_the_running_version_matches_the_declared_one` |

**Gaps.**

- Signing tests use throwaway keys generated at run time and skip when `ssh-keygen` is missing; the real release key is never exercised by a signing test, and `test_the_committed_allowed_signers_is_a_placeholder_or_a_real_key` accepts either.
- `test_setup_with_the_shipped_placeholder_cannot_verify_and_refuses` skips once the real key is embedded (`tests/test_phase52_release_signing.py:346`) — the placeholder-refusal path then loses coverage by design.
- The end-to-end publish harness runs only in a git checkout (`tests/test_phase52_release_signing.py:400`).
- No test checks that the `docs/CHANGELOG.md` heading matches the version (stated in the Testing guide; no such test found).
