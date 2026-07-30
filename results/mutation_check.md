# Mutation check: can the adversarial suite fail?

Each row breaks exactly one control in `src/sharing/schema.sql`, runs the
full test suite, and records which attack caught it. Regenerate with
`scripts/mutation_check.sh`.

| # | control removed | caught | first failing tests |
|---|---|---|---|
| 1 | RLS policy: partner-org restriction | **yes** | `test_attacks.py::test_attack_is_held_by_the_rls_arm[aggregate_count_all];test_attacks.py::test_attack_is_held_by_the_rls_arm[cross_partner_row_probe] test_attacks.py::test_positive_controls_all_pass` |
| 2 | RLS policy: classification ceiling | **yes** | `test_attacks.py::test_attack_is_held_by_the_rls_arm[predicate_probe_hidden_row];test_attacks.py::test_attack_is_held_by_the_rls_arm[aggregate_count_all] test_attacks.py::test_attack_is_held_by_the_rls_arm[exists_subquery_oracle]` |
| 3 | RLS policy: region scope | **yes** | `test_attacks.py::test_attack_is_held_by_the_rls_arm[aggregate_count_all];test_attacks.py::test_positive_controls_all_pass test_credentials.py::test_credential_is_transaction_local_and_does_not_leak` |
| 4 | view: cost column masking | **yes** | `test_attacks.py::test_attack_is_held_by_the_rls_arm[aggregate_sum_masked_column];test_attacks.py::test_attack_is_held_by_the_rls_arm[order_by_masked_column] test_attacks.py::test_attack_is_held_by_the_rls_arm[masked_column_in_predicate]` |
| 5 | view: contact column masking | **yes** | `test_view_masking.py::test_every_sensitive_column_is_masked_by_a_case` |
| 6 | current_auth: delegation revocation/expiry check | **yes** | `test_attacks.py::test_attack_is_held_by_the_rls_arm[revoked_delegation_valid_credential];test_revocation.py::test_db_checked_revocation_halts_within_its_declared_bound test_revocation.py::test_an_inflight_request_completes_and_the_next_is_denied` |
| 7 | current_auth: delegation chain walk to root | **yes** | `test_attacks.py::test_attack_is_held_by_the_rls_arm[orphan_chain_mid_revocation];test_attacks.py::test_attack_is_held_by_the_rls_arm[expired_parent_live_child]` |
| 8 | current_auth: grant liveness (approved/unrevoked/unexpired) | **yes** | `test_attacks.py::test_attack_is_held_by_the_rls_arm[expired_grant];test_attacks.py::test_attack_is_held_by_the_rls_arm[unapproved_grant] test_attacks.py::test_attack_is_held_by_the_rls_arm[revoked_grant_valid_credential]` |
| 9 | current_auth: credential subject must match the delegatee | **yes** | `test_attacks.py::test_attack_is_held_by_the_rls_arm[forge_foreign_org_agent];test_attacks.py::test_attack_is_held_by_the_rls_arm[delegation_credential_swap]` |
| 10 | verify_credential: signature comparison | **yes** | `test_attacks.py::test_attack_is_held_by_the_rls_arm[forge_subject_keep_signature];test_attacks.py::test_attack_is_held_by_the_rls_arm[forge_extend_expiry] test_credentials.py::test_tampered_claims_fail_closed_returning_null` |
| 11 | verify_credential: expiry check | **yes** | `test_credentials.py::test_expired_credential_rejected;test_revocation.py::test_token_only_enforcement_keeps_working_after_revocation` |
| 12 | delegation trigger: narrowing enforcement | **yes** | `test_delegation_rules.py::test_region_wider_than_grant_is_refused` |

After restoring the original schema the suite is green again (all passed).
