package cases

func Ledger() []Row {
	rows := []Row{
		fixtureRow("R1.2.optional_headscale", "R1.2", "A local App remains valid when Headscale and the connector are absent", "domain.optional_headscale_local_app", "./internal/domain", "TestInstallationSchema/optional_headscale_allows_local_app"),
		fixtureRow("R1.2.concrete_prerequisites", "R1.2", "Absent optional components return concrete prerequisite codes and never mode_incompatible", "domain.concrete_prerequisite_codes", "./internal/domain", "TestInstallationSchema/concrete_prerequisite_codes"),
		fixtureRow("R1.3.singleton_components", "R1.3", "The installation schema has exactly one optional Headscale and connector slot", "domain.singleton_optional_components", "./internal/domain", "TestInstallationSchema/single_optional_component_fields"),
		fixtureRow("R3.4.shared_domain_schema", "R3.4", "All callers can share one canonical typed installation schema without alternate decoding", "domain.shared_installation_schema", "./internal/domain", "TestInstallationSchema/single_schema_round_trip_is_canonical"),
		fixtureRow("R1.8.strict_ga_decoder", "R1.8", "Unknown, placeholder, alpha, and unsupported domain input is rejected", "domain.strict_decoder", "./internal/domain", "TestInstallationSchema/strict_decoder_rejects_unknown_and_alpha_fields"),
		fixtureRow("R11.4.no_commercial_gates", "R11.4", "Edition, license, quota, and call-home fields are impossible in the community schema", "domain.no_commercial_gate_fields", "./internal/domain", "TestInstallationSchema/commercial_gate_fields_are_impossible"),
		fixtureRow("R5.2.closed_target_union", "R5.2", "Each App has exactly one supported local_http or tailnet_http target", "domain.closed_target_union", "./internal/domain", "TestInstallationSchema/target_union_is_closed"),
		fixtureRow("R5.2.typed_readiness", "R5.2", "HTTP readiness is mandatory and WebSocket readiness is an explicit typed option", "domain.typed_target_readiness", "./internal/domain", "TestInstallationSchema/target_readiness_and_websocket_are_typed"),
		fixtureRow("R5.2.local_endpoint_realizations", "R5.2", "Local HTTP uses exactly one of the three protected endpoint realizations", "domain.local_endpoint_realizations", "./internal/domain", "TestInstallationSchema/local_endpoint_realizations_are_closed"),
		fixtureRow("R5.8.closed_publication_union", "R5.8", "Each App has exactly one supported domain_https or temporary_ip_http publication", "domain.closed_publication_union", "./internal/domain", "TestInstallationSchema/publication_union_is_closed"),
		fixtureRow("R7.1.applied_identity_invariants", "R7.1", "Publication state retains or rejects applied identity only as a complete pair", "domain.applied_identity_invariants", "./internal/domain", "TestInstallationSchema/publication_state_preserves_applied_identity"),
		fixtureRow("R7.1.complete_publication_bundle", "R7.1", "Applied bundles carry the complete identity required by their publication kind", "domain.complete_publication_bundle", "./internal/domain", "TestInstallationSchema/publication_bundle_is_kind_complete"),
		fixtureRow("R7.1.activation_prior_binding", "R7.1", "An activating prior bundle exactly matches the retained applied identity", "domain.activation_prior_binding", "./internal/domain", "TestInstallationSchema/activation_prior_matches_applied_identity"),
		fixtureRow("R7.1.managed_process_observation", "R7.1", "Managed process requested state has a separate nullable typed runtime observation", "domain.managed_process_observation", "./internal/domain", "TestInstallationSchema/managed_process_state_includes_runtime_observation"),
		fixtureRow("R6.1.initial_unpublished_state", "R6.1", "A new resource starts sticky unpublished with no fabricated applied identity", "domain.initial_unpublished_state", "./internal/domain", "TestInstallationSchema/new_resource_is_sticky_unpublished_without_applied_identity"),
		fixtureRow("R6.1.publication_type_change_boundary", "R6.1", "Publication type and temporary authority can change only while unpublished", "domain.publication_type_change_boundary", "./internal/domain", "TestInstallationSchema/publication_type_changes_require_unpublished_state"),
		fixtureRow("R7.3.current_applied_separation", "R7.3", "Pending current configuration never rewrites the immutable applied identity", "domain.current_applied_separation", "./internal/domain", "TestInstallationSchema/current_and_applied_digests_stay_distinct"),
		fixtureRow("R5.1.explicit_stable_resource_id", "R5.1", "A resource ID is explicit and remains stable when its display name changes", "domain.stable_resource_identity", "./internal/domain", "TestInstallationSchema/stable_id_is_explicit"),
		fixtureRow("R7.2.publication_status_projection", "R7.2", "Status distinguishes possible live contraction from verified closure", "domain.publication_status_projection", "./internal/domain", "TestInstallationSchema/status_distinguishes_pending_and_closure"),
		fixtureRow("R7.2.activating_status", "R7.2", "Activating publication is displayed as may-be-live", "domain.activating_status", "./internal/domain", "TestInstallationSchema/activating_status_is_may_be_live"),
		fixtureRow("R7.2.published_healthy_status", "R7.2", "Published healthy status is distinct", "domain.published_healthy_status", "./internal/domain", "TestInstallationSchema/published_healthy_status_is_distinct"),
		fixtureRow("R7.2.published_degraded_status", "R7.2", "Published degraded status is distinct", "domain.published_degraded_status", "./internal/domain", "TestInstallationSchema/published_degraded_status_is_distinct"),
		fixtureRow("R7.2.published_unknown_status", "R7.2", "Published unknown status is distinct", "domain.published_unknown_status", "./internal/domain", "TestInstallationSchema/published_unknown_status_is_distinct"),
		fixtureRow("R7.2.recent_operation_failure", "R7.2", "A recent operation failure is additive and never overwrites publication state", "domain.recent_operation_failure", "./internal/domain", "TestInstallationSchema/recent_operation_failure_is_additive"),
		fixtureRow("R3.6.closed_action_vocabulary", "R3.6", "The typed action vocabulary accepts only supported GA actions", "domain.closed_action_vocabulary", "./internal/domain", "TestInstallationSchema/action_vocabulary_is_closed"),
		fixtureRow("R3.6.closed_action_targets", "R3.6", "Every typed action accepts only its closed target kind and stable target identity", "domain.closed_action_targets", "./internal/domain", "TestInstallationSchema/operation_targets_are_closed"),
		fixtureRow("R7.2.closed_result_vocabulary", "R7.2", "Operation results use only succeeded, failed, partial, interrupted, or unknown", "domain.closed_result_vocabulary", "./internal/domain", "TestInstallationSchema/result_vocabulary_is_closed"),

		fixtureRow("R1.7.magicdns_domain_overlap", "R1.7", "MagicDNS namespace overlap with a public exact domain is rejected", "reservations.magicdns_overlap", "./internal/reservations", "TestConflictRegistry/magicdns_namespace_overlap_is_rejected"),
		fixtureRow("R1.7.exact_domain_collision", "R1.7", "Headscale control and App exact-domain collisions are rejected", "reservations.exact_domain_collision", "./internal/reservations", "TestConflictRegistry/exact_domain_collision_is_rejected"),
		fixtureRow("R1.7.resource_name_collision", "R1.7", "Normalized resource names are exclusive", "reservations.resource_name_collision", "./internal/reservations", "TestConflictRegistry/resource_name_collision_is_rejected"),
		fixtureRow("R1.7.listener_collision", "R1.7", "Public listener protocol and port reservations are exclusive", "reservations.listener_collision", "./internal/reservations", "TestConflictRegistry/listener_collision_is_rejected"),
		fixtureRow("R1.7.local_tcp_listener_collision", "R1.7", "A local TCP socket-activation listener conflicts atomically with every reserved TCP port", "reservations.local_tcp_listener_collision", "./internal/reservations", "TestConflictRegistry/local_tcp_listener_collision_is_rejected"),
		fixtureRow("R1.7.credential_collision", "R1.7", "Credential IDs are exclusive", "reservations.credential_collision", "./internal/reservations", "TestConflictRegistry/credential_collision_is_rejected"),
		fixtureRow("R1.7.pending_applied_claim_union", "R1.7", "Pending configuration retains every last-applied domain, listener, credential, and managed-path claim", "reservations.pending_applied_claim_union", "./internal/reservations", "TestConflictRegistry/pending_applied_identity_remains_reserved"),
		fixtureRow("R1.7.managed_path_overlap", "R1.7", "Equal or nested managed paths are rejected", "reservations.managed_path_overlap", "./internal/reservations", "TestConflictRegistry/managed_path_overlap_is_rejected"),
		fixtureRow("R1.7.atomic_conflict_transaction", "R1.7", "A failed conflict transaction leaves the committed registry unchanged", "reservations.atomic_failure", "./internal/reservations", "TestConflictRegistry/failed_replacement_is_atomic"),
		fixtureRow("R1.7.stale_conflict_transaction", "R1.7", "A generation-stale conflict transaction cannot commit", "reservations.stale_transaction", "./internal/reservations", "TestConflictRegistry/stale_transaction_is_rejected"),
		fixtureRow("R5.1.stable_conflict_owner", "R5.1", "Conflict ownership derives from immutable resource ID rather than name or filename", "reservations.stable_owner", "./internal/reservations", "TestConflictRegistry/stable_owner_is_not_derived_from_name_or_filename"),

		stepFixtureRow("S2", "R8.4.clean_absolute_path", "R8.4", "Managed path validation rejects unclean and out-of-root paths", "filetxn.clean_absolute_path", "./internal/filetxn", "TestNoFollowMetadataAndBoundaryValidation/unclean_and_outside_paths"),
		stepFixtureRow("S2", "R8.4.no_follow_components", "R8.4", "Managed path validation rejects symbolic-link path components", "filetxn.no_follow_components", "./internal/filetxn", "TestNoFollowMetadataAndBoundaryValidation/symlink_parent"),
		stepFixtureRow("S2", "R2.13.regular_single_link_target", "R2.13", "Managed file transactions reject symbolic-link and multiply-linked targets", "filetxn.regular_single_link_target", "./internal/filetxn", "TestNoFollowMetadataAndBoundaryValidation/symlink_and_hardlink_targets/hardlink"),
		stepFixtureRow("S2", "R2.13.same_mount_boundary", "R2.13", "Managed file traversal rejects a mount crossing even when rooted at slash", "filetxn.mount_boundary", "./internal/filetxn", "TestNoFollowMetadataAndBoundaryValidation/mount_crossing"),
		stepFixtureRow("S2", "R7.13.atomic_file_lifecycle", "R7.13", "Create, replacement, and removal reach durable atomic states without residual tombstones", "filetxn.atomic_lifecycle", "./internal/filetxn", "TestAtomicFileLifecycle/create_replace_remove"),
		stepFixtureRow("S2", "R7.13.concurrent_identity_fence", "R7.13", "Concurrent target replacement is rejected without activating the staged object", "filetxn.concurrent_identity_fence", "./internal/filetxn", "TestCreateAndReplaceRejectConcurrentTargetChanges/replace"),
		stepFixtureRow("S2", "R2.13.bounded_file_operations", "R2.13", "File transactions enforce content bounds, dispositions, and cancellation", "filetxn.bounded_operations", "./internal/filetxn", "TestPutEnforcesSizeDispositionAndCancellation/bounded_input_and_operation"),
		stepFixtureRow("S2", "R8.3.protected_secret_staging", "R8.3", "Final-mode staged content remains behind a helper-owned 0700 directory until commit", "filetxn.protected_staging", "./internal/filetxn", "TestProtectedStagingDirectory/keeps_final_file_behind_owner_only_parent"),
		stepFixtureRow("S2", "R2.13.staging_reread", "R2.13", "A verified staging object reaches the post-reread fault boundary without target mutation", "filetxn.staging_reread", "./internal/filetxn", "TestPutFaultBoundariesLeaveCompleteTargetOrInertStaging/after_verify"),
		stepFixtureRow("S2", "R10.15.filetxn_write_failure", "R10.15", "An injected staging write failure leaves the target unchanged and identifiable inert staging", "filetxn.write_failure", "./internal/filetxn", "TestPutFaultBoundariesLeaveCompleteTargetOrInertStaging/before_write"),
		stepFixtureRow("S2", "R10.15.filetxn_chmod_failure", "R10.15", "An injected staging metadata failure leaves the target unchanged and identifiable inert staging", "filetxn.chmod_failure", "./internal/filetxn", "TestPutFaultBoundariesLeaveCompleteTargetOrInertStaging/before_metadata"),
		stepFixtureRow("S2", "R10.15.filetxn_fsync_failure", "R10.15", "An injected staging fsync failure leaves the target unchanged and identifiable inert staging", "filetxn.fsync_failure", "./internal/filetxn", "TestPutFaultBoundariesLeaveCompleteTargetOrInertStaging/before_file_sync"),
		stepFixtureRow("S2", "R10.15.filetxn_rename_failure", "R10.15", "An injected rename failure leaves the target unchanged and verified inert staging", "filetxn.rename_failure", "./internal/filetxn", "TestPutFaultBoundariesLeaveCompleteTargetOrInertStaging/before_rename"),
		stepFixtureRow("S2", "R10.15.filetxn_post_rename_crash", "R10.15", "An interruption after rename reports a namespace-changed state and preserves an identifiable tombstone", "filetxn.post_rename_crash", "./internal/filetxn", "TestPutFaultBoundariesLeaveCompleteTargetOrInertStaging/after_rename"),
		stepFixtureRow("S2", "R10.15.filetxn_durable_crash", "R10.15", "An interruption after directory synchronization reports a durable state", "filetxn.durable_crash", "./internal/filetxn", "TestPutFaultBoundariesLeaveCompleteTargetOrInertStaging/after_directory_sync"),

		stepFixtureRow("S3", "R8.10.ordered_lock_handoff", "R8.10", "Exposure and mutation-admission locks reject reverse acquisition order", "locks.ordered_handoff", "./internal/locks", "TestIndependentLockContract/ordered_handoff_and_reverse_rejection"),
		stepFixtureRow("S3", "R8.10.cross_manager_lock_contention", "R8.10", "Process-wide lock order and kernel contention apply across manager instances", "locks.cross_manager_contention", "./internal/locks", "TestIndependentLockContract/cross_manager_contention_is_bounded"),
		stepFixtureRow("S3", "R8.10.held_lock_identity", "R8.10", "A held lease rejects replacement of its configured lock inode", "locks.held_identity", "./internal/locks", "TestIndependentLockContract/held_lease_detects_lock_path_replacement"),

		stepFixtureRow("S3", "R7.8.atomic_ownership_inventory", "R7.8", "Durable ownership records retain canonical path and listener evidence independently of normal state", "ownership.atomic_inventory", "./internal/ownership", "TestOwnershipEvidenceContract/atomic_record_inventory_and_orphan_classification"),
		stepFixtureRow("S3", "R7.8.corrupt_ownership_evidence", "R7.8", "Corrupt or symbolic-link ownership records make the inventory incomplete", "ownership.corrupt_evidence", "./internal/ownership", "TestOwnershipEvidenceContract/corrupt_or_symlink_record_is_never_inventory_authority"),
		stepFixtureRow("S3", "R7.8.monotonic_ownership_cas", "R7.8", "Activation ownership updates compare revisions and cannot narrow prior inventory", "ownership.monotonic_cas", "./internal/ownership", "TestOwnershipEvidenceContract/activation_updates_are_monotonic_and_never_narrow_inventory"),
		stepFixtureRow("S3", "R7.8.cross_resource_ownership_collision", "R7.8", "Two resources cannot claim the same managed path or listener", "ownership.cross_resource_collision", "./internal/ownership", "TestOwnershipEvidenceContract/cross_resource_physical_collisions_are_rejected"),

		stepFixtureRow("S3", "R7.4.challenge_reactivation_priority", "R7.4", "Challenge and reactivation expansion require their exact current generation identities", "safety.exact_expansion_identity", "./internal/safety", "TestSafetyPriorityAndGuardContract/challenge_and_reactivation_require_exact_generation"),
		stepFixtureRow("S3", "R7.4.elapsed_edgeone_deadline", "R7.4", "An elapsed EdgeOne deadline contracts publication even before timer marker creation", "safety.edgeone_deadline", "./internal/safety", "TestSafetyPriorityAndGuardContract/elapsed_edgeone_deadline_is_authority_without_timer_marker"),
		stepFixtureRow("S3", "R7.4.headscale_expansion_identity", "R7.4", "Headscale challenge and reactivation use separate exact control and certificate identities", "safety.headscale_identity", "./internal/safety", "TestSafetyPriorityAndGuardContract/global_close_blocks_app_but_not_matching_headscale_challenge"),
		stepFixtureRow("S3", "R8.10.mandatory_guard_registration", "R8.10", "An expansion operation without a registered mandatory guard fails closed", "safety.guard_registration", "./internal/safety", "TestSafetyPriorityAndGuardContract/unregistered_operation_is_blocked"),

		stepFixtureRow("S3", "R7.9.contraction_stop_payload", "R7.9", "A contraction stop fence requires its closed contraction authority payload", "safety.contraction_stop_payload", "./internal/safety", "TestSafetySchemaContract/closed_stop_fence_payloads/contraction"),
		stepFixtureRow("S3", "R7.9.ingress_stop_payload", "R7.9", "An ingress-activation stop fence requires its closed intent and generation payload", "safety.ingress_stop_payload", "./internal/safety", "TestSafetySchemaContract/closed_stop_fence_payloads/ingress_activation"),
		stepFixtureRow("S3", "R7.9.certificate_stop_payload", "R7.9", "A certificate-activation stop fence requires its closed pointer and expiry payload", "safety.certificate_stop_payload", "./internal/safety", "TestSafetySchemaContract/closed_stop_fence_payloads/certificate_activation"),
		stepFixtureRow("S3", "R7.9.edgeone_stop_payload", "R7.9", "An EdgeOne-refresh stop fence requires its closed ACL and deadline payload", "safety.edgeone_stop_payload", "./internal/safety", "TestSafetySchemaContract/closed_stop_fence_payloads/edgeone_refresh"),
		stepFixtureRow("S3", "R7.9.maintenance_stop_payload", "R7.9", "A maintenance stop fence requires its immutable envelope transition payload", "safety.maintenance_stop_payload", "./internal/safety", "TestSafetySchemaContract/closed_stop_fence_payloads/maintenance_transition"),
		stepFixtureRow("S3", "R7.9.upgrade_stop_payload", "R7.9", "A generation-upgrade stop fence requires its immutable envelope transition payload", "safety.upgrade_stop_payload", "./internal/safety", "TestSafetySchemaContract/closed_stop_fence_payloads/generation_upgrade"),

		stepFixtureRow("S3", "R7.9.closed_resource_intents", "R7.9", "App and Headscale safety intents are complete, exclusive, and reject one-sided EdgeOne authority", "safety.closed_resource_intents", "./internal/safety", "TestSafetySchemaContract/resource_markers_and_intents_are_closed"),
		stepFixtureRow("S3", "R7.15.closing_convergence", "R7.15", "Closing clears only into an exact ownership-bound unpublished generation", "safety.closing_convergence", "./internal/safety", "TestSafetyConvergenceProofs/closing_normalizes_to_exact_unpublished_generation"),
		stepFixtureRow("S3", "R7.15.stop_fence_convergence", "R7.15", "Stop-fence clearing binds every App's exact unpublished generation and reconciled intents", "safety.stop_fence_convergence", "./internal/safety", "TestSafetyConvergenceProofs/stop_clear_binds_every_unpublished_generation"),
		stepFixtureRow("S3", "R7.15.headscale_expiry_convergence", "R7.15", "Headscale certificate expiry clears only with its exact completed reactivation", "safety.headscale_expiry_convergence", "./internal/safety", "TestSafetyConvergenceProofs/headscale_expiry_clear_requires_matching_reactivation"),
		stepFixtureRow("S3", "R7.15.unique_marker_clearers", "R7.15", "Every independent marker and stop-fence kind has one closed clearing role", "safety.unique_clearers", "./internal/safety", "TestSafetySchemaContract/unique_clear_roles"),
		stepFixtureRow("S3", "R7.15.atomic_maintenance_transition", "R7.15", "Maintenance begins with global and per-App closure and converts to dependency authority atomically", "safety.atomic_maintenance", "./internal/safety", "TestMaintenanceCompoundTransitionsAreAtomicAndNarrow/atomic_marker_handoff"),
		stepFixtureRow("S3", "R7.15.transition_replacement_ownership", "R7.15", "Repair cannot replace or clear a transition owned by another role", "safety.transition_ownership", "./internal/safety", "TestSafetyTransitionOwnershipRejectsReplacementBypass/wrong_role_and_binding_replacement"),
		stepFixtureRow("S3", "R7.15.normal_emergency_pairing", "R7.15", "Normal safety commits reject missing, one-sided, stale, or unconverged global-close authority", "safety.normal_emergency_pairing", "./internal/safety", "TestSafetyStoreRequiresLockGenerationAndUniqueClearer/missing_state_generation_pair_and_convergent_clear"),

		stepFixtureRow("S3", "R7.9.emergency_slot_recovery", "R7.9", "The two-slot emergency authority recovers the latest intact contraction and commits without allocation", "safety.emergency_slot_recovery", "./internal/safety", "TestEmergencyBackingSurvivesSlotCorruptionAndCommitsWithoutAllocation/slot_recovery_and_zero_allocation_commit"),
		stepFixtureRow("S3", "R10.15.emergency_interrupted_write", "R10.15", "An interrupted emergency slot write leaves at least one complete checksummed authority", "safety.emergency_interrupted_write", "./internal/safety", "TestEmergencyWriteInterruptionLeavesAValidCompleteSlot/interrupted_write_preserves_complete_authority"),
		stepFixtureRow("S3", "R10.15.emergency_stale_instance", "R10.15", "Emergency authority reload rejects stale instances, inactive downgrade, and runtime recreation", "safety.emergency_stale_instance", "./internal/safety", "TestEmergencyBackingReloadsAcrossInstancesAndNeverDowngradesToInactiveSlot/fresh_multi_instance_authority_and_no_runtime_recreate"),
		stepFixtureRow("S3", "R10.15.emergency_ambiguous_commit", "R10.15", "A lost emergency write acknowledgement poisons the writer and total slot corruption fails closed", "safety.emergency_ambiguous_commit", "./internal/safety", "TestEmergencyBackingRejectsTotalCorruptionAndPoisonsAmbiguousWriter/ambiguous_commit_poison_and_total_corruption"),

		fixtureRow("R10.10.atomic_ledger_rows", "R10.10", "The clause ledger rejects duplicate, malformed, and non-atomic rows", "qualification.atomic_ledger_rows", "./internal/qualification/cases", "TestLedgerContract/atomic_rows_validate"),
		fixtureRow("R10.10.parent_only_selectors", "R10.10", "Parent-only clause, scope, and test selectors are rejected", "qualification.parent_selectors_rejected", "./internal/qualification/cases", "TestLedgerContract/parent_only_selectors_are_rejected"),
		fixtureRow("R10.10.package_ownership", "R10.10", "Focused execution rejects a ledger package omitted from PKGS", "qualification.package_ownership", "./internal/qualification/cases", "TestRunnerContract/missing_package_is_rejected"),
		fixtureRow("R10.10.per_leaf_execution", "R10.10", "Focused execution requires and records one passing terminal event for every exact leaf", "qualification.per_leaf_execution", "./internal/qualification/cases", "TestRunnerContract/exact_leaf_execution_is_required_and_recorded"),
	}
	return rows
}

func fixtureRow(clauseID, requirement, behavior, caseID, pkg, test string) Row {
	return stepFixtureRow("S1", clauseID, requirement, behavior, caseID, pkg, test)
}

func stepFixtureRow(step, clauseID, requirement, behavior, caseID, pkg, test string) Row {
	return Row{
		SourceAnchor:     ".pi-work/requirements.md#" + requirement,
		ClauseID:         clauseID,
		Behavior:         behavior,
		ImplementingStep: step,
		CaseID:           caseID,
		Package:          pkg,
		Test:             test,
		Profile:          "local_go",
		Prerequisite:     "go_toolchain",
		Kind:             KindFixture,
		VerificationMode: VerificationTestAssertion,
		DeferRule:        DeferNever,
		SuccessStatus: StatusTriple{
			Preflight: PreflightNotApplicable,
			Gate:      GatePassed,
			Live:      LiveNotApplicable,
		},
	}
}
