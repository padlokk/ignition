================================================================================
 🚦 IGNITION ROADMAP v1.0
================================================================================

Document Purpose: Translate IGNITE_CONCEPTS into an execution path with milestones, exit criteria, and story point budgets. Updated 2025-09-28.

--------------------------------------------------------------------------------
 PHASE 0 — Discovery Alignment (5 pts)
--------------------------------------------------------------------------------
Goal: Confirm shared understanding of ignition authority concepts and align stakeholders.

Milestone 0.1 — Concept Canon (2 pts)
  • Deliver IGNITE_CONCEPTS reference (terminology, lifecycle, invariants, recipient strategy).
  • Stakeholders sign off on definitions and security requirements.
  • Exit: Concept doc approved; open questions tracked.

Milestone 0.2 — Systems Inventory (3 pts)
  • Audit existing Cage modules leveraged by Ignite (CRUD, audit, error, recipient APIs).
  • Identify gaps (signatures, storage, env handling) for later phases.
  • Exit: Inventory report + dependency matrix appended to CONTINUE.md.

--------------------------------------------------------------------------------
 PHASE 1 — Authority Core (21 pts)
--------------------------------------------------------------------------------
Goal: Implement validated authority chain primitives and storage.

Milestone 1.1 — Data Model Concrete (8 pts)
  • Finalize `AuthorityChain`, `AuthorityKey`, metadata persistence format.
  • Implement storage adapters (filesystem vault MVP) with tamper evidence.
  • Align module tree with RSB `MODULE_SPEC` / `PRELUDE_POLICY`; document prelude exports.
  • Exit: Unit tests for chain operations; metadata hash checks pass.

Milestone 1.2 — Proof Engine Real (6 pts)
  • Replace mock signatures with Ed25519 (or chosen) cryptography using canonical JSON payloads.
  • Enforce proof expiry/renewal hooks; subject/authority checks wired; archive historical proofs.
  • Deliver confidence test suite covering tampering, expiry, replay scenarios.
  • Exit: Validation suite verifying allowed & disallowed pairs.

Milestone 1.3 — Passphrase Policy Enforcement (7 pts)
  • KDF selection (Argon2id) + configurable policy enforcement.
  • Danger-mode confirmations & env guardrails implemented.
  • Exit: Policy tests + CLI prompt UX signed off.

--------------------------------------------------------------------------------
 PHASE 2 — Ignition Operations (26 pts)
--------------------------------------------------------------------------------
Goal: Build end-to-end ignition key lifecycle flows on top of Cage/age recipient management.

Milestone 2.1 — Key Generation Pipeline (9 pts)
  • Wire `AuthorityAgeKeyGenerator` to storage + audit logging.
  • Record recipient set versions when keys are minted.
  • Add runtime guard ensuring `age` binary is available (friendly error).
  • Exit: Integration test creating X→M→R chain locally with recipient audit trail.

Milestone 2.2 — Rotation & Revocation (8 pts)
  • Cascade invalidation logic; tombstone registry; notifications stub.
  • Emit affected-keys manifest (fingerprint, md5, scope) so automation can repair artifacts.
  • Update recipient sets to drop revoked keys and trigger re-encryption where needed.
  • Exit: Tests covering rotation of M/R/I and enforcement of child invalidation.

Milestone 2.3 — Status & Discovery (9 pts)
  • `ignite ls`, `ignite status`, proof renewal reporting, recipient set inspection.
  • Admin CLI exposes proof verification (`ignite proof --verify`) for operator confidence.
  • Background job stub documenting future automation.
  • Exit: CLI smoke tests; docs updated for operators.

--------------------------------------------------------------------------------
 PHASE 3 — CLI & Integration (18 pts)
--------------------------------------------------------------------------------
Goal: Ship RSB-based CLI integrating authority operations with Cage.

Milestone 3.1 — CLI Surface (6 pts)
  • Implement RSB bootstrap + dispatch in `src/bin/cli_ignite.rs`.
  • Command handlers for create/rotate/revoke/ls/status invoked, plus developer test hooks (e.g., proof verify).
  • Exit: CLI help/inspect output validated.

Milestone 3.2 — Cage Bridge Hardening (6 pts)
  • Validate CRUD operations under authority and recipient constraints.
  • Ensure audit entries cross-link to key fingerprints and recipient set hashes.
  • Establish CLI smoke harness + ceremony integration per TEST_ORGANIZATION standard.
  • Exit: Integration tests using filesystem fixtures.

Milestone 3.3 — Automation Channels (6 pts)
  • Document env variable patterns; implement secret-manager shim.
  • Provide sample GitHub Actions / CI harness config using recipient-aware flows.
  • Exit: Example workflows run in dry-run mode.

--------------------------------------------------------------------------------
 PHASE 4 — Hardening & Release (14 pts)
--------------------------------------------------------------------------------
Goal: Production readiness with security sign-off and documentation.

Milestone 4.1 — Security Audit & Threat Drills (5 pts)
  • Run tabletop scenarios for key compromise & recovery.
  • Capture findings, adjust controls as required.
  • Exit: Audit report stored; issues filed.

Milestone 4.2 — Documentation & Training (4 pts)
  • Update operator guides, recovery runbooks, API docs.
  • Produce quick-start and troubleshooting appendices.
  • Exit: Docs reviewed by ops & security.

Milestone 4.3 — Release Cut & Handoff (5 pts)
  • Tag release candidate; ensure CI/CD pipelines green.
  • Handoff checklist completed in CONTINUE.md.
  • Exit: Ignite 0.1.0 tagged; adoption plan approved.

--------------------------------------------------------------------------------
 NEXT ACTIONS
--------------------------------------------------------------------------------
1. Populate TASKS.txt with story-point tickets mapped to milestones. (Done)
2. Clarify cryptographic choice (Milestone 1.2 dependency).
3. Define storage backend strategy and recipient scoping rules before starting Milestone 1.1/2.1.
