// Package verifier — authority_evaluator_mutation_switches.go holds
// the Group 8.1 mutation-audit switches for the authority-snapshot
// shortcut and the classification loop in authority_evaluator.go.
// Declared in their own file so the audit-v775 runner's line-local
// rewrite can target exactly one declaration per gate.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the authority-chain walk's integrity  │
//	│  invariants. Setting any to false permanently re-opens one  │
//	│  of the three defects Group 8.1 closed:                     │
//	│                                                             │
//	│   • Constraint-laundering via the snapshot shortcut         │
//	│     (muEnableSnapshotMembershipValidation). Off skips       │
//	│     scopeMembershipValid for harvested entries, letting a   │
//	│     malicious authorized signer publish a snapshot whose    │
//	│     EvidencePointers reference fraudulent or historically   │
//	│     rejected entries and have them treated as active        │
//	│     constraints.                                            │
//	│                                                             │
//	│   • CPU exhaustion via unbounded snapshot evidence walk     │
//	│     (muEnableSnapshotEvidenceCap). Off lifts the 256-       │
//	│     pointer verifier-side cap, restoring the O(attacker-    │
//	│     chosen) walk the envelope writer's snapshot exemption   │
//	│     allows through admission.                               │
//	│                                                             │
//	│   • Dead classification-loop skip-guard                     │
//	│     (muEnableClassificationGuard). Off removes the          │
//	│     ConstraintUnclassified-gate from the classification     │
//	│     loop. The guard is load-bearing AFTER the enum shift    │
//	│     (Group 8.1 Defect 1): pre-classified entries must be    │
//	│     left alone; unclassified entries get classified.        │
//	│                                                             │
//	│   • Snapshot shape mis-recognition                          │
//	│     (muEnableSnapshotShapeCheck). Off admits non-snapshot   │
//	│     entries into the shortcut branch.                       │
//	│                                                             │
//	│   • Authority-chain cycle-visited map drops                 │
//	│     (muEnableAuthorityChainCycleGuard). Off lets corrupted  │
//	│     chains loop; the maxAuthorityChainDepth cap eventually  │
//	│     fires instead — catching a future developer accidental- │
//	│     ly removing the cycle guard.                            │
//	│                                                             │
//	│  The switches exist so the audit runner can flip them and   │
//	│  observe that the binding tests fire; any other use is      │
//	│  wrong.                                                     │
//	│                                                             │
//	│  Binding tests (verifier/authority_evaluator.mutation-audit.yaml): │
//	│    muEnableClassificationGuard          →                   │
//	│      TestEvaluateAuthority_ClassificationLoopGuardIsLoadBearing │
//	│    muEnableSnapshotMembershipValidation →                   │
//	│      TestEvaluateAuthority_SnapshotEvidenceMembershipValidated │
//	│    muEnableSnapshotEvidenceCap          →                   │
//	│      TestEvaluateAuthority_SnapshotEvidenceCapEnforced      │
//	│    muEnableSnapshotShapeCheck           →                   │
//	│      TestEvaluateAuthority_SnapshotShapeCheck_Binding       │
//	│    muEnableAuthorityChainCycleGuard     →                   │
//	│      TestEvaluateAuthority_CycleGuardIsLoadBearing          │
//	└─────────────────────────────────────────────────────────────┘
package verifier

// MaxSnapshotEvidencePointers caps the length of the EvidencePointers
// walk inside EvaluateAuthority's snapshot shortcut.
//
// The envelope writer exempts snapshot entries from the admission-time
// MaxEvidencePointers check (isAuthoritySnapshotShape in
// core/envelope/serialize.go), which is correct for admission
// semantics but means the verifier walks whatever length the snapshot
// claims. An authorized signer publishing a snapshot with, say,
// 500,000 evidence pointers would stall any downstream light client
// or node running EvaluateAuthority into an unbounded fetch-and-
// deserialize loop (OOM / CPU exhaustion).
//
// 256 is chosen to comfortably cover any realistic snapshot payload
// (the largest scopes observed in operation publish ≤20 active
// constraints) while still being a hard structural bound on the
// verifier-side walk. Exceeding the cap terminates the walk at the
// boundary.
const MaxSnapshotEvidencePointers = 256

// muEnableClassificationGuard gates the
// `if allEntries[i].State != ConstraintUnclassified { continue }`
// skip-guard at the head of the classification loop. After the
// Group 8.1 enum shift (ConstraintUnclassified = 0), this guard is
// load-bearing: entries the snapshot branch or other upstream logic
// has pre-classified must be left alone; entries left at the zero
// value (ConstraintUnclassified) must be classified. Off removes the
// guard and lets the classification loop overwrite every entry's
// State on each iteration, which in practice does not break the
// current walk (the only pre-classified path is snapshot entries,
// and re-classifying them is fine) but a future developer wiring
// additional pre-classification into the snapshot or walk branches
// needs the guard to ensure their pre-classification survives the
// loop.
const muEnableClassificationGuard = true

// muEnableSnapshotMembershipValidation gates the
// `scopeMembershipValid` call inside the classification loop for
// snapshot-harvested entries. After the Group 8.1 enum shift,
// snapshot-harvested entries arrive at the classification loop at
// ConstraintUnclassified and run through classifyConstraint and
// scopeMembershipValid on equal footing with chain-walked entries.
// An entry whose signer was NOT in the governing scope's
// AuthoritySet at the entry's admission position is reclassified
// as ConstraintOverridden and drops from the active constraint set.
// Off restores a code path that skips the membership check for
// harvested entries — the constraint-laundering exploit the
// structural fix exists to prevent. Binding test:
// TestEvaluateAuthority_SnapshotEvidenceMembershipValidated asserts
// laundering succeeds with the gate off and fails with it on.
const muEnableSnapshotMembershipValidation = true

// muEnableSnapshotEvidenceCap gates the MaxSnapshotEvidencePointers
// cap enforced inside EvaluateAuthority's snapshot branch. On
// (production), the snapshot walk terminates at MaxSnapshotEvidencePointers
// regardless of the admitted snapshot's declared EvidencePointers
// length. Off removes the cap and restores the O(attacker-chosen)
// walk the envelope writer's snapshot-exemption allows through
// admission.
const muEnableSnapshotEvidenceCap = true

// muEnableSnapshotShapeCheck gates the isAuthoritySnapshotEntry
// predicate's branch that admits an entry into the shortcut. On,
// only entries whose shape matches (Path C + TargetRoot +
// PriorAuthority + non-empty EvidencePointers) enter the shortcut.
// Off admits every entry into the shortcut branch — walked Path A
// or Path B entries would be treated as snapshots, erasing their
// chain-walk and membership checks. Binding test:
// TestEvaluateAuthority_SnapshotShapeCheck_Binding.
const muEnableSnapshotShapeCheck = true

// muEnableAuthorityChainCycleGuard gates the visited-position map
// check at the top of the authority-chain walk. On, a position
// already observed in the current walk terminates the loop (cycle
// detected). Off removes the cycle check and relies on
// maxAuthorityChainDepth to eventually terminate a corrupted chain.
// The binding test asserts the CYCLE guard catches a loop in fewer
// than maxAuthorityChainDepth iterations; with the gate off, the
// depth cap still fires but only after many more fetches and
// deserializes.
const muEnableAuthorityChainCycleGuard = true
