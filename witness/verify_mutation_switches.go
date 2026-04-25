// Package witness — verify_mutation_switches.go holds the ADR-005
// §6 mutation-audit switch for witness/verify.go. Declared in its
// own file so the audit-v775 runner's line-local rewrite can target
// exactly one declaration.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the three structural checks inside   │
//	│  VerifyTreeHead: quorum-count pre-check, per-signer         │
//	│  uniqueness, and witness-key set membership. Setting any to │
//	│  false permanently admits a class of witness-cosignature    │
//	│  forgery:                                                   │
//	│                                                             │
//	│   • muEnableWitnessQuorumCount — structural quorum gate     │
//	│     (Group 6.1). Off lets undersized witness sets slip      │
//	│     past the early pre-check.                               │
//	│                                                             │
//	│   • muEnableUniqueSigners — per-signer deduplication        │
//	│     (Group 8.3). Off lets a single signer's cosignature     │
//	│     appearing multiple times in head.Signatures count       │
//	│     multiple times toward quorum.                           │
//	│                                                             │
//	│   • muEnableWitnessKeyMembership — defensive key-set        │
//	│     membership (Group 8.3). Off admits successful           │
//	│     signatures whose PubKeyID is not in the caller-         │
//	│     supplied witness key set. (Phase 1 already rejects      │
//	│     unknown-key signatures at the primitive layer; this     │
//	│     gate is defense-in-depth at the witness layer against   │
//	│     future Phase-1 refactors that might relax the check.)   │
//	│                                                             │
//	│  Binding tests (witness/verify.mutation-audit.yaml):        │
//	│    muEnableWitnessQuorumCount    →                          │
//	│      TestWitnessQuorumCount_Binding                         │
//	│    muEnableUniqueSigners         →                          │
//	│      TestWitnessUniqueSigners_Binding                       │
//	│    muEnableWitnessKeyMembership  →                          │
//	│      TestWitnessKeyMembership_Binding                       │
//	└─────────────────────────────────────────────────────────────┘
package witness

// muEnableWitnessQuorumCount gates the (len(witnessKeys) < quorumK)
// pre-check inside VerifyTreeHead. When true (production), the gate
// rejects with a specific "witness set size %d < quorum %d" error
// before any cryptographic verification runs. When false, the
// pre-check is removed and undersized witness sets fall through to
// the Phase-1 primitive — which may return a less-specific error
// or silently accept the operation depending on signature shape.
const muEnableWitnessQuorumCount = true

// muEnableUniqueSigners gates the post-verify uniqueness check
// inside VerifyTreeHead: no single witness signer's cosignature may
// count more than once toward quorum. On (production), a head that
// repeats the same PubKeyID across multiple Signatures entries
// returns ErrInsufficientWitnesses once duplicates are deduplicated
// below K. Off, repeats count individually — an attacker who
// obtains one valid cosignature could replay it to satisfy K-of-N
// with a single key.
const muEnableUniqueSigners = true

// muEnableWitnessKeyMembership gates the defensive post-verify
// membership check: every successful signature's PubKeyID MUST be
// in the caller-supplied witness key set. On (production), a
// signature whose PubKeyID is outside the provided set is rejected
// even if the underlying Phase-1 primitive accepted it. Off, the
// membership check short-circuits — Phase 1 already performs the
// lookup today, so in practice the gate asserts defense-in-depth
// against future Phase-1 refactors that might relax the check.
const muEnableWitnessKeyMembership = true
