Part 1: The Types of Identity Recovery (The "What")
Because the SDK supports different paradigms of identity, the outcome of a recovery changes depending on who you are.

1. Entity / Institutional Recovery (did:web)
The Concept: In-Place Succession. An institution (like a court) owns the domain. The identity outlives the key.

The Result: The identifier (did:web:court.gov#clerk) stays exactly the same. The institution simply updates their hosted did.json to point to a new public key and publishes a Succession Entry on the log. All historical signatures remain perfectly valid; only the key authorized to write new entries changes.

2. Individual Web3 Recovery (did:pkh)
The Concept: Transition via Mapping Escrow. For an Ethereum wallet, the cryptography is the identity. You cannot rotate a MetaMask key and keep the same address.

The Result: The user must create a brand-new wallet (did:pkh:...0xNew). They prove their real-world identity to network administrators, who decrypt their mapping_escrow to verify they owned 0xOld. The admins then publish a Succession Entry that mathematically links the new wallet to the old wallet's unbroken history.

3. Self-Certifying Ephemeral Recovery (did:key)
The Concept: No Recovery. * The Result: If you lose the private key to a did:key, the identity is permanently dead. There is no escrow, no governance, and no succession. You simply generate a new one and start over.

Part 2: The Mechanisms of Execution (The "How")
When a key is lost or stolen, how does the system authorize the Succession Entry to transition the identity? The SDK provides two mechanisms:

1. Cooperative Recovery (M-of-N Cryptographic Escrow)
Used for: Lost hardware tokens, forgotten passwords, or graceful staff transitions.

How it works: The user's master key was previously split using Pedersen VSS into N shares and encrypted using ECIES for N independent Escrow Nodes. During recovery, the user requests their shares back. If M nodes cooperate, the SDK decrypts the shares, mathematically reconstructs the original key, and seamlessly authorizes the succession to a new key.

2. Arbitrated / Hostile Recovery (Consensus Override)
Used for: Stolen keys, rogue employees, or catastrophic failure of the Escrow Nodes.

How it works: A monitoring node detects malicious behavior and publishes a Contest, instantly locking the compromised identity out of the system. The network administrators (the AuthoritySet) then vote. If a supermajority of administrators—plus an independent witness—cosign an Override, the SDK mathematically bypasses the escrow nodes, strips authority from the stolen key, and grants it to the legitimate owner's new key.

Part 3: The 5 System Layers of Recovery (The "Where")
A successful recovery doesn't just happen in a vacuum; it ripples through all five layers of the SDK's trust architecture. Here is how a recovery flows from the innermost cryptography to global federation.

Layer 1: The Origin Layer (Envelope Signatures)
What happens: The new key (or the network administrators, in the case of a hostile override) constructs a Succession or Override entry. This entry is hashed and signed using ECDSA or Ed25519.

Integrity Check: The admission gate verifies that the signature mathematically matches the entity authorized to execute the recovery (e.g., verifying the supermajority of admin signatures).

Layer 2: The Structural Layer (Merkle Inclusion & SMT)
What happens: The log operator appends the recovery entry to the ledger. Crucially, the Sparse Merkle Tree (SMT) state is updated.

Integrity Check: The log's AuthorityTip mathematically shifts. The old, compromised key is evicted from the SMT state, and the new key is recorded as the sole authority for that DID moving forward. Any future attempts by the old key to write to the log will result in an Optimistic Concurrency Control (OCC) rejection.

Layer 3: The Consensus Layer (Witness Cosignatures)
What happens: Independent witness nodes observe that the SMT state has changed to reflect the recovery.

Integrity Check: The witnesses use BLS12-381 (optimistic aggregation) or ECDSA to cosign the new log state. They mathematically attest: "We agree that Identity A has successfully transitioned to Key B according to the network's governance rules."

Layer 4: The Federated Layer (Cross-Log Proofs)
What happens: If the recovered user interacts with a foreign network (e.g., Court A sends a document to Court B), Court B needs to know the user's key was recovered.

Integrity Check: Court A bundles a Cross-Log Proof containing the SMT state and the witness cosignatures from Layer 3. Court B verifies this proof, inherently trusting the recovery without needing a centralized API call.

Layer 5: The Semantic & Transport Layer (Domain Rules & ECIES)
What happens: This layer protects the real-world data driving the recovery.

Integrity Check: If it was a Web3 (did:pkh) transition, this layer uses ECIES to safely transport and decrypt the mapping_escrow, proving the human behind the keyboard is the actual doctor or clerk they claim to be, satisfying the domain's strict business rules before the math is allowed to execute.