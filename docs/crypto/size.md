1. Why Standard CT Doesn't Work for Ortholog
In traditional Web PKI CT logs, the payload (an X.509 certificate) is usually only a few kilobytes. Embedding that directly into the Merkle tree leaf and distributing it via static tiles is easy.
However, Ortholog is built to handle complex threshold cryptography (PRE fragments, BLS cosignatures) and potentially massive sealed judicial artifacts (up to 1MB per entry, as configured in your operator.yaml).

If you embedded 1MB payloads directly into Tessera's Merkle tree:

You would instantly shatter the c2sp.org/tlog-tiles 64KB spec limit.

Tessera's storage costs (Spanner/Aurora) would skyrocket.

Distributing the log via CDN would become painfully slow and bandwidth-heavy.

2. The Solution: Hash-Only Tiles (The Dumb Vault)
By restricting the tessera-personality's POST /add endpoint to accept exactly 32 bytes (the canonical_hash), you achieve several massive wins:

Protocol Compatibility: Your tiles remain microscopic and perfectly compliant with the c2sp.org/tlog-tiles ecosystem.

Domain Opacity: As proof_adapter.go states, Tessera never sees the full data. It doesn't know if it's sequencing a PRE Grant, a court order, or a grocery list. It just sequences hashes.

Throughput: Tessera can sequence 32-byte arrays infinitely faster than it can parse and store megabyte-sized JSON envelopes.

3. The Tradeoff: The "Scanner Gap"
As you correctly noted, the tradeoff for this optimization is that an asynchronous Log Scanner (tailing the MinIO tiles) is now flying blind. It downloads a tile and just sees a list of cryptographic hashes. It cannot parse a SplitID, evaluate a SignerDID, or trigger an Equivocation Alert because it lacks the underlying bytes.

4. How the Network Must Adapt: The Dual-Fetch Model
Because of this constraint, your Log Scanners (and independent network auditors) must implement a Dual-Fetch Architecture:

Fetch the Trust (from Tessera/MinIO): The scanner tails the static, immutable tiles. This gives the scanner the undeniable, cryptographically verified order of events: "At Sequence 100, the hash was 0xABC..."

Fetch the Data (from the Operator/Object Store): To actually read the entry, the scanner must take that sequence number (or hash) and make a secondary call to the Operator's bulk storage layer (e.g., querying GET /v1/entries/100 or pulling directly from the persistent EntryWriter bucket).

Hydrate and Verify: The scanner downloads the full bytes, independently hashes them to ensure they match 0xABC, and then parses the SplitID to update its local read-replica.