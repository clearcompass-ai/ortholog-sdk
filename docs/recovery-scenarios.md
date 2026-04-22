Based on the comprehensive architecture documents for both the **`recording-network`** and **`judicial-network`**, here are 5 distinct, real-world scenarios demonstrating how the Ortholog SDK's primitives handle complex, high-stakes workflows in practice. 



---

### Scenario 1: The "Record, Don't Index" Real Estate Closing (`recording-network`)
**The Context:** A family purchases a home in Davidson County. The title company submits a closing package containing a Warranty Deed and a Mortgage.
**The Execution:**
* **The Submission:** The Deputy Recorder verifies the notarization and formatting. The SDK encrypts the document images using standard AES-GCM (because these are public records, no Umbral PRE is needed). 
* **The Recording:** The SDK executes a batch `PublishArtifact` followed by a single atomic `BuildRootEntity` entry on the county's recordings log. The `Domain Payload` contains the unencrypted metadata: `grantor`, `grantee`, `parcel_id`, and the AES-encrypted `artifact_cids`.
* **The Result:** The log instantly provides an immutable inclusion proof and sequence number. The log *does not* index this parcel. Instead, external scrapers (like the Title Company's software) use `ScanFromPosition` to read the payload, spot the `parcel_id`, and update their own proprietary Chain of Title databases.

### Scenario 2: The Sealed Evidence Chain of Custody (`judicial-network`)
**The Context:** In a high-profile criminal case, a detective submits sensitive bodycam footage. It must be strictly sealed, accessible only to the judge and later the defense attorney.
**The Execution:**
* **The Protection:** The judicial network uses Umbral Proxy Re-Encryption (PRE). The SDK generates a *per-artifact delegation key* (`GenerateDelegationKey`) so the Master Key is never exposed. The footage is encrypted (`PRE_Encrypt`), generating a public `Capsule` and `ciphertext` stored on the log. 
* **The Grant:** Weeks later, the judge issues a court order granting the defense attorney access. The SDK evaluates `CheckGrantAuthorization` in "sealed" mode, verifying the defense attorney is on the explicit allowlist. 
* **The Result:** The network nodes use the KFrags to generate CFrags (re-encryption fragments) specifically for the defense attorney's public key. The defense attorney decrypts the footage locally. A `BuildCommentary` audit entry is permanently written to the log proving exactly when and to whom access was granted, establishing a cryptographically verifiable chain of custody.



### Scenario 3: The Tax Lien Attachment and Release (`recording-network`)
**The Context:** A property owner fails to pay property taxes, and the county attaches a tax lien to their parcel. Two years later, the owner pays the debt, and the lien must be released.
**The Execution:**
* **The Attachment:** The tax authority submits the lien. The SDK executes a `BuildEnforcement` (Path C) entry targeting the original deed's log position. The Sparse Merkle Tree (SMT) `Authority_Tip` advances. Any external indexer running `EvaluateAuthority` will now see a `ConstraintActive` flag indicating an active encumbrance.
* **The Release:** Once paid, a new `BuildEnforcement` entry is recorded referencing the lien release. The `Authority_Tip` advances again.
* **The Result:** The SDK's `EvaluateAuthority` now returns `ConstraintOverridden`. Because logs are append-only, the history of the lien and its subsequent release is preserved perfectly forever, but current queries reflect the clean title.

### Scenario 4: Cross-County Appellate Review (`judicial-network`)
**The Context:** A civil case judgment in a municipal court is appealed to a higher State Appellate Court. 
**The Execution:**
* **The Hierarchy:** Municipal courts anchor their logs to the County log, which anchors to the State log (`BuildAnchorEntry`). 
* **The Proof:** When the appellate judge reviews the case, the municipal court provides a `CrossLogProof`. The State Court SDK runs `VerifyCrossLogProof`. 
* **The Result:** Because both courts share the state-level anchor hierarchy, the appellate court can cryptographically verify that the lower court's judgment is authentic, unaltered, and properly sequenced *without* relying on a fragile API integration or centralized state database. 



### Scenario 5: Judicial Roster Sync and Officer Retirement (`judicial-network`)
**The Context:** A long-serving judge in a civil division retires, and a newly elected judge takes their place. The court's IT department updates the `officers.yaml` configuration file.
**The Execution:**
* **The Synchronization:** The deployment's automation runs the `roster_sync.go` service. It uses `QueryBySignerDID` to query the operator and SDK's `WalkDelegationTree` to map out the live cryptographic permissions of every officer.
* **The Reconciliation:** The SDK detects that the retired judge's DID is missing from the YAML but active on the log, so it automatically fires a `BuildRevocation` entry. It sees the new judge is in the YAML but not on the log, so it fires a `BuildDelegation` entry.
* **The Result:** The retired judge is instantly stripped of their cryptographic authority to sign new orders. The new judge is seamlessly granted authority. The institutional court identity (`did:web`) remains perfectly secure, and all historical rulings by the retired judge remain valid.