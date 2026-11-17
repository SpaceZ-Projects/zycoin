# Sapling commitment trees and witnesses

## Purpose and scope

Record local Sapling commitment-tree, note-position, authentication-path,
witness-update, and scanner integration behavior.

## Implemented functionality

The shared depth-32 tree supports validated commitment appends, roots,
positions, witnesses, authentication paths, and incremental witness updates.
Paths reconstruct their recorded local anchors. The scanner's full-tree mode
checks configured activation boundary, ordered compact transactions,
contiguous block hashes, per-block tree sizes, tip/range continuity, and
ending-block stability. `SaplingCommitmentTree.require_root_in_history()` and
`SaplingTreeScanResult.validate_spend_anchor()` reject malformed roots and
anchors absent from the locally retained root history. The scan result also
checks each generated witness anchor before returning it.
`validate_sapling_spend_witness(witness, tree_state)` additionally consumes a
Spend witness and explicit full-scan context, checking witness host
preconditions, selected note/position consistency, the computed authentication
path root, and the declared anchor without changing R1CS state.

## Verification and compatibility status

Offline tree and witness behavior matches the pinned upstream results for
empty through four-leaf trees. Every leaf position in tree sizes one through
four has matching anchors and 32 siblings, including witness updates. Tests
cover reordered/omitted commitments, corrupted paths, wrong roots, invalid
positions, historical-root divergence, and the full `2^32` capacity boundary.
These results verify local tree mechanics, not consensus correctness of a
caller-supplied ordering.

The offline tree/witness implementation is **Verified** against its retained
reference fixture. Lightwalletd-derived positions and integration are
**Partially Verified**: scanner consistency tests are mocked; endpoint
metadata is not independent consensus evidence. External anchor
authentication and spendability remain **Unverified**.

## Limitations

Transaction/output indices are not Sapling note positions. Partial compact
scans never receive positions. The full scan derives order from endpoint
compact blocks and cannot independently authenticate chain state. No
spendability claim follows from a local valid witness or anchor. The tree
retains every prefix root and implements no expiry or bounded anchor window;
any root still in that history passes local membership validation. This is
not evidence that a root is accepted by consensus. Sapling transaction
construction, serialization, proving, and broadcast do not exist, so the
preflight is not yet wired to a transaction output boundary. A future
builder must call the scan-result guard before serialization or proving.
Circuit-level conditional-anchor semantics, including zero-value behavior,
remain unchanged.

### Spend anchor membership preflight

The tree-level `require_root_in_history(root)` checks canonical 32-byte field
encoding and membership in the tree's retained roots. The tree-aware
`SaplingTreeScanResult.validate_spend_anchor(anchor)` exposes this as a
transaction preflight and fails explicitly if the tree state is unavailable.
It accepts the current root and any historical prefix root still retained;
there is no stale-root expiry policy in the current tree implementation.
Unknown or malformed roots are rejected before this helper returns. The
scanner's witness-selection path also validates its generated anchor. These
checks have no transaction serialization or proving side effects because
those Sapling transaction APIs are not implemented.

The Spend validator reuses the production `_prepare_witness` checks for
scalar/point encodings, IVK and identity transmission key, value and note
commitments, path structure and conditional anchor semantics, public inputs,
and nullifier consistency. It additionally requires a scan result beginning
at activation, a current root consistent with the tree, output count matching
tree size, and the selected note commitment at the requested position. It
checks the path-computed root and declared anchor independently against the
retained history. For zero value they may differ, preserving the circuit's
conditional relation, while both still need local root membership.

Focused validation and regression passed (**15 tests**) for current and
historical roots,
unknown and malformed encodings, unavailable tree state, and the existing
zero-value conditional-anchor and production Spend satisfaction regressions.
Targeted Ruff, `compileall`, `git diff --check`, and Pylance diagnostics for
the changed source, facade, and test files passed with no diagnostics.

## References and provenance

See the [independent Merkle verification report](sapling-merkle-reference-verification.md),
the [pinned fixture](../tests/fixtures/sapling_merkle_tree_reference.json),
and the [historical compatibility record](coin-registry-compatibility-audit.md).
