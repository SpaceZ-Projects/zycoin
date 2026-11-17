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

Focused validation passed (**10 tests**) for current and historical roots,
unknown and malformed encodings, unavailable tree state, and the existing
zero-value conditional-anchor and production Spend satisfaction regressions.
Ruff `--select F`, `compileall`, `git diff --check`, and Pylance diagnostics
for the changed production files passed. The default targeted Ruff check
reported 21 existing findings, which were not changed.

## References and provenance

See the [independent Merkle verification report](sapling-merkle-reference-verification.md),
the [pinned fixture](../tests/fixtures/sapling_merkle_tree_reference.json),
and the [historical compatibility record](coin-registry-compatibility-audit.md).
