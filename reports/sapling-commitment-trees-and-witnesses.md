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
ending-block stability.

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
spendability claim follows from a local valid witness or anchor.

## References and provenance

See the [independent Merkle verification report](sapling-merkle-reference-verification.md),
the [pinned fixture](../tests/fixtures/sapling_merkle_tree_reference.json),
and the [historical compatibility record](coin-registry-compatibility-audit.md).
