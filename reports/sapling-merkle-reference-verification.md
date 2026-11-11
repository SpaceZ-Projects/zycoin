# Sapling Merkle reference verification

## Purpose and scope

Record independent upstream verification of Sapling MerkleCRH roots,
authentication paths, witness updates, and tree-capacity behavior.

## Reference implementation and provenance

Expected outputs were generated independently with upstream
`sapling-crypto` 0.9.0, revision
`88a7946b4a3066787776e11f0a502654167e022d`, and
`incrementalmerkletree` 0.9.0. MerkleCRH known-answer provenance is pinned to
`zcash-test-vectors` revision
`78321beacb0e0477e33cd002b56585a107c2708c`. The repository retains outputs
and metadata in
[`tests/fixtures/sapling_merkle_tree_reference.json`](../tests/fixtures/sapling_merkle_tree_reference.json).
The temporary Rust generator and Cargo files were removed to maintain the
Python-only project; the independent fixture and provenance remain.

## Findings and status

ZyCoin's depth-32 implementation matches the pinned MerkleCRH known-answer
vector and upstream roots for empty, one-, two-, three-, and four-leaf trees.
It matches upstream `IncrementalWitness` positions, anchors, and all 32
siblings for each leaf at tree sizes one through four, including sequential
updates. The independent comparison found and corrected a reversed level
personalization mapping. The upstream full-tree test confirms size `2^32`
and rejects an additional append; ZyCoin's guard covers that boundary without
performing billions of appends.

These offline reference comparisons are **Verified** for the listed input
sets. They do not authenticate live chain commitment ordering or anchors.

## Verification and limitations

The historical record lists the 45-test full-suite result for the witness
verification state and successful compile/package/clean-install checks.
Earlier validation stages had different counts; those are not combined into
a synthetic current count. No live Lightwalletd endpoint was used for the
independent tree phase. BitcoinZ spending remains gated.

See the [tree and witness report](sapling-commitment-trees-and-witnesses.md)
and [historical compatibility record](coin-registry-compatibility-audit.md)
for scanner behavior, exact upstream revisions, known-answer provenance, and
the retained fixture hash.
