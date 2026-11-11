# Sapling nullifier derivation

## Purpose and scope

Record the pure-Python Sapling nullifier derivation and its key, note, and
position evidence. Nullifier derivation is separate from transaction signing.

## Implemented functionality

The implementation derives the required nullifier key component from ZIP32,
reconstructs the note commitment point from validated note data, combines it
with the note-position base and supplied global note-tree position, and
applies the Sapling `Zcash_nf` BLAKE2s PRF.

## Verification and status

Tests validate the `nk` derived from ZIP32 components and match all ten
expected `note_nf` values in the pinned upstream
`sapling_key_components.json` vectors. V1 and v2 notes are accepted only from
commitment-checked decrypted note objects. Invalid key types and note
positions are rejected as covered by the implementation's test record.
Nullifier derivation is **Implemented, Verified** against these upstream
vectors; this does not verify scanner position provenance.

## Limitations

Compact spend records include chain nullifiers, but scanner matching of those
nullifiers to locally derived notes is **Missing**. A correct nullifier
requires the correct global note-tree position. BitcoinZ spending remains
gated on its unverified ZIP32 account path; nullifier vectors do not establish
spendability.

## Sources and verification record

Pinned upstream source:
[Zcash Sapling key-component vectors](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/test-vectors/json/sapling_key_components.json).
The local fixture is
[`tests/fixtures/sapling_nullifier_reference.json`](../tests/fixtures/sapling_nullifier_reference.json).
See the [historical compatibility record](coin-registry-compatibility-audit.md)
for broader Sapling statuses and test counts.
