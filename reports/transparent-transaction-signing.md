# Transparent transaction construction and signing

## Purpose and scope

Record the offline transparent transaction API and its deliberately narrow
coin/network compatibility gate.

## Implemented functionality

The public API includes `TransparentInput`, `TransparentOutput`,
`UnsignedTransparentTransaction`, `SignedTransparentTransaction`,
`create_unsigned_transaction`, `sign_transaction`,
`verify_transaction_signatures`, and `zip243_signature_hash`. The enabled
subset is BitcoinZ mainnet P2PKH with Overwintered v4, ZIP-243, configured
Canopy branch ID, compressed BIP-44 keys, and `SIGHASH_ALL`. Input/output
ordering is preserved and fees are explicit.

## Verification and status

All 10 upstream ZIP-243 reference sighash cases pass. Deterministic synthetic
single- and multi-input P2PKH tests exercise construction, serialization,
signing, verification, fee/order rules, and tamper rejection. BitcoinZ status
remains **Partially Verified**: no independent complete signed-transaction
vector or live wallet comparison was recorded. Other coin/network signing
combinations remain **Unsupported**.

## Limitations

The builder does not select UTXOs, estimate fees, or generate change.
Sapling, JoinSplits, P2SH inputs, other hash types/formats, and broadcasting
are unsupported. The API fails closed when signing parameters or verified
derivation/address parameters are missing.

## Verification record and sources

The 10 upstream digest vectors are retained in
[`tests/fixtures/zip243_reference.json`](../tests/fixtures/zip243_reference.json).
Python 3.10.11 validation recorded 34 passing tests and successful
`compileall`; wheel/sdist and clean-wheel API/resource checks passed. The full
coin matrix and test context remain in the
[historical compatibility record](coin-registry-compatibility-audit.md).
