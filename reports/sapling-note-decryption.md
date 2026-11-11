# Sapling note decryption

## Purpose and scope

Record shared Sapling IVK/FVK trial decryption, ZIP-212 version selection, and
the evidence boundaries for chain-specific support.

## Implemented functionality

The shared implementation trials note decryption from incoming or full
viewing keys and checks the recovered note commitment. ZIP-212 configuration
selects v1/v2 behavior based on activation, grace period, and transaction
position/coinbase rules. This is decryption/scanning support, not note
creation or spending.

## Verification and compatibility status

The published Zcash v1 note-encryption fixture is decrypted and commitment
checked under Zcash and BitcoinZ configurations. It recovers the published
value, diversifier, plaintext prefix, and commitment. Synthetic tests exercise
ZIP-212 v2 and grace-period boundaries, IVK/FVK, wrong keys, malformed values,
and commitment mismatch. Synthetic results are not live-chain evidence.

BitcoinZ remains **Partially Verified**: a bounded live output was captured,
but no matching controlled key and independently known plaintext were
available. Zcash mainnet is **Partially Verified** for note decryption: v1
reference coverage exists, while no on-chain note/key pair or verified v2
fixture was recorded. Other networks remain Unverified or Unsupported in the
[per-network matrix](coin-registry-compatibility-audit.md).

## Limitations and provenance

The compact API supplies only the commitment, ephemeral key, and 52-byte
ciphertext prefix; it omits the AEAD tag/memo required for full authentication.
The BitcoinZ on-chain replay with an unrelated published IVK correctly returns
no note and is only a negative trial.

Reference provenance and exact fixture/height evidence are in the
[historical comparison and BitcoinZ live-chain record](coin-registry-compatibility-audit.md).
