# BIP-39 mnemonic and seed handling

## Purpose and scope

Document recovery phrase validation and the shared seed input used for
transparent BIP-44 and Sapling ZIP32 derivation.

## Implemented functionality

The documented public API generates and validates 24-word English BIP-39
phrases and derives the standard 64-byte seed with an optional passphrase.
Transparent and Sapling branches can use the same seed while following their
separate purpose-specific derivation schemes.

## Verification and status

The guide's BIP-39 example was executed against the installed package in the
recorded documentation validation. Seed use is exercised in the transparent
and ZIP32 derivation flows; historical suite counts and wheel checks are
preserved in the [historical compatibility record](coin-registry-compatibility-audit.md).
No separate BIP-39 vector count or standalone mnemonic-specific test result
was recorded in the available reports; no stronger verification claim is
made here.

**Compatibility status:** implementation and example usage are documented
and exercised as part of package validation. Standalone mnemonic/vector
compatibility is **Unverified in the retained report evidence**.

## Limitations and security

The phrase, optional passphrase, seed, and derived keys are secret wallet
material. Documentation uses generated examples only. Python does not
guarantee secret zeroization; do not print, log, commit, or send production
recovery material.

## References

See [BIP-39 and transparent addresses in the user guide](../docs/USER_GUIDE.md#bip-39-and-transparent-addresses)
and the [historical compatibility record](coin-registry-compatibility-audit.md).
