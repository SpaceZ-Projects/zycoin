# Transparent derivation and address generation

## Purpose and scope

Record the BIP-44 derivation, configured address serialization, and coin/network
evidence available for the dynamic registry.

## Implemented functionality

Transparent keys derive from the shared BIP-39 seed using a network's
configured BIP-44 path. Address, script, and WIF serialization use configured
network parameters. Missing or unverified derivation paths fail closed rather
than being inferred.

## Findings and compatibility status

The Phase 9.10 audit covered all eight configured coin definitions and nine
networks. SLIP-0044 evidence supports coin types BitcoinZ 177, Flux 19167,
Zclassic 147, Zcash 133, Zero 323, and testnet type 1. Gemlink, KomodoClassic,
and ZeroClassic path identity remain unverified and derivation-gated.

Address parameter serialization was checked for every configured prefix and
compared with upstream chain parameters. BitcoinZ's serializer also matched
the recorded published P2PKH vector. However, the available evidence did not
include independent derived-address vectors for all configurations:
derivation is Partially Verified, while serialization is Verified for the
parameters exercised. Consult the [historical per-network results](coin-registry-compatibility-audit.md)
before interpreting status per coin.

## Verification and limitations

Derivation tests covered multiple accounts and address indices for supported
paths. A successful codec round-trip does not independently establish
parameter provenance. No unverified coin type or path is claimed supported.
Exact suite results and source provenance remain in the full record.

## References

See [transparent address usage](../docs/USER_GUIDE.md#bip-39-and-transparent-addresses),
the [coin registry report](coin-registry-and-network-compatibility.md), and
the [historical compatibility record](coin-registry-compatibility-audit.md).
