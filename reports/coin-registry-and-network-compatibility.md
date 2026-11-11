# Coin registry and network compatibility

## Purpose and scope

Record dynamic discovery and compatibility findings for every configured coin
and network. The audit enumerated all eight JSON coin definitions and nine
networks as of 2026-11-02.

## Implemented functionality

The registry discovers and validates JSON configurations at runtime. Adding a
compatible coin requires a configuration file rather than a coin-specific
implementation module. Validation covers network/address parameters,
derivation templates and coin identity, endpoint consistency, and supported
Lightwalletd RPC declarations.

## Findings and compatibility status

The current per-network matrix and its status definitions are retained in the
[historical compatibility record](coin-registry-compatibility-audit.md).
The audit distinguishes Verified, Partially Verified, Unverified,
Unsupported, and Unavailable. A valid configuration or successful endpoint
connection alone does not establish protocol compatibility.

Confirmed configuration corrections include the BitcoinZ and Zcash
`GetTaddressTxids` RPC spelling and rejecting inferred BIP-44 paths when
configured path evidence is missing. Bitcore's explicit address-not-found 404
is normalized as an empty history; malformed responses fail explicitly.

## Verification and limitations

- CPython 3.10.11: the registry-specific test run recorded 11 passing tests.
- Later full-suite and packaging results are in the historical record; counts
  from different project states are preserved as historical, not presented
  as one current run.
- Eight configured coins do not mean eight fully compatible coins. Coin,
  network, capability, and endpoint statuses remain distinct.

## Sources and provenance

See the [full audit](coin-registry-compatibility-audit.md) for all network
tables, endpoint results, exact historical test counts, configuration
  provenance, and upstream references. The runtime configurations are JSON
  files under [`src/coins/`](../src/coins/).
