# Lightwalletd compatibility

## Purpose and scope

Record configured Lightwalletd endpoint availability, transparent and Sapling
compact scanning evidence, and the limits on endpoint-derived positions.

## Implemented functionality

The shared client supports configured RPCs for chain information, block
ranges, transparent transactions, and Sapling compact outputs. The scanner
can parse compact outputs and a separate full-range scan builds local
commitment-tree state with continuity checks. Partial compact scans do not
assign note positions.

## Findings and compatibility status

The audit recorded successful live Lightwalletd information/latest-block,
bounded transparent/Sapling scanning, `GetTaddressTransactions`, and
`GetTransaction` checks for BitcoinZ and Zcash mainnet. Twenty-block checks
returned 14 BitcoinZ and 6 Zcash Sapling compact outputs. BitcoinZ's bounded
real-chain scan returned 51 compact outputs over heights 1865913–1865932 and
retrieved a transaction at height 1865916. Other configured networks lack
Lightwalletd support or endpoints. Testnet has no configured endpoint.

These are endpoint/functionality observations, not chain consensus
authentication. The exact endpoint/network statuses are retained in the
[per-network matrix](coin-registry-compatibility-audit.md).

## Limitations and verification

Ordinary compact scans do not establish note-tree positions. The full-tree
scanner requires activation-boundary, block-order/hash continuity,
per-block-tree-size, range-tip, and ending-block consistency checks; mocks
cover missing ranges and changed/reorganized responses. No live endpoint was
independently verified as a consensus source. Lightwalletd-reported hashes and
tree sizes are not cryptographic consensus proofs.

See the [Sapling tree and witness report](sapling-commitment-trees-and-witnesses.md)
and [historical compatibility record](coin-registry-compatibility-audit.md).

## References and provenance

Endpoint and RPC declarations are in the per-coin JSON under
[`src/coins/`](../src/coins/). BitcoinZ compact output evidence is retained in
[`tests/fixtures/btcz_mainnet_compact_output.json`](../tests/fixtures/btcz_mainnet_compact_output.json);
the historical record includes scan ranges and endpoint-reported fields.
