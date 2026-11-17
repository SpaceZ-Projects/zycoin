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

The gRPC service namespace is selected by the required
`lightwalletd.proto_package` setting on configured networks: `cash.bitcoinz`
for BitcoinZ and `cash.z` for Zcash. The client binds every method in the
checked-in `CompactTxStreamer` descriptor to that namespace while retaining
the existing protobuf message classes and serializers. This is service-path
routing only; it does not establish that the BitcoinZ service implements the
same protocol version or wire schema as the checked-in Zcash definitions.

## Findings and compatibility status

The audit recorded successful live Lightwalletd information/latest-block,
bounded transparent/Sapling scanning, `GetTaddressTransactions`, and
`GetTransaction` checks for BitcoinZ and Zcash mainnet. Twenty-block checks
previously recorded 14 BitcoinZ and 6 Zcash Sapling compact outputs. A
re-probe of the retained BitcoinZ range 1865913–1865932 returned 51 compact
outputs and 28 Sapling spends and retrieved a transaction at height 1865916.
Other configured networks lack Lightwalletd support or endpoints. Testnet has
no configured endpoint.

These are endpoint/functionality observations, not chain consensus
authentication. The exact endpoint/network statuses are retained in the
[per-network matrix](coin-registry-compatibility-audit.md).

## Sapling nullifier status

The pinned LWP v0.6.0 protocol defines `CompactTx.spends[].nf` and streams
shielded compact blocks through `GetBlockRange`. If `poolTypes` is empty, the
protocol specifies the legacy shielded-pool response; the scanner uses this
form to avoid depending on optional pool filtering. The protocol also defines
`GetBlockRangeNullifiers`, but marks it deprecated in favor of `GetBlockRange`.
Neither ZEC nor BTCZ's configured RPC lists declares the dedicated RPC; both
declare `GetBlockRange`.

The spent-status scanner verifies a full note-height-to-tip range, block/hash
continuity, and a stable reported tip. This establishes endpoint-reported
coverage only. ZEC's endpoint/compact-block capability remains unverified.
BTCZ compact Sapling fields are partially verified, but the live endpoint
does not report an LWP protocol version and reports zero Sapling tree sizes
even in output-bearing sampled blocks. Its spent-status result therefore
remains `UNKNOWN` before scanning. Even a complete scan would require explicit
caller trust for `UNSPENT`; no endpoint response is independent consensus
authentication. See the [BTCZ interoperability audit](btcz-lightwalletd-interoperability-audit.md).

The spent-status regressions exercise observed and absent nullifiers, full
versus incomplete ranges, protocol and capability rejection, malformed
responses, unavailable services, hash continuity, and stable-tip checks.
Their verification results are recorded in Phases 9.21.67–68 of the
authoritative Spend report.

## Limitations and verification

Ordinary compact scans do not establish note-tree positions. The full-tree
scanner requires activation-boundary, block-order/hash continuity,
per-block-tree-size, range-tip, and ending-block consistency checks; mocks
cover missing ranges and changed/reorganized responses. The BTCZ endpoint's
zero tree sizes fail the scanner's output-count consistency check. No live
endpoint was independently verified as a consensus source. Lightwalletd-
reported hashes and tree sizes are not cryptographic consensus proofs.

See the [Sapling tree and witness report](sapling-commitment-trees-and-witnesses.md)
and [historical compatibility record](coin-registry-compatibility-audit.md).

## References and provenance

Endpoint and RPC declarations are in the per-coin JSON under
[`src/coins/`](../src/coins/). BitcoinZ compact output evidence is retained in
[`tests/fixtures/btcz_mainnet_compact_output.json`](../tests/fixtures/btcz_mainnet_compact_output.json);
the historical record includes scan ranges and endpoint-reported fields.
The namespace-to-path mapping is covered by
[`tests/test_lightwalletd_routing.py`](../tests/test_lightwalletd_routing.py);
these local tests do not certify live endpoint protocol compatibility.

## Coin-specific service routing verification

The configured BitcoinZ mainnet service package is `cash.bitcoinz`, and
Zcash mainnet is `cash.z`. Missing packages on configured networks, malformed
or unsupported package names, and a Zcash namespace assigned to BitcoinZ (or
vice versa) are rejected during configuration validation. Direct client
construction also requires an explicit supported package. User-defined coins
remain supported when they explicitly select one of the recognized packages.

The client uses the existing `CompactTxStreamer` protobuf descriptor to bind
all 21 declared RPC methods under the selected service namespace. Message
classes, request serialization, and response deserialization remain the
checked-in Zcash-generated definitions; service-path routing does not prove
those definitions are wire-compatible with BitcoinZ.

The final focused run
`python -m pytest -q tests/test_lightwalletd_routing.py tests/test_coin_registry.py tests/test_sapling_spent_status.py`
passed **70 tests and 113 subtests**. The regressions verify both package
namespaces across all descriptor methods, explicit configuration validation,
the existing custom-coin discovery behavior, and preservation of configured
request timeout and protobuf serialization behavior. `compileall`,
Pylance diagnostics for the changed Python files, `git diff --check`, and
Ruff's `E4`, `E7`, `E9`, and `F` checks passed; the new routing test file also
passes full Ruff checks. The full Ruff run on existing implementation files
still reports unrelated pre-existing style findings, which were left
unchanged. No endpoint was probed as part of this routing-only change.
