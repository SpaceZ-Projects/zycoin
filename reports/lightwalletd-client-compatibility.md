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
for BitcoinZ and `cash.z` for Zcash. The client selects a coin-specific
`CompactTxStreamer` descriptor and binds RPC paths from that descriptor.
Compatible BTCZ wire responses are converted to the existing public Zcash
message classes only after parsing with the BTCZ schema and discarding fields
unknown to that schema.

## Pinned LWP schema compatibility matrix

The comparison uses
[BTCZ `service.proto`](https://github.com/z-bitcoinz/lightwalletd-bitcoinz/blob/5e3fd6f1f59917fd2e517098857070f689657285/walletrpc/service.proto)
and
[BTCZ `compact_formats.proto`](https://github.com/z-bitcoinz/lightwalletd-bitcoinz/blob/5e3fd6f1f59917fd2e517098857070f689657285/walletrpc/compact_formats.proto),
compared with the pinned
[Zcash LWP v0.6.0 `service.proto`](https://github.com/zcash/lightwallet-protocol/blob/299805c19011a027d2c48c5e912dd05041f76156/walletrpc/service.proto)
and
[Zcash `compact_formats.proto`](https://github.com/zcash/lightwallet-protocol/blob/299805c19011a027d2c48c5e912dd05041f76156/walletrpc/compact_formats.proto).
Both definitions use proto3. Wire type 0 is varint; wire type 2 is
length-delimited. Proto3 scalar fields have no explicit presence and default to
zero, `false`, or the empty string/bytes; repeated fields default empty.
Singular message fields have presence. Repeated enums are packed as wire type 2
by default and are also decodable as unpacked wire type 0. Package names do
not affect field encoding.

### Service messages

| Message / field | BTCZ schema | Zcash v0.6.0 schema | Presence, wire type, and consequence |
|---|---|---|---|
| `BlockID.1` | `uint64 height` | Same | Scalar, wire 0; absent means 0. |
| `BlockID.2` | `bytes hash` | Same | Scalar, wire 2; absent means empty bytes. |
| `BlockRange.1` | `BlockID start` | Same | Message, wire 2; absent message is unset. |
| `BlockRange.2` | `BlockID end` | Same | Message, wire 2; absent message is unset. |
| `BlockRange.3` | Not defined | Repeated enum `PoolType poolTypes` | Packed wire 2 (enum values are varints); empty means server default. BTCZ cannot select pools from this field. |
| `TxFilter.1–3` | `BlockID block`, `uint64 index`, `bytes hash` | Same | Fields 1/2/3; wire 2/0/2. |
| `RawTransaction.1–2` | `bytes data`, `uint64 height` | Same | Fields 1/2; wire 2/0. Height 0 remains the proto3 default. |
| `SendResponse.1–2` | `int32 errorCode`, `string errorMessage` | Same | Fields 1/2; wire 0/2. |
| `LightdInfo.1` | `string version` | Same | Wire 2; default empty. |
| `LightdInfo.2` | `string vendor` | Same | Wire 2; default empty. |
| `LightdInfo.3` | `bool taddrSupport` | Same | Wire 0; default false. |
| `LightdInfo.4` | `string chainName` | Same | Wire 2; default empty. |
| `LightdInfo.5` | `uint64 saplingActivationHeight` | Same | Wire 0; default 0. |
| `LightdInfo.6` | `string consensusBranchId` | Same | Wire 2; default empty. |
| `LightdInfo.7` | `uint64 blockHeight` | Same | Wire 0; default 0. |
| `LightdInfo.8–11` | `string gitCommit`, `branch`, `buildDate`, `buildUser` | Same | Wire 2; each defaults empty. |
| `LightdInfo.12` | `uint64 estimatedHeight` | Same | Wire 0; default 0. |
| `LightdInfo.13–15` | `string zcashdBuild`, `zcashdSubversion`, `donationAddress` | Same | Wire 2; each defaults empty. |
| `LightdInfo.16` | Not defined | `string upgradeName` | Zcash-only, wire 2, default empty. |
| `LightdInfo.17` | Not defined | `uint64 upgradeHeight` | Zcash-only, wire 0, default 0. |
| `LightdInfo.18` | Not defined | `string lightwalletProtocolVersion` | Zcash-only, wire 2, default empty and no proto3 scalar presence. Absence or an unknown BTCZ field cannot prove LWP support. |
| `TransparentAddressBlockFilter.1–2` | `string address`, `BlockRange range` | Same | Wire 2/2; Zcash permits implementations to reject a nested nonempty `range.poolTypes`. ZyCoin rejects such BTCZ selectors before invoking gRPC. |
| `Duration.1` | `int64 intervalUs` | Same | Wire 0; default 0. |
| `PingResponse.1–2` | `int64 entry`, `int64 exit` | Same | Wire 0; both default 0. |
| `Address.1` | `string address` | Same | Wire 2; default empty. |
| `AddressList.1` | Repeated `string addresses` | Same | Wire 2 per value; defaults empty. |
| `Balance.1` | `int64 valueZat` | Same | Wire 0; default 0. |
| `Exclude.1` / `GetMempoolTxRequest.1` | Repeated `bytes txid` | Repeated `bytes exclude_txid_suffixes` | Wire 2 per value; both describe excluded txid suffixes and share field 1. BTCZ has no field 3. |
| `GetMempoolTxRequest.2–3` | Not defined | Field 2 reserved; field 3 repeated `PoolType poolTypes` | BTCZ request schema has no pool selector; ZyCoin rejects Zcash-only nonempty selectors. |
| `TreeState.1–6` | `string network`, `uint64 height`, `string hash`, `uint32 time`, `string saplingTree`, `string orchardTree` | Same | Wire 2/0/2/0/2/2; scalar defaults apply, and the tree strings are not authenticated by the schema. |
| `TreeState.7` | Not defined | `string ironwoodTree` | Zcash-only, wire 2, default empty. BTCZ conversion discards it. |
| `GetSubtreeRootsArg.1–3` | `uint32 startIndex`, enum `shieldedProtocol`, `uint32 maxEntries` | Same | Wire 0/0/0. BTCZ enum values are Sapling=0 and Orchard=1; Zcash adds Ironwood=2, which ZyCoin rejects for BTCZ. |
| `SubtreeRoot.2–4` | `bytes rootHash`, `bytes completingBlockHash`, `uint64 completingBlockHeight` | Same | Wire 2/2/0; field 1 is unused in both. |
| `GetAddressUtxosArg.1–3` | Repeated `string addresses`, `uint64 startHeight`, `uint32 maxEntries` | Same | Wire 2/0/0; repeated addresses default empty. |
| `GetAddressUtxosReply.1–6` | `bytes txid`, `int32 index`, `bytes script`, `int64 valueZat`, `uint64 height`, `string address` | Same | Wire 2/0/2/0/0/2; scalar defaults apply. |
| `GetAddressUtxosReplyList.1` | Repeated `GetAddressUtxosReply addressUtxos` | Same | Wire 2; defaults empty. |
| `StandardFee.1–2` / `GetStandardFee` | Message and RPC absent | `uint64 feeZat`, `uint32 estimatorVersion`; `GetStandardFee(Empty) -> StandardFee` | Zcash-only; the BTCZ descriptor does not bind this method. |
| `PoolType` enum | Not defined | `POOL_TYPE_INVALID=0`, `TRANSPARENT=1`, `SAPLING=2`, `ORCHARD=3`, `IRONWOOD=4` | Enum values are varints (wire 0); repeated fields normally use packed wire 2. |
| `ShieldedProtocol` enum | `sapling=0`, `orchard=1` | Same plus `ironwood=2` | Ironwood value 2 is not a supported BTCZ selector. |
| `ChainSpec`, `Empty` | No fields | Same | Empty messages serialize to zero bytes. |

### Compact formats

| Message / field | BTCZ schema | Zcash v0.6.0 schema | Presence, wire type, and consequence |
|---|---|---|---|
| `ChainMetadata.1–2` | `uint32 saplingCommitmentTreeSize`, `uint32 orchardCommitmentTreeSize` | Same | Wire 0; absent means 0. The value 0 is not accepted as consistent when Sapling outputs require a nonzero tree size. |
| `ChainMetadata.3` | Not defined | `uint32 ironwoodCommitmentTreeSize` | Zcash-only wire 0; discarded by BTCZ decoding. |
| `CompactBlock.1` | `uint32 protoVersion` | Reserved/removed | BTCZ wire 0, Zcash treats the tag as unknown. This is a compact-storage format field, not `lightwalletProtocolVersion`. |
| `CompactBlock.2–6` | `uint64 height`, `bytes hash`, `bytes prevHash`, `uint32 time`, `bytes header` | Same | Wire 0/2/2/0/2; proto3 defaults apply. BTCZ documents `header` as `(hash, prevHash, time)` or a full header; Zcash says it should be unset and, if used, contain the full header. Neither form authenticates the block. |
| `CompactBlock.7` | Repeated `CompactTx vtx` | Same | Wire 2; defaults empty. |
| `CompactBlock.8` | `ChainMetadata chainMetadata` | Same | Wire 2 with message presence. Missing metadata stays missing after conversion. |
| `CompactTx.1` | `uint64 index` | Same | Wire 0; default 0. |
| `CompactTx.2` | `bytes hash` | `bytes txid` | Both wire 2 and field 2. BTCZ describes the block-explorer hash; Zcash explicitly requires protocol order and no reversal. The adapter does not transform bytes, so this wire match alone does not establish semantic byte-order compatibility. |
| `CompactTx.3` | `uint32 fee` | Same | Wire 0; default 0. |
| `CompactTx.4–6` | Repeated Sapling spends, Sapling outputs, Orchard actions | Same | Wire 2; defaults empty. |
| `CompactTx.7–8` | Not defined | Repeated `CompactTxIn vin`, `TxOut vout` | Zcash-only wire 2. BTCZ compact transactions are shielded-only; these tags are discarded rather than represented as empty transparent data. |
| `CompactTx.9` | Not defined | Repeated `CompactOrchardAction ironwoodActions` | Zcash-only wire 2; discarded by BTCZ decoding. |
| `CompactTxIn.1–2` | Message absent | `bytes prevoutTxid`, `uint32 prevoutIndex` | Zcash-only, wire 2/0. |
| `TxOut.1–2` | Message absent | `uint64 value`, `bytes scriptPubKey` | Zcash-only, wire 0/2. |
| `CompactSaplingSpend.1` | `bytes nf` | Same | Wire 2; default empty. Both schemas represent the Sapling nullifier in this field. |
| `CompactSaplingOutput.1–3` | `bytes cmu`, `bytes ephemeralKey`, `bytes ciphertext` | Same | Wire 2; same field numbers and meanings (32-byte `cmu`, 32-byte key, 52-byte ciphertext prefix are semantic validations, not protobuf length rules). |
| `CompactOrchardAction.1–4` | `bytes nullifier`, `bytes cmx`, `bytes ephemeralKey`, `bytes ciphertext` | Same | Wire 2; same field numbers and documented meanings. |

### RPC names and signatures

Both services use the same path suffix and streaming cardinality for the 20
common RPCs below. Message package names differ. Only `GetMempoolTx` has a
different request message name; its field-1 repeated bytes representation is
wire-compatible. BTCZ has no `GetStandardFee`.

| RPC | BTCZ request → response | Zcash request → response | Cardinality |
|---|---|---|---|
| `GetLatestBlock` | `ChainSpec → BlockID` | Same | Unary → unary |
| `GetBlock` | `BlockID → CompactBlock` | Same | Unary → unary |
| `GetBlockNullifiers` | `BlockID → CompactBlock` | Same | Unary → unary |
| `GetBlockRange` | `BlockRange → CompactBlock` | Same | Unary → stream |
| `GetBlockRangeNullifiers` | `BlockRange → CompactBlock` | Same | Unary → stream |
| `GetTransaction` | `TxFilter → RawTransaction` | Same | Unary → unary |
| `SendTransaction` | `RawTransaction → SendResponse` | Same | Unary → unary |
| `GetTaddressTxids` | `TransparentAddressBlockFilter → RawTransaction` | Same | Unary → stream |
| `GetTaddressTransactions` | `TransparentAddressBlockFilter → RawTransaction` | Same | Unary → stream |
| `GetTaddressBalance` | `AddressList → Balance` | Same | Unary → unary |
| `GetTaddressBalanceStream` | `Address → Balance` | Same | Client stream → unary |
| `GetMempoolTx` | `Exclude → CompactTx` | `GetMempoolTxRequest → CompactTx` | Unary → stream |
| `GetMempoolStream` | `Empty → RawTransaction` | Same | Unary → stream |
| `GetTreeState` | `BlockID → TreeState` | Same | Unary → unary |
| `GetLatestTreeState` | `Empty → TreeState` | Same | Unary → unary |
| `GetSubtreeRoots` | `GetSubtreeRootsArg → SubtreeRoot` | Same | Unary → stream |
| `GetAddressUtxos` | `GetAddressUtxosArg → GetAddressUtxosReplyList` | Same | Unary → unary |
| `GetAddressUtxosStream` | `GetAddressUtxosArg → GetAddressUtxosReply` | Same | Unary → stream |
| `GetLightdInfo` | `Empty → LightdInfo` | Same | Unary → unary |
| `Ping` | `Duration → PingResponse` | Same | Unary → unary |
| `GetStandardFee` | Absent | `Empty → StandardFee` | Zcash only |

### Adapter behavior and limits

The checked-in BTCZ `.proto` files and generated descriptors pin the BTCZ
message/RPC schema separately from Zcash. For BTCZ calls, requests are parsed
through BTCZ descriptors before serialization; responses are parsed through
BTCZ descriptors, unknown fields are discarded, then shared wire-compatible
fields are converted to the existing public Zcash message classes. This
prevents an unknown BTCZ field 18 from being exposed as
`lightwalletProtocolVersion`, and prevents Zcash-only `vin`, `vout`, Ironwood,
or metadata fields from being misread as BTCZ data.

The public Sapling range adapter converts exactly `[SAPLING]` to BTCZ's
default shielded-only range, a safe superset based on the pinned BTCZ compact
block implementation. Other nonempty pool selectors, nested transparent
range selectors, `GetMempoolTx.poolTypes`, and the Zcash-only Ironwood subtree
selector fail with `LightwalletdCapabilityError`. The BTCZ descriptor does
not bind `GetStandardFee`. No adapter creates Sapling tree-size metadata or
relaxes existing scanner checks.

The shared RPC signatures do not imply identical response semantics.
Zcash's `GetBlock` may include transparent `vin`/`vout` fields; BTCZ compact
transactions are shielded-only and have no corresponding fields. Zcash's
`GetBlockRange` supports pool pruning, while BTCZ has no selector field and
returns its legacy shielded compact data. The pinned Zcash schema marks
`GetBlockNullifiers` and `GetBlockRangeNullifiers` deprecated; these methods
are not used to establish spent-status coverage. Zcash also defines
Ironwood-specific selectors and fields that the BTCZ descriptor cannot
represent.

The literal wire vectors in
[`tests/fixtures/lightwalletd_schema_wire_vectors.json`](../tests/fixtures/lightwalletd_schema_wire_vectors.json)
come from the pinned field numbers and are not endpoint responses. Schema
conversion tests cover protocol-version field 18, poolTypes, BTCZ's
`protoVersion`, the CompactTx field-2 alias, Sapling fields, TreeState, unknown
fields, malformed wire data, and unsupported RPC/request capabilities.

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

## Coin-specific service and schema compatibility verification

The configured BitcoinZ mainnet service package is `cash.bitcoinz`, and
Zcash mainnet is `cash.z`. Missing packages on configured networks, malformed
or unsupported package names, and a Zcash namespace assigned to BitcoinZ (or
vice versa) are rejected during configuration validation. Direct client
construction also requires an explicit supported package. User-defined coins
remain supported when they explicitly select one of the recognized packages.

The client selects the pinned BTCZ schema (20 RPCs) or Zcash schema (21 RPCs),
and constructs method paths from that service descriptor. For BTCZ calls,
requests and responses are decoded with BTCZ message types; supported common
fields are converted by wire format to existing public Zcash message classes.
The BTCZ adapter strips unknown fields, so `LightdInfo` field 18 cannot be
mistaken for a server-reported protocol version. Unsupported Zcash-only
selectors fail explicitly. The complete field and RPC matrix above is the
compatibility record; it does not establish that a live endpoint implements
either pinned descriptor.

The focused post-schema run
`.venv\Scripts\python.exe -m pytest -q tests\test_lightwalletd_routing.py tests\test_coin_registry.py tests\test_sapling_spent_status.py`
passed **76 tests and 135 subtests**. It covers namespace configuration,
every per-coin RPC path, descriptor and wire-field differences, unknown and
malformed fields, Sapling range adaptation, compact Sapling/TreeState
conversion, missing tree metadata, and the existing fail-closed spent-status
gate. This is local schema/routing evidence only. No live endpoint was probed
through the new `cash.bitcoinz` service path for this schema task, and neither
these tests nor the prior endpoint responses constitute consensus
authentication.

Static validation passed: `compileall`, targeted Ruff correctness checks on
the changed handwritten Python and full Ruff checks on the routing tests,
Pylance diagnostics for those changed Python files, generated-file syntax
checks, and `git diff --check`. Pylance reported no diagnostics in the
handwritten files; it emitted only unused-symbol hints in standard generated
protobuf boilerplate. The generated descriptors were also imported and
exercised with protobuf 4.25.3, the declared minimum runtime.
