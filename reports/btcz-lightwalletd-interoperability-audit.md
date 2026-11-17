# BitcoinZ Lightwalletd Sapling interoperability audit

## Decision

BitcoinZ Lightwalletd Sapling compact blocks are **Partially Verified** for the
bounded operations tested below. End-to-end LWP v0.6.0 compatibility is
**Unverified**: the endpoint does not report `lightwalletProtocolVersion`,
because the matched BTCZ server source has no such protobuf field or response
assignment. The endpoint does return Sapling compact outputs and spend
nullifiers, but its compact-block Sapling tree sizes default to zero in the
sampled output-bearing blocks.

ZyCoin's spent-status API therefore remains fail-closed for this endpoint:
without a reported supported protocol version, it returns `UNKNOWN` before
requesting a block range. It must not infer `UNSPENT` from empty compact-block
data. No endpoint response is independently authenticated as consensus data.

## Evidence scope

The configured endpoint is `lightd.btcz.rocks:443`. Bounded read-only probes
used ZyCoin's existing gRPC client. The endpoint reported:

- chain `main`, Sapling activation height **328500**;
- server version `v1.1.1-inject-heartbeat`;
- Git commit prefix `5e3fd6f`;
- an empty `lightwalletProtocolVersion`;
- latest height **1875241** during the principal range probe.

The commit prefix matches
[z-bitcoinz/lightwalletd-bitcoinz commit
`5e3fd6f1f59917fd2e517098857070f689657285`](https://github.com/z-bitcoinz/lightwalletd-bitcoinz/commit/5e3fd6f1f59917fd2e517098857070f689657285).
That commit is unsigned on GitHub, and the endpoint's `gitCommit` is
self-reported; this identifies a matching public source revision but does not
attest the deployed binary.

The BitcoinZ Core source revision pinned in
[`src/coins/btcz.json`](../src/coins/btcz.json) is
[`a25305eec6cd18d4f5b61f67c655743503093b1f`](https://github.com/btcz/bitcoinz/commit/a25305eec6cd18d4f5b61f67c655743503093b1f).
The protocol comparison uses the pinned
[LWP v0.6.0 service definition](https://github.com/zcash/lightwallet-protocol/blob/299805c19011a027d2c48c5e912dd05041f76156/walletrpc/service.proto)
and [compact formats](https://github.com/zcash/lightwallet-protocol/blob/299805c19011a027d2c48c5e912dd05041f76156/walletrpc/compact_formats.proto).

## Capability matrix

| Capability | Status | Evidence and limitation |
|---|---|---|
| Endpoint reachability, `GetLightdInfo` | **Verified** | The configured TLS endpoint responded. `GetLightdInfo` reports chain, activation, software version, and commit prefix. |
| Configured gRPC service namespace | **Verified locally; endpoint compatibility unverified** | ZyCoin config selects `cash.bitcoinz`; local routing tests confirm every method path uses `/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/...`. This does not establish that the deployed endpoint implements the checked-in message schema or LWP v0.6.0. |
| LWP v0.6.0 version declaration | **Unverified** | The live `lightwalletProtocolVersion` is empty. The matched BTCZ `LightdInfo` proto ends at field 15 and the response constructor does not assign field 18. Software version is not a protocol version. |
| `GetLatestBlock` | **Verified for the probe** | Returned a 32-byte hash at height 1875241; a direct `GetBlock` at that height returned the same height and hash. |
| Inclusive `GetBlockRange` and block linkage | **Partially Verified** | Activation, historical-output, and tip ranges returned consecutive heights. Every adjacent `prevHash` matched the preceding block hash; predecessor links were checked for heights 1865913 and 1875239. This is bounded endpoint evidence, not consensus authentication. |
| Sapling compact output and spend fields | **Partially Verified** | Heights 1865913–1865932 returned 51 outputs and 28 spends. Sampled output fields were 32-byte `cmu`, 32-byte ephemeral key, and 52-byte ciphertext; sampled Sapling nullifiers were 32 bytes. This does not establish completeness for all heights. |
| Sapling compact tree-size metadata | **Unsupported for reliable size checks** | All 20 blocks in the output-bearing range reported size 0 despite 51 outputs; the refreshed tip window also reported zero with one Sapling output. The server decodes `trees.sapling.size` from verbose `getblock`, but pinned Core `blockToJSON` has no `trees` member; Go JSON unmarshalling leaves the nested `uint32` at its zero value. The server copies that zero into `ChainMetadata`; ZyCoin rejects the mismatch. |
| `GetTreeState` | **Partially Verified** | Direct read-only calls returned state at activation height 328500 and at tip height 1875242. The Sapling state strings were nonempty (6 and 748 hex characters respectively); state serialization and roots were not independently decoded or authenticated. This RPC is not declared in ZyCoin's configured BTCZ RPC list or client wrapper. |
| Sapling activation boundary | **Partially Verified** | The pinned Core `chainparams.cpp` activates both Overwinter and Sapling at 328500. `GetBlockRange(328500, 328502)` succeeded. `GetBlock(328499)` failed while parsing transaction 0 with `fOverwinter flag must be set`. The matched Lightwalletd parser explicitly rejects non-Overwintered transactions and versions below 4; this is a parser limitation at the pre-activation boundary, not evidence that the chain block is malformed. |
| `GetBlockRangeNullifiers` | **Unverified at the endpoint** | The matched server source defines the RPC, but ZyCoin does not configure or call it, and no live RPC probe was made. The scanner uses the ordinary `GetBlockRange`, whose sampled compact transactions include Sapling spends. |
| ElectrumZ nullifier/spent lookup | **Unsupported** | The inspected ElectrumZ server is a separate Electrum-protocol indexer with generic BitcoinZ block/transaction parsing; no LWP or Sapling nullifier-query path was found. It does not establish Sapling spent status. |
| Consensus authentication / trusted negative result | **Unsupported by these probes** | Reported hashes, block ranges, tree state, and nullifiers come from the endpoint. They are not independent header, consensus, or completeness proofs. |

## Wire and server behavior

The matched server source implements `GetLatestBlock` using BitcoinZ
`getblockchaininfo` and returns the best-chain height and hash. `GetBlockRange`
iterates the inclusive range. Its parser converts a block to compact form only
when a transaction has shielded elements, so an empty `vtx` is the protocol's
expected compact representation for a block with no Sapling/Orchard shielded
transaction. It does **not** mean the full block has no transparent
transactions or that absent data proves a note unspent.

For Sapling, the server parser serializes `CompactSaplingSpend.nf` and compact
output `cmu`, ephemeral key, and ciphertext prefix. The corresponding field
numbers and wire types are compatible with the pinned protocol's Sapling
compact fields. The server's checked-in `service.proto` identifies the package as
`cash.bitcoinz.wallet.sdk.rpc`, and its `BlockRange` contains only `start` and
`end` (no v0.6.0 `poolTypes` field). Its `LightdInfo` definition ends at field
15. The pinned Zcash LWP v0.6.0 schema instead defines `poolTypes` and
`lightwalletProtocolVersion` at field 18. The endpoint returns responses to
ZyCoin's standard Zcash service-path calls, but the BTCZ checked-in proto and
observed wire behavior do not establish full v0.6.0 conformance.

For tree sizes, `common.getBlockFromRPC()` unmarshals verbose BitcoinZ
`getblock` JSON into `BitcoinZRpcReplyGetblock1.Trees.Sapling.Size`, calls
`block.ToCompact()`, then assigns that value to
`ChainMetadata.SaplingCommitmentTreeSize`. Pinned BitcoinZ Core
`blockToJSON()` emits `finalsaplingroot` and `valuePools`, but does not emit a
`trees` JSON member. Because the Go field is a non-pointer `uint32`,
unmarshalling the missing nested field leaves it at zero; there is no
server-side error or fallback. The zero is then serialized into every compact
block from that RPC path. This precisely accounts for the live zero-size
observations.

The pinned Core does have a `z_gettreestate` RPC, which the BTCZ server calls
for `GetTreeState`; the server forwards the returned Sapling `FinalState`
string. That response is serialized tree state, not an explicit per-block
leaf-count field. Neither the checked-in Core `blockToJSON` JSON nor the
server's tree-state reply path exposes a verified integer that can safely be
copied into `ChainMetadata`. Recovering the size from the state would require
a protocol-correct decoder and focused Core/server tests; accumulating output
counts would require complete activation-to-height history and correct
reorg/cache handling. Neither method is implemented or independently
verified here. The exact size must not be inferred from the zero field,
compact block alone, or the tree-state string without that work.

## Spent-status consequence

`verify_sapling_note_spent_status()` requires an explicit Lightwalletd
protocol version of at least 0.6.0 before it requests the tip or block range.
This endpoint returns an empty version field, so the API returns `UNKNOWN`
without scanning, even if the caller opts into backend trust. This is
intentional fail-closed behavior; do not use the reported software version as
a substitute for LWP version. The scanner's `UNSPENT` outcome remains gated on
complete, stable coverage and explicit caller trust, and still would not be a
consensus-authenticated result.

No live transaction was submitted. No credentials were used. No prolonged
monitoring or full-chain scan was performed.

## Local regression evidence

The local suite now checks that BTCZ configuration reports partial compact
capability, that an endpoint response with the observed empty protocol-version
field produces `UNKNOWN` before tip/range access, and that BTCZ compact
protobuf fields survive serialization/parsing. Scanner regressions reject the
observed zero tree size, non-activation starting heights, malformed or
missing shielded metadata, and broken block-hash links. These are local
implementation tests; they are separate from the bounded live endpoint
observations above.
The final focused spent-status and coin-registry run passed **65 tests** and
**103 subtests**. This does not certify endpoint completeness or consensus
authenticity.

## Coin-specific service namespace routing

ZyCoin now configures BitcoinZ mainnet with `proto_package: "cash.bitcoinz"`.
The client binds all 21 methods in its existing `CompactTxStreamer` descriptor
to `/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/<Method>` while retaining
the checked-in protobuf message definitions. Local tests also assert Zcash's
`cash.z` path, reject missing, malformed, unsupported, or coin-mismatched
configuration, and preserve explicit namespace selection for custom coin
definitions. This verifies ZyCoin's local routing only; it does not establish
that the live BTCZ endpoint implements the checked-in message schema or LWP
v0.6.0.

The final focused run across routing, coin registry, and spent-status tests
passed **70 tests and 113 subtests**. BTCZ spent status remains fail-closed
when the endpoint does not report a supported protocol version. No live
endpoint check was performed for this routing change.

## Follow-up — root-cause trace and refreshed endpoint probe (2026-11-17)

### Protocol version path

The endpoint's reported `version` (`v1.1.1-inject-heartbeat`) is the server
build version, not the LWP version. In the matched BTCZ source:

1. `Makefile` sets linker variables for `common.Version`, `GitCommit`,
   `Branch`, `BuildDate`, and `BuildUser`; `Version` is generated from
   `git describe --tags`. There is no LWP-version build variable.
2. `walletrpc/service.proto` defines `LightdInfo` only through field 15
   (`donationAddress`). It has no field 18
   (`lightwalletProtocolVersion`).
3. `common.GetLightdInfo()` builds the response and sets the build fields,
   chain name, activation height, and tip data, but cannot assign the absent
   protocol field.
4. `frontend.GetLightdInfo()` returns that response unchanged. Protobuf
   serialization therefore omits field 18; a client generated from the
   official v0.6.0 schema reads its default empty string.

The pinned official
[LWP v0.6.0 `service.proto`](https://github.com/zcash/lightwallet-protocol/blob/299805c19011a027d2c48c5e912dd05041f76156/walletrpc/service.proto)
defines `lightwalletProtocolVersion = 18`; its
[compact format](https://github.com/zcash/lightwallet-protocol/blob/299805c19011a027d2c48c5e912dd05041f76156/walletrpc/compact_formats.proto)
defines the per-block Sapling commitment-tree size in
`ChainMetadata.saplingCommitmentTreeSize`. The BTCZ fork proto also lacks the
v0.6.0 `BlockRange.poolTypes` field, so the blank version is not merely an
unreported-but-otherwise-established compatibility claim. The software build
string must not be used to pass ZyCoin's protocol gate.

### Tree-size source path and safe-fix assessment

The causal server path is:

`bitcoinzd getblock(height, 1)` → JSON unmarshal into
`BitcoinZRpcReplyGetblock1.Trees.Sapling.Size` → raw block parse and
`block.ToCompact()` → overwrite
`ChainMetadata.SaplingCommitmentTreeSize` from that `Size` → gRPC response.

At pinned Core revision
[`a25305e`](https://github.com/btcz/bitcoinz/blob/a25305eec6cd18d4f5b61f67c655743503093b1f/src/rpc/blockchain.cpp),
`blockToJSON()` includes `finalsaplingroot` and `valuePools` but no nested
`trees` JSON member. Go's JSON decoder silently leaves the missing non-pointer
integer at zero, and Lightwalletd currently does not validate the missing
field before copying it. The zero is serialized as metadata; compact-block
serialization is not where it is lost.

Core's `z_gettreestate` is an available source of serialized tree state, and
the server's `GetTreeState` handler returns its `FinalState`. This means Core
has tree-state data from which a count might be reconstructible, but the
source path inspected does not expose a verified tree-size integer.
Extracting a count requires a separately verified parser for the precise
BitcoinZ tree-state encoding, or a server-maintained count with complete
activation history and reorg/cache correctness. Neither is established by
the available source or this ZyCoin repository. Accordingly, no server-side
code or tests were changed: this repository does not contain the Go server or
BitcoinZ Core, and a guessed tree size or a zero fallback is unsafe. The
upstream correction must add a tested, exact count source (preferably an
explicit Core RPC/JSON value or a protocol-correct tree-state decoder) and
reject missing metadata rather than default it. Server tests should cover
missing `trees`, exact known heights with and without Sapling outputs,
monotonic post-block sizes, and reorg/cache rebuild behavior before
deployment.

### Refreshed bounded live evidence

Read-only probes to `lightd.btcz.rocks:443` were repeated with a 12-second RPC
deadline and no credentials. On this run:

| Probe | Result |
|---|---|
| `GetLightdInfo` | `version=v1.1.1-inject-heartbeat`, `lightwalletProtocolVersion=""`, Sapling activation 328500, reported height 1875269, commit prefix `5e3fd6f`. |
| `GetLatestBlock` | Height 1875269, hash `9a85dcdc4917f401dc101d9e0f8da7cdc8409b2eeee4f3465292f09e53040000`. |
| Activation range 328500–328502 | 3 blocks; 0 Sapling outputs/spends; tree sizes `[0,0,0]`; all adjacent hash links matched. |
| Historical range 1865913–1865932 | 20 blocks; 51 outputs, 28 spends; every reported tree size was zero; all adjacent hash links matched. |
| Tip range 1875267–1875269 | 3 blocks; 1 output, 0 spends; all reported tree sizes zero; adjacent hash links matched. |
| `GetBlock(328499)` | Failed with `fOverwinter flag must be set`, consistent with the server parser's pre-activation limitation. |
| `GetTreeState(328500)` | Reply height was 328500; Sapling state string length 6 (`000000`). The returned hash was not independently cross-checked. |
| `GetTreeState(1875269)` | Reply height was 1875269; Sapling state string length 748. It was not decoded into a tree size or authenticated; the returned hash was not independently cross-checked. |

This refresh confirms the same blank protocol field and zero-size behavior
while the endpoint tip advanced from the earlier probe. Hash linkage and
the returned TreeState heights are endpoint consistency observations only,
not independent consensus authentication.

### Result and remaining gate

No safe correction can be applied in ZyCoin: both faults originate in the
external BTCZ server/Core integration. A server/Core change and its own
focused tests are required to populate LWP v0.6.0 metadata and supply exact
per-block tree sizes. Until then ZyCoin's scanner continues to reject
inconsistent tree sizes, and spent-status remains `UNKNOWN` because the
protocol version is unconfirmed.

**Validation:** the focused spent-status and BTCZ scanner regressions passed
**11 tests**. No BTCZ server/Core tests were run because those Go/C++ sources
are not part of this repository. No transactions, broadcasts, credentials,
or long-running monitoring were used.

### Source references

- [BTCZ Lightwalletd `Makefile`](https://github.com/z-bitcoinz/lightwalletd-bitcoinz/blob/5e3fd6f1f59917fd2e517098857070f689657285/Makefile) — build-time version variables.
- [BTCZ Lightwalletd `service.proto`](https://github.com/z-bitcoinz/lightwalletd-bitcoinz/blob/5e3fd6f1f59917fd2e517098857070f689657285/walletrpc/service.proto) — fork schema, `LightdInfo` fields, and range shape.
- [BTCZ Lightwalletd `common/common.go`](https://github.com/z-bitcoinz/lightwalletd-bitcoinz/blob/5e3fd6f1f59917fd2e517098857070f689657285/common/common.go) — `GetLightdInfo`, JSON structs, and compact metadata assignment.
- [BTCZ Lightwalletd `frontend/service.go`](https://github.com/z-bitcoinz/lightwalletd-bitcoinz/blob/5e3fd6f1f59917fd2e517098857070f689657285/frontend/service.go) — gRPC info response and `GetTreeState`.
- [BitcoinZ Core `blockchain.cpp`](https://github.com/btcz/bitcoinz/blob/a25305eec6cd18d4f5b61f67c655743503093b1f/src/rpc/blockchain.cpp) — pinned `blockToJSON()` output.
- [Official pinned LWP v0.6.0 service schema](https://github.com/zcash/lightwallet-protocol/blob/299805c19011a027d2c48c5e912dd05041f76156/walletrpc/service.proto) and [compact schema](https://github.com/zcash/lightwallet-protocol/blob/299805c19011a027d2c48c5e912dd05041f76156/walletrpc/compact_formats.proto).
- [Upstream Lightwalletd `common/common.go`](https://github.com/zcash/lightwalletd/blob/master/common/common.go) — reference implementation reports `LightwalletProtocolVersion` and copies Core tree sizes; this link is current source, not a pinned BTCZ deployment artifact.
