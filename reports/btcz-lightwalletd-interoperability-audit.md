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

## Coin-specific service namespace routing (previous milestone)

ZyCoin now configures BitcoinZ mainnet with `proto_package: "cash.bitcoinz"`.
The earlier namespace-only client bound 21 methods from one descriptor to
`/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/<Method>`. That routing-only
implementation has since been replaced by per-coin descriptors; its test
count below is historical and is superseded by the schema-aware results at
the end of this report.

At that routing-only milestone, the focused run passed 70 tests and 113
subtests. BTCZ spent status remained fail-closed when the endpoint did not
report a supported protocol version. No endpoint check was performed for that
routing change.

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

## Schema-aware client implementation and verification (2026-11-17)

The client now uses separate checked-in descriptors generated from the pinned
BTCZ and Zcash LWP definitions. The full field-number, wire-type, default and
presence, RPC-signature, and cardinality comparison is in the
[Lightwalletd compatibility matrix](lightwalletd-client-compatibility.md#pinned-lwp-schema-compatibility-matrix).
Source versions are BTCZ Lightwalletd
`5e3fd6f1f59917fd2e517098857070f689657285` and Zcash LWP v0.6.0
`299805c19011a027d2c48c5e912dd05041f76156`.

The local descriptor comparison establishes 20 BTCZ RPCs versus 21 Zcash
RPCs; BTCZ has no `GetStandardFee`. BTCZ `LightdInfo` ends at field 15
(versus Zcash fields 16–18), and BTCZ `BlockRange` has only `start` and `end`
(versus Zcash's repeated `poolTypes` at field 3). The compact schemas share
Sapling spend/output fields, but BTCZ `CompactBlock.protoVersion` is field 1
where Zcash reserves that tag; BTCZ `CompactTx.hash` and Zcash `txid` are both
field-2 bytes. Zcash adds transparent `vin`/`vout`, Ironwood compact metadata,
and Ironwood tree-state fields. These differences are represented by distinct
descriptors rather than inferred from the package name.

For BTCZ, the client parses responses with the BTCZ descriptor before
discarding unknown fields and converting shared wire-compatible content to
the public message classes. Thus a field-18 byte sequence cannot manufacture
a Lightwalletd protocol version. Requests with unsupported pool selectors or
Ironwood subtree selection fail explicitly. A Sapling-only `GetBlockRange`
request is translated to BTCZ's default shielded range; no other selector is
silently dropped. Missing tree metadata remains missing, and the known BTCZ
zero tree sizes are not repaired or accepted by the scanner.

Focused local validation:

```text
.venv\Scripts\python.exe -m pytest -q tests\test_lightwalletd_routing.py tests\test_coin_registry.py tests\test_sapling_spent_status.py
76 passed, 135 subtests passed
```

These are schema/adapter and fail-closed regression results, not endpoint
interoperability evidence. No request was made to
`lightd.btcz.rocks:443` through the newly selected `cash.bitcoinz` namespace
for this task. Earlier live observations used the then-configured service
path and cannot establish that the endpoint implements this descriptor or
LWP v0.6.0. BTCZ spent status therefore remains `UNKNOWN`, its sampled tree
metadata still blocks full-tree scanning, and endpoint data is not
consensus-authenticated.

| Capability | Current status | Evidence boundary |
|---|---|---|
| Pinned BTCZ/Zcash field and RPC schema comparison | **Verified locally** | Descriptor tests and the pinned-source matrix establish declared field tags, wire types, defaults/presence, and service signatures. This does not verify a deployed server. |
| `cash.bitcoinz` / `cash.z` client routing | **Verified locally** | Routing tests cover every method in each descriptor. The BTCZ endpoint was not queried through `cash.bitcoinz` during this task. |
| BTCZ endpoint interoperability with this schema / LWP v0.6.0 | **Unverified** | The endpoint has not been tested through the new BTCZ namespace and its reported protocol version was blank in prior probes. |
| BTCZ tree-size metadata / full-tree scan support | **Unsupported for reliable size checks** | Earlier endpoint samples reported zero sizes despite Sapling activity; local validation deliberately rejects inconsistent metadata. |
| BTCZ spent status | **Unknown / fail-closed** | No verified protocol version or complete trusted coverage; the client must not report `UNSPENT`. |
| Consensus authentication from Lightwalletd data | **Unsupported** | Protobuf or endpoint responses do not independently authenticate roots, blocks, or scan completeness. |
