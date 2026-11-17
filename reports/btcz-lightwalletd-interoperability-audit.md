# BitcoinZ Lightwalletd Sapling interoperability audit

## Decision

BitcoinZ Lightwalletd Sapling compact blocks are **Partially Verified** for the
bounded operations tested below. End-to-end LWP v0.6.0 compatibility is
**Unverified**: the endpoint does not report `lightwalletProtocolVersion`, and
its checked-in server protocol definition predates that field. The endpoint
does return Sapling compact outputs and spend nullifiers, but its compact-block
Sapling tree sizes are incorrect in the sampled output-bearing blocks.

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
| LWP v0.6.0 version declaration | **Unverified** | The live `lightwalletProtocolVersion` is empty. The matched server's `LightdInfo` source and `GetLightdInfo` construction do not define/populate field 18. Software version is not a protocol version. |
| `GetLatestBlock` | **Verified for the probe** | Returned a 32-byte hash at height 1875241; a direct `GetBlock` at that height returned the same height and hash. |
| Inclusive `GetBlockRange` and block linkage | **Partially Verified** | Activation, historical-output, and tip ranges returned consecutive heights. Every adjacent `prevHash` matched the preceding block hash; predecessor links were checked for heights 1865913 and 1875239. This is bounded endpoint evidence, not consensus authentication. |
| Sapling compact output and spend fields | **Partially Verified** | Heights 1865913–1865932 returned 51 outputs and 28 spends. Sampled output fields were 32-byte `cmu`, 32-byte ephemeral key, and 52-byte ciphertext; sampled Sapling nullifiers were 32 bytes. This does not establish completeness for all heights. |
| Sapling compact tree-size metadata | **Unsupported for reliable size checks** | All 20 blocks in the output-bearing range reported size 0 despite 51 outputs; recent sampled blocks also reported 0. The exact server source reads `trees.sapling.size` from verbose `getblock`, but the pinned Core `blockToJSON` response has no `trees` member. The absent JSON field decodes to zero. ZyCoin's tree scanner rejects the resulting size mismatch rather than accepting it. |
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
compact fields. The server's checked-in `service.proto` is not fully in sync
with its generated gRPC service code; observed calls use the standard Zcash
gRPC service path and succeeded. This source-generation mismatch is another
reason not to certify the whole endpoint as LWP v0.6.0 from source inspection
alone.

For tree sizes, `common.getBlockFromRPC()` reads `Trees.Sapling.Size` from
verbose BitcoinZ `getblock`. In the pinned Core source, `blockToJSON()` emits
the Sapling root and value-pool information but not a `trees` object. The
Lightwalletd JSON struct therefore receives a default size of zero. The live
range containing 51 Sapling outputs but reporting zero tree size confirms the
observable mismatch. Although `GetTreeState` responded, that does not repair
the per-block metadata required for the local full-tree scanner.

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
