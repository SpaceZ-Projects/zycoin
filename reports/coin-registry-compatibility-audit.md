# ZyCoin Historical Compatibility Record

Audit date: 2026-11-02
Runtime: CPython 3.10.11
Scope: every JSON definition under `src/coins/`; 8 coin IDs and 9 networks.

## Status key

- **Verified** — exercised successfully against a reference vector or configured live endpoint.
- **Partially Verified** — shared behavior or endpoint responded, but a coin parameter or complete fixture is still unverified.
- **Unverified** — configuration or behavior lacks sufficient authoritative evidence.
- **Unsupported** — configuration explicitly disables or does not provide the capability.
- **Unavailable** — a configured public endpoint did not respond successfully during this bounded test.

## Per-network results

| Coin/network | Transparent derivation and serialization | Electrum | Bitcore | Lightwalletd availability and scanning | Sapling configuration and ZIP32 derivation | Sapling compact-output retrieval | Sapling note decryption |
|---|---|---|---|---|---|---|---|
| BitcoinZ mainnet (`btcz`) | **Partially Verified** — BIP44 path `m/44'/177'/{account}'` derived from the shared BIP-39 seed; address/WIF serialization round-tripped. Prefix provenance is still marked unverified in JSON. | **Verified** — SSL negotiation, history, and transaction retrieval succeeded. | **Verified** — status, bounded history, and transaction retrieval succeeded; a later fresh address returned HTTP 404, now normalized as empty history. | **Verified** — live info/latest-block calls, bounded transparent and Sapling scans, `GetTaddressTransactions`, and `GetTransaction` succeeded. | **Partially Verified** — activation/ZIP-212 configuration and note-decryption parameters are present; ZIP32 path remains explicitly unverified and wallet derivation stays gated. | **Verified** — 20-block live range returned 14 Sapling compact outputs. | **Partially Verified** — reference v1 note decrypts and commitment-checks under BTCZ ZIP-212 heights; no BTCZ-specific on-chain fixture or v2 fixture was available. |
| Flux mainnet (`flux`) | **Partially Verified** — configured address codecs round-trip; BIP44 coin type/path are unverified and not generated. | **Unavailable** — configured Electrum SSL servers were unreachable. | **Partially Verified** — status and bounded empty-history calls succeeded. | **Unsupported** — no Lightwalletd endpoint configured. | **Unverified** — partial Sapling data; ZIP32 coin type/path are absent. | **Unsupported** | **Unverified** |
| Gemlink mainnet (`glink`) | **Partially Verified** — configured address codecs round-trip; BIP44 coin type/path are unverified and not generated. | **Unsupported** | **Partially Verified** — status and bounded empty-history calls succeeded. | **Unsupported** | **Unverified** — Sapling status is unknown; no ZIP32 path. | **Unsupported** | **Unverified** |
| KomodoClassic mainnet (`kmdcl`) | **Partially Verified** — configured address codecs round-trip; BIP44 coin type/path are unverified and not generated. | **Unavailable** — configured Electrum SSL server was unreachable. | **Unavailable** — configured Bitcore status request timed out. | **Unsupported** | **Unverified** — Sapling status is unknown; no ZIP32 path. | **Unsupported** | **Unverified** |
| Zclassic mainnet (`zcl`) | **Partially Verified** — BIP44 path `m/44'/147'/{account}'` derived from the shared BIP-39 seed; address/WIF serialization round-tripped. Prefix provenance remains unverified in JSON. | **Unsupported** | **Partially Verified** — status and bounded empty-history calls succeeded; no transaction was available for retrieval. | **Unsupported** | **Unverified** — Sapling is partial and has no ZIP32 coin type/path. | **Unsupported** | **Unverified** |
| Zcash mainnet (`zec`) | **Partially Verified** — BIP44 path `m/44'/133'/{account}'` derived from the shared BIP-39 seed; address/WIF serialization round-tripped. Prefix provenance remains unverified in JSON. | **Unsupported** | **Unsupported** | **Verified** — live info/latest-block calls, bounded transparent and Sapling scans, `GetTaddressTransactions`, and `GetTransaction` succeeded. | **Verified** — verified parameters and ZIP32 path `m/32'/133'/{account}'`; same BIP-39 seed derived a Sapling key/address, and the master key matched the upstream ZIP32 vector. | **Verified** — 20-block live range returned 6 Sapling compact outputs. | **Partially Verified** — upstream Zcash v1 note decrypted and commitment-checked; configured ZIP-212 boundary rejected v1 after grace. A v2 fixture was not exercised. |
| Zcash testnet (`zec`) | **Partially Verified** — BIP44 path `m/44'/1'/{account}'` derived from the shared BIP-39 seed; testnet address serialization round-tripped. | **Unsupported** | **Unsupported** | **Unsupported** — no testnet Lightwalletd endpoint configured. | **Partially Verified** — Sapling activation/HRPs are configured, but ZIP32 derivation path is not verified. | **Unsupported** | **Unverified** — no verified note-decryption capability is configured. |
| Zero mainnet (`zer`) | **Partially Verified** — configured address codecs round-trip; BIP44 coin type/path are unverified and not generated. | **Unsupported** | **Partially Verified** — status and bounded empty-history calls succeeded. | **Unsupported** | **Unsupported** — explicitly marked unsupported in JSON. | **Unsupported** | **Unsupported** |
| ZeroClassic mainnet (`zerc`) | **Partially Verified** — configured address codecs round-trip; BIP44 coin type/path are unverified and not generated. | **Unsupported** | **Partially Verified** — status and bounded empty-history calls succeeded. | **Unsupported** | **Unverified** — partial Sapling data; ZIP32 coin type/path are absent. | **Unsupported** | **Unverified** |

## Changes made

- The registry now reloads the configured JSON directory on each discovery call. Adding a valid coin JSON is immediately visible without a fixed coin list or per-coin implementation module.
- Configuration validation now checks address-prefix lengths and required verified prefixes, hardened BIP44/ZIP32 coin-type bounds, standard derivation templates, transparent/Sapling coin identity, endpoint consistency, and supported Lightwalletd RPC names.
- Corrected the configured `GetAddressTxids` typo to the actual `GetTaddressTxids` RPC in BitcoinZ and Zcash definitions.
- BIP44 path generation now consumes and verifies the configured path instead of silently constructing a path from the coin type.
- Bitcore history treats the explorer's explicit `404 Address not found` response as an empty history and rejects invalid history limits.
- Corrected wheel package data so the BIP-39 wordlist is included. The deleted README has since been recreated with the public APIs, tested examples, capability boundaries, and security limitations.
- Added automated registry, configuration, transparent serialization, BIP44/ZIP32, and note-decryption fixture tests.
- Phase 9.15 binds witnesses to historical tree size/root and adds scanner boundary, tip, and ending-block consistency checks without treating endpoint data as consensus proof.
- Phase 9.16 corrected Sapling Merkle personalization: `_combine_at_level` now passes the tree level directly to MerkleCRH. Before the fix, the empty root disagreed with upstream (`132ef6...` locally versus `fbc2f4...` upstream).
- Phase 9.16 independently generated and checked the retained tree fixture against upstream `sapling-crypto` 0.9.0 / `incrementalmerkletree` 0.9.0. During Phase 9.17 the auxiliary Rust generator and Cargo files were removed to keep the repository Python-only; the fixture outputs, pinned upstream revisions, known-answer vector, and SHA-256 evidence remain.

## Verification evidence and limits

- `py -3.10 -m pytest -q tests\test_coin_registry.py`: **11 passed** on Python 3.10.11 during Phase 9.6. Phase 9.7 results are below.
- Phase 9.15 rerun: `py -3.10 -m pytest -q` — **45 passed**; `py -3.10 -m compileall -q src tests` — passed.
- Phase 9.15 packaging: `py -3.10 setup.py sdist bdist_wheel` — passed; installed the generated wheel to a clean target and verified the `zycoin` import, all 8 packaged coin JSON files, and the 15,164-byte English wordlist.
- Phase 9.15 scanner tests exercise multiple blocks, multiple transactions and outputs, missing ranges, wrong activation predecessor, inconsistent tree sizes, changed ending blocks, and changed tips. No live Lightwalletd endpoint was re-probed in this phase.
- Phase 9.16: the independent upstream reference execution produced root/path snapshots at sizes 0–4 and checked the depth-32 capacity boundary. Its saved outputs continue to match ZyCoin; the generator itself is not retained in this Python-only project.
- Phase 9.16 targeted tree/scanner tests: **6 passed** on Python 3.10.11.
- Phase 9.16 final validation: `py -3.10 -m pytest -q` — **46 passed**; `py -3.10 -m compileall -q src tests` — passed; `py -3.10 setup.py sdist bdist_wheel` — passed.
- Phase 9.16 clean installation: installed `zycoin-1.1.2-py3-none-any.whl` into a temporary target, imported the package, enumerated all 8 packaged coin configurations, read the 15,164-byte wordlist, and matched the installed package's MerkleCRH output to the pinned known-answer vector.
- Phase 9.16 reference reproducibility: the pinned upstream generator was rerun and its outputs remained stable. After Phase 9.17 removed the obsolete generator-command metadata, the retained fixture SHA-256 is `21FB4FB364CD56216CE964DB3D89DC97CB4E26A7F24470EA64527F98B549C4CD`.
- `py -3.10 -m compileall -q src tests`: passed.
- Built `zycoin-1.1.2-py3-none-any.whl`, installed it into a clean target directory, and verified `zycoin` imports, coin JSON discovery, and BIP-39 wordlist access.
- Live network checks were read-only and deadline-bounded. They used generated test addresses, requested limited Bitcore histories and one-/20-block Lightwalletd ranges, and did not broadcast transactions.
- Reference fixtures: [Sapling note encryption](https://github.com/zcash/zcash-test-vectors/blob/master/test-vectors/json/sapling_note_encryption.json) and [ZIP32](https://github.com/zcash/zcash-test-vectors/blob/master/test-vectors/json/sapling_zip32.json).
- The note-decryption fixture is the upstream Zcash v1 note-encryption vector. It verifies shared decryption, pre-ZIP-212 v1 acceptance, and post-grace rejection at the configured Zcash/BitcoinZ heights. It does not establish a BitcoinZ-specific chain transaction or test ZIP-212 v2 decryption.
- Address codec round trips establish serializer/parser consistency, not authoritative correctness of coin prefixes. Configurations marked unverified remain so.
- No production secrets or broadcast transactions were used.

## Phase 9.7 — Sapling verification and documentation update

The registry remains dynamic: the audit covers all 8 discovered coin JSON
definitions and all 9 configured networks. The shared note-decryption
implementation was not rewritten; the added tests exercise ZIP-212 version
selection, boundary heights, coinbase/index-zero behavior, IVK/FVK trial
decryption, wrong keys, and malformed or commitment-mismatched outputs.

| Coin/network | Sapling parameters and derivation | Compact outputs | Note decryption |
|---|---|---|---|
| BitcoinZ mainnet (`btcz`) | **Partially Verified** — activation 328500, ZIP-212 activation 1735000, and grace period 32256 are exercised from its configuration; ZIP32 derivation path remains unverified and wallet derivation remains gated. | **Verified** — the Phase 9.6 bounded live Lightwalletd scan returned compact outputs. | **Partially Verified** — upstream Zcash v1 reference fixture decrypts using BTCZ's configured ZIP-212 heights; synthetic v2 fixture exercises configured boundary rules. No BitcoinZ on-chain note/key fixture was verified, so real-chain decryption is not claimed. |
| Flux mainnet (`flux`) | **Unverified** — Acadia parameters are partial; ZIP32 coin type/path and ZIP-212 values are absent. | **Unsupported** — no Lightwalletd endpoint is configured. | **Unverified** — note decryption is not enabled. |
| Gemlink mainnet (`glink`) | **Unverified** — Sapling parameters are incomplete and no ZIP32 path is configured. | **Unsupported** — no Lightwalletd endpoint is configured. | **Unverified** — note decryption is not enabled. |
| KomodoClassic mainnet (`kmdcl`) | **Unverified** — Sapling parameters and ZIP32 path are incomplete. | **Unsupported** — no Lightwalletd endpoint is configured. | **Unverified** — note decryption is not enabled. |
| Zclassic mainnet (`zcl`) | **Unverified** — Sapling activation data is present, but ZIP32 coin type/path and ZIP-212 configuration are absent. | **Unsupported** — no Lightwalletd endpoint is configured. | **Unverified** — note decryption is not enabled. |
| Zcash mainnet (`zec`) | **Verified** — ZIP32 path `m/32'/133'/{account}'` and configured activation/ZIP-212 values are exercised; the master spending key also matches the upstream ZIP32 vector. | **Verified** — the Phase 9.6 bounded live Lightwalletd scan returned compact outputs. | **Partially Verified** — upstream Zcash v1 reference fixture decrypts and checks the commitment; synthetic v2 fixtures exercise activation, both grace-period edges, coinbase/index-zero selection, and post-grace behavior. No on-chain note/key pair is included. |
| Zcash testnet (`zec`) | **Partially Verified** — activation and address HRPs are configured; ZIP32 derivation path and ZIP-212 parameters are not verified/configured. | **Unsupported** — no testnet Lightwalletd endpoint is configured. | **Unverified** — verified note-decryption capability is not configured. |
| Zero mainnet (`zer`) | **Unsupported** — Sapling is explicitly disabled. | **Unsupported** | **Unsupported** |
| ZeroClassic mainnet (`zerc`) | **Unverified** — Sapling data is partial and no ZIP32 path/ZIP-212 rules are configured. | **Unsupported** — no Lightwalletd endpoint is configured. | **Unverified** — note decryption is not enabled. |

### Phase 9.7 evidence and limits

- The upstream `sapling_note_encryption.json` reference set contains v1
  plaintexts only. ZIP-212 v2 coverage therefore uses deterministic synthetic
  test outputs constructed from the published ZIP-212 derivation rules; those
  fixtures test the shared implementation and network-configured rules, not a
  real transaction or an independently published v2 vector.
- ZIP-212 tests cover v1 acceptance before activation, v1/v2 acceptance during
  grace for non-coinbase transactions, the first and last grace blocks,
  v2-only coinbase/index-zero selection during grace, and v2-only behavior at
  the first post-grace height. Tests also cover IVK and FVK inputs, a
  non-matching key, malformed fields, and a tampered note commitment.
- BitcoinZ is the primary non-Zcash configured test target. Its parameters
  receive v1 reference and synthetic v2 fixture coverage, but the available
  public Lightwalletd output scan was not paired with a known BitcoinZ viewing
  key and expected decrypted note. Do not describe that as real-chain
  BitcoinZ note decryption.
- `py -3.10 -m pytest -q`: **16 passed** on Python 3.10.11; source/test
  compilation passed.
- All **9** README Python examples executed successfully against the installed
  wheel, including bounded BTCZ Electrum, Bitcore, and Lightwalletd reads.
  The 10-block Lightwalletd example returned 14 compact outputs and no matches
  for the published reference IVK; this is endpoint/compact-output evidence,
  not real-chain note decryption.
- Built and installed `zycoin-1.1.2-py3-none-any.whl` into a separate target
  directory. Imports resolved from that installed wheel; the package included
  all 8 coin definitions, the 2048-word BIP-39 resource, and the README
  long-description metadata.
- `git diff --check` reports only the pre-existing trailing whitespace in
  `src/crypto.py:104`; it was left unchanged.

## Phase 9.8 — BitcoinZ real-chain Sapling verification

| Coin/network | Result | Evidence |
|---|---|---|
| BitcoinZ mainnet (`btcz`) | **Partially Verified** | The configured Lightwalletd endpoint returned confirmed compact Sapling outputs and raw transaction data. The existing `scan_sapling_notes()` API replayed a stored on-chain compact output offline, but no matching controlled viewing key or independently known plaintext could be established. No real-chain decryption claim is made. |

### Confirmed on-chain output

- Endpoint: `lightd.btcz.rocks:443`; chain name `main`; reported Sapling
  activation height matched configured height **328500**.
- A bounded, inclusive 20-block `GetBlockRange` scan covered heights
  **1865913–1865932** and returned **51** compact Sapling outputs. A repeated
  check retrieved transaction data using Lightwalletd `GetTransaction`.
- Stored compact-output fixture:
  [`tests/fixtures/btcz_mainnet_compact_output.json`](../tests/fixtures/btcz_mainnet_compact_output.json)
- Transaction: `2a35efbe318b79b1e357b8ad6145561bd90dd37200a9dcc691adf1a05cdc8dd3`,
  at height **1865916**, block hash
  `e13e65970ada9ad749fcc5be815cdeae4a01faad98d3c4fa792c224144070000`,
  transaction index **1**, Sapling output index **0**. At the observed tip
  height **1865934**, Lightwalletd reported the raw transaction at height
  1865916 (3321 bytes), confirming it was present in the chain response.
- The fixture stores the compact output's commitment, ephemeral key, and
  52-byte ciphertext prefix. Its height is beyond the configured ZIP-212
  first post-grace height (**1767256**), so valid decryption must select
  ZIP-212 v2.
- An offline `scan_sapling_notes()` regression test replays the stored
  Lightwalletd compact data using the published Zcash reference-vector IVK;
  it returns no notes. This is only a negative trial with an unrelated key,
  not a positive decryption test or independent proof of plaintext contents.

### Missing evidence and final limitation

- BitcoinZ's public upstream
  [note-encryption test](https://github.com/btcz/bitcoinz/blob/a25305eec6cd18d4f5b61f67c655743503093b1f/src/gtest/test_noteencryption.cpp)
  creates a note under `REGTEST`, with a zeroed test spending key, and encrypts
  it locally. Its
  [Sapling note test](https://github.com/btcz/bitcoinz/blob/a25305eec6cd18d4f5b61f67c655743503093b1f/src/gtest/test_sapling_note.cpp)
  and [ZIP32 test](https://github.com/btcz/bitcoinz/blob/a25305eec6cd18d4f5b61f/src/gtest/test_zip32.cpp)
  are note/derivation vectors. None pairs a mainnet transaction with the
  recipient IVK/FVK and expected decrypted note.
- The live confirmed transaction does not disclose its Sapling recipient key
  or plaintext, and no controlled test key is known to correspond to it.
  Compact fields expose the commitment, ephemeral key, and ciphertext prefix,
  but not plaintext, value, or diversifier. Consequently these expected note
  values cannot be independently established from available evidence.
- Obtaining a positive chain fixture would require either an already-published
  BitcoinZ test transaction with its controlled viewing key and expected note,
  or a previously received transaction to a controlled test key. No such
  fixture was found. No transaction was constructed, signed, or broadcast for
  this audit.
- **BTCZ note decryption remains Partially Verified.** The stored real-chain
  compact fixture is reproducible offline and negative tests remain in place,
  but there is no positive real-chain decryption regression test. The shared
  implementation and BitcoinZ configuration were left unchanged because no
  compatibility defect was demonstrated.

### Phase 9.8 verification

- `py -3.10 -m pytest -q`: **17 passed** on Python 3.10.11; source/test
  compilation passed. The suite includes offline replay through
  `scan_sapling_notes()` and malformed-output, wrong-key, and
  commitment-mismatch cases.
- Bounded live Lightwalletd checks were read-only and limited to 20 blocks,
  200 compact outputs, and one transaction retrieval. No production secrets
  or broadcasting operations were used.
- Built and installed `zycoin-1.1.2-py3-none-any.whl` into an isolated target
  directory; installed-package import and JSON/wordlist resource access
  succeeded.

## Phase 9.9 — BitcoinZ Sapling compatibility comparison

| BitcoinZ mainnet area | Status | Findings |
|---|---|---|
| Sapling cryptography compatibility | **Verified** | The shared engine decrypts the published Zcash Sapling v1 vector under both ZEC and BTCZ network configurations. It recovers the published 100,000,000 value and diversifier, exact 52-byte plaintext prefix, and commitment. BitcoinZ's upstream code uses the same Sapling key-agreement FFI and `Zcash_SaplingKDF` domain. |
| Configuration | **Verified** for mainnet Sapling/ZIP-212 heights | BitcoinZ mainnet Sapling activates at 328500 and Canopy/ZIP-212 at 1735000; Zcash mainnet uses 419200 and 1046400 respectively. Both configure a 32256-block grace period and Sapling branch ID `76b809bb`. BTCZ's ZIP32 wallet path remains unverified and gated. |
| Compact-output parsing | **Verified** | A fresh bounded scan of the exact fixture block returned the recorded txid, transaction/output indices, commitment, ephemeral key, and corrected 52-byte ciphertext prefix. `GetTransaction` returned the same height and a 3321-byte transaction response. The offline scanner replay test exercises the same protobuf-to-compact-output conversion. |
| Positive real-chain note decryption | **Unverified** (overall capability remains **Partially Verified**) | The captured output is beyond ZIP-212 grace and therefore requires v2. No matching controlled IVK/FVK or independently established plaintext/value/diversifier is available. The unrelated published IVK returning no match is expected and is not evidence of a decryption failure. |

### Protocol and fixture analysis

- BitcoinZ and Zcash do not require distinct Sapling cryptography. In the
  pinned BitcoinZ
  [NoteEncryption.cpp](https://github.com/btcz/bitcoinz/blob/a25305eec6cd18d4f5b61f67c655743503093b1f/src/zcash/NoteEncryption.cpp),
  note key agreement calls `librustzcash_sapling_ka_agree`, and
  `KDF_Sapling` uses BLAKE2b-256 with `Zcash_SaplingKDF` over the shared secret
  and ephemeral key before ChaCha20-Poly1305 encryption.
  [Note.cpp](https://github.com/btcz/bitcoinz/blob/a25305eec6cd18d4f5b61f67c655743503093b1f/src/zcash/Note.cpp)
  delegates note commitment computation to `librustzcash_sapling_compute_cm`.
  These are standard Sapling primitives; the differences are chain upgrade
  schedules and chain identifiers, not BitcoinZ-specific key agreement,
  encryption, or commitment construction.
- The [ZIP-212 specification](https://zips.z.cash/zip-0212) deploys with
  Canopy, requires v2 note plaintext after activation, allows the specified
  32256-block transition grace for non-coinbase outputs, and requires v2 for
  coinbase outputs during grace. BitcoinZ's pinned
  [chain parameters](https://github.com/btcz/bitcoinz/blob/a25305eec6cd18d4f5b61f67c655743503093b1f/src/chainparams.cpp)
  place Sapling at 328500 and Canopy at 1735000; Zcash's pinned chain
  [parameters](https://github.com/zcash/zcash/blob/558f686599586f55def3db86955d74d3be44605e/src/chainparams.cpp)
  use 419200 and 1046400. The BTCZ JSON heights match the active source
  assignments (the source also contains an older commented Canopy height).
  At the captured BTCZ transaction height 1865916, ZIP-212 v2 is active.
- The [published Zcash note-encryption vector](https://github.com/zcash/zcash-test-vectors/blob/master/test-vectors/json/sapling_note_encryption.json)
  supplies the IVK, encrypted compact prefix, ephemeral key, commitment,
  expected plaintext prefix, value, and diversifier. Tests run this same
  independent vector through the shared engine under both ZEC and BTCZ
  network configurations. The recovered plaintext and Pedersen commitment
  match the vector. V2 boundary behavior is separately tested for both
  networks using synthetic outputs; those synthetic cases are not chain
  evidence.
- The stored real-chain fixture previously had two ciphertext-prefix
  characters transcribed incorrectly (`...bd83e9...`). A fresh exact-height
  Lightwalletd read confirmed the on-chain bytes are `...bd83c9...`; the
  fixture is corrected. The transaction ID, height, block hash, commitment,
  and ephemeral key already matched the endpoint.
- A stored-output replay through `scan_sapling_notes()` with the unrelated
  public reference IVK correctly returns no note. The compact API exposes
  only `cmu`, `ephemeralKey`, and 52 ciphertext bytes; without the matching
  viewing key and plaintext reference, it cannot establish a positive
  on-chain decryption result.

### Phase 9.9 verification

- `py -3.10 -m pytest -q`: **18 passed** on Python 3.10.11; source/test
  compilation passed. Tests cover the independent v1 fixture under both
  configs, expected plaintext/value/diversifier and commitment, IVK/FVK
  handling, v1/v2 network boundaries, malformed data, wrong keys, and
  commitment mismatch.
- A read-only Lightwalletd scan was limited to the single fixture height
  (1865916), at most 200 compact outputs, and one transaction retrieval. It
  confirmed the saved prefix and all other selected compact fields.
- No production viewing keys were used. No spending, signing, transaction
  construction, or broadcasting occurred.
- Built and installed `zycoin-1.1.2-py3-none-any.whl` into an isolated target;
  package imports, dynamic coin discovery, BitcoinZ configuration, and the
  packaged 2048-word BIP-39 list were verified.

## Phase 9.10 — Transparent derivation and client compatibility

The audit again enumerated all **8 coin JSON definitions and 9 networks**.
Statuses below describe evidence from this phase; endpoint connection alone is
not treated as proof of RPC functionality.

| Coin/network | Transparent BIP44 derivation | Address serialization | Electrum connectivity/functionality | Bitcore connectivity/functionality | Address history (Electrum / Bitcore) | Transaction retrieval (Electrum / Bitcore) | Subscription support (Electrum / Bitcore) |
|---|---|---|---|---|---|---|---|
| BitcoinZ mainnet (`btcz`) | **Partially Verified** — registered type 177 and standard path are sourced and derived for multiple accounts/indices; no independent coin-wallet derived-address vector was available. | **Verified** — address, script, WIF prefixes match BitcoinZ chain parameters; serializer also matches a published P2PKH vector. | **Verified** — all 3 configured servers answered `server.version` over TCP, SSL, and WSS; header/scripthash subscription, history, and known transaction RPCs succeeded over SSL. Plain WS failed on the configured port; WSS succeeded. | **Verified** — status, bounded history, known transaction, and Socket.IO subscribe/unsubscribe calls succeeded. | **Partially Verified / Partially Verified** — generated unused addresses returned empty histories; no positive history fixture was used. | **Verified / Verified** — the known BTCZ txid `2a35efbe318b79b1e357b8ad6145561bd90dd37200a9dcc691adf1a05cdc8dd3` was retrieved from both clients. | **Partially Verified / Partially Verified** — subscription calls succeeded; live notification delivery was not observed. Electrum servers reject remote unsubscribe RPCs, so the shared client now stops local notification processing instead. |
| Flux mainnet (`flux`) | **Partially Verified** — registered type 19167 and standard path are sourced and exercised; no independent coin-wallet derived-address vector was available. | **Verified** — configured mainnet prefixes match Flux chain parameters; serialization reference vector passed. | **Partially Verified** — `electrumx.runonflux.io` answered over TCP; its SSL/WS/WSS probes and all tested transports on `electrumx2.runonflux.io` were unavailable. Version, headers, scripthash subscription, and empty history worked on the reachable endpoint. | **Partially Verified** — status, bounded history, and Socket.IO calls succeeded; no known Flux transaction was retrieved. | **Partially Verified / Partially Verified** — only empty histories for generated unused addresses were observed. | **Unverified / Unverified** — no known Flux transaction ID was tested. | **Partially Verified / Partially Verified** — subscription calls succeeded on responding endpoints; no notification event was observed. |
| Gemlink mainnet (`glink`) | **Unverified** — configured type 407 has no verified coin-specific registration/path source; generation remains gated. | **Verified** — prefixes match Gemlink chain parameters; serialization reference vector passed. | **Unsupported** — no Electrum endpoint configured. | **Partially Verified** — REST status and bounded history worked; configured Socket.IO endpoint rejected the handshake with HTTP 400. | **Unsupported / Partially Verified** — Bitcore returned an empty history for a generated unused address. | **Unsupported / Unverified** — no known Gemlink transaction was tested. | **Unsupported / Unavailable** — configured Socket.IO handshake returned HTTP 400. |
| KomodoClassic mainnet (`kmdcl`) | **Unverified** — type 141 is registered to Komodo; no evidence established that it is the correct KomodoClassic wallet path. | **Verified** — prefixes match KomodoClassic chain parameters; serialization reference vector passed. | **Unavailable** — configured Electrum host failed bounded TCP, SSL, WS, and WSS probes. | **Unavailable** — configured REST status/history and Socket.IO handshake timed out. | **Unavailable / Unavailable** | **Unavailable / Unavailable** | **Unavailable / Unavailable** |
| Zclassic mainnet (`zcl`) | **Partially Verified** — registered type 147 and standard path are sourced and exercised; no independent coin-wallet derived-address vector was available. | **Verified** — prefixes match Zclassic chain parameters; serialization reference vector passed. | **Unsupported** — no Electrum endpoint configured. | **Partially Verified** — REST status and bounded history worked; configured Socket.IO endpoint returned HTTP 404. | **Unsupported / Partially Verified** — Bitcore returned an empty history for a generated unused address. | **Unsupported / Unverified** — no known Zclassic transaction was tested. | **Unsupported / Unavailable** — configured Socket.IO handshake returned HTTP 404. |
| Zcash mainnet (`zec`) | **Partially Verified** — registered type 133 and standard path are sourced and exercised; no independent final-address vector was available. | **Verified** — prefixes match pinned Zcash chain parameters; serialization reference vector passed. | **Unsupported** — no Electrum endpoint configured. | **Unsupported** — no Bitcore API configured. | **Unsupported / Unsupported** | **Unsupported / Unsupported** | **Unsupported / Unsupported** |
| Zcash testnet (`zec`) | **Partially Verified** — standard testnet type 1/path is sourced and exercised; no independent final-address vector was available. | **Verified** — prefixes match pinned Zcash testnet chain parameters; serialization reference vector passed. | **Unsupported** | **Unsupported** | **Unsupported / Unsupported** | **Unsupported / Unsupported** | **Unsupported / Unsupported** |
| Zero mainnet (`zer`) | **Partially Verified** — registered type 323 and standard path are sourced and exercised; no independent coin-wallet derived-address vector was available. | **Verified** — prefixes match Zero chain parameters; serialization reference vector passed. | **Unsupported** — no Electrum endpoint configured. | **Partially Verified** — REST status and bounded history worked; configured Socket.IO endpoint returned HTTP 400. | **Unsupported / Partially Verified** — Bitcore returned an empty history for a generated unused address. | **Unsupported / Unverified** — no known Zero transaction was tested. | **Unsupported / Unavailable** — configured Socket.IO handshake returned HTTP 400. |
| ZeroClassic mainnet (`zerc`) | **Unverified** — configured type 133 is registered to Zcash; no evidence established it as the correct ZeroClassic wallet path. | **Verified** — prefixes match ZeroClassic chain parameters; serialization reference vector passed. | **Unsupported** — no Electrum endpoint configured. | **Partially Verified** — REST status/history and Socket.IO subscription calls succeeded; no known transaction was retrieved. | **Unsupported / Partially Verified** — Bitcore returned an empty history for a generated unused address. | **Unsupported / Unverified** | **Unsupported / Partially Verified** — subscription calls succeeded, but notification delivery was not observed. |

### Phase 9.10 evidence, fixes, and limits

- Compared every configured network's WIF, P2PKH, and P2SH parameters against
  that coin's upstream `chainparams.cpp`. This identified previously
  under-reported, but correctly configured, prefixes. The JSON now records
  upstream provenance and marks those address parameters verified; schema
  validation requires provenance for any verified address configuration.
- SLIP-0044 confirms the coin types for BitcoinZ (177), Flux (19167), Zclassic
  (147), Zcash (133), and Zero (323); the Zcash testnet uses the standard
  testnet type 1. Flux and Zero's verified registration evidence is now in
  their JSON. Gemlink, KomodoClassic, and ZeroClassic remain derivation-gated:
  no authoritative evidence confirmed their configured path identity.
- Derived receive addresses for accounts 0 and 1 at indices 0 and 7 across
  networks with verified parameters. Address serialization was checked for
  every configured prefix, and the shared P2PKH encoder matched the published
  `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` public-key vector. Final coin-specific
  BIP44 address vectors were not available, so derivation is **Partially
  Verified**, not fully verified, for networks with verified path parameters.
- Implemented native Python Electrum WS/WSS transport using the declared
  `websockets` dependency; the manager now includes `ws` as a fallback option.
  A local WebSocket server test exercises version negotiation, subscriptions,
  history, transaction retrieval, cancellation cleanup, and close behavior.
- Live BTCZ Electrum servers return `-32601` for remote header/scripthash
  unsubscribe methods. The shared client now suppresses local notifications
  on unsubscribe rather than issuing unsupported RPCs. BTCZ's configured
  WSS transport succeeds; plaintext WS on that same port does not.
- Bitcore history parsing now rejects malformed response shapes with explicit
  `ValueError`s rather than leaking attribute errors. Missing transactions
  remain normalized to `None`, while other HTTP failures propagate.
- Bounded read-only probes tested each configured Electrum host over TCP, SSL,
  WS, and WSS, and each configured Bitcore REST/Socket.IO endpoint. Generated
  ephemeral test addresses were used for limited history queries. The BTCZ
  transaction retrieval check used the public on-chain fixture txid listed
  above; no broadcast, signing, or production secret was used.
- Empty address histories prove response handling only, not retrieval of a
  populated account history. Socket subscription requests were accepted on
  the endpoints marked partially verified, but a real notification event was
  not observed. Failed/unreachable public endpoints are reported as
  **Unavailable**, not as defects in the shared client.
- `py -3.10 -m pytest -q`: **28 passed** on Python 3.10.11.
  `py -3.10 -m compileall -q src tests` passed.
- `git diff --check` still reports only the pre-existing trailing whitespace
  in `src/crypto.py:104`; this unrelated line was not changed.

## Phase 9.11 — Transparent transaction signing

The implementation adds shared transaction construction and signing APIs, but
the only enabled combination is BitcoinZ mainnet's configured transparent
P2PKH subset: Overwintered version 4, ZIP-243, the configured Canopy consensus
branch ID, compressed BIP44 keys, and `SIGHASH_ALL`. The builder preserves
input/output ordering and requires an explicit fee; it does not select UTXOs,
estimate fees, or create change. Sapling spends, JoinSplits, P2SH inputs,
additional signing hash types, other formats, and broadcasting are not
implemented.

| Coin/network | Transparent signing status | Evidence and limits |
|---|---|---|
| BitcoinZ mainnet (`btcz`) | **Partially Verified** | All 10 upstream ZIP-243 reference sighash cases pass. Offline synthetic single- and multi-input P2PKH transactions derive BIP44 keys, serialize, sign, verify, and exercise fee/order/tamper rejection. No independently generated full signed-transaction reference vector or live coin-wallet comparison is included, so full signing compatibility is not claimed. |
| Flux mainnet (`flux`) | **Unsupported** | Signing format, consensus branch rules, and signature compatibility are not configured/verified. |
| Gemlink mainnet (`glink`) | **Unsupported** | Verified signing parameters and derivation path are not configured. |
| KomodoClassic mainnet (`kmdcl`) | **Unsupported** | Verified signing parameters and derivation path are not configured. |
| Zclassic mainnet (`zcl`) | **Unsupported** | Transaction signing format and consensus branch rules are not configured/verified. |
| Zcash mainnet (`zec`) | **Unsupported** | ZIP-243 vectors validate the shared digest primitive only; Zcash signing is not enabled/configured. |
| Zcash testnet (`zec`) | **Unsupported** | No verified signing parameters are configured. |
| Zero mainnet (`zer`) | **Unsupported** | Transaction signing format and consensus branch rules are not configured/verified. |
| ZeroClassic mainnet (`zerc`) | **Unsupported** | Verified signing parameters and derivation path are not configured. |

### Phase 9.11 implementation and validation notes

- Added the exported `TransparentInput`, `TransparentOutput`,
  `UnsignedTransparentTransaction`, `SignedTransparentTransaction`,
  `create_unsigned_transaction`, `sign_transaction`,
  `verify_transaction_signatures`, and `zip243_signature_hash` APIs.
- Signing is fail-closed unless the selected network explicitly declares
  verified signing parameters, verified BIP44 derivation, and verified address
  parameters. Missing signing declarations default to unsupported.
- Verification checks the canonical unsigned metadata, transaction version
  group, branch-related digest, output ordering, input outpoints and sequences,
  compressed P2PKH public keys, strict pushes, DER signatures, and low-S
  signatures. Invalid signatures/data return `False`.
- `tests/fixtures/zip243_reference.json` contains the 10 upstream ZIP-243
  digest vectors. Tests also use deterministic synthetic keys/outpoints only;
  they do not spend, broadcast, or use production wallet material.
- The compatibility status remains **Partially Verified** for BTCZ signing:
  passing upstream sighash vectors plus internal generated-signature checks do
  not substitute for an independent signed-transaction vector from BitcoinZ
  Core or another authoritative implementation.
- `py -3.10 -m pytest -q`: **34 passed** on Python 3.10.11;
  `py -3.10 -m compileall -q src tests` passed.
- Built both wheel and sdist from an isolated copy, installed the wheel into a
  clean target, and verified public signing exports, dynamic coin discovery,
  packaged BIP-39 wordlist access, and the README offline-signing example.
  Confirmed the source archive includes the ZIP-243 regression fixture.

## Phase 9.12 — Sapling spending and signing foundation

### BitcoinZ protocol facts and configuration

BitcoinZ mainnet configures Sapling activation at height **328500** and
ZIP-212 activation at **1735000**, with a **32256-block** grace period whose
last block is **1767255**; **1767256** is the first post-grace height. The
shared note decryptor applies ZIP-212 v1/v2
selection, including the configured transaction-index/coinbase rules. This is
note-decryption behavior, not proof that outputs can be safely constructed for
spending.

The configured Sapling transaction format is Overwintered version **4** with
version group **`0x892f2085`**, the format used by ZIP-243 Sapling transactions.
The BTCZ mainnet configuration's transaction-signing branch ID for the
configured Canopy epoch is **`0xe9ff75a6`**. The Sapling activation branch ID
**`0x76b809bb`** in the Sapling parameter section identifies that upgrade; it
must not be reused as a current transaction's branch ID. ZIP-243 requires the
consensus branch ID for the transaction's intended epoch, so future upgrades
require new verified epoch configuration. ZIP-225 version-5 transactions are
not implemented by the existing v4 transparent transaction code.

The candidate ZIP32 path `m/32'/177'/{account}'` is marked **unverified** in
`src/coins/btcz.json`. Runtime checks confirm `SaplingWallet.from_mnemonic()`
and direct wallet construction both reject BTCZ mainnet. No BitcoinZ
spending-key path or BitcoinZ Sapling spending claim is enabled.

### Component status

| Sapling spending component | Status | Evidence / blocker |
|---|---|---|
| ZIP32 extended spending-key derivation | **Implemented, Verified** | `ExtendedSpendingKey` implements master, hardened-child, non-hardened viewing-child, and internal-key derivation. Automated tests match upstream `sapling_zip32.json` vectors for master, `m/1`, `m/1/2'`, a non-hardened FVK child, IVK, OVK, `ak`, `nk`, and internal key components. ZIP32 child indices and spending scalars now reject booleans rather than treating `True` as integer 1. |
| BIP-39 seed to ZIP32 key | **Implemented, Verified** | The existing 24-word BIP-39 seed path feeds ZIP32 master derivation; tests use the shared BIP-39 seed for transparent and Sapling branches. |
| Zcash mainnet ZIP32 account path | **Verified parameters; no spend** | Configured path is `m/32'/133'/{account}'`; existing derivation/address tests cover it. This verifies derivation only, not note spendability or transaction signing. |
| BitcoinZ mainnet ZIP32 account path | **Unverified, Gated** | Candidate `m/32'/177'/{account}'` has no verified BitcoinZ wallet-path evidence. Both wallet factory and direct constructor reject the network. |
| Spend/authorization/nullifier key components | **Implemented, Verified** | ZIP32 vectors verify `ask`, `nsk`, `ak`, `nk`, OVK, and IVK key-component derivation. This does not implement spend authorization signing. |
| ZIP-212 note decryption and note-commitment check | **Partially Verified** | Shared decryptor passes the upstream v1 note fixture and synthetic v2/boundary tests. It has no matching BitcoinZ real-chain viewing-key fixture; compact ciphertext omits the AEAD tag/memo. |
| Sapling nullifier derivation | **Implemented, Verified** | Shared Sapling derivation reconstructs the note commitment point, combines it with the note-position base and supplied global note-tree position, then applies the Sapling `Zcash_nf` BLAKE2s PRF. The automated test validates the `nk` from ZIP32 components and matches all 10 expected `note_nf` values in the pinned upstream `sapling_key_components.json` vectors. V1 and v2 notes can be converted only from commitment-checked decrypted outputs. |
| Sapling nullifier matching | **Missing** | Compact protobuf spend records carry chain nullifiers, but the scanner does not match them to locally derived nullifiers. |
| Sapling MerkleCRH and commitment-tree root | **Implemented, Verified** | The 32-level tree uses the protocol Pedersen hash, uncommitted leaf value 1, canonical field nodes, and the protocol's direct little-endian 6-bit level personalization. It matches the pinned upstream `zcash-test-vectors` MerkleCRH known-answer vector (revision `78321beacb0e0477e33cd002b56585a107c2708c`) and byte-for-byte matches roots from the pinned upstream `sapling-crypto` 0.9.0 implementation (revision `88a7946b4a3066787776e11f0a502654167e022d`) for empty, one-, two-, three-, and four-leaf trees. Independent comparison exposed and fixed an inverted level-personalization mapping in `_combine_at_level`. |
| Offline note positions and authentication paths | **Implemented, Verified** | ZyCoin matches upstream `IncrementalWitness` positions, anchors, and all 32 siblings for every leaf at every tree size from 1 through 4, including sequential witness updates. Reordered and omitted leaves produce roots different from the reference; tests also reject corrupted paths, incorrect roots, invalid positions, and divergent historical roots. This verifies append-order tree behavior, not whether a caller's supplied order is consensus-correct. |
| Full 32-level capacity boundary | **Implemented, Verified** | The pinned upstream implementation constructs a structurally full depth-32 tree, reports size `2^32`, and rejects an additional append. A targeted ZyCoin guard test exercises the same capacity boundary without attempting billions of appends. |
| Lightwalletd note positions and witness integration | **Partially Verified** | The full-tree scanner starts only at configured Sapling activation; it requires configured `GetBlock`/`GetLatestBlock`, checks the pre-activation boundary, verifies ordered unique compact transactions, contiguous block hashes and per-block tree sizes, and re-fetches the ending block to detect a changed range or tip. Mocked multi-block/multi-transaction, missing-range, boundary mismatch, and reorg cases pass. No live endpoint was verified, and endpoint metadata/hashes are not independent consensus proofs. A partial compact scan never receives positions. |
| External anchor authentication and spendability | **Unverified** | Paths reconstruct the locally computed root, but the library does not independently authenticate that root against consensus-verified chain state. A valid local path and endpoint-reported tree size do not prove a note is spendable. |
| Sapling spend proof | **Missing** | No Groth16 spend prover or bundled trusted Sapling spend parameters. Configuration's `sapling-spend.params` string is not an actual repository resource. |
| Sapling output proof and ZIP-212 output construction | **Missing** | No output note encryption/prover or bundled output parameters. The decryptor's ZIP-212 handling does not implement note creation. |
| Spend authorization signature | **Missing** | No RedJubjub spend-authorization signing integration or Sapling spend-description assembler. |
| Binding signature | **Missing** | No Sapling value-balance construction or binding-key/signature implementation. |
| Sapling transaction construction/serialization | **Missing** | The existing transaction serializer/parser and Phase 9.11 signer support only transparent inputs/outputs; they cannot serialize or validate Sapling spend/output descriptions or proofs. |

The retained root and witness fixture was generated and independently checked
using upstream Sapling `CommitmentTree<Node, 32>` and `IncrementalWitness`
from `sapling-crypto` revision
`88a7946b4a3066787776e11f0a502654167e022d` and
`incrementalmerkletree` 0.9.0. Fixture metadata records the exact source
revisions, protocol encoding, inputs, and expected outputs. Its multi-leaf
roots and witness paths were produced by this separate upstream
implementation, not by ZyCoin. The temporary generator was removed in Phase
9.17 to honor the Python-only repository constraint; the independent fixture
and known-answer vector are retained.

The scanner's Lightwalletd protobuf schema declares `GetTreeState`,
`GetLatestTreeState`, and `GetSubtreeRoots`, but the client has no methods for
them. Ordinary compact scans expose `transaction_index` and `output_index`,
which are not note-tree positions, and intentionally do not claim positions.
The separate activation-to-height scanner assigns positions by compact
transaction/output order only after checking the pre-activation boundary,
range tip, block ordering, hash continuity, and per-block
`saplingCommitmentTreeSize`. It rechecks the final block to detect a reorg
during scanning. These endpoint consistency checks detect incomplete or
changed responses but do not independently authenticate the chain or its
anchors. Although the protobuf schema includes Sapling spend nullifiers, the
scanner does not match them to local notes.

### Safely gated future transaction contract

No callable Sapling transaction builder is exposed. Before one can be
implemented, its request must bind validated note data and ZIP32 account to a
verified tree position, authentication path, common anchor, ordered output
notes, explicit fee, expiry height, network, ZIP-212 era rules, and the
epoch-specific consensus branch ID. It must reject inconsistent anchors,
invalid witnesses, value imbalance, malformed keys, and unconfigured network
parameters before invoking proof/signature primitives. A transaction is not
signable until spend/output proofs, authorization signatures, binding
signatures, canonical serialization, and independent verification all exist.
No placeholder proving/signing API was added.

### Authoritative references and verification

- [ZIP-32 — Shielded Hierarchical Deterministic Wallets](https://zips.z.cash/zip-0032)
- [ZIP-212 — Recipient-Derived Ephemeral Secret / note plaintext versions](https://zips.z.cash/zip-0212)
- [ZIP-243 — Sapling transaction signature validation](https://zips.z.cash/zip-0243)
- [ZIP-225 — Version-5 transaction format](https://zips.z.cash/zip-0225)
- [Zcash Sapling ZIP32 reference vectors](https://github.com/zcash/zcash-test-vectors/blob/master/test-vectors/json/sapling_zip32.json)
- [Pinned Zcash Sapling key-component and nullifier vectors](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/test-vectors/json/sapling_key_components.json)
- [Pinned Zcash Sapling MerkleCRH and tree reference](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/merkle_tree.py)
- [Pinned Sapling commitment-tree reference implementation](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/tree.rs)
- [Pinned incremental Merkle tree implementation](https://github.com/zcash/incrementalmerkletree/tree/0.9.0/incrementalmerkletree/src)
- Independent expected outputs: [`tests/fixtures/sapling_merkle_tree_reference.json`](../tests/fixtures/sapling_merkle_tree_reference.json).
- BitcoinZ network, upgrade, and parameter provenance is recorded in
  [`src/coins/btcz.json`](../src/coins/btcz.json).

`py -3.10 -m pytest -q`: **45 passed** on Python 3.10.11;
`py -3.10 -m compileall -q src tests` passed. Wheel and sdist builds passed;
the nullifier and Merkle-tree reference fixtures are included in the sdist.
A clean-target wheel install passed `zycoin.sapling_tree` and scanner imports
plus coin-resource access. Sapling roots and paths match the pinned upstream
reference fixture. No live Lightwalletd endpoint was used for this phase, and
the BitcoinZ ZIP32 path remains gated. These vectors do not prove a Sapling
note is spendable. No spending key from production, live spend, proof
generation, or transaction broadcast was used. `git diff --check` reports only
the pre-existing trailing whitespace at `src/crypto.py:104`, which was left
unchanged.

## Sapling Groth16 proof-generation readiness

The pure-Python Groth16 audit found no implementation or package resources
for BLS12-381 G1/G2 and pairings, a Groth16 prover/verifier, Sapling Spend or
Output circuit synthesis, or authenticated Sapling spend/output proving
parameters. The existing Jubjub, ZIP32, note, nullifier, and commitment-tree
primitives do not supply those components. Coin JSON parameter filenames are
declarations only.

**Status unchanged:** Sapling spend/output proof generation and independent
proof verification remain **Unsupported**; Sapling spending remains gated.
BitcoinZ's ZIP32 account path and endpoint-derived witness/anchor trust remain
separate blockers. No proof-shaped placeholder API was added, no proving
parameters were downloaded, and no benchmark is applicable without a prover.

The audit references pinned upstream `sapling-crypto` 0.9.0 revision
`88a7946b4a3066787776e11f0a502654167e022d` for the separate Spend/Output
circuits, parameter readers, Groth16 prover API, BLS12-381 dependencies, and
192-byte proof encoding. The detailed findings and remaining blockers are in
[`sapling-groth16-proof-generation.md`](sapling-groth16-proof-generation.md).
CPython 3.10.11 regression tests for this audit state: **47 passed**.

### Follow-up: BLS12-381 arithmetic and pairing

The subsequent Phase 9.19 implementation adds pure-Python Fp/Fr/Fp2/Fp6/Fp12
arithmetic, G1/G2 operations and compressed encodings, subgroup checks, and an
optimal-Ate pairing. The generator pairing matches all twelve Fp12
coefficients from pinned independent `py_ecc` v8.0.0 reference output, and a
pairing bilinearity regression test passes. This updates only the BLS primitive
status: Sapling circuits, proving parameters, Groth16 proof generation and
verification, Sapling signatures, and transaction assembly remain
unsupported; Sapling spending remains gated. The pairing implementation is
not constant-time or production-ready. Details and benchmark measurements are
in [`bls12-381-arithmetic-and-pairing.md`](bls12-381-arithmetic-and-pairing.md).

### Follow-up: Sapling circuit foundation

Phase 9.20 adds a generic scalar-field R1CS builder, deterministic witness-free
shape serialization, and local foundation tests. It does not implement any
Sapling-specific gadget or either circuit. Pinned upstream v0.9.0 reference
tests assert 98,777 Spend constraints and 7,827 Output constraints, but ZyCoin
does not yet synthesize or reproduce either circuit, public-input vector,
constraint hash, or count. Proof generation, signatures, transaction
construction, and Sapling spending remain unsupported/gated. See
[`sapling-circuit-implementation.md`](sapling-circuit-implementation.md).
