# ZyCoin

ZyCoin is a Python library for discovering JSON-backed coin networks, deriving
transparent wallet keys and addresses, and using asynchronous Electrum,
Bitcore, and Lightwalletd clients. It also contains shared Sapling ZIP32 wallet
derivation, bounded Sapling compact-output trial decryption, and a narrowly
gated offline transparent transaction signing API.

The package intentionally distinguishes configured behavior from verified
behavior. A JSON entry is not proof that a coin's network parameters or public
endpoint are correct. In particular, do not treat an unverified derivation path
as a wallet standard.

## Requirements and installation

- Python 3.10 or later (examples and tests in this repository use Python
  3.10.11).
- Install from the repository root:

  ```powershell
  py -3.10 -m pip install .
  ```

- The package uses `ecdsa`, `pyaes`, `aiohttp`, `websockets`, `grpcio`, and
  `protobuf`; package installation resolves these dependencies.

## Coins and networks

Coin definitions are loaded from packaged JSON files under `src/coins/`.
Discovery is dynamic: the library validates every `*.json` definition and does
not maintain a fixed coin list. A configuration can be added without writing a
coin-specific Python module.

```python
from zycoin.coins import get_coin_config, get_coin_ids, get_coin_network

print(get_coin_ids())
for coin_id in get_coin_ids():
    coin = get_coin_config(coin_id)
    for network_id in coin.networks:
        network = get_coin_network(coin_id, network_id)
        print(
            coin_id,
            network_id,
            network.transparent_derivation["status"],
            network.sapling["status"],
        )
```

In the current repository configuration, the IDs discovered are `btcz`,
`flux`, `glink`, `kmdcl`, `zcl`, `zec`, `zer`, and `zerc`. Network availability
and capabilities vary by definition. Read each network's `transparent`,
`sapling`, `electrum`, `bitcore`, and `lightwalletd` status/configuration
before using it. Missing or unverified values are not inferred by the library.

## BIP-39 key derivation and addresses

A BIP-39 mnemonic is the recovery phrase. Its optional BIP-39 passphrase is
normalized and included in seed derivation, so changing it changes the keys and
addresses. A wallet password is separate: it is used only when encrypting or
decrypting an exported key record. Derivation and in-memory address generation
do not require a wallet password. ZyCoin does not save keys or create a storage
backend.

Transparent wallets use the configured, verified BIP-44 path and coin/network
parameters. Sapling wallets use their separately verified ZIP32 path and
Sapling address parameters. The derivation standards are never interchanged.

```python
from zycoin.mnemonic import generate_mnemonic
from zycoin.wallet import SaplingWallet, TransparentWallet

phrase = generate_mnemonic()
passphrase = "optional BIP-39 passphrase"
transparent = TransparentWallet.from_mnemonic(
    phrase, "zec", network="mainnet", passphrase=passphrase
)
sapling = SaplingWallet.from_mnemonic(
    phrase, network="zec-mainnet", passphrase=passphrase
)

transparent_address = transparent.address(index=0, change=0)
sapling_address = sapling.default_payment_address(account=0).encode()
# Do not print or persist the phrase or private key material.
```

The branches are independent. Create only the branch you need. `TransparentWallet`
provides `address()` for P2PKH addresses and `derive_private_key()` when a library
operation needs the child key; the latter returns sensitive bytes. `SaplingWallet`
provides `default_payment_address()`, `payment_address()`, viewing-key accessors,
and `derive_spending_key()` for operations that need the ZIP32 key. Address-only
methods derive from the private wallet internally but return only the address.

```python
from zycoin.wallet import TransparentWallet

wallet = TransparentWallet.from_mnemonic(phrase, "zec", account=0)
address = wallet.address()
```

```python
from zycoin.wallet import SaplingWallet

wallet = SaplingWallet.from_mnemonic(phrase, network="zec-mainnet")
address = wallet.default_payment_address().encode()
```

To persist key material yourself, explicitly request an encrypted record and
supply a distinct wallet password. No file or database is written by these
methods. Here `wallet_password` is supplied by the caller and is not the
BIP-39 passphrase.

```python
transparent_record = transparent.to_record(wallet_password)
sapling_record = sapling.to_record(wallet_password)
transparent_copy = TransparentWallet.from_record(
    transparent_record, wallet_password
)
sapling_copy = SaplingWallet.from_record(sapling_record, wallet_password)
```

Both `from_record(record, password)` methods reject incorrect passwords.
`SaplingWallet.restore(record, password)` remains as an alias for
`from_record`. The former required password argument to
`SaplingWallet.from_mnemonic` has been removed; pass the BIP-39 passphrase via
`passphrase=` instead. The lower-level `from_bip39_seed()` remains available for
callers that already manage BIP-44 paths and keystore operations; its historical
optional `password=` parameter still encrypts that keystore for compatibility.
`sign_transaction()` no longer takes a wallet password; it derives keys in
memory and does not export or persist them.

Sapling wallet derivation is gated by verified ZIP32 parameters. In the current
configuration, Zcash mainnet has a verified path `m/32'/133'/{account}'`;
BitcoinZ's ZIP32 path is explicitly unverified and wallet derivation is disabled.
Other networks may have partial Sapling configuration without enough data for a
wallet. If derivation is not verified, the wallet API raises
`SaplingCapabilityError`. Python does not guarantee secure key zeroization.

## Electrum and Bitcore clients

Client instances use a loaded `CoinNetworkConfig`, and asynchronous operations
must run inside an event loop. Electrum chooses among the configured servers
and ports; the example bounds connection and query time and only reads history
and, if present, one transaction.

```python
import asyncio

from zycoin.clients.electrum import ElectrumClient
from zycoin.coins import get_coin_network
from zycoin.mnemonic import generate_mnemonic
from zycoin.wallet import TransparentWallet


async def main():
    coin_id, network_id = "btcz", "mainnet"
    network = get_coin_network(coin_id, network_id)
    wallet = TransparentWallet.from_mnemonic(generate_mnemonic(), coin_id, network=network_id)
    address = wallet.address()
    client = ElectrumClient(network, protocol="ssl")
    try:
        await asyncio.wait_for(client.connect(), timeout=10)
        history = await asyncio.wait_for(client.get_history(address), timeout=10)
        print("history entries:", len(history))
        if history:
            tx = await asyncio.wait_for(
                client.get_transaction(history[0]["tx_hash"]),
                timeout=10,
            )
            print("transaction retrieved:", tx is not None)
    finally:
        await client.close()


asyncio.run(main())
```

Bitcore exposes HTTP API methods and an optional Socket.IO event connection.
History requests are limited here; the client closes its HTTP and event
resources in `finally`.

```python
import asyncio

from zycoin.clients.bitcore import BitcoreClient
from zycoin.coins import get_coin_network
from zycoin.mnemonic import generate_mnemonic
from zycoin.wallet import TransparentWallet


async def main():
    coin_id, network_id = "btcz", "mainnet"
    network = get_coin_network(coin_id, network_id)
    wallet = TransparentWallet.from_mnemonic(generate_mnemonic(), coin_id, network=network_id)
    address = wallet.address()
    client = BitcoreClient(network, timeout=5)
    try:
        await asyncio.wait_for(client.connect(), timeout=10)
        history = await asyncio.wait_for(
            client.get_history(address, limit=5),
            timeout=10,
        )
        print("history entries:", len(history))
        if history:
            tx = await asyncio.wait_for(
                client.get_transaction(history[0]["tx_hash"]),
                timeout=10,
            )
            print("transaction retrieved:", tx is not None)
    finally:
        await client.close()


asyncio.run(main())
```

An unconfigured or unavailable server raises a connection/RPC/HTTP error; it
does not imply that the corresponding client implementation is unsupported.
No client example calls transaction broadcast.

## Lightwalletd scanning and Sapling note trial decryption

Lightwalletd scans are inclusive and bounded. `scan_transparent` returns
transparent transactions for the requested addresses. `scan_sapling_compact_outputs`
returns compact Sapling outputs; these contain only the 52-byte encrypted
plaintext prefix, not the complete ciphertext, AEAD tag, or memo.
`scan_sapling_notes` applies IVK/FVK trial decryption and checks the note
commitment. `None` from `decrypt_sapling_compact_output` means no valid note
was found for that key. A returned compact note is not AEAD-authenticated.

## Sapling commitment-tree positions and witnesses

`SaplingCommitmentTree` implements the 32-level Sapling commitment tree and
accepts canonical 32-byte note commitments in consensus order. `append()`
returns the global Sapling note-tree position; a transaction's output index is
not that position. `root` returns the current 32-byte anchor. `witness(position)`
returns a `SaplingMerkleWitness` containing the 32 sibling nodes, position,
network identity, and anchor. The witness verifies its path on construction
and exposes `verify()` and `update(tree)`. Witnesses record their original tree
size; updating one requires the new tree to retain the same root at that
historical size, so a witness from a divergent same-network tree is rejected.

The ordinary compact-output scanner deliberately does not assign positions.
`scan_sapling_commitment_tree` does so only for a complete scan beginning at
the configured Sapling activation height. It requires ordered, unique
transactions, contiguous block hashes, per-block `chainMetadata`, and an
exact match between each reported Sapling tree size and the commitments
appended so far. The scanner also requires configured `GetBlock` and
`GetLatestBlock` support, checks the activation predecessor, confirms the
requested range is at or below the initial tip, and re-fetches the final block
to detect a changed chain during the scan. Missing or inconsistent data raises
a scan error rather than returning positions that look valid.

The returned paths are relative to the final scanned tree root. This does not
authenticate Lightwalletd responses against independently verified block
headers: the client-provided tree sizes and block hashes are consistency
checks, not a consensus proof. A scan is therefore only as trustworthy as its
endpoint and the completeness of its compact data. The implementation retains
commitments in memory to generate/update paths; memory use grows with the
number of scanned Sapling outputs. Requests remain bounded by `max_blocks`
and `max_outputs`. These boundary and reorg checks improve endpoint
consistency, but do not independently verify positions or anchors against
consensus.

### Independent Sapling tree reference verification

The local commitment-tree roots and witness paths are compared byte-for-byte
with a fixture generated by the
[pinned upstream `zcash/sapling-crypto` 0.9.0 revision](https://github.com/zcash/sapling-crypto/tree/88a7946b4a3066787776e11f0a502654167e022d)
(`88a7946b4a3066787776e11f0a502654167e022d) and
its [`incrementalmerkletree` 0.9.0](https://github.com/zcash/incrementalmerkletree/tree/0.9.0/incrementalmerkletree/src)
dependency. The fixture records roots for
the empty tree and each prefix of four canonical leaves, plus every witness
path and anchor at each prefix. The upstream `IncrementalWitness` is advanced
after each append, independently checking incremental updates. Expected
outputs are preserved in
[`tests/fixtures/sapling_merkle_tree_reference.json`](../tests/fixtures/sapling_merkle_tree_reference.json);
the fixture records upstream repositories, exact revisions, and protocol
parameters. The reference implementation is external; this Python-only
project does not include a Rust generator or native Rust dependency.

The upstream reference also checks the pinned upstream MerkleCRH known-answer
vector and that a structurally full 32-level tree has capacity `2^32` and
rejects another append. Tests cover reordered or missing leaves, invalid
positions, corrupted paths, incorrect anchors, and witness updates. This
verifies tree calculations for supplied ordered commitments; it does not
verify that endpoint-supplied commitments or positions match consensus data.
Scanner positions remain **Partially Verified**, and BitcoinZ Sapling spending
remains gated.

Example: make a small, read-only Zcash scan beginning at Sapling activation.
The short range is for API demonstration; it does not produce a spendable-note
claim. A server that omits tree metadata is not eligible for position tracking.

```python
import asyncio

from zycoin.clients.lightwalletd import LightwalletdClient
from zycoin.coins import get_coin_network
from zycoin.scanning import scan_sapling_commitment_tree


async def main():
    network = get_coin_network("zec", "mainnet")
    if not network.lightwalletd_endpoints:
        raise RuntimeError("no Lightwalletd endpoint is configured")
    endpoint = network.lightwalletd_endpoints[0]
    host, separator, port = endpoint.rpartition(":")
    if not separator:
        raise ValueError("configured Lightwalletd endpoint must include a port")

    client = LightwalletdClient(host, int(port), tls=True, rpc_timeout=10)
    activation = network.sapling["activation_height"]
    try:
        await client.connect()
        latest = await client.get_latest_block(timeout=10)
        if latest.height < activation:
            raise RuntimeError("the endpoint has not reached Sapling activation")
        end_height = min(activation + 1, latest.height)
        result = await scan_sapling_commitment_tree(
            client,
            network=network,
            start_height=activation,
            end_height=end_height,
            max_blocks=end_height - activation + 1,
            max_outputs=100,
            timeout=10,
        )
        if result.outputs:
            output = result.outputs[0]
            witness = result.witness_for(output)
            print(output.position, witness.anchor.hex(), witness.verify())
    finally:
        await client.close()


asyncio.run(main())
```

`ScanCapabilityError` indicates the configured network, endpoint activation,
or required tree metadata is unavailable; `ScanError` indicates malformed,
incomplete, or inconsistent block/commitment data. Replaying a historical
range from activation may exceed practical output and memory bounds. Do not
use a partial scan's positions or root as a spending witness.

The example uses a deterministic, public upstream Zcash test-vector IVK solely
to demonstrate the API; it is not a wallet key. Replace it only with an
appropriately protected viewing key that you control. A random generated
wallet is not expected to match chain outputs.

```python
import asyncio

from zycoin.clients.lightwalletd import LightwalletdClient
from zycoin.coins import get_coin_network
from zycoin.mnemonic import generate_mnemonic
from zycoin.wallet import TransparentWallet
from zycoin.scanning import (
    scan_sapling_compact_outputs,
    scan_sapling_notes,
    scan_transparent,
)


async def main():
    coin_id, network_id = "btcz", "mainnet"
    network = get_coin_network(coin_id, network_id)
    endpoints = network.lightwalletd_endpoints
    if not endpoints:
        raise RuntimeError("no Lightwalletd endpoint is configured")
    host, separator, port = endpoints[0].rpartition(":")
    if not separator:
        raise ValueError("configured Lightwalletd endpoint must include a port")

    wallet = TransparentWallet.from_mnemonic(generate_mnemonic(), coin_id, network=network_id)
    address = wallet.address()
    client = LightwalletdClient(
        host,
        int(port),
        tls=True,
        connection_timeout=5,
        rpc_timeout=10,
    )
    try:
        await client.connect()
        latest = await client.get_latest_block(timeout=10)
        start = max(0, latest.height - 9)
        transactions = await scan_transparent(
            client,
            [address],
            network=network,
            start_height=start,
            end_height=latest.height,
            max_blocks=10,
            max_transactions=100,
            timeout=10,
        )
        print("transparent matches:", len(transactions))

        compact_outputs = await scan_sapling_compact_outputs(
            client,
            network=network,
            start_height=start,
            end_height=latest.height,
            max_blocks=10,
            max_outputs=100,
            timeout=10,
        )
        print("Sapling compact outputs:", len(compact_outputs))

        # Published test-vector material, not a private wallet key.
        reference_ivk = bytes.fromhex(
            "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
        )
        notes = await scan_sapling_notes(
            client,
            reference_ivk,
            network=network,
            start_height=start,
            end_height=latest.height,
            max_blocks=10,
            max_outputs=100,
            timeout=10,
        )
        print("matching reference-vector notes:", len(notes))
    finally:
        await client.close()


asyncio.run(main())
```

To try an FVK instead of the IVK in `scan_sapling_notes`, pass the
`ExtendedFullViewingKey` returned by `SaplingWallet.full_viewing_key()` or its
serialized 169-byte form. FVK and IVK data are sensitive. A key derived from an
arbitrary fresh phrase will normally return no matching notes.

This example shows direct compact-output trials using both forms on a bounded
Zcash scan. It generates a disposable local phrase, does not display any key
material, and is expected to find no matches.

```python
import asyncio

from zycoin.addresses import get_network
from zycoin.clients.lightwalletd import LightwalletdClient
from zycoin.coins import get_coin_network
from zycoin.mnemonic import generate_mnemonic
from zycoin.note_decryption import decrypt_sapling_compact_output
from zycoin.scanning import scan_sapling_compact_outputs
from zycoin.wallet import SaplingWallet


async def main():
    network = get_network("zec-mainnet")
    coin_network = get_coin_network("zec", "mainnet")
    host, separator, port = coin_network.lightwalletd_endpoints[0].rpartition(":")
    if not separator:
        raise ValueError("configured Lightwalletd endpoint must include a port")

    wallet = SaplingWallet.from_mnemonic(
        generate_mnemonic(),
        network=network.name,
    )
    ivk = wallet.incoming_viewing_key(account=0)
    fvk = wallet.full_viewing_key(account=0)
    client = LightwalletdClient(
        host,
        int(port),
        tls=True,
        connection_timeout=5,
        rpc_timeout=10,
    )
    try:
        await client.connect()
        latest = await client.get_latest_block(timeout=10)
        start = max(network.sapling_activation_height, latest.height - 4)
        outputs = await scan_sapling_compact_outputs(
            client,
            network=coin_network,
            start_height=start,
            end_height=latest.height,
            max_blocks=5,
            max_outputs=50,
            timeout=10,
        )
        ivk_matches = []
        fvk_matches = []
        for output in outputs:
            ivk_note = decrypt_sapling_compact_output(output, ivk, coin_network)
            fvk_note = decrypt_sapling_compact_output(output, fvk, coin_network)
            if ivk_note is not None:
                ivk_matches.append(ivk_note)
            if fvk_note is not None:
                fvk_matches.append(fvk_note)
        print("IVK matches:", len(ivk_matches))
        print("FVK matches:", len(fvk_matches))
    finally:
        await client.close()


asyncio.run(main())
```

To test the shared decryptor directly against the upstream Zcash v1 reference
fixture:

```python
from zycoin.coins import get_coin_network
from zycoin.note_decryption import decrypt_sapling_compact_output
from zycoin.scanning import SaplingCompactOutput

network = get_coin_network("zec", "mainnet")
output = SaplingCompactOutput(
    txid="published-zcash-reference-vector",
    height=0,
    transaction_index=1,
    output_index=0,
    cmu=bytes.fromhex(
        "635572f572a8a1a0b7acbc0afc6d66f14a02efacde7bdf03443ed4c3e551d470"
    ),
    ephemeral_key=bytes.fromhex(
        "ded68f05c658fcae5ae218646ff844406f84426784040d0bef2b09cb3848c4dc"
    ),
    ciphertext_prefix=bytes.fromhex(
        "8d6b27e7eff59bfba01d6588badd366ce59b4d5b0ef93bebcbf211417c56ae7"
        "00ae18244bac2fb6437db01f83dc149e2786ec4ec"
    ),
)
reference_ivk = bytes.fromhex(
    "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
)
zip212_height = network.sapling["zip212_activation_height"]
note = decrypt_sapling_compact_output(
    output,
    reference_ivk,
    network,
    height=zip212_height - 1,
)
assert note is not None
print(note.value, note.zip212_version)
```

The v1 vector above is a Zcash reference fixture, not a BitcoinZ transaction.
The library's BitcoinZ decryption parameters and ZIP-212 behavior have shared
fixture coverage, but no verified BitcoinZ on-chain note/key pair is included
in this repository. Do not interpret that fixture or a successful compact
output scan as proof of BitcoinZ real-chain note decryption.

## Sapling spending status

The shared ZIP32 implementation derives extended spending keys, authorization
key components, nullifier-key components, outgoing viewing keys, and viewing
keys. Its ZIP32 master, hardened-child, external-viewing-child, internal key,
and nullifier derivation transformations are covered by upstream Zcash
vectors. This validates key derivation rules; it does not make the result a
spendable note or a signer. The BTCZ mainnet path
`m/32'/177'/{account}'` remains unverified and is gated.

Sapling spend construction is **not implemented**. Ordinary scanned compact
outputs and decrypted notes do not contain a commitment-tree authentication
path or global note position. The separate full-tree scanner can compute
endpoint-attested positions and paths only when it starts at Sapling activation
and verifies the returned ordering and per-block tree sizes. It does not
independently authenticate the endpoint's chain data. The Lightwalletd
protobuf's tree-state and subtree-root RPCs are not implemented.

Validated note nullifier derivation is implemented and matches the upstream
Sapling key-component vectors. Given an independently verified note-tree
position, the API derives a nullifier from the validated note commitment and
the corresponding `nk`. The scanner does not match local nullifiers against
chain spends. Ordinary compact scanning alone does not provide enough
information to derive a spendable note's nullifier. The BitcoinZ ZIP32 account
path remains unverified and gated.

Offline Sapling Merkle tree and authentication-path construction match the
pinned Zcash reference fixture. Full-chain scanner positioning is **partially
verified** because Lightwalletd tree sizes and hashes are consistency checks,
not independent block-header or consensus proofs. This does not establish
spendability, particularly for BitcoinZ whose ZIP32 path remains gated.

Sapling spend proofs, Sapling output proofs, spend authorization signatures,
binding signatures, and Sapling transaction assembly/serialization remain
missing. ZyCoin now includes a pure-Python BLS12-381 arithmetic and pairing
module, but it does not implement Sapling circuits, Groth16, or authenticated
proving parameters. Coin configuration parameter filenames are declarations,
not bundled resources. No placeholder proof/signature API is provided. The
existing transparent BitcoinZ signer does not accept or construct Sapling
spends. See the [BLS12-381 implementation report](../reports/bls12-381-arithmetic-and-pairing.md)
and the [Sapling circuit status report](../reports/sapling-circuit-implementation.md)
for the generic R1CS foundation, upstream circuit inputs/counts, and remaining
blockers. See also the [Groth16 readiness report](../reports/sapling-groth16-proof-generation.md).

The nullifier API is in `zycoin.nullifiers`. `SaplingNote` accepts the
commitment, diversifier base, transmission key, value, commitment randomness,
and ZIP-212 note version, and validates that those fields reconstruct the
supplied note commitment. Prefer `SaplingNote.from_decrypted()` to build it
from a note that has already passed compact-output decryption and commitment
validation. Then use `nullifier_deriving_key()` with an extended ZIP32 key (or
its validated 32-byte `nk`) and `derive_sapling_nullifier(nk, note, position)`.
The position must be the verified global Sapling note-tree position in
`[0, 2^32)`; transaction and output indices are not substitutes. These APIs
derive a value only and do not establish that the note has a valid witness or
can be spent.

A future spend-request contract must include, at minimum, selected notes with
validated value and note randomness, the corresponding ZIP32 account/key,
verified note-tree position and authentication path, a common verified anchor,
ordered output addresses/values and ZIP-212 randomness rules, explicit fee,
expiry height, network, and epoch-specific consensus branch ID. Construction
must reject inconsistent anchors, invalid paths, value imbalance, unsupported
ZIP-212 eras, or unverified network rules. This is a design contract only, not
a current callable API.

## Offline transparent transaction signing

The public signing API is intentionally gated to BitcoinZ mainnet and a narrow
transparent-only subset: Overwintered version 4, the configured ZIP-243
consensus branch ID, compressed BIP44-derived P2PKH inputs, and
`SIGHASH_ALL`. Sapling spends, JoinSplits, P2SH inputs, other signing hash
types, other transaction formats, and other coin/network combinations are
unsupported. A configured capability is not a claim of full coin compatibility;
see the per-network signing status in the audit.
The branch ID is the configured current Canopy ID; a future network upgrade
requires explicit re-verification and configuration before signing under new
consensus rules.

The caller supplies input outpoints, their confirmed values and addresses,
ordered outputs, and an explicit fee. The builder checks that input value minus
output value equals that fee. It does not discover UTXOs, estimate fees, select
coins, or create change automatically. Supply the change output yourself and
review all transaction details. `sign_transaction` returns serialized
transaction hex and the transaction ID. Verification returns `False` for
malformed or invalid signatures; attempting to build/sign on an unsupported
network raises `TransparentTransactionError`.

This copyable example uses a newly generated phrase and a deliberately
synthetic outpoint. It is an offline API exercise, not a spendable transaction.
Never use synthetic input data to construct a real transaction.

```python
from zycoin import (
    TransparentInput,
    TransparentOutput,
    create_unsigned_transaction,
    sign_transaction,
    verify_transaction_signatures,
)
from zycoin.mnemonic import generate_mnemonic
from zycoin.wallet import TransparentWallet

coin_id, network_id = "btcz", "mainnet"
phrase = generate_mnemonic()
wallet = TransparentWallet.from_mnemonic(phrase, coin_id, network=network_id)


def address(change, index):
    return wallet.address(index=index, change=change)


source_address = address(0, 0)
unsigned = create_unsigned_transaction(
    coin_id,
    inputs=[
        TransparentInput(
            txid="11" * 32,
            output_index=0,
            value=10_000,
            address=source_address,
            account=0,
            address_index=0,
        )
    ],
    outputs=[
        TransparentOutput(address(0, 1), 8_000),
        TransparentOutput(address(1, 0), 1_500),
    ],
    fee=500,
    network=network_id,
    expiry_height=0,
)
signed = sign_transaction(unsigned, phrase)
assert verify_transaction_signatures(unsigned, signed.raw)
print("offline signature verified:", signed.txid)
# Do not print or persist phrase, private keys, or signed raw transaction data.
# This synthetic outpoint is not a real UTXO.
```

`zip243_signature_hash` is also exposed for ZIP-243 digest verification against
reference vectors. It accepts a serialized version-4 transaction, script code,
optional transparent input index, hash type, input amount, and consensus branch
ID. The digest helper covers the ZIP-243 hash-type cases represented in the
upstream vectors; transaction signing itself is deliberately restricted to
`SIGHASH_ALL`.

## Adding a coin

1. Add `<coin-id>.json` under the packaged `coins/` directory, with a matching
   lowercase `id`.
2. Provide network prefixes, endpoint declarations, supported RPC names, and
   derivation paths only when supported by authoritative coin sources.
3. Use the existing schema status values to distinguish `supported_verified_parameters`,
   `configured_unverified`, `partial`, `unverified`, and `unsupported`.
4. Do not copy another coin's coin type, address prefixes, activation heights,
   HRPs, ZIP-212 rules, branch IDs, or endpoint support.
5. Run the tests and verify each configured endpoint separately. Registry
   discovery does not automatically verify live services or coin parameters.

No separate implementation module is needed for a coin compatible with the
existing address formats and shared client/derivation interfaces. A novel
protocol or address scheme may require a shared implementation change.

## Verification status and limitations

Statuses in the [reports index](../reports/README.md) and its linked
compatibility reports
mean:

- **Verified**: exercised against an authoritative reference fixture or a
  configured endpoint, with the evidence scope stated.
- **Partially Verified**: some behavior is exercised, but coin-specific
  parameters, a chain-linked fixture, or another part remains unverified.
- **Unverified**: insufficient evidence to claim support.
- **Unsupported**: explicitly disabled or not implemented/configured.
- **Unavailable**: a configured endpoint did not respond during a bounded test.

Endpoint availability does not establish correct coin identity or behavior.
Transparent address codec round-trips do not establish prefix provenance.
Lightwalletd compact scans do not establish that a viewing key decrypts a
chain note. The compact API omits full ciphertext and AEAD authentication data,
so successful trial decryption validates ZIP-212 constraints and the note
commitment but cannot authenticate a note's memo or complete ciphertext.
ZIP32 wallet derivation remains disabled for BitcoinZ until its path is
verified. ZIP-212 v2 synthetic tests exercise the shared rules, not a real-chain
v2 note.

This library is not a hardware wallet or audited signing system. Examples are
generated-key and test oriented. Live client examples are bounded and
read-only; the offline signing demonstration uses a synthetic outpoint and is
not spendable. No example broadcasts transactions or persists generated
recovery phrases. Keep recovery material offline, use a unique strong password
for encrypted wallet records, and review coin/network status before using any
derived address or signing capability.
