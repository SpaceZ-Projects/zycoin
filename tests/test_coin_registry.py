import asyncio
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from hashlib import blake2b
from pathlib import Path
from unittest.mock import AsyncMock, patch

from src.addresses import SaplingCapabilityError, SaplingPaymentAddress, get_network
from src.clients.bitcore import BitcoreClient
from src.clients.electrum import ElectrumClient
from src.clients.lightwalletd import LightwalletdClient
from src.clients.protocol import compact_formats_pb2, service_pb2
from src.coin_loader import get_coin_ids, load_coin_configs
from src.coin_schemas import CoinConfig, ConfigurationError
from src.crypto import (
    Enumeration,
    TYPE_ADDRESS,
    TYPE_PUBKEY,
    TYPE_SCRIPT,
    address_to_script,
    deserialize_privkey,
    get_address_from_output_script,
    hash_160,
    hash160_to_p2sh,
    opcodes,
    parse_scriptSig,
    public_key_to_p2pkh,
    script_GetOp,
    script_GetOpName,
    serialize_privkey,
)
from src.derivation import (
    SCALAR_MODULUS,
    ExtendedSpendingKey,
    _prf_expand,
    _to_scalar,
)
from src.jubjub import group_hash
from src.keystore import bip44_derivation, from_bip39_seed
from src.manager import ClientManager
from src.mnemonic import _entropy_to_mnemonic, mnemonic_to_seed
from src.note_decryption import (
    SaplingNoteDecryptionError,
    _chacha20_xor,
    _note_commitment_u,
    decrypt_sapling_compact_output,
)
from src.nullifiers import (
    SaplingNote,
    SaplingNullifierError,
    derive_sapling_nullifier,
    nullifier_deriving_key,
)
from src.scanning import (
    ScanCapabilityError,
    ScanError,
    SaplingCompactOutput,
    scan_sapling_commitment_tree,
    scan_sapling_notes,
)
from src.sapling_tree import (
    SAPLING_MERKLE_TREE_DEPTH,
    SaplingCommitmentTree,
    SaplingMerkleWitness,
    SaplingTreeError,
    merkle_hash,
)
from src.transparent import (
    TransparentInput,
    TransparentOutput,
    TransparentTransactionError,
    create_unsigned_transaction,
    sign_transaction,
    verify_transaction_signatures,
    zip243_signature_hash,
    _parse_transaction_for_test,
)
from src.wallet import SaplingWallet, TransparentWallet
from websockets.asyncio.server import serve


ROOT = Path(__file__).resolve().parents[1]


def make_zip212_v2_output(ivk, height, transaction_index=1):
    rseed = bytes(range(32))
    diversifier = None
    diversifier_base = None
    for candidate in range(256):
        candidate_bytes = candidate.to_bytes(11, "little")
        base = group_hash(b"Zcash_gd", candidate_bytes)
        if base is not None:
            diversifier = candidate_bytes
            diversifier_base = base
            break
    if diversifier_base is None:
        raise AssertionError("could not construct a valid test diversifier")

    rcm = _to_scalar(_prf_expand(rseed, b"\x04"))
    esk = _to_scalar(_prf_expand(rseed, b"\x05"))
    if not esk:
        raise AssertionError("test rseed unexpectedly derived a zero esk")
    transmission_key = diversifier_base.multiply(ivk)
    ephemeral_key = diversifier_base.multiply(esk).encode()
    value = 123_456_789
    cmu = _note_commitment_u(
        rcm,
        diversifier_base,
        transmission_key,
        value,
    )
    plaintext = (
        b"\x02"
        + diversifier
        + value.to_bytes(8, "little")
        + rseed
    )
    shared_secret = (
        group_hash(b"Zcash_gd", diversifier)
        .multiply(ivk * 8)
        .multiply(esk)
        .encode()
    )
    key = blake2b(
        shared_secret + ephemeral_key,
        digest_size=32,
        person=b"Zcash_SaplingKDF",
    ).digest()
    return SaplingCompactOutput(
        txid="synthetic-zip212-v2",
        height=height,
        transaction_index=transaction_index,
        output_index=0,
        cmu=cmu,
        ephemeral_key=ephemeral_key,
        ciphertext_prefix=_chacha20_xor(key, plaintext),
    )


class CoinRegistryTests(unittest.TestCase):
    def setUp(self):
        self.configs = load_coin_configs(reload=True)
        self.mnemonic = _entropy_to_mnemonic(bytes(32))

    def test_registry_discovers_every_json_definition(self):
        expected = tuple(sorted(path.stem for path in (ROOT / "src" / "coins").glob("*.json")))
        self.assertEqual(get_coin_ids(), expected)
        self.assertEqual(tuple(sorted(self.configs)), expected)

    def test_new_json_is_discovered_without_restarting_loader(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            template = json.loads((ROOT / "src" / "coins" / "zec.json").read_text())
            template["id"] = "auditcoin"
            template["name"] = "Audit Coin"
            template["symbol"] = "AUD"
            (root / "auditcoin.json").write_text(json.dumps(template))
            with patch("src.coin_loader._DEFINITIONS", root):
                self.assertEqual(tuple(load_coin_configs()), ("auditcoin",))
                template["id"] = "secondcoin"
                template["name"] = "Second Coin"
                template["symbol"] = "SEC"
                (root / "secondcoin.json").write_text(json.dumps(template))
                self.assertEqual(
                    tuple(sorted(load_coin_configs())),
                    ("auditcoin", "secondcoin"),
                )

    def test_verified_derivation_templates_match_coin_identity(self):
        for coin_id, coin in self.configs.items():
            for network_id, network in coin.networks.items():
                transparent = network.transparent_derivation
                if transparent.get("status") == "supported_verified_parameters":
                    expected = f"m/44'/{transparent['coin_type']}'/{{account}}'"
                    self.assertEqual(transparent["path"], expected)
                    self.assertEqual(
                        bip44_derivation(7, coin_id, network_id),
                        expected.format(account=7),
                    )

                sapling = network.sapling
                if sapling.get("derivation_path_status") == "supported_verified_parameters":
                    expected = f"m/32'/{sapling['zip32_coin_type']}'/{{account}}'"
                    self.assertEqual(sapling["derivation_path"], expected)
                    self.assertEqual(
                        sapling["zip32_coin_type"],
                        transparent.get("coin_type"),
                    )

    def test_every_address_prefix_has_verified_upstream_provenance(self):
        for path in sorted((ROOT / "src" / "coins").glob("*.json")):
            definition = json.loads(path.read_text(encoding="utf-8"))
            for network_id, network in definition["networks"].items():
                address = network["address"]
                with self.subTest(coin=path.stem, network=network_id):
                    self.assertEqual(address["verification"], "verified")
                    self.assertTrue(address["verification_sources"])

    def test_bip44_paths_derive_and_serialize_for_verified_networks(self):
        for coin_id, coin in self.configs.items():
            for network_id, network in coin.networks.items():
                if network.transparent_derivation.get(
                    "status"
                ) != "supported_verified_parameters":
                    continue
                path = bip44_derivation(0, coin_id, network_id)
                store = from_bip39_seed(
                    self.mnemonic,
                    "",
                    path,
                    coin_id,
                    network_id,
                    password="unit-test-only",
                )
                public_key = bytes.fromhex(store.derive_pubkey(0, 0))
                address = public_key_to_p2pkh(public_key, network)
                expected_script = (
                    "76a914" + hash_160(public_key).hex() + "88ac"
                )
                self.assertEqual(address_to_script(address, network), expected_script)

                secret = bytes(31) + b"\x01"
                encoded = serialize_privkey(
                    secret,
                    True,
                    "p2pkh",
                    internal_use=True,
                    net=network,
                )
                self.assertEqual(deserialize_privkey(encoded, network)[1], secret)

    def test_address_serialization_round_trips_configured_prefixes(self):
        public_key = bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        key_hash = hash_160(public_key)
        for coin in self.configs.values():
            for network in coin.networks.values():
                if network.p2pkh_prefix is not None:
                    address = public_key_to_p2pkh(public_key, network)
                    self.assertTrue(address_to_script(address, network).startswith("76a914"))
                if network.p2sh_prefix is not None:
                    address = hash160_to_p2sh(key_hash, network)
                    self.assertTrue(address_to_script(address, network).startswith("a914"))

    def test_p2pkh_serialization_matches_published_reference_vector(self):
        public_key = bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        network = replace(
            self.configs["zec"].get_network("mainnet"),
            p2pkh_prefix=b"\x00",
        )
        self.assertEqual(
            public_key_to_p2pkh(public_key, network),
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        )

    def test_script_opcode_parser_and_standard_output_script_detection(self):
        test_enum = Enumeration("test", [("OP_FIRST", 4), "OP_SECOND"])
        self.assertEqual(test_enum.OP_SECOND, 5)
        self.assertEqual(test_enum.whatis(4), "OP_FIRST")
        self.assertEqual(opcodes.OP_0, 0)
        self.assertEqual(opcodes.OP_PUSHDATA1, 76)
        self.assertEqual(opcodes.OP_PUSHDATA2, 77)
        self.assertEqual(opcodes.OP_PUSHDATA4, 78)
        self.assertEqual(opcodes.OP_CHECKSIG, 172)
        self.assertEqual(opcodes.whatis(0xB1), "OP_CHECKLOCKTIMEVERIFY")
        self.assertEqual(script_GetOpName(opcodes.OP_CHECKSIG), "CHECKSIG")
        self.assertEqual(
            list(script_GetOp(bytes((2, 0xAA, 0xBB, opcodes.OP_CHECKSIG)))),
            [(2, b"\xaa\xbb", 3), (opcodes.OP_CHECKSIG, None, 4)],
        )
        self.assertEqual(
            list(script_GetOp(bytes((opcodes.OP_PUSHDATA1, 2, 0xAA, 0xBB)))),
            [(opcodes.OP_PUSHDATA1, b"\xaa\xbb", 4)],
        )
        self.assertEqual(
            list(script_GetOp(
                bytes((opcodes.OP_PUSHDATA2, 2, 0, 0xAA, 0xBB))
            )),
            [(opcodes.OP_PUSHDATA2, b"\xaa\xbb", 5)],
        )
        self.assertEqual(
            list(script_GetOp(
                bytes((opcodes.OP_PUSHDATA4, 2, 0, 0, 0, 0xAA, 0xBB))
            )),
            [(opcodes.OP_PUSHDATA4, b"\xaa\xbb", 7)],
        )
        self.assertIsNone(parse_scriptSig({}, bytes((opcodes.OP_DUP,))))
        with patch("builtins.print") as print_mock:
            parse_scriptSig({}, bytes((opcodes.OP_PUSHDATA1,)))
        print_mock.assert_called_once()

        network = self.configs["zec"].get_network("mainnet")
        public_key = bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        p2pk_script = bytes((len(public_key),)) + public_key + bytes(
            (opcodes.OP_CHECKSIG,)
        )
        self.assertEqual(
            get_address_from_output_script(p2pk_script, net=network),
            (TYPE_PUBKEY, public_key.hex()),
        )

        p2pkh_address = public_key_to_p2pkh(public_key, network)
        self.assertEqual(
            get_address_from_output_script(
                bytes.fromhex(address_to_script(p2pkh_address, network)),
                net=network,
            ),
            (TYPE_ADDRESS, p2pkh_address),
        )

        p2sh_hash = bytes(range(20))
        p2sh_address = hash160_to_p2sh(p2sh_hash, network)
        self.assertEqual(
            get_address_from_output_script(
                bytes.fromhex(address_to_script(p2sh_address, network)),
                net=network,
            ),
            (TYPE_ADDRESS, p2sh_address),
        )

        unknown_script = bytes((opcodes.OP_RETURN, 1, 0x42))
        self.assertEqual(
            get_address_from_output_script(unknown_script, net=network),
            (TYPE_SCRIPT, unknown_script.hex()),
        )

    def test_multiple_accounts_and_indices_derive_for_verified_networks(self):
        for coin_id, coin in self.configs.items():
            for network_id, network in coin.networks.items():
                if network.transparent_derivation.get(
                    "status"
                ) != "supported_verified_parameters":
                    continue
                for account in (0, 1):
                    store = from_bip39_seed(
                        self.mnemonic,
                        "",
                        bip44_derivation(account, coin_id, network_id),
                        coin_id,
                        network_id,
                        password="zycoin-audit-test",
                    )
                    for for_change in (0,):
                        for index in (0, 7):
                            public_key = bytes.fromhex(
                                store.derive_pubkey(for_change, index)
                            )
                            address = public_key_to_p2pkh(public_key, network)
                            self.assertTrue(address)
                            self.assertTrue(
                                address_to_script(address, network).startswith(
                                    "76a914"
                                )
                            )

    def test_zip32_derivation_and_sapling_address_round_trip(self):
        network = get_network("zec-mainnet")
        root = ExtendedSpendingKey.master(mnemonic_to_seed(self.mnemonic))
        account = root.derive_path(network.default_derivation_path.format(account=0))
        address = account.to_full_viewing_key().derive_address(0, network)
        self.assertEqual(
            SaplingPaymentAddress.decode(address.encode(), network),
            address,
        )

    def test_same_bip39_phrase_derives_verified_transparent_and_sapling_branches(self):
        coin_id, network_id = "zec", "mainnet"
        transparent_path = bip44_derivation(0, coin_id, network_id)
        transparent_wallet = from_bip39_seed(
            self.mnemonic,
            "",
            transparent_path,
            coin_id,
            network_id,
            password="test-only-password",
        )
        sapling_wallet = SaplingWallet.from_mnemonic(
            self.mnemonic,
            network="zec-mainnet",
        )

        self.assertEqual(transparent_path, "m/44'/133'/0'")
        self.assertEqual(
            sapling_wallet.network.default_derivation_path.format(account=0),
            "m/32'/133'/0'",
        )
        self.assertEqual(
            mnemonic_to_seed(self.mnemonic),
            mnemonic_to_seed(self.mnemonic, passphrase=""),
        )
        self.assertTrue(transparent_wallet.derive_pubkey(0, 0))
        self.assertTrue(sapling_wallet.default_payment_address(account=0).encode())

    def test_high_level_wallet_derivation_and_encrypted_records(self):
        coin_id, network_id = "zec", "mainnet"
        transparent = TransparentWallet.from_mnemonic(
            self.mnemonic, coin_id, network_id
        )
        sapling = SaplingWallet.from_mnemonic(
            self.mnemonic, network="zec-mainnet"
        )
        self.assertTrue(transparent.address())
        self.assertTrue(transparent.derive_private_key())
        self.assertTrue(sapling.default_payment_address().encode())

        password = "record-encryption-test"
        transparent_record = transparent.to_record(password)
        sapling_record = sapling.to_record(password)
        self.assertNotIn("xprv", transparent_record)
        self.assertIn("encrypted_xprv", transparent_record)
        self.assertIn("encrypted_xsk", sapling_record)

        restored_transparent = TransparentWallet.from_record(
            transparent_record, password
        )
        restored_sapling = SaplingWallet.from_record(sapling_record, password)
        self.assertEqual(restored_transparent.address(), transparent.address())
        self.assertEqual(
            restored_transparent.derive_private_key(),
            transparent.derive_private_key(),
        )
        self.assertEqual(
            restored_sapling.default_payment_address().encode(),
            sapling.default_payment_address().encode(),
        )
        with self.assertRaises(ValueError):
            TransparentWallet.from_record(transparent_record, "wrong-password")
        with self.assertRaises(ValueError):
            SaplingWallet.from_record(sapling_record, "wrong-password")

    def test_bip39_passphrase_changes_both_key_branches_and_addresses(self):
        transparent_a = TransparentWallet.from_mnemonic(
            self.mnemonic, "zec", passphrase="alpha"
        )
        transparent_b = TransparentWallet.from_mnemonic(
            self.mnemonic, "zec", passphrase="beta"
        )
        sapling_a = SaplingWallet.from_mnemonic(
            self.mnemonic, passphrase="alpha"
        )
        sapling_b = SaplingWallet.from_mnemonic(
            self.mnemonic, passphrase="beta"
        )
        self.assertNotEqual(
            transparent_a.derive_private_key(),
            transparent_b.derive_private_key(),
        )
        self.assertNotEqual(transparent_a.address(), transparent_b.address())
        self.assertNotEqual(
            sapling_a.derive_spending_key().serialize(),
            sapling_b.derive_spending_key().serialize(),
        )
        self.assertNotEqual(
            sapling_a.default_payment_address().encode(),
            sapling_b.default_payment_address().encode(),
        )

    def test_transparent_addresses_are_generated_on_verified_networks(self):
        for coin_id, coin in self.configs.items():
            for network_id, network in coin.networks.items():
                if (
                    network.transparent_derivation.get("status")
                    != "supported_verified_parameters"
                    or network.p2pkh_prefix is None
                ):
                    continue
                with self.subTest(coin=coin_id, network=network_id):
                    wallet = TransparentWallet.from_mnemonic(
                        self.mnemonic, coin_id, network_id
                    )
                    address = wallet.address()
                    self.assertTrue(
                        address_to_script(address, network).startswith("76a914")
                    )

    def test_low_level_transparent_derivation_does_not_need_password(self):
        store = from_bip39_seed(
            self.mnemonic,
            "",
            bip44_derivation(0, "zec"),
            "zec",
        )
        self.assertTrue(store.derive_pubkey(0, 0))
        self.assertTrue(store.get_private_key([0, 0], None)[0])

    def test_zip32_master_matches_upstream_reference_vector(self):
        # Reference: zcash/zcash-test-vectors sapling_zip32.json.
        root = ExtendedSpendingKey.master(bytes(range(32)))
        self.assertEqual(
            root.serialize().hex(),
            "000000000000000000d0947c4b03bf72a37ab44f72276d1cf3fdcd7ebf3e733"
            "48b7e550d752018668eb6c00c93d36032b9a268e99e86a860776560bf0e83c"
            "1a10b51f607c9547425068204ede83b2f1fbd84f9b45d7f996e2ebd0a030ad"
            "243b48ed39f748a8821ea06395884890323b9d4933c021db89bcf767df21977"
            "b2ff0683848321a4df4afb2177c17cb75b7796afb39f0f3e91c924607da56fa"
            "9a20e283509bc8a3ef996a172",
        )

    def test_zip32_child_and_internal_keys_match_upstream_vectors(self):
        root = ExtendedSpendingKey.master(bytes(range(32)))
        self.assertEqual(nullifier_deriving_key(root), root.nk)
        self.assertEqual(
            nullifier_deriving_key(root.to_full_viewing_key()),
            root.nk,
        )
        child = root.derive_child(1)
        hardened_child = child.derive_child((1 << 31) + 2)

        self.assertEqual(
            child.serialize().hex(),
            "0114c2713a010000000147110c691a03b9d9f0ba9005c5e790a595b7f04e3329"
            "d2fa438a6705dabce6282bc197a516287c8ea8f68c424abad302b45cdf954079"
            "61d7b8b455267a350ce7a32988fdca1efcd6d1c4c562e629c2e96b2c3f7eda04"
            "ac4efd1810ff6bba015f1381fc8886da6a02dffeefcf503c40fa8f5a36f7a714"
            "2fd81b5518c5a47474e04de832a2d791ec129ab9002b91c9e9cdeed79241a7c"
            "4960e5178d870c1b4dc",
        )
        self.assertEqual(
            hardened_child.ask.to_bytes(32, "little").hex(),
            "8be8113cee3413a71f82c41fc8da517be134049832e6825c92da6b84fee4c60d",
        )
        self.assertEqual(
            hardened_child.nsk.to_bytes(32, "little").hex(),
            "3778059dc569e7d0d32391573f951bbde92fc6b9cf614773661c5c273aa6990c",
        )
        self.assertEqual(
            hardened_child.ovk.hex(),
            "cf81182e96223c028ce3d6eb4794d3113b95069d14c57588e193b65efc2813bc",
        )
        self.assertEqual(
            hardened_child.dk.hex(),
            "a3eda19f9eff46ca12dfa1bf10371b48d1b4a40c4d05a0d8dce0e7dc62b07b37",
        )
        self.assertEqual(
            hardened_child.chain_code.hex(),
            "97ce15f4ed1b9739b0262a463bcb3dc9b3bd2323a9baa441ca42777383a8d435",
        )
        self.assertEqual(
            hardened_child.ak.hex(),
            "a6c5925a0f85fa4f1e405e3a4970d0c4a4b4814438f4e9d4520e20f7fdcf3841",
        )
        self.assertEqual(
            hardened_child.nk.hex(),
            "304e305916216beb7b654d8aae50ecd188fcb384bc36c00c664f307725e2ee11",
        )
        self.assertEqual(
            hardened_child.incoming_viewing_key.to_bytes(32, "little").hex(),
            "a2a13c1e38b45984445803e430a683c90bb2e14d4c8692ff253a6484dd9bb504",
        )
        self.assertEqual(
            hardened_child.outgoing_viewing_key,
            hardened_child.ovk,
        )

        viewing_child = hardened_child.to_full_viewing_key().derive_child(3)
        self.assertEqual(
            viewing_child.serialize().hex(),
            "0348c18375030000008d937bcf81ba430d5b49afc0a403367b1fd99879ecba41"
            "be051c5a4aa7d6e7e8b185c57b509c2536c4f2d326d766c8fab25447de5375a9"
            "328d649ddabd97a6a3db88049e02d207568afc42e07db2abed500b2701c01bbf"
            "f36399764b81c0664f69b9e0fa1c4b3deb91d53beee871156121474b8b62ef241"
            "34478dc3499691af6becb50c363bb2ed9da5c3043ceb0f1a0527bf836b29a35"
            "f7c0c9f261123be56e",
        )
        self.assertEqual(
            viewing_child.incoming_viewing_key.to_bytes(32, "little").hex(),
            "b0a5f337232f2c3dac70c2a410fa561fc45d8cc59cda246d31c8b1715a57d900",
        )

        internal = root.derive_internal()
        self.assertEqual(
            internal.nsk.to_bytes(32, "little").hex(),
            "511233636b95fd0afb6bf8193a7d8f49efd736a988775c54f956687646eaab07",
        )
        self.assertEqual(
            internal.ovk.hex(),
            "9dc477fe1e7d282913f651654d3985f09d53c2d3b5763d7a723bcbd6ee053d5a",
        )
        self.assertEqual(
            internal.dk.hex(),
            "40ddc56e6975138c0839e580b54d6d999dc616843cfe041e8f388b124ef7b5ed",
        )
        self.assertEqual(
            internal.nk.hex(),
            "a3831a5c6933f8ec6aa5ce316c508b7991cd94d3bdb700a1c427a6ae15e72fb5",
        )
        self.assertEqual(
            internal.incoming_viewing_key.to_bytes(32, "little").hex(),
            "790577321c511804636ee6baa4eea779b4a46a5a12f85d365074a09d054f3401",
        )

    def test_bitcoinz_sapling_wallet_derivation_stays_gated(self):
        bitcoinz_network = get_network("btcz-mainnet")
        spending_key = ExtendedSpendingKey.master(
            mnemonic_to_seed(self.mnemonic)
        )
        with self.assertRaises(SaplingCapabilityError):
            SaplingWallet.from_mnemonic(
                self.mnemonic,
                network="btcz-mainnet",
            )
        with self.assertRaises(SaplingCapabilityError):
            SaplingWallet(spending_key, bitcoinz_network)

    def test_zip32_rejects_boolean_indices_and_spending_scalars(self):
        root = ExtendedSpendingKey.master(bytes(range(32)))
        with self.assertRaises(ValueError):
            root.derive_child(True)
        with self.assertRaises(ValueError):
            root.to_full_viewing_key().derive_child(True)
        with self.assertRaises(ValueError):
            ExtendedSpendingKey(
                ask=True,
                nsk=0,
                ovk=bytes(32),
                dk=bytes(32),
                chain_code=bytes(32),
            )

    def test_sapling_nullifiers_match_all_official_reference_vectors(self):
        fixture_path = (
            ROOT / "tests" / "fixtures" / "sapling_nullifier_reference.json"
        )
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertIn("sapling_key_components.json", fixture["source"])
        self.assertEqual(len(fixture["cases"]), 10)
        positions_seen = set()
        for case in fixture["cases"]:
            with self.subTest(position=case["note_pos"]):
                diversifier_base = group_hash(
                    b"Zcash_gd",
                    bytes.fromhex(case["default_d"]),
                )
                self.assertIsNotNone(diversifier_base)
                note = SaplingNote(
                    note_commitment=bytes.fromhex(case["note_cmu"]),
                    diversifier_base=diversifier_base.encode(),
                    transmission_key=bytes.fromhex(case["default_pk_d"]),
                    value=case["note_v"],
                    commitment_randomness=int.from_bytes(
                        bytes.fromhex(case["note_r"]),
                        "little",
                    ),
                    zip212_version=1,
                )
                spending_key = ExtendedSpendingKey(
                    ask=int.from_bytes(bytes.fromhex(case["ask"]), "little"),
                    nsk=int.from_bytes(bytes.fromhex(case["nsk"]), "little"),
                    ovk=bytes.fromhex(case["ovk"]),
                    dk=bytes(32),
                    chain_code=bytes(32),
                )
                self.assertEqual(
                    nullifier_deriving_key(spending_key).hex(),
                    case["nk"],
                )
                self.assertEqual(
                    nullifier_deriving_key(
                        spending_key.to_full_viewing_key()
                    ).hex(),
                    case["nk"],
                )
                self.assertEqual(
                    derive_sapling_nullifier(
                        bytes.fromhex(case["nk"]),
                        note,
                        case["note_pos"],
                    ).hex(),
                    case["note_nf"],
                )
                positions_seen.add(case["note_pos"])
                self.assertNotEqual(
                    derive_sapling_nullifier(
                        bytes.fromhex(case["nk"]),
                        note,
                        (case["note_pos"] + 1) % (1 << 32),
                    ).hex(),
                    case["note_nf"],
                )
        self.assertEqual(len(positions_seen), len(fixture["cases"]))

    def test_sapling_nullifier_note_creation_from_decrypted_v1_and_v2(self):
        zcash = self.configs["zec"].get_network("mainnet")
        output = SaplingCompactOutput(
            txid="published-zcash-reference-vector",
            height=zcash.sapling["zip212_activation_height"] - 1,
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
        ivk = bytes.fromhex(
            "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
        )
        decrypted_v1 = decrypt_sapling_compact_output(output, ivk, zcash)
        validated_v1 = SaplingNote.from_decrypted(decrypted_v1, ivk, zcash)
        self.assertEqual(validated_v1.zip212_version, 1)
        self.assertEqual(validated_v1.note_commitment, output.cmu)

        fvk = ExtendedSpendingKey.master(
            mnemonic_to_seed(self.mnemonic)
        ).to_full_viewing_key()
        height_v2 = (
            zcash.sapling["zip212_activation_height"]
            + zcash.sapling["zip212_grace_period_blocks"]
        )
        output_v2 = make_zip212_v2_output(
            fvk.incoming_viewing_key,
            height_v2,
        )
        decrypted_v2 = decrypt_sapling_compact_output(output_v2, fvk, zcash)
        validated_v2 = SaplingNote.from_decrypted(decrypted_v2, fvk, zcash)
        self.assertEqual(validated_v2.zip212_version, 2)
        self.assertEqual(validated_v2.note_commitment, output_v2.cmu)

    def test_sapling_nullifier_rejects_invalid_keys_notes_and_positions(self):
        fixture_path = (
            ROOT / "tests" / "fixtures" / "sapling_nullifier_reference.json"
        )
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        case = fixture["cases"][1]
        diversifier_base = group_hash(
            b"Zcash_gd",
            bytes.fromhex(case["default_d"]),
        )
        valid_note = SaplingNote(
            bytes.fromhex(case["note_cmu"]),
            diversifier_base.encode(),
            bytes.fromhex(case["default_pk_d"]),
            case["note_v"],
            int.from_bytes(bytes.fromhex(case["note_r"]), "little"),
            1,
        )
        key = bytes.fromhex(case["nk"])
        for bad_key in (
            None,
            True,
            bytearray(key),
            bytes(31),
            bytes(33),
            b"\x01" + bytes(31),
            bytes(32),
        ):
            with self.subTest(key=repr(bad_key)[:20]), self.assertRaises(
                SaplingNullifierError
            ):
                nullifier_deriving_key(bad_key)

        for bad_position in (True, -1, 1 << 32, 1.5, "1", None):
            with self.subTest(position=bad_position), self.assertRaises(
                SaplingNullifierError
            ):
                derive_sapling_nullifier(key, valid_note, bad_position)

        for bad_note in (None, b"not a note", object()):
            with self.subTest(note=type(bad_note).__name__), self.assertRaises(
                SaplingNullifierError
            ):
                derive_sapling_nullifier(key, bad_note, case["note_pos"])

        valid_note_fields = {
            "note_commitment": valid_note.note_commitment,
            "diversifier_base": valid_note.diversifier_base,
            "transmission_key": valid_note.transmission_key,
            "value": valid_note.value,
            "commitment_randomness": valid_note.commitment_randomness,
            "zip212_version": valid_note.zip212_version,
        }
        mismatched_commitment = bytearray(valid_note.note_commitment)
        mismatched_commitment[0] ^= 1
        invalid_notes = (
            {**valid_note_fields, "note_commitment": bytes(31)},
            {**valid_note_fields, "note_commitment": b"\xff" * 32},
            {
                **valid_note_fields,
                "note_commitment": bytes(mismatched_commitment),
            },
            {**valid_note_fields, "value": True},
            {**valid_note_fields, "value": -1},
            {**valid_note_fields, "value": 1 << 64},
            {**valid_note_fields, "commitment_randomness": True},
            {
                **valid_note_fields,
                "commitment_randomness": SCALAR_MODULUS,
            },
            {**valid_note_fields, "zip212_version": True},
            {**valid_note_fields, "diversifier_base": bytes(32)},
            {**valid_note_fields, "transmission_key": bytes(32)},
        )
        for malformed_note in invalid_notes:
            with self.subTest(note=malformed_note), self.assertRaises(
                SaplingNullifierError
            ):
                SaplingNote(**malformed_note)

    def test_note_decryption_fixture_uses_each_coins_zip212_heights(self):
        # Compact fields are from the zcash/zcash-test-vectors reference vector.
        output = SaplingCompactOutput(
            txid="reference-vector",
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
        viewing_key = bytes.fromhex(
            "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
        )
        for coin_id in ("zec", "btcz"):
            network = self.configs[coin_id].get_network()
            zip212_height = network.sapling["zip212_activation_height"]
            note = decrypt_sapling_compact_output(
                output,
                viewing_key,
                network,
                height=zip212_height - 1,
            )
            self.assertIsNotNone(note)
            self.assertEqual(note.value, 100_000_000)
            self.assertEqual(note.diversifier.hex(), "f19d9b797e39f337445839")
            self.assertEqual(
                note.note_commitment.hex(),
                "635572f572a8a1a0b7acbc0afc6d66f14a02efacde7bdf03443ed4c3e551d470",
            )
            self.assertEqual(
                note.plaintext_prefix.hex(),
                "01f19d9b797e39f33744583900e1f5050000000039176dac39ace498"
                "0ecc8d778e89860255ec3615060000000000000000000000",
            )
            self.assertEqual(note.zip212_version, 1)
            in_grace = decrypt_sapling_compact_output(
                output,
                viewing_key,
                network,
                height=zip212_height,
            )
            self.assertIsNotNone(in_grace)
            self.assertEqual(in_grace.zip212_version, 1)
            self.assertIsNone(
                decrypt_sapling_compact_output(
                    replace(output, transaction_index=0),
                    viewing_key,
                    network,
                    height=zip212_height,
                )
            )
            self.assertIsNone(
                decrypt_sapling_compact_output(
                    output,
                    viewing_key,
                    network,
                    height=(
                        zip212_height
                        + network.sapling["zip212_grace_period_blocks"]
                    ),
                )
            )

    def test_zip212_v2_reference_rules_work_for_zcash_and_bitcoinz(self):
        ivk = int.from_bytes(
            bytes.fromhex(
                "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
            ),
            "little",
        )
        for coin_id in ("zec", "btcz"):
            network = self.configs[coin_id].get_network()
            sapling = network.sapling
            start = sapling["zip212_activation_height"]
            grace_end = start + sapling["zip212_grace_period_blocks"]
            for height in (start, grace_end - 1, grace_end):
                with self.subTest(coin=coin_id, height=height):
                    output = make_zip212_v2_output(ivk, height)
                    note = decrypt_sapling_compact_output(
                        output,
                        ivk,
                        network,
                    )
                    self.assertIsNotNone(note)
                    self.assertEqual(note.zip212_version, 2)
                    self.assertEqual(note.value, 123_456_789)
                    if height < grace_end:
                        coinbase_output = replace(output, transaction_index=0)
                        coinbase_note = decrypt_sapling_compact_output(
                            coinbase_output,
                            ivk,
                            network,
                        )
                        self.assertIsNotNone(coinbase_note)
                        self.assertEqual(coinbase_note.zip212_version, 2)

    def test_zip212_v1_v2_activation_grace_and_coinbase_rules(self):
        network = self.configs["zec"].get_network()
        sapling = network.sapling
        activation = sapling["zip212_activation_height"]
        grace_end = activation + sapling["zip212_grace_period_blocks"]
        ivk = int.from_bytes(
            bytes.fromhex(
                "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
            ),
            "little",
        )
        v1 = SaplingCompactOutput(
            txid="upstream-sapling-v1",
            height=activation - 1,
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
        v2 = make_zip212_v2_output(ivk, activation)

        before_activation = decrypt_sapling_compact_output(
            v1,
            ivk,
            network,
            height=activation - 1,
        )
        self.assertIsNotNone(before_activation)
        self.assertEqual(before_activation.zip212_version, 1)
        self.assertIsNone(
            decrypt_sapling_compact_output(
                v2,
                ivk,
                network,
                height=activation - 1,
            )
        )

        for height in (activation, grace_end - 1):
            self.assertEqual(
                decrypt_sapling_compact_output(
                    v1,
                    ivk,
                    network,
                    height=height,
                ).zip212_version,
                1,
            )
            self.assertEqual(
                decrypt_sapling_compact_output(
                    v2,
                    ivk,
                    network,
                    height=height,
                ).zip212_version,
                2,
            )
            coinbase_v1 = replace(v1, transaction_index=0)
            coinbase_v2 = replace(v2, transaction_index=0)
            self.assertIsNone(
                decrypt_sapling_compact_output(
                    coinbase_v1,
                    ivk,
                    network,
                    height=height,
                )
            )
            self.assertEqual(
                decrypt_sapling_compact_output(
                    coinbase_v2,
                    ivk,
                    network,
                    height=height,
                ).zip212_version,
                2,
            )

        self.assertIsNone(
            decrypt_sapling_compact_output(
                v1,
                ivk,
                network,
                height=grace_end,
            )
        )
        self.assertEqual(
            decrypt_sapling_compact_output(
                v2,
                ivk,
                network,
                height=grace_end,
            ).zip212_version,
            2,
        )
        self.assertIsNone(
            decrypt_sapling_compact_output(
                v1,
                ivk,
                network,
                height=activation,
                is_coinbase=True,
            )
        )

    def test_zip212_v2_trial_decryption_accepts_ivk_and_fvk(self):
        seed = mnemonic_to_seed(self.mnemonic)
        fvk = ExtendedSpendingKey.master(seed).to_full_viewing_key()
        for coin_id in ("zec", "btcz"):
            network = self.configs[coin_id].get_network()
            height = (
                network.sapling["zip212_activation_height"]
                + network.sapling["zip212_grace_period_blocks"]
            )
            output = make_zip212_v2_output(fvk.incoming_viewing_key, height)

            for viewing_key in (fvk.incoming_viewing_key, fvk):
                note = decrypt_sapling_compact_output(
                    output,
                    viewing_key,
                    network,
                )
                self.assertIsNotNone(note)
                self.assertEqual(note.value, 123_456_789)
                self.assertEqual(note.zip212_version, 2)

            self.assertIsNone(
                decrypt_sapling_compact_output(
                    output,
                    fvk.incoming_viewing_key + 1,
                    network,
                )
            )

    def test_note_decryption_rejects_malformed_compact_outputs_and_keys(self):
        network = self.configs["zec"].get_network()
        output = SaplingCompactOutput(
            txid="upstream-sapling-v1",
            height=network.sapling["zip212_activation_height"] - 1,
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
        ivk = bytes.fromhex(
            "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
        )
        for malformed in (
            replace(output, cmu=b"\xff" * 32),
            replace(output, ephemeral_key=b"\x00" * 32),
            replace(output, ciphertext_prefix=b"short"),
        ):
            with self.subTest(output=malformed):
                with self.assertRaises(SaplingNoteDecryptionError):
                    decrypt_sapling_compact_output(malformed, ivk, network)

        tampered_commitment = replace(output, cmu=bytes([output.cmu[0] ^ 1]) + output.cmu[1:])
        self.assertIsNone(
            decrypt_sapling_compact_output(tampered_commitment, ivk, network)
        )
        with self.assertRaises(SaplingNoteDecryptionError):
            decrypt_sapling_compact_output(output, b"short", network)

    def test_bitcoinz_uses_its_configured_zip212_heights(self):
        network = self.configs["btcz"].get_network()
        sapling = network.sapling
        self.assertEqual(sapling["activation_height"], 328500)
        self.assertEqual(sapling["zip212_activation_height"], 1735000)
        self.assertEqual(sapling["zip212_grace_period_blocks"], 32256)
        self.assertEqual(sapling["consensus_branch_id_hex"], "76b809bb")
        self.assertEqual(network.branch_id, int("e9ff75a6", 16))
        self.assertEqual(sapling["note_decryption_status"], "supported_verified_parameters")

        ivk = int.from_bytes(
            bytes.fromhex(
                "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
            ),
            "little",
        )
        height = (
            sapling["zip212_activation_height"]
            + sapling["zip212_grace_period_blocks"]
        )
        output = make_zip212_v2_output(ivk, height)
        note = decrypt_sapling_compact_output(output, ivk, network)
        self.assertIsNotNone(note)
        self.assertEqual(note.zip212_version, 2)

    def test_unverified_coin_types_do_not_generate_bip44_paths(self):
        with self.assertRaises(ConfigurationError):
            bip44_derivation(0, "glink")
        with self.assertRaises(ConfigurationError):
            bip44_derivation(0, "kmdcl")
        with self.assertRaises(ConfigurationError):
            bip44_derivation(0, "zerc")
        with self.assertRaises(ValueError):
            bip44_derivation(True, "zec")

    def test_mismatched_verified_path_is_rejected(self):
        definition = json.loads((ROOT / "src" / "coins" / "zec.json").read_text())
        definition["networks"]["mainnet"]["transparent_derivation"]["path"] = (
            "m/44'/1'/{account}'"
        )
        with self.assertRaises(ConfigurationError):
            CoinConfig.from_mapping(definition)


class BitcoreHistoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_address_is_empty_history_and_limit_is_checked(self):
        client = object.__new__(BitcoreClient)
        with patch.object(
            BitcoreClient,
            "get",
            new_callable=AsyncMock,
            side_effect=RuntimeError('HTTP 404: {"error":"Address not found"}'),
        ) as get:
            self.assertEqual(await client.get_history("test-address", limit=1), [])
            get.assert_awaited_once_with("txs?address=test-address&limit=1")

        with self.assertRaises(ValueError):
            await client.get_history("test-address", limit=0)


class TransparentClientCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    async def _network_for_websocket_port(self, port):
        network = load_coin_configs()["btcz"].get_network("mainnet")
        electrum = dict(network.electrum)
        electrum["servers"] = ["127.0.0.1"]
        electrum["ports"] = dict(electrum["ports"], websocket=port)
        return replace(network, electrum=electrum)

    async def test_native_websocket_electrum_rpc_and_subscriptions(self):
        async def handler(connection):
            async for raw in connection:
                request = json.loads(raw)
                result = {
                    "server.version": ["test-electrum", "1.4"],
                    "blockchain.headers.subscribe": {"height": 42},
                    "blockchain.scripthash.subscribe": None,
                    "blockchain.scripthash.get_history": [],
                    "blockchain.transaction.get": {"txid": "test-tx"},
                }[request["method"]]
                await connection.send(
                    json.dumps({"id": request["id"], "result": result})
                )

        async with serve(handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            network = await self._network_for_websocket_port(port)
            client = ElectrumClient(network, protocol="ws")
            try:
                await client.connect()
                self.assertEqual(await client.server_version(), ["test-electrum", "1.4"])
                self.assertEqual(
                    await client.subscribe_headers(),
                    {"height": 42},
                )
                self.assertEqual(client.height, 42)
                client.on_block_events = AsyncMock()
                await client._dispatch_message(
                    json.dumps(
                        {
                            "method": "blockchain.headers.subscribe",
                            "params": [{"height": 43, "hex": "00"}],
                        }
                    )
                )
                await asyncio.sleep(0)
                self.assertEqual(client.on_block_events.await_count, 1)
                address = public_key_to_p2pkh(
                    bytes.fromhex(
                        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    ),
                    network,
                )
                await client.subscribe_address(address)
                self.assertEqual(await client.get_history(address), [])
                await client.unsubscribe_address(address)
                await client.unsubscribe_headers()
                self.assertEqual(client._subscribed_addresses, {})
                self.assertFalse(client._headers_subscribed)
                await client._dispatch_message(
                    json.dumps(
                        {
                            "method": "blockchain.headers.subscribe",
                            "params": [{"height": 44, "hex": "00"}],
                        }
                    )
                )
                await asyncio.sleep(0)
                self.assertEqual(client.on_block_events.await_count, 1)
                self.assertEqual(
                    await client.get_transaction("test-tx"),
                    {"txid": "test-tx"},
                )
            finally:
                await client.close()

    async def test_cancelling_electrum_rpc_removes_pending_request(self):
        request_received = asyncio.Event()

        async def handler(connection):
            async for _ in connection:
                request_received.set()

        async with serve(handler, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            network = await self._network_for_websocket_port(port)
            client = ElectrumClient(network, protocol="ws")
            try:
                await client.connect()
                request = asyncio.create_task(client.server_version())
                await asyncio.wait_for(request_received.wait(), timeout=2)
                request.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await request
                self.assertEqual(client._pending, {})
            finally:
                await client.close()

    async def test_client_manager_keeps_electrum_and_bitcore_independent(self):
        manager = ClientManager()
        electrum = manager.add("btcz", protocol="ws")
        self.assertIsInstance(electrum, ElectrumClient)
        self.assertEqual(manager.get_protocol("btcz"), "ws")
        self.assertIn("bitcore", manager.protocols["btcz"])
        self.assertIn("wss", manager.protocols["btcz"])

        manager = ClientManager()
        bitcore = manager.add("btcz", protocol="bitcore")
        self.assertIsInstance(bitcore, BitcoreClient)
        self.assertEqual(manager.get_protocol("btcz"), "bitcore")
        self.assertNotIsInstance(bitcore, ElectrumClient)

        manager = ClientManager()
        lightwalletd = manager.add("zec", protocol="lightwalletd")
        self.assertEqual(manager.get_protocol("zec"), "lightwalletd")
        self.assertEqual(lightwalletd.host, "zec.rocks")


class BitcoreResponseTests(unittest.IsolatedAsyncioTestCase):
    async def test_history_normalizes_valid_and_empty_responses(self):
        client = object.__new__(BitcoreClient)
        with patch.object(
            BitcoreClient,
            "get",
            new_callable=AsyncMock,
            side_effect=[
                {"txs": [{"txid": "known-tx", "blockheight": 123}]},
                {"txs": []},
                {},
            ],
        ):
            self.assertEqual(
                await client.get_history("test-address"),
                [{"tx_hash": "known-tx", "height": 123}],
            )
            self.assertEqual(await client.get_history("test-address"), [])
            self.assertEqual(await client.get_history("test-address"), [])

    async def test_malformed_history_response_is_rejected(self):
        client = object.__new__(BitcoreClient)
        for response in (
            None,
            {"txs": "not-a-list"},
            {"txs": [None]},
            {"txs": [{"txid": "tx", "blockheight": "high"}]},
        ):
            with self.subTest(response=response), patch.object(
                BitcoreClient,
                "get",
                new_callable=AsyncMock,
                return_value=response,
            ):
                with self.assertRaises(ValueError):
                    await client.get_history("test-address")

    async def test_history_cancellation_propagates(self):
        client = object.__new__(BitcoreClient)
        request_started = asyncio.Event()

        async def wait_for_response(_client, _endpoint):
            request_started.set()
            await asyncio.Event().wait()

        with patch.object(
            BitcoreClient,
            "get",
            new=wait_for_response,
        ):
            request = asyncio.create_task(client.get_history("test-address"))
            await asyncio.wait_for(request_started.wait(), timeout=1)
            request.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request

    async def test_missing_transaction_is_normalized_and_other_errors_surface(self):
        client = object.__new__(BitcoreClient)
        with patch.object(
            BitcoreClient,
            "get",
            new_callable=AsyncMock,
            side_effect=[
                RuntimeError("HTTP 404: transaction not found"),
                RuntimeError("HTTP 503: explorer unavailable"),
            ],
        ):
            self.assertIsNone(await client.get_transaction("missing"))
            with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
                await client.get_transaction("unavailable")


class TransparentSigningTests(unittest.TestCase):
    password = "offline-zycoin-test-password"

    def setUp(self):
        self.phrase = _entropy_to_mnemonic(bytes(32))
        self.network = load_coin_configs()["btcz"].get_network("mainnet")
        self.stores = {}
        self.addresses = {}
        for account in (0, 1):
            store = from_bip39_seed(
                self.phrase,
                "",
                bip44_derivation(account, "btcz"),
                "btcz",
                password=self.password,
            )
            self.stores[account] = store
            for change, index in ((0, 0), (0, 1), (0, 7), (1, 0)):
                public_key = bytes.fromhex(store.derive_pubkey(change, index))
                self.addresses[(account, change, index)] = public_key_to_p2pkh(
                    public_key,
                    self.network,
                )

    def test_sighash_matches_all_official_zip243_vectors_offline(self):
        fixture_path = ROOT / "tests" / "fixtures" / "zip243_reference.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertIn("zip_0243.json", fixture["source"])
        self.assertEqual(len(fixture["cases"]), 10)
        for vector in fixture["cases"]:
            with self.subTest(
                input=vector["transparent_input"],
                hash_type=vector["hash_type"],
            ):
                digest = zip243_signature_hash(
                    bytes.fromhex(vector["tx"]),
                    bytes.fromhex(vector["script_code"]),
                    (
                        None
                        if vector["transparent_input"] == -1
                        else vector["transparent_input"]
                    ),
                    vector["hash_type"],
                    vector["amount"],
                    vector["consensus_branch_id"],
                )
                self.assertEqual(digest.hex(), vector["sighash"])

    def test_signs_multiple_inputs_and_outputs_with_change_and_exact_fee(self):
        inputs = (
            TransparentInput(
                "11" * 32,
                0,
                120_000,
                self.addresses[(0, 0, 0)],
                0,
                0,
            ),
            TransparentInput(
                "22" * 32,
                2,
                80_000,
                self.addresses[(1, 0, 1)],
                1,
                1,
            ),
        )
        outputs = (
            TransparentOutput(self.addresses[(0, 0, 1)], 130_000),
            TransparentOutput(self.addresses[(0, 1, 0)], 60_000),
        )
        unsigned = create_unsigned_transaction(
            "btcz",
            inputs,
            outputs,
            fee=10_000,
            expiry_height=1_900_000,
        )
        signed = sign_transaction(
            unsigned,
            self.phrase,
                    )
        self.assertEqual(signed.coin_id, "btcz")
        self.assertEqual(signed.network_id, "mainnet")
        self.assertEqual(signed.fee, 10_000)
        self.assertTrue(verify_transaction_signatures(unsigned, signed.raw))
        self.assertEqual(
            signed.txid,
            hashlib.sha256(
                hashlib.sha256(bytes.fromhex(signed.raw)).digest()
            ).digest()[::-1].hex(),
        )
        parsed = _parse_transaction_for_test(bytes.fromhex(signed.raw))
        self.assertEqual(len(parsed.inputs), 2)
        self.assertEqual(len(parsed.outputs), 2)
        self.assertEqual(parsed.inputs[0].outpoint[:32], bytes.fromhex("11" * 32)[::-1])
        self.assertEqual(parsed.inputs[1].outpoint[:32], bytes.fromhex("22" * 32)[::-1])

    def test_signs_single_input_and_verifies_signature_independently(self):
        address = self.addresses[(0, 0, 0)]
        unsigned = create_unsigned_transaction(
            "btcz",
            (TransparentInput("33" * 32, 1, 50_000, address, 0, 0),),
            (
                TransparentOutput(self.addresses[(0, 0, 1)], 40_000),
                TransparentOutput(self.addresses[(0, 1, 0)], 9_000),
            ),
            fee=1_000,
        )
        signed = sign_transaction(
            unsigned,
            self.phrase,
                    )
        self.assertTrue(verify_transaction_signatures(unsigned, signed.raw))

        raw = bytearray.fromhex(signed.raw)
        raw[47] ^= 1
        self.assertFalse(verify_transaction_signatures(unsigned, raw.hex()))
        self.assertFalse(verify_transaction_signatures(unsigned, "00"))
        sequence_tampered = bytearray.fromhex(signed.raw)
        sequence_tampered[46] ^= 1
        self.assertFalse(
            verify_transaction_signatures(unsigned, sequence_tampered.hex())
        )

    def test_invalid_transactions_and_unverified_coin_signing_fail_closed(self):
        address = self.addresses[(0, 0, 0)]
        source = (TransparentInput("44" * 32, 0, 10_000, address, 0, 0),)
        output = (TransparentOutput(self.addresses[(0, 0, 1)], 9_000),)
        with self.assertRaises(TransparentTransactionError):
            create_unsigned_transaction("btcz", source, output, fee=999)
        with self.assertRaises(TransparentTransactionError):
            create_unsigned_transaction(
                "btcz",
                source,
                (TransparentOutput("invalid-address", 9_000),),
                fee=1_000,
            )
        with self.assertRaises(TransparentTransactionError):
            create_unsigned_transaction(
                "btcz",
                (source[0], source[0]),
                output,
                fee=11_000,
            )
        for coin_id, coin_config in load_coin_configs().items():
            for network_id, network_config in coin_config.networks.items():
                if (
                    network_config.transparent_signing.get("status")
                    == "supported_verified_parameters"
                ):
                    continue
                with self.subTest(coin=coin_id, network=network_id), self.assertRaises(
                    TransparentTransactionError
                ):
                    create_unsigned_transaction(
                        coin_id,
                        source,
                        output,
                        fee=1_000,
                        network=network_id,
                    )

    def test_input_derivation_indices_are_validated(self):
        source = TransparentInput(
            "77" * 32,
            0,
            10_000,
            self.addresses[(0, 0, 0)],
            0,
            0,
        )
        output = (TransparentOutput(self.addresses[(0, 0, 1)], 9_000),)
        for field, value in (
            ("account", -1),
            ("address_index", 0x80000000),
            ("change", 2),
        ):
            with self.subTest(field=field), self.assertRaises(
                    TransparentTransactionError
            ):
                    create_unsigned_transaction(
                        "btcz",
                        (replace(source, **{field: value}),),
                        output,
                        fee=1_000,
                    )

    def test_signing_rejects_input_address_not_derived_from_phrase(self):
        other_address = self.addresses[(1, 0, 0)]
        unsigned = create_unsigned_transaction(
            "btcz",
            (TransparentInput("55" * 32, 0, 10_000, other_address, 0, 0),),
            (TransparentOutput(self.addresses[(0, 0, 1)], 9_000),),
            fee=1_000,
        )
        with self.assertRaisesRegex(TransparentTransactionError, "does not match"):
            sign_transaction(
                unsigned,
                self.phrase,
                            )

    def test_signer_rejects_unsigned_bytes_not_matching_metadata(self):
        address = self.addresses[(0, 0, 0)]
        unsigned = create_unsigned_transaction(
            "btcz",
            (TransparentInput("66" * 32, 0, 10_000, address, 0, 0),),
            (TransparentOutput(self.addresses[(0, 0, 1)], 9_000),),
            fee=1_000,
        )
        tampered_raw = unsigned.raw[:-2] + "01"
        from dataclasses import replace

        with self.assertRaisesRegex(
            TransparentTransactionError,
            "bytes do not match",
        ):
            sign_transaction(
                replace(unsigned, raw=tampered_raw),
                self.phrase,
                            )


class BitcoinZCompactOutputFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_chain_output_replays_through_scan_without_matching_key(self):
        fixture_path = ROOT / "tests" / "fixtures" / "btcz_mainnet_compact_output.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        network = load_coin_configs()["btcz"].get_network("mainnet")
        transaction = fixture["transaction"]
        output_data = fixture["compact_output"]

        self.assertEqual(fixture["coin"], "btcz")
        self.assertEqual(fixture["network"], "mainnet")
        self.assertEqual(
            transaction["txid"],
            "2a35efbe318b79b1e357b8ad6145561bd90dd37200a9dcc691adf1a05cdc8dd3",
        )
        self.assertEqual(
            transaction["block_hash"],
            "e13e65970ada9ad749fcc5be815cdeae4a01faad98d3c4fa792c224144070000",
        )
        self.assertEqual(
            transaction["height"],
            fixture["observed_tip_height"] - 18,
        )
        self.assertEqual(
            network.sapling["zip212_activation_height"]
            + network.sapling["zip212_grace_period_blocks"],
            1_767_256,
        )
        self.assertGreater(transaction["height"], 1_767_256)
        compact_output = compact_formats_pb2.CompactSaplingOutput(
            cmu=bytes.fromhex(output_data["cmu"]),
            ephemeralKey=bytes.fromhex(output_data["ephemeral_key"]),
            ciphertext=bytes.fromhex(output_data["ciphertext_prefix"]),
        )
        self.assertEqual(len(compact_output.cmu), 32)
        self.assertEqual(len(compact_output.ephemeralKey), 32)
        self.assertEqual(len(compact_output.ciphertext), 52)
        compact_tx = compact_formats_pb2.CompactTx(
            index=transaction["transaction_index"],
            txid=bytes.fromhex(transaction["txid"])[::-1],
            outputs=[compact_output],
        )
        block = compact_formats_pb2.CompactBlock(
            height=transaction["height"],
            hash=bytes.fromhex(transaction["block_hash"]),
            vtx=[compact_tx],
        )
        client = object.__new__(LightwalletdClient)

        async def get_block_range(_client, _request, *, timeout=None):
            yield block

        with patch.object(
            LightwalletdClient,
            "get_lightd_info",
            new=AsyncMock(
                return_value=service_pb2.LightdInfo(
                    chainName="main",
                    saplingActivationHeight=network.sapling["activation_height"],
                )
            ),
        ), patch.object(
            LightwalletdClient,
            "get_block_range",
            new=get_block_range,
        ):
            notes = await scan_sapling_notes(
                client,
                bytes.fromhex(
                    "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
                ),
                network=network,
                start_height=transaction["height"],
                end_height=transaction["height"],
                max_blocks=1,
                max_outputs=1,
            )

        self.assertEqual(notes, ())


class SaplingCommitmentTreeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "sapling_merkle_tree_reference.json")
            .read_text(encoding="utf-8")
        )
        self.network = load_coin_configs()["zec"].get_network("mainnet")

    def test_merkle_hash_matches_pinned_upstream_vector(self):
        vector = self.fixture["pedersen_merkle_crh_vector"]
        self.assertEqual(SAPLING_MERKLE_TREE_DEPTH, 32)
        self.assertEqual(
            merkle_hash(
                vector["level"],
                bytes.fromhex(vector["left"]),
                bytes.fromhex(vector["right"]),
            ).hex(),
            vector["expected"],
        )
        with self.assertRaises(SaplingTreeError):
            merkle_hash(True, bytes.fromhex(vector["left"]), bytes.fromhex(vector["right"]))
        for invalid_depth in (-1, 32):
            with self.subTest(depth=invalid_depth), self.assertRaises(
                SaplingTreeError
            ):
                merkle_hash(
                    invalid_depth,
                    bytes.fromhex(vector["left"]),
                    bytes.fromhex(vector["right"]),
                )
        with self.assertRaises(SaplingTreeError):
            merkle_hash(0, b"\xff" * 32, bytes.fromhex(vector["right"]))

    def test_incremental_roots_and_witness_paths_match_reference_fixture(self):
        tree = SaplingCommitmentTree(self.network)
        self.assertEqual(tree.size, 0)
        self.assertEqual(tree.root.hex(), self.fixture["empty_root"])
        self.assertEqual(
            tree.root.hex(),
            self.fixture["roots_by_size"][0],
        )

        positions = []
        historical_witnesses = []
        for tree_size, commitment in enumerate(self.fixture["commitments"], start=1):
            positions.append(tree.append(bytes.fromhex(commitment)))
            self.assertEqual(tree.size, tree_size)
            self.assertEqual(tree.root.hex(), self.fixture["roots_by_size"][tree_size])
            if historical_witnesses:
                historical_witnesses = [
                    witness.update(tree) for witness in historical_witnesses
                ]
            historical_witnesses.append(tree.witness(positions[-1]))
            expected_snapshot = self.fixture["witnesses_by_size"][tree_size]
            self.assertEqual(expected_snapshot["tree_size"], tree_size)
            self.assertEqual(tree.root.hex(), expected_snapshot["anchor"])
            self.assertEqual(len(expected_snapshot["witnesses"]), tree_size)
            for position, (witness, expected) in enumerate(
                zip(historical_witnesses, expected_snapshot["witnesses"])
            ):
                with self.subTest(tree_size=tree_size, position=position):
                    self.assertEqual(witness.position, position)
                    self.assertEqual(witness.tree_size, tree_size)
                    self.assertEqual(witness.note_commitment.hex(), expected["note_commitment"])
                    self.assertEqual(
                        [node.hex() for node in witness.authentication_path],
                        expected["authentication_path"],
                    )
                    self.assertEqual(witness.anchor.hex(), expected["anchor"])
                    self.assertTrue(witness.verify())
        self.assertEqual(tuple(positions), tuple(range(len(self.fixture["commitments"]))))
        self.assertEqual(tree.root.hex(), self.fixture["final_root"])

    def test_reference_detects_reordered_missing_and_boundary_cases(self):
        baseline = SaplingCommitmentTree(self.network)
        for commitment in self.fixture["commitments"]:
            baseline.append(bytes.fromhex(commitment))
        self.assertEqual(baseline.root.hex(), self.fixture["final_root"])

        reordered = SaplingCommitmentTree(self.network)
        for commitment in reversed(self.fixture["commitments"]):
            reordered.append(bytes.fromhex(commitment))
        self.assertNotEqual(reordered.root, baseline.root)

        missing = SaplingCommitmentTree(self.network)
        for index, commitment in enumerate(self.fixture["commitments"]):
            if index != 1:
                missing.append(bytes.fromhex(commitment))
        self.assertNotEqual(missing.root, baseline.root)

        boundary = self.fixture["full_tree_boundary"]
        capacity = 1 << SAPLING_MERKLE_TREE_DEPTH
        self.assertEqual(boundary["capacity"], capacity)
        self.assertEqual(boundary["full_tree_size"], capacity)
        self.assertTrue(boundary["append_rejected"])
        with patch.object(baseline, "_size", capacity):
            with self.assertRaisesRegex(SaplingTreeError, "tree is full"):
                baseline.append(bytes.fromhex(self.fixture["commitments"][0]))

    def test_witness_updates_and_rejects_bad_positions_paths_and_networks(self):
        tree = SaplingCommitmentTree(self.network)
        position = tree.append(bytes.fromhex(self.fixture["commitments"][0]))
        initial = tree.witness(position)
        for commitment in self.fixture["commitments"][1:]:
            tree.append(bytes.fromhex(commitment))
        updated = initial.update(tree)
        self.assertEqual(updated.anchor, tree.root)
        self.assertTrue(updated.verify())

        with self.assertRaises(SaplingTreeError):
            tree.witness(True)
        with self.assertRaises(SaplingTreeError):
            tree.witness(tree.size)
        with self.assertRaises(SaplingTreeError):
            tree.witness(1 << SAPLING_MERKLE_TREE_DEPTH)
        with self.assertRaises(SaplingTreeError):
            tree.append(bytes(31))
        with self.assertRaises(SaplingTreeError):
            tree.append(b"\xff" * 32)

        bad_path = list(updated.authentication_path)
        bad_path[0] = bytes([bad_path[0][0] ^ 1]) + bad_path[0][1:]
        with self.assertRaises(SaplingTreeError):
            SaplingMerkleWitness(
                note_commitment=updated.note_commitment,
                position=updated.position,
                tree_size=updated.tree_size,
                authentication_path=tuple(bad_path),
                anchor=updated.anchor,
                coin_id=updated.coin_id,
                network_id=updated.network_id,
            )
        with self.assertRaisesRegex(SaplingTreeError, "does not match anchor"):
            SaplingMerkleWitness(
                note_commitment=updated.note_commitment,
                position=updated.position,
                tree_size=updated.tree_size,
                authentication_path=updated.authentication_path,
                anchor=bytes(32),
                coin_id=updated.coin_id,
                network_id=updated.network_id,
            )
        with self.assertRaises(SaplingTreeError):
            SaplingMerkleWitness(
                note_commitment=updated.note_commitment,
                position=1 << SAPLING_MERKLE_TREE_DEPTH,
                tree_size=updated.tree_size,
                authentication_path=updated.authentication_path,
                anchor=updated.anchor,
                coin_id=updated.coin_id,
                network_id=updated.network_id,
            )

        other_network = load_coin_configs()["zec"].get_network("testnet")
        with self.assertRaises(SaplingTreeError):
            initial.update(SaplingCommitmentTree(other_network))
        unsupported = load_coin_configs()["zer"].get_network("mainnet")
        with self.assertRaises(SaplingTreeError):
            SaplingCommitmentTree(unsupported)

        original_tree = SaplingCommitmentTree(self.network)
        original_tree.append(bytes.fromhex(self.fixture["commitments"][0]))
        original_tree.append(bytes.fromhex(self.fixture["commitments"][1]))
        stale = original_tree.witness(0)
        divergent_tree = SaplingCommitmentTree(self.network)
        divergent_tree.append(bytes.fromhex(self.fixture["commitments"][0]))
        divergent_tree.append(bytes.fromhex(self.fixture["commitments"][2]))
        with self.assertRaisesRegex(SaplingTreeError, "historical root"):
            stale.update(divergent_tree)

        with self.assertRaises(SaplingTreeError):
            SaplingMerkleWitness(
                note_commitment=updated.note_commitment,
                position=updated.position,
                tree_size=updated.tree_size,
                authentication_path=updated.authentication_path[:-1],
                anchor=updated.anchor,
                coin_id=updated.coin_id,
                network_id=updated.network_id,
            )


class SaplingTreeScannerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.network = load_coin_configs()["zec"].get_network("mainnet")
        self.fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "sapling_merkle_tree_reference.json")
            .read_text(encoding="utf-8")
        )

    def _output(self, commitment):
        return compact_formats_pb2.CompactSaplingOutput(
            cmu=bytes.fromhex(commitment),
            ephemeralKey=bytes(32),
            ciphertext=bytes(52),
        )

    def _block(self, height, block_hash, previous_hash, tree_size, transactions):
        tx_values = []
        for tx_index, outputs in transactions:
            tx_values.append(
                compact_formats_pb2.CompactTx(
                    index=tx_index,
                    txid=bytes([tx_index + 1]) * 32,
                    outputs=[self._output(commitment) for commitment in outputs],
                )
            )
        return compact_formats_pb2.CompactBlock(
            height=height,
            hash=block_hash,
            prevHash=previous_hash,
            chainMetadata=compact_formats_pb2.ChainMetadata(
                saplingCommitmentTreeSize=tree_size,
            ),
            vtx=tx_values,
        )

    async def _scan(
        self,
        blocks,
        start,
        end,
        *,
        latest_height=None,
        latest_hash=None,
        predecessor_hash=None,
        end_snapshot_hash=None,
    ):
        client = object.__new__(LightwalletdClient)
        if latest_height is None:
            latest_height = end
        if latest_hash is None:
            latest_hash = (
                bytes(blocks[-1].hash)
                if blocks and latest_height == end
                else b"\x77" * 32
            )

        async def get_block_range(_client, _request, *, timeout=None):
            for block in blocks:
                yield block

        async def get_block(_client, block_id, *, timeout=None):
            if block_id.height == start - 1:
                return compact_formats_pb2.CompactBlock(
                    height=start - 1,
                    hash=(
                        predecessor_hash
                        if predecessor_hash is not None
                        else (
                            bytes(blocks[0].prevHash)
                            if blocks
                            else b"\x01" * 32
                        )
                    ),
                    prevHash=b"\x00" * 32,
                )
            matching = next(
                (block for block in blocks if block.height == block_id.height),
                None,
            )
            if matching is None:
                raise AssertionError(f"unexpected boundary height {block_id.height}")
            if (
                block_id.height == end
                and end_snapshot_hash is not None
            ):
                return compact_formats_pb2.CompactBlock(
                    height=end,
                    hash=end_snapshot_hash,
                )
            return matching

        with patch.object(
            LightwalletdClient,
            "get_lightd_info",
            new=AsyncMock(
                return_value=service_pb2.LightdInfo(
                    chainName="main",
                    saplingActivationHeight=self.network.sapling["activation_height"],
                )
            ),
        ), patch.object(
            LightwalletdClient,
            "get_latest_block",
            new=AsyncMock(
                return_value=service_pb2.BlockID(
                    height=latest_height,
                    hash=latest_hash,
                )
            ),
        ), patch.object(
            LightwalletdClient,
            "get_block",
            new=get_block,
        ), patch.object(
            LightwalletdClient,
            "get_block_range",
            new=get_block_range,
        ):
            return await scan_sapling_commitment_tree(
                client,
                network=self.network,
                start_height=start,
                end_height=end,
                max_blocks=end - start + 1,
                max_outputs=10,
            )

    async def test_scan_assigns_positions_only_with_complete_ordered_tree_sizes(self):
        activation = self.network.sapling["activation_height"]
        block_hash_1 = b"\x11" * 32
        block_hash_2 = b"\x22" * 32
        blocks = (
            self._block(
                activation,
                block_hash_1,
                b"\x01" * 32,
                3,
                (
                    (
                        0,
                        (
                            self.fixture["commitments"][0],
                            self.fixture["commitments"][1],
                        ),
                    ),
                    (4, (self.fixture["commitments"][2],)),
                ),
            ),
            self._block(
                activation + 1,
                block_hash_2,
                block_hash_1,
                3,
                (),
            ),
        )
        result = await self._scan(blocks, activation, activation + 1)

        self.assertEqual([entry.position for entry in result.outputs], [0, 1, 2])
        self.assertEqual(
            [
                (entry.compact_output.height, entry.compact_output.transaction_index)
                for entry in result.outputs
            ],
            [(activation, 0), (activation, 0), (activation, 4)],
        )
        self.assertEqual(
            [entry.compact_output.output_index for entry in result.outputs],
            [0, 1, 0],
        )
        for entry in result.outputs:
            witness = result.witness_for(entry)
            self.assertEqual(witness.note_commitment, entry.compact_output.cmu)
            self.assertTrue(witness.verify())

    async def test_scan_rejects_incomplete_or_inconsistent_commitment_streams(self):
        activation = self.network.sapling["activation_height"]
        block = self._block(
            activation,
            b"\x11" * 32,
            b"\x01" * 32,
            2,
            ((1, (self.fixture["commitments"][0],)),),
        )
        with self.assertRaisesRegex(ScanError, "tree size"):
            await self._scan((block,), activation, activation)

        missing_sizes = compact_formats_pb2.CompactBlock(
            height=activation,
            hash=b"\x11" * 32,
            prevHash=b"\x01" * 32,
        )
        with self.assertRaisesRegex(ScanCapabilityError, "tree sizes"):
            await self._scan((missing_sizes,), activation, activation)

        duplicate_indices = self._block(
            activation,
            b"\x11" * 32,
            b"\x01" * 32,
            2,
            (
                (1, (self.fixture["commitments"][0],)),
                (1, (self.fixture["commitments"][1],)),
            ),
        )
        with self.assertRaisesRegex(ScanError, "block order"):
            await self._scan((duplicate_indices,), activation, activation)

        out_of_order_transactions = self._block(
            activation,
            b"\x11" * 32,
            b"\x01" * 32,
            2,
            (
                (4, (self.fixture["commitments"][0],)),
                (1, (self.fixture["commitments"][1],)),
            ),
        )
        with self.assertRaisesRegex(ScanError, "block order"):
            await self._scan(
                (out_of_order_transactions,),
                activation,
                activation,
            )

        duplicate_txids = self._block(
            activation,
            b"\x11" * 32,
            b"\x01" * 32,
            2,
            (
                (1, (self.fixture["commitments"][0],)),
                (2, (self.fixture["commitments"][1],)),
            ),
        )
        duplicate_txids.vtx[1].txid = duplicate_txids.vtx[0].txid
        with self.assertRaisesRegex(ScanError, "duplicate compact transaction"):
            await self._scan((duplicate_txids,), activation, activation)

        first = self._block(
            activation,
            b"\x11" * 32,
            b"\x01" * 32,
            1,
            ((1, (self.fixture["commitments"][0],)),),
        )
        disconnected = self._block(
            activation + 1,
            b"\x22" * 32,
            b"\x99" * 32,
            2,
            ((2, (self.fixture["commitments"][1],)),),
        )
        with self.assertRaisesRegex(ScanError, "hash-contiguous"):
            await self._scan((first, disconnected), activation, activation + 1)

        duplicate_block = self._block(
            activation + 1,
            b"\x11" * 32,
            b"\x11" * 32,
            1,
            (),
        )
        with self.assertRaisesRegex(ScanError, "duplicate compact block"):
            await self._scan((first, duplicate_block), activation, activation + 1)

        with self.assertRaisesRegex(ScanError, "returned 1 blocks"):
            await self._scan((first,), activation, activation + 1)

        with self.assertRaisesRegex(ScanCapabilityError, "from Sapling activation"):
            await self._scan((block,), activation + 1, activation + 1)

        with self.assertRaisesRegex(ScanError, "returned 0 blocks"):
            await self._scan((), activation, activation)

        with self.assertRaisesRegex(ScanCapabilityError, "does not cover"):
            await self._scan(
                (block,),
                activation,
                activation,
                latest_height=activation - 1,
            )

        with self.assertRaisesRegex(ScanError, "pre-activation boundary"):
            await self._scan(
                (first,),
                activation,
                activation,
                predecessor_hash=b"\x55" * 32,
            )

        with self.assertRaisesRegex(ScanError, "chain changed"):
            await self._scan(
                (first,),
                activation,
                activation,
                end_snapshot_hash=b"\x99" * 32,
            )

        with self.assertRaisesRegex(ScanError, "tip changed"):
            await self._scan(
                (first,),
                activation,
                activation,
                latest_hash=b"\x99" * 32,
            )


if __name__ == "__main__":
    unittest.main()
