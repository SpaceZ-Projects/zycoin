import json
import unittest
from pathlib import Path

from src.sapling_spend_reference import (
    PINNED_SAPLING_CRYPTO_COMMIT,
    PINNED_TEST_SEED,
    PUBLIC_INPUT_ORDER,
    RNG_VERSION,
    XorShiftRng,
    generate_external_cv_witnesses,
    generate_pinned_test_witness,
)
from src.sapling_tree import merkle_hash
from tests.sapling_spend_independent_reference import (
    _decode_point,
    _derive_ivk,
    _derive_nk,
    _find_group_hash,
    _group_hash,
)
from tests.sapling_spend_independent_reference import (
    _derive_nullifier as independent_nullifier,
)
from tests.sapling_spend_independent_reference import (
    _merkle_root as independent_merkle_root,
)
from tests.sapling_spend_independent_reference import (
    _note_commitment as independent_note_commitment,
)
from tests.sapling_spend_independent_reference import (
    generate_pinned_test_witness as generate_independent_witness,
)
from tests.sapling_spend_independent_reference import (
    value_commitment as independent_value_commitment,
)

CV_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_spend_external_cv_reference.json"
)
NULLIFIER_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_nullifier_reference.json"
)
MERKLE_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_merkle_tree_reference.json"
)


class SpendReferenceTests(unittest.TestCase):
    def test_pinned_xorshift_seed_and_word_order(self):
        rng = XorShiftRng(PINNED_TEST_SEED)
        self.assertEqual(
            [rng.next_u32() for _ in range(8)],
            [
                0x2BDE1419,
                0x2F004699,
                0xA363CF0D,
                0xA6E8F393,
                0x7D4D458B,
                0x5054F035,
                0xEDF24695,
                0xC6744D3,
            ],
        )

        rng = XorShiftRng(PINNED_TEST_SEED)
        self.assertEqual(
            rng.next_u64(),
            0x2F0046992BDE1419,
        )

    def test_external_upstream_value_commitment_vectors(self):
        fixture = json.loads(CV_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(
            fixture["source_revision"],
            PINNED_SAPLING_CRYPTO_COMMIT,
        )
        self.assertEqual(fixture["rng"]["version"], RNG_VERSION)
        witnesses = generate_external_cv_witnesses()
        self.assertEqual(len(witnesses), len(fixture["cases"]))
        for witness, expected in zip(witnesses, fixture["cases"]):
            with self.subTest(value=witness.value):
                self.assertEqual(witness.value, expected["value"])
                self.assertEqual(witness.rcv, expected["rcv"])
                self.assertEqual(
                    witness.value_commitment.u,
                    int(expected["cv_u"]),
                )
                self.assertEqual(
                    witness.value_commitment.v,
                    int(expected["cv_v"]),
                )

    def test_complete_seeded_witness_is_deterministic_and_well_formed(self):
        witness = generate_pinned_test_witness(0)
        self.assertEqual(witness, generate_pinned_test_witness(0))
        self.assertEqual(len(witness.authentication_path), 32)
        self.assertEqual(
            witness.position,
            sum(
                int(direction) << level
                for level, (_, direction) in enumerate(
                    witness.authentication_path
                )
            ),
        )

        node = witness.note_commitment.u.to_bytes(32, "little")
        for level, (sibling, direction) in enumerate(
            witness.authentication_path
        ):
            sibling_bytes = sibling.to_bytes(32, "little")
            node = merkle_hash(
                level,
                sibling_bytes if direction else node,
                node if direction else sibling_bytes,
            )
        self.assertEqual(int.from_bytes(node, "little"), witness.anchor)

        self.assertEqual(len(witness.nullifier), 32)
        self.assertEqual(len(witness.public_inputs), 7)
        self.assertEqual(
            tuple(witness.public_inputs[:2]),
            (witness.randomized_key.u, witness.randomized_key.v),
        )
        self.assertEqual(
            tuple(witness.public_inputs[2:4]),
            (witness.value_commitment.u, witness.value_commitment.v),
        )
        self.assertEqual(witness.public_inputs[4], witness.anchor)
        self.assertEqual(
            witness.public_inputs[5],
            int.from_bytes(witness.nullifier, "little") & ((1 << 254) - 1),
        )
        self.assertEqual(
            witness.public_inputs[6],
            int.from_bytes(witness.nullifier, "little") >> 254,
        )
        serialized = witness.as_dict()
        self.assertEqual(serialized["public_input_order"], list(PUBLIC_INPUT_ORDER))
        self.assertEqual(serialized["bellman_implicit_one"], 1)
        self.assertEqual(
            serialized["proof_generation_key"]["ak"],
            witness.ak.encode().hex(),
        )

    def test_seeded_witness_matches_separate_affine_reference(self):
        independent = generate_independent_witness(0)
        current = generate_pinned_test_witness(0)
        self.assertEqual(independent.as_dict(), current.as_dict())
        self.assertEqual(
            independent.public_inputs,
            (
                independent.randomized_key.u,
                independent.randomized_key.v,
                independent.cv.u,
                independent.cv.v,
                independent.anchor,
                *(
                    int.from_bytes(independent.nullifier, "little")
                    & ((1 << 254) - 1),
                    int.from_bytes(independent.nullifier, "little") >> 254,
                ),
            ),
        )
        self.assertEqual(len(independent.public_inputs), 7)
        self.assertEqual(len(independent.authentication_path), 32)
        self.assertTrue(
            all(
                item == independent.authentication_path[0]
                for item in independent.authentication_path
            )
        )

    def test_independent_affine_value_commitments_match_published_vectors(self):
        fixture = json.loads(CV_FIXTURE.read_text(encoding="utf-8"))
        for expected in fixture["cases"]:
            with self.subTest(value=expected["value"]):
                point = independent_value_commitment(
                    expected["value"], expected["rcv"]
                )
                self.assertEqual(point.u, int(expected["cv_u"]))
                self.assertEqual(point.v, int(expected["cv_v"]))

    def test_note_and_nullifier_match_independent_key_component_vector(self):
        case = json.loads(
            NULLIFIER_FIXTURE.read_text(encoding="utf-8")
        )["cases"][0]
        ask = int.from_bytes(bytes.fromhex(case["ask"]), "little")
        nsk = int.from_bytes(bytes.fromhex(case["nsk"]), "little")
        ak = _find_group_hash(b"Zcash_G_", b"").multiply(ask)
        nk = _derive_nk(nsk)
        self.assertEqual(nk.encode().hex(), case["nk"])
        ivk = _derive_ivk(ak, nk)
        g_d = _group_hash(b"Zcash_gd", bytes.fromhex(case["default_d"]))
        if g_d is None:
            self.fail("published key-component diversifier is invalid")
        pk_d = g_d.multiply(ivk)
        self.assertEqual(pk_d.encode().hex(), case["default_pk_d"])
        rcm = int.from_bytes(bytes.fromhex(case["note_r"]), "little")
        note_cm = independent_note_commitment(
            case["note_v"], g_d, pk_d, rcm
        )
        self.assertEqual(
            note_cm.u.to_bytes(32, "little").hex(),
            case["note_cmu"],
        )
        self.assertEqual(
            independent_nullifier(nk, note_cm, case["note_pos"]).hex(),
            case["note_nf"],
        )

    def test_merkle_root_matches_independent_authentication_path(self):
        fixture = json.loads(MERKLE_FIXTURE.read_text(encoding="utf-8"))
        path_case = fixture["witnesses"][0]
        path = tuple(
            (
                int.from_bytes(bytes.fromhex(node), "little"),
                bool((path_case["position"] >> level) & 1),
            )
            for level, node in enumerate(path_case["authentication_path"])
        )
        root, position = independent_merkle_root(
            int.from_bytes(
                bytes.fromhex(path_case["note_commitment"]), "little"
            ),
            path,
        )
        self.assertEqual(position, path_case["position"])
        self.assertEqual(
            root.to_bytes(32, "little").hex(),
            path_case["anchor"],
        )

    def test_randomized_key_matches_published_signature_vector(self):
        fixture = json.loads(
            (
                Path(__file__).parent
                / "fixtures"
                / "sapling_randomized_authorization_key_reference.json"
            ).read_text(encoding="utf-8")
        )
        case = fixture["case"]
        ak = _decode_point(bytes.fromhex(case["ak"]))
        ar = int.from_bytes(bytes.fromhex(case["ar"]), "little")
        spending_base = _find_group_hash(b"Zcash_G_", b"")
        rk = ak + spending_base.multiply(ar)
        self.assertEqual(rk.encode().hex(), case["rk"])


if __name__ == "__main__":
    unittest.main()
