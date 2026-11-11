import io
import unittest

from tests.sapling_output_query_compatibility import (
    QueryCompatibilityError,
    _read_export_section,
    compare_point_sequences,
    validate_query_index_mapping,
)


def _valid_mapping():
    a = [
        {"query_index": 0, "upstream_identity": "Input(0)", "local_column": 0},
        {"query_index": 1, "upstream_identity": "Aux(0)", "local_column": 6},
    ]
    b = [
        {"query_index": 0, "upstream_identity": "Input(0)", "local_column": 0},
        {"query_index": 1, "upstream_identity": "Aux(1)", "local_column": 7},
    ]
    ic = [
        {"query_index": 0, "upstream_identity": "Input(0)", "local_column": 0},
        {"query_index": 1, "upstream_identity": "Input(1)", "local_column": 1},
    ]
    return {
        "a_query": a,
        "b_g1_query": b,
        "b_g2_query": b,
        "ic_query": ic,
    }


class SaplingOutputQueryCompatibilityTests(unittest.TestCase):
    def test_exact_point_bytes_and_order_match(self):
        points = (bytes((index,)) * 4 for index in range(3))
        local = (bytes((index,)) * 4 for index in range(3))
        result = compare_point_sequences("A", points, local, 3)
        self.assertEqual(result["point_count"], 3)
        self.assertEqual(result["encoded_bytes"], 12)

    def test_reordered_entries_are_rejected(self):
        with self.assertRaisesRegex(QueryCompatibilityError, "point 0 differs"):
            compare_point_sequences(
                "H",
                (b"first", b"other"),
                (b"other", b"first"),
                2,
            )

    def test_altered_point_encoding_is_rejected(self):
        with self.assertRaisesRegex(QueryCompatibilityError, "point 1 differs"):
            compare_point_sequences(
                "L",
                (b"point-0", b"point-1"),
                (b"point-0", b"point-X"),
                2,
            )

    def test_missing_and_extra_entries_are_rejected(self):
        with self.assertRaisesRegex(QueryCompatibilityError, "missing point 1"):
            compare_point_sequences("A", (b"one",), (b"one",), 2)
        with self.assertRaisesRegex(QueryCompatibilityError, "extra points"):
            compare_point_sequences("B_G1", (b"one", b"two"), (b"one",), 1)

    def test_incorrect_sparse_indices_are_rejected(self):
        expected = _valid_mapping()
        reordered = _valid_mapping()
        reordered["a_query"] = list(reversed(reordered["a_query"]))
        with self.assertRaisesRegex(QueryCompatibilityError, "indices differ"):
            validate_query_index_mapping(reordered, expected)

        wrong_index = _valid_mapping()
        wrong_index["b_g1_query"][1]["query_index"] = 0
        with self.assertRaisesRegex(QueryCompatibilityError, "indices differ"):
            validate_query_index_mapping(wrong_index, expected)

    def test_reordered_or_truncated_export_sections_are_rejected(self):
        reordered = io.BytesIO(b"\x01h" + (8_191).to_bytes(4, "big"))
        with self.assertRaisesRegex(QueryCompatibilityError, "expected Bellman section ic"):
            _read_export_section(reordered, "ic", 6)

        truncated = io.BytesIO(b"\x02ic\x00\x00")
        with self.assertRaisesRegex(QueryCompatibilityError, "truncated"):
            _read_export_section(truncated, "ic", 6)


if __name__ == "__main__":
    unittest.main()
