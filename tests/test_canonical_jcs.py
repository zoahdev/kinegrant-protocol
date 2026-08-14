from __future__ import annotations

import hashlib
import unittest

from kinegrant.canonical import canonical_json, content_id, digest


class JcsEncodingTests(unittest.TestCase):
    def assert_jcs(self, value: object, expected: str) -> None:
        self.assertEqual(canonical_json(value).decode("utf-8"), expected)

    def test_object_members_sorted_by_utf16_code_units(self) -> None:
        self.assert_jcs({"b": 1, "a": 2}, '{"a":2,"b":1}')

    def test_rfc8785_example_mixed_types(self) -> None:
        self.assert_jcs(
            {"c": 0, "b": "0", "a": None},
            '{"a":null,"b":"0","c":0}',
        )

    def test_integral_floats_use_integer_notation(self) -> None:
        self.assert_jcs({"a": 1.0, "b": 1}, '{"a":1,"b":1}')

    def test_negative_zero_is_serialized_as_zero(self) -> None:
        self.assert_jcs({"x": -0.0}, '{"x":0}')

    def test_small_exponents_follow_ecmascript_notation(self) -> None:
        self.assert_jcs({"x": 1e-7}, '{"x":1e-7}')
        self.assert_jcs({"x": 1e-6}, '{"x":0.000001}')
        self.assert_jcs({"x": 0.00001}, '{"x":0.00001}')

    def test_large_numbers_follow_ecmascript_notation(self) -> None:
        self.assert_jcs({"x": 1e20}, '{"x":100000000000000000000}')
        self.assert_jcs({"x": 1e21}, '{"x":1e+21}')

    def test_shortest_float_round_trip_is_preserved(self) -> None:
        self.assert_jcs({"x": 0.1}, '{"x":0.1}')
        self.assert_jcs({"x": 1.2345678901234567e30}, '{"x":1.2345678901234567e+30}')

    def test_line_separators_are_escaped(self) -> None:
        self.assert_jcs({"x": "a\u2028b"}, '{"x":"a\\u2028b"}')
        self.assert_jcs({"x": "a\u2029b"}, '{"x":"a\\u2029b"}')

    def test_control_characters_are_escaped(self) -> None:
        self.assert_jcs({"x": "a\x01b"}, '{"x":"a\\u0001b"}')
        self.assert_jcs({"x": "a\nb"}, '{"x":"a\\nb"}')

    def test_supplementary_plane_sorting_matches_utf16(self) -> None:
        # U+1D11E encodes as surrogate pair D834 DD1E, which sorts before U+E000.
        self.assert_jcs(
            {"\ue000": 2, "\U0001d11e": 1},
            '{"\U0001d11e":1,"\ue000":2}',
        )

    def test_non_ascii_strings_are_not_escaped(self) -> None:
        self.assert_jcs({"x": "开门"}, '{"x":"开门"}')

    def test_nan_and_infinity_are_rejected(self) -> None:
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                canonical_json({"x": bad})

    def test_unsafe_integers_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            canonical_json({"x": 2**53})
        with self.assertRaises(ValueError):
            canonical_json({"x": -(2**53)})
        self.assert_jcs({"x": 2**53 - 1}, f'{{"x":{2**53 - 1}}}')

    def test_non_string_member_names_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            canonical_json({1: "x"})

    def test_arrays_preserve_order(self) -> None:
        self.assert_jcs([3, 1, 2], "[3,1,2]")

    def test_digest_is_sha256_of_jcs(self) -> None:
        value = {"b": 2, "a": 1}
        expected = "sha256:" + hashlib.sha256(b'{"a":1,"b":2}').hexdigest()
        self.assertEqual(digest(value), expected)
        self.assertEqual(content_id("kg", value), f"kg:{expected.split(':', 1)[1]}")

    def test_jcs_matches_plain_json_for_existing_wire_objects(self) -> None:
        # Objects emitted by the reference implementation must not change digest.
        sample = {
            "type": "kinegrant:ActionRequest",
            "version": "0.1",
            "request_id": "req-1",
            "agent": "delivery-robot-07",
            "target": "door-7",
            "action": "open",
            "purpose": "delivery",
            "issued_at": "2026-08-14T00:00:00Z",
            "context": {},
        }
        import json

        self.assertEqual(
            canonical_json(sample),
            json.dumps(
                sample,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
