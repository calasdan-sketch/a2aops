"""AgentCard signature verification: known-answer vectors made by the official
Python SDK signer (public keys only), runtime-generated ECDSA keys, and attacks."""

import copy
import hashlib
import json
import secrets
import unittest
from pathlib import Path

from a2aops import cardsig, jws

FIX = Path(__file__).parent / "fixtures"
VECTORS = json.loads((FIX / "signed_cards_sdk.json").read_text())


class TestCurves(unittest.TestCase):
    def test_generators_have_the_group_order(self):
        for c in (jws.P256, jws.P384):
            self.assertTrue(c.on_curve(c.g))
            self.assertIsNone(c.mul(c.n, c.g))
            self.assertIsNotNone(c.mul(c.n - 1, c.g))

    def test_runtime_ecdsa_roundtrip_and_tamper(self):
        for curve, h in ((jws.P256, hashlib.sha256), (jws.P384, hashlib.sha384)):
            d = secrets.randbelow(curve.n - 2) + 1
            pub = curve.mul(d, curve.g)
            k = secrets.randbelow(curve.n - 2) + 1
            sig = jws.ecdsa_sign_for_tests(curve, d, b"hello", h, k)
            self.assertTrue(jws.ecdsa_verify(curve, pub, b"hello", sig, h))
            self.assertFalse(jws.ecdsa_verify(curve, pub, b"hellp", sig, h))
            flipped = bytes([sig[0] ^ 1]) + sig[1:]
            self.assertFalse(jws.ecdsa_verify(curve, pub, b"hello", flipped, h))
            self.assertFalse(jws.ecdsa_verify(curve, pub, b"hello", sig[:-1], h))
            zero = b"\0" * len(sig)
            self.assertFalse(jws.ecdsa_verify(curve, pub, b"hello", zero, h))
            # a point not on the curve is rejected
            self.assertFalse(jws.ecdsa_verify(curve, (pub[0], pub[1] ^ 1), b"hello", sig, h))


class TestJcs(unittest.TestCase):
    def test_rfc8785_examples(self):
        # RFC 8785 appendix B number samples
        for value, text in ((1e21, "1e+21"), (1e-7, "1e-7"), (0.000001, "0.000001"),
                            (333333333.33333329, "333333333.3333333"), (4.5, "4.5"),
                            (2e-3, "0.002"), (1.0, "1"), (-0.0, "0"), (1e20, "100000000000000000000"),
                            (123456789012345680000.0, "123456789012345680000")):
            self.assertEqual(jws.canonicalize(value), text, value)

    def test_key_order_is_by_utf16_code_unit_and_strings_are_literal(self):
        obj = {"\u20ac": 1, "\U0001f600": 2, "a": 3, "\r": 4}
        with self.assertRaises(jws.JwsError):
            jws.canonicalize("\ud83d")          # a lone surrogate is not valid JSON text
        self.assertEqual(jws.canonicalize(obj), '{"\\r":4,"a":3,"\u20ac":1,"\U0001f600":2}')
        self.assertEqual(jws.canonicalize("\u2028\x7f"), '"\u2028\x7f"')
        self.assertEqual(jws.canonicalize("\x01"), '"\\u0001"')

    def test_deep_nesting_is_refused_not_a_crash(self):
        deep = cur = []
        for _ in range(400):
            nxt = []
            cur.append(nxt)
            cur = nxt
        with self.assertRaises(jws.JwsError):
            jws.canonicalize(deep)

    def test_nan_and_huge_ints_refused(self):
        with self.assertRaises(jws.JwsError):
            jws.canonicalize(float("nan"))
        with self.assertRaises(jws.JwsError):
            jws.canonicalize(2 ** 60)


class TestSdkVectors(unittest.TestCase):
    """Cards signed by the official a2a-sdk signer must verify here."""

    def check(self, name):
        v = VECTORS[name]
        return jws.verify_signature(v["card"], v["card"]["signatures"][0], [v["jwk"]])

    def test_es256_es384_rs256_verify(self):
        for name in ("ES256", "ES384", "RS256"):
            self.assertEqual(self.check(name), ("valid", "spec"), name)

    def test_sdk_profile_difference_is_reported_not_hidden(self):
        # capabilities: {} is REQUIRED (spec keeps it) but the SDK signer drops it
        self.assertEqual(self.check("ES256-empty-capabilities"), ("valid", "sdk"))
        diags = cardsig.verify_card(VECTORS["ES256-empty-capabilities"]["card"],
                                    [VECTORS["ES256-empty-capabilities"]["jwk"]])
        self.assertIn("G909", [d.code for d in diags])

    def test_tampering_breaks_every_vector(self):
        for name in ("ES256", "ES384", "RS256"):
            v = copy.deepcopy(VECTORS[name])
            v["card"]["skills"][0]["description"] += " (edited)"
            out, _ = jws.verify_signature(v["card"], v["card"]["signatures"][0], [v["jwk"]])
            self.assertEqual(out, "invalid", name)

    def test_wrong_key_is_invalid_and_wrong_kid_is_no_key(self):
        v = copy.deepcopy(VECTORS["ES256"])
        other = copy.deepcopy(VECTORS["ES384"]["jwk"])
        other["kid"] = "test-key-1"
        out, _ = jws.verify_signature(v["card"], v["card"]["signatures"][0], [other])
        self.assertIn(out, ("refused", "invalid"))      # P-384 key cannot verify an ES256 header
        v["jwk"]["kid"] = "someone-else"
        out, _ = jws.verify_signature(v["card"], v["card"]["signatures"][0], [v["jwk"]])
        self.assertEqual(out, "no-key")

    def test_key_type_chooses_algorithm_family(self):
        v = copy.deepcopy(VECTORS["RS256"])
        card = v["card"]
        sig = dict(card["signatures"][0])
        hdr = json.loads(jws.b64u_decode(sig["protected"]))
        for bad_alg in ("none", "HS256", "ES256"):
            hdr["alg"] = bad_alg
            sig["protected"] = jws.b64u_encode(json.dumps(hdr).encode())
            out, _ = jws.verify_signature(card, sig, [v["jwk"]])
            self.assertEqual(out, "refused", bad_alg)
        hdr["alg"] = "PS256"
        sig["protected"] = jws.b64u_encode(json.dumps(hdr).encode())
        self.assertEqual(jws.verify_signature(card, sig, [v["jwk"]])[0], "unsupported")

    def test_malformed_entries_do_not_crash(self):
        card = VECTORS["ES256"]["card"]
        for sig in ({}, {"protected": "!!", "signature": "x"}, {"protected": "e30", "signature": "abc"},
                    {"protected": jws.b64u_encode(b"[1]"), "signature": "abc"}):
            out, _ = jws.verify_signature(card, sig, [VECTORS["ES256"]["jwk"]])
            self.assertEqual(out, "malformed")


class TestVerifyCard(unittest.TestCase):
    def test_no_signatures_is_an_error(self):
        diags = cardsig.verify_card({"name": "x"}, [])
        self.assertEqual([d.code for d in diags], ["G901"])

    def test_jku_is_ignored_by_default_and_never_fetched(self):
        v = VECTORS["ES256"]
        calls = []
        diags = cardsig.verify_card(v["card"], [], fetch=lambda *a: calls.append(a) or {"keys": [v["jwk"]]})
        self.assertEqual(calls, [])                                   # attacker URL not fetched
        self.assertNotIn("G902", [d.code for d in diags])             # and no key => not verified
        self.assertIn("G905", [d.code for d in diags])

    def test_trust_jku_only_on_the_cards_own_host(self):
        v = VECTORS["ES256"]
        calls = []

        def fetch(url, timeout):
            calls.append(url)
            return {"keys": [v["jwk"]]}

        d1 = cardsig.verify_card(v["card"], [], card_host="evil.example", trust_jku=True, fetch=fetch)
        self.assertEqual(calls, [])
        self.assertNotIn("G902", [d.code for d in d1])
        d2 = cardsig.verify_card(v["card"], [], card_host="example.com", trust_jku=True, fetch=fetch)
        self.assertEqual(calls, ["https://example.com/jwks.json"])
        self.assertIn("G902", [d.code for d in d2])

    def test_runtime_signed_card_end_to_end(self):
        curve = jws.P256
        d = secrets.randbelow(curve.n - 2) + 1
        x, y = curve.mul(d, curve.g)
        jwk = {"kty": "EC", "crv": "P-256", "kid": "rt", "x": jws.b64u_encode(x.to_bytes(32, "big")),
               "y": jws.b64u_encode(y.to_bytes(32, "big"))}
        card = json.loads((FIX / "card_v1_valid.json").read_text())
        card.pop("signatures", None)
        prot = jws.b64u_encode(json.dumps({"alg": "ES256", "kid": "rt", "typ": "JOSE"}).encode())
        payload = jws.b64u_encode(jws.canonical_payload(card))
        sig = jws.ecdsa_sign_for_tests(curve, d, f"{prot}.{payload}".encode(), hashlib.sha256,
                                       secrets.randbelow(curve.n - 2) + 1)
        card["signatures"] = [{"protected": prot, "signature": jws.b64u_encode(sig)}]
        self.assertIn("G902", [x.code for x in cardsig.verify_card(card, [jwk])])
        card["name"] = "Mallory"
        self.assertIn("G903", [x.code for x in cardsig.verify_card(card, [jwk])])


if __name__ == "__main__":
    unittest.main()
