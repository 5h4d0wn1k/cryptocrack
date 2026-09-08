"""Decode / hashes / hygiene / dh-mitm / cpa tests."""
import unittest

from cryptocrack import decode, hashes, hygiene, dh_mitm, cpa
from cryptocrack.primitives import md5, sha1


class TestCaesar(unittest.TestCase):
    def test_known_shift(self):
        best = decode.caesar_bruteforce("Khoor Zruog")[0]
        self.assertEqual(best[1], "Hello World")

    def test_roundtrip_preserves_punctuation(self):
        out = decode.caesar_bruteforce("Jryy qbar!")[0][1]
        self.assertEqual(out, "Well done!")


class TestVigenere(unittest.TestCase):
    def test_decrypt(self):
        self.assertEqual(decode.vigenere_decrypt("Rijvs Uyvjn", "KEY"),
                         "Hello World")

    def test_ignores_nonalpha(self):
        self.assertEqual(decode.vigenere_decrypt("1Zv Sfv", "AB"), "1Zu Sev")


class TestXorSingleByte(unittest.TestCase):
    def test_recovers_key(self):
        orig = "Hello World"
        ct = bytes([ord(c) ^ 0x20 for c in orig])
        key, text, _ = decode.xor_single_byte(ct)
        self.assertEqual(key, 0x20)
        self.assertEqual(text, orig)

    def test_recovers_various_key(self):
        orig = "'Twas brillig, and the slithy toves"
        ct = bytes([ord(c) ^ 0x2a for c in orig])
        key, text, _ = decode.xor_single_byte(ct)
        self.assertEqual(key, 0x2a)
        self.assertEqual(text, orig)


class TestEncodings(unittest.TestCase):
    def test_hex(self):
        self.assertEqual(decode.hex_decode("48656c6c6f20576f726c64"),
                         "Hello World")

    def test_base64(self):
        self.assertEqual(decode.base64_decode("SGVsbG8gV29ybGQ="), "Hello World")

    def test_auto_detects_hex(self):
        r = decode.auto_decode("48656c6c6f20576f726c64")
        self.assertEqual(r["hex"], "Hello World")

    def test_auto_detects_base64(self):
        r = decode.auto_decode("SGVsbG8gV29ybGQ=")
        self.assertEqual(r["base64"], "Hello World")


class TestHashIdentify(unittest.TestCase):
    def test_md5_ambiguous(self):
        h = hashes.identify_hash(md5(b"password").hex())
        self.assertIn(h["type"], ("MD5", "NTLM"))
        self.assertEqual(h["confidence"], "medium")

    def test_sha1_high(self):
        h = hashes.identify_hash(sha1(b"password").hex())
        self.assertEqual(h["type"], "SHA-1")
        self.assertEqual(h["confidence"], "high")

    def test_md5crypt(self):
        h = hashes.identify_hash("$1$salt1234$HJCsv4hSeVLHo3hVyl4nh0")
        self.assertEqual(h["type"], "MD5-crypt ($1$)")

    def test_sha512crypt(self):
        h = hashes.identify_hash("$6$rounds=5000$its$FMASy05ZxOx5Z1EkdFJTAWGM"
                                 "h1uqJ4jbD.Oboo51stMbT9kiKpGF0jXXHV5kx6KE4X"
                                 "khSdq2HbRWiELSDc.vM.")
        self.assertEqual(h["type"], "SHA-512-crypt ($6$)")


class TestHygiene(unittest.TestCase):
    def test_weak_common_password(self):
        r = hygiene.password_strength("password")
        self.assertEqual(r["level"], "weak")

    def test_strong_password(self):
        r = hygiene.password_strength("Tr0ub4dor&3")
        self.assertEqual(r["level"], "strong")

    def test_common_password_check(self):
        self.assertTrue(hygiene.check_common_password("password"))
        self.assertFalse(hygiene.check_common_password("Xk7#qLm2zWp9"))

    def test_key_validation_rejects_weak(self):
        v = hygiene.validate_key_hex("00000000000000000000000000000000")
        self.assertFalse(v["valid"])
        self.assertTrue(any("identical" in e.lower() for e in v["errors"]))

    def test_key_with_entropy_ok(self):
        v = hygiene.validate_key_hex("9f86d081884c7d659a2feaa0c55ad015")
        self.assertTrue(v["valid"])


class TestDhMitm(unittest.TestCase):
    def test_simulation(self):
        r = dh_mitm.simulate_dh_mitm()
        self.assertTrue(r["mitm"]["different_keys"])
        self.assertNotEqual(r["alice_key"], r["bob_key"])

    def test_generator_classification(self):
        # small safe prime 23 = 2*11+1: g=2 -> order-11 subgroup, g=5 order 22
        v = dh_mitm.validate_generator(2, 23)
        self.assertTrue(v["valid"])
        self.assertEqual(v["class"], "prime-subgroup")
        v2 = dh_mitm.validate_generator(5, 23)
        self.assertTrue(v2["valid"])
        self.assertEqual(v2["class"], "full")
        bad = dh_mitm.validate_generator(1, 23)
        self.assertFalse(bad["valid"])

    def test_safe_prime_default(self):
        self.assertTrue(dh_mitm._is_prime_miller_rabin(23))


class TestCpa(unittest.TestCase):
    def test_xts_tweak_deterministic(self):
        k2 = bytes(16)
        self.assertEqual(cpa.xts_tweak_block(3, k2),
                         cpa.xts_tweak_block(3, k2))
        self.assertNotEqual(cpa.xts_tweak_block(3, k2),
                            cpa.xts_tweak_block(4, k2))

    def test_alpha_mul_consistent(self):
        # multiply by x in GF(2^128)
        self.assertEqual(cpa._alpha_mul(bytes(16)), bytes(16))
        self.assertEqual(cpa._alpha_mul(bytes([1]) + bytes(15)),
                         bytes([2]) + bytes(15))

    def test_synthetic_attack_recovers_key(self):
        import random
        random.seed(0)
        k1 = bytes.fromhex("deadbeefcafebabe4141414141414141")
        traces, _ = cpa.generate_synthetic_traces(80, secret_key=k1 + bytes(16))
        recovered, corrs = cpa.cpa_attack(traces)
        self.assertEqual(recovered, k1)

    def test_run_demo(self):
        import random
        random.seed(1)
        r = cpa.run_demo(150)
        self.assertTrue(r["success"])
        self.assertEqual(r["key_bytes_recovered"], 16)


if __name__ == "__main__":
    unittest.main()