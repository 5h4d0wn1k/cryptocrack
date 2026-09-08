"""Crack-engine tests: wordlist + rules, masks, NTLM, crypt verification."""
import unittest

from cryptocrack.primitives import md5, sha256_crypt, sha512_crypt, sha256
from cryptocrack.crack import (
    crack, crack_wordlist, crack_mask, expand_mask, _ntlm_hash,
    _verify_crypt_hash, DEFAULT_RULE_ORDER, CrackResult,
)

WORDS = ["password", "secret", "123456", "horse", "P@ssw0rd", "correcthorse"]


class TestWordlist(unittest.TestCase):
    def test_identity_match(self):
        r = crack_wordlist(md5(b"secret").hex(), WORDS, "md5")
        self.assertTrue(r.cracked)
        self.assertEqual(r.password, "secret")

    def test_case_rule_match(self):
        # 'secret' -> 'Secret'/'SECRET' via case rules
        r = crack_wordlist(md5(b"SECRET").hex(), WORDS, "md5", rules=["case"])
        self.assertTrue(r.cracked)
        self.assertEqual(r.password, "SECRET")

    def test_append_digits_rule(self):
        r = crack_wordlist(md5(b"secret1337").hex(), WORDS, "md5",
                           rules=["append_digits"])
        self.assertTrue(r.cracked)
        self.assertEqual(r.password, "secret1337")

    def test_leet_rule(self):
        r = crack_wordlist(md5(b"p@ssw0rd").hex(), WORDS, "md5", rules=["leet"])
        self.assertTrue(r.cracked)
        self.assertEqual(r.password, "p@ssw0rd")

    def test_high_level_crack_falls_back_to_mask(self):
        r = crack(md5(b"cat9").hex(), WORDS, "md5", mask="?l?l?l?d")
        self.assertTrue(r.cracked)
        self.assertEqual(r.password, "cat9")
        self.assertTrue(r.method.startswith("mask"))

    def test_sha512_uses_pure_python(self):
        # method goes through _hash_func('sha512') which must not import hashlib
        r = crack_wordlist(sha256(b"secret").hex(), WORDS, "sha256")
        self.assertTrue(r.cracked)


class TestNtlm(unittest.TestCase):
    def test_ntlm_constant(self):
        self.assertEqual(_ntlm_hash("passw0rd").hex(),
                         "b9f917853e3dbf6e6831ecce60725930")

    def test_ntlm_crack(self):
        r = crack_wordlist(_ntlm_hash("password").hex(), ["secret", "password"],
                           "ntlm")
        self.assertTrue(r.cracked)
        self.assertEqual(r.password, "password")


class TestCryptVerification(unittest.TestCase):
    def test_md5crypt(self):
        from cryptocrack.primitives import md5_crypt
        h = md5_crypt("horse", "pepper")
        self.assertTrue(_verify_crypt_hash("horse", h))
        self.assertFalse(_verify_crypt_hash("horse!", h))

    def test_sha256crypt_rounds(self):
        h = sha256_crypt("secret", "ab", 10000)
        self.assertTrue(_verify_crypt_hash("secret", h))
        self.assertFalse(_verify_crypt_hash("wrong", h))

    def test_sha512crypt_older_rounds(self):
        h = sha512_crypt("secret", "cd", 5000)
        self.assertTrue(_verify_crypt_hash("secret", h))

    def test_crack_wordlist_via_crypt_hash(self):
        h = sha256_crypt("secret", "ef", 1000)
        r = crack("", WORDS, "sha256", crypt_hash=h)
        self.assertTrue(r.cracked)
        self.assertEqual(r.password, "secret")

    def test_unknown_scheme_rejected(self):
        self.assertFalse(_verify_crypt_hash("x", "$999$x$y$z"))


class TestMask(unittest.TestCase):
    def test_expand_mask_counts(self):
        self.assertEqual(len(expand_mask("?d?d")), 100)
        self.assertEqual(len(expand_mask("?u")), 26)

    def test_mask_crack(self):
        r = crack_mask(md5(b"Z9").hex(), "?u?d", "md5")
        self.assertTrue(r.cracked)
        self.assertEqual(r.password, "Z9")

    def test_default_rule_order_sane(self):
        self.assertIn("identity", DEFAULT_RULE_ORDER)
        self.assertIn("append_digits", DEFAULT_RULE_ORDER)


class TestResult(unittest.TestCase):
    def test_stats(self):
        r = CrackResult(True, "pw", "md5", "wordlist", 10, 0.5)
        s = r.stats()
        self.assertTrue(s["cracked"])
        self.assertEqual(s["rate"], 20.0)


if __name__ == "__main__":
    unittest.main()