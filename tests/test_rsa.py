"""RSA attack tests: wiener, fermat, hastad, small-e, common modulus, CPA demo."""
import math
import random
import unittest

from cryptocrack.rsa_attacks import (
    _modinv, _is_prime_miller_rabin, generate_rsa_key, rsa_encrypt, rsa_decrypt,
    wiener_attack, fermat_factor, hastad_broadcast, small_e_root,
    common_modulus, chosen_message_cpa_check,
)


def nextprime(n):
    n = n | 1
    while not _is_prime_miller_rabin(n, k=40):
        n += 2
    return n


class TestMillerRabin(unittest.TestCase):
    def test_known_primes(self):
        for p in (452159, 452161, 15485863, 1000003):
            self.assertTrue(_is_prime_miller_rabin(p, 40))

    def test_known_composites(self):
        for c in (452155, 452157, 3233, 1000003 * 1000003):
            self.assertFalse(_is_prime_miller_rabin(c, 40))

    def test_nextprime_like_loop(self):
        base = 452151  # odd base; n must advance odd->odd to reach 452159
        candidate = base
        while not _is_prime_miller_rabin(candidate, 40):
            candidate += 2
        self.assertEqual(candidate, 452159)


class TestKeygen(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        p, q = nextprime(999983), nextprime(1000009)
        key = generate_rsa_key(p, q)
        self.assertTrue(key["n"] > 1)
        m = 424242
        c = rsa_encrypt(m, key["e"], key["n"])
        self.assertEqual(rsa_decrypt(c, key["d"], key["n"]), m)


class TestWiener(unittest.TestCase):
    def test_small_d(self):
        w = wiener_attack(e=2489, n=11413)
        self.assertTrue(w["success"])
        self.assertEqual(w["d"], 9)


class TestFermat(unittest.TestCase):
    def test_close_primes(self):
        random.seed(7)
        p = nextprime(random.randrange(10**11, 2 * 10**11))
        q = nextprime(p + 6)
        f = fermat_factor(p * q, max_iter=10**7)
        self.assertTrue(f["success"])
        self.assertCountEqual([f["p"], f["q"]], [p, q])


class TestHastad(unittest.TestCase):
    def test_broadcast_e3(self):
        random.seed(3)
        m = 98765431
        ns, cs = [], []
        while len(ns) < 3:
            pp = nextprime(random.randint(3, 10**13))
            qq = nextprime(random.randint(3, 10**13))
            nn = pp * qq
            if nn > m**3 and math.gcd(3, (pp - 1) * (qq - 1)) == 1:
                ns.append(nn)
                cs.append(pow(m, 3, nn))
        h = hastad_broadcast(3, ns, cs)
        self.assertTrue(h["success"])
        self.assertEqual(h["plaintext"], m)


class TestSmallERoot(unittest.TestCase):
    def test_unpadded_cube(self):
        m, e, n = 14, 3, 3233   # 14^3 = 2744 < n: no wraparound
        s = small_e_root(pow(m, e, n), e, n)
        self.assertTrue(s["success"])
        self.assertEqual(s["plaintext"], m)


class TestCommonModulus(unittest.TestCase):
    def test_shared_n(self):
        p, q = 101, 113
        n = p * q
        phi = (p - 1) * (q - 1)
        e1, e2 = 17, 19
        while math.gcd(e1, phi) != 1:
            e1 += 2
        while math.gcd(e2, phi) != 1:
            e2 += 2
        m = 987654321 % n
        c1, c2 = pow(m, e1, n), pow(m, e2, n)
        r = common_modulus(c1, c2, e1, e2, n)
        self.assertTrue(r["success"])
        self.assertEqual(r["plaintext"], m)


class TestCpaVulnerability(unittest.TestCase):
    def test_textbook_rsa_is_deterministic(self):
        p, q = 61, 53
        n = p * q
        e = 17
        key = generate_rsa_key(p, q)
        d = key["d"]
        enc = lambda m: rsa_encrypt(m, e, n)
        dec = lambda c: rsa_decrypt(c, d, n)
        r = chosen_message_cpa_check(e, n, enc, dec)
        self.assertTrue(r["deterministic"])
        # 0^e and 1^e are their own ciphertexts: textbook RSA is IND-CPA-broken
        self.assertTrue(r["encrypted_zero_is_zero"])
        self.assertTrue(r["encrypted_one_is_one"])

    def test_modinv(self):
        self.assertEqual(_modinv(3, 11), 4)
        self.assertEqual((3 * 4) % 11, 1)


if __name__ == "__main__":
    unittest.main()