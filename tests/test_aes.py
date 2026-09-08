"""AES-cipher tests: FIPS-197 vectors + CBC / ECB / bitflip behaviors."""
import unittest

from cryptocrack.aes_attacks import (
    aes_encrypt_block, aes_decrypt_block, pkcs7_pad, pkcs7_unpad,
    pkcs7_valid, cbc_encrypt, cbc_decrypt, detect_ecb,
    cbc_bitflip_with_known_pt, PaddingOracle, padding_oracle_attack,
)

FIPS_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIPS_PT = bytes.fromhex("00112233445566778899aabbccddeeff")


class TestFips197Vectors(unittest.TestCase):
    def test_aes128(self):
        self.assertEqual(aes_encrypt_block(FIPS_PT, FIPS_KEY).hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_aes192(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
        self.assertEqual(aes_encrypt_block(FIPS_PT, key).hex(),
                         "dda97ca4864cdfe06eaf70a0ec0d7191")

    def test_aes256(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                            "101112131415161718191a1b1c1d1e1f")
        self.assertEqual(aes_encrypt_block(FIPS_PT, key).hex(),
                         "8ea2b7ca516745bfeafc49904b496089")

    def test_decrypt_roundtrip(self):
        for key in [bytes.fromhex("00" * 16), FIPS_KEY]:
            ct = aes_encrypt_block(FIPS_PT, key)
            self.assertEqual(aes_decrypt_block(ct, key).hex(), FIPS_PT.hex())


class TestPkcs7(unittest.TestCase):
    def test_pad_roundtrip(self):
        for size in range(0, 40):
            self.assertEqual(pkcs7_unpad(pkcs7_pad(b"A" * size, 16)),
                             b"A" * size)

    def test_pad_adds_full_block(self):
        p = pkcs7_pad(b"B" * 16, 16)
        self.assertEqual(len(p), 32)
        self.assertTrue(pkcs7_valid(p))

    def test_invalid_padding_rejected(self):
        self.assertFalse(pkcs7_valid(bytes(16)))


class TestCbc(unittest.TestCase):
    def test_roundtrip_with_random_iv(self):
        pt = b"attack at dawn with a much longer message!!"
        ct, iv = cbc_encrypt(pt, FIPS_KEY)
        self.assertEqual(cbc_decrypt(ct, FIPS_KEY, iv), pkcs7_pad(pt, 16))
        self.assertEqual(pkcs7_unpad(cbc_decrypt(ct, FIPS_KEY, iv)), pt)

    def test_iv_differs_per_encryption(self):
        _, iv1 = cbc_encrypt(b"hello", FIPS_KEY)
        _, iv2 = cbc_encrypt(b"hello", FIPS_KEY)
        self.assertNotEqual(iv1, iv2)


class TestEcbDetect(unittest.TestCase):
    def test_detects_ecb(self):
        rep = pkcs7_pad(b"YELLOW SUBMARINE" * 20, 16)
        ct = b"".join(aes_encrypt_block(rep[i:i + 16], FIPS_KEY)
                      for i in range(0, len(rep), 16))
        self.assertTrue(detect_ecb(ct)["is_ecb"])

    def test_cbc_not_detected(self):
        rep = pkcs7_pad(b"YELLOW SUBMARINE" * 20, 16)
        ct, iv = cbc_encrypt(rep, FIPS_KEY)
        self.assertFalse(detect_ecb(ct)["is_ecb"])


class TestBitflip(unittest.TestCase):
    def test_flips_first_byte(self):
        pt = b"AAAAAAAABBBBBBBB"
        ct, iv = cbc_encrypt(pt, FIPS_KEY, iv=bytes(16))
        new_iv = cbc_bitflip_with_known_pt(iv, ct[:16], FIPS_KEY, 0x41, 0x58, 0)
        got = pkcs7_unpad(cbc_decrypt(ct, FIPS_KEY, new_iv))
        self.assertEqual(got, b"XAAAAAAABBBBBBBB")

    def test_flips_between_blocks(self):
        pt = b"AAAAAAAABBBBBBBB"
        ct, iv = cbc_encrypt(pt, FIPS_KEY, iv=bytes(16))
        new_iv = cbc_bitflip_with_known_pt(iv, ct[:16], FIPS_KEY, 0x41, 0x42, 7)
        got = pkcs7_unpad(cbc_decrypt(ct, FIPS_KEY, new_iv))
        self.assertEqual(got, b"AAAAAAABBBBBBBBB")  # byte 7: A -> B


class TestPaddingOracle(unittest.TestCase):
    def test_recover_plaintext(self):
        oracle = PaddingOracle(FIPS_KEY)
        oracle.start()
        try:
            secret = b"the oracle always tells the truth"
            ct, iv = oracle.encrypt(secret)
            interm = padding_oracle_attack(oracle.oracle, iv, ct)
            blocks, prev, out = [], iv, []
            for i in range(0, len(ct), 16):
                blk = ct[i:i + 16]
                d = interm[i:i + 16]
                out.append(bytes(a ^ b for a, b in zip(prev, d)))
                prev = blk
            got = pkcs7_unpad(b"".join(out))
            self.assertEqual(got, secret)
        finally:
            oracle.stop()


if __name__ == "__main__":
    unittest.main()