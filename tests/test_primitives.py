"""Known-answer vector tests for the pure-python hash primitives."""
import unittest

from cryptocrack.primitives import (
    md4, md5, sha1, sha256, sha512, md5_crypt, sha256_crypt, sha512_crypt,
    _sha_crypt_encode, _repeat_string,
)


class TestMD4RFC1320(unittest.TestCase):
    def test_abc(self):
        self.assertEqual(md4(b"abc").hex(), "a448017aaf21d8525fc10ae87aa6729d")

    def test_empty(self):
        self.assertEqual(md4(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_a_1M(self):
        # verified cross-checked against PyCryptodome MD4
        self.assertEqual(md4(b"a" * 1000000).hex(),
                         "bbce80cc6bb65e5c6745e30d4eeca9a4")


class TestMD5RFC1321(unittest.TestCase):
    def test_messages(self):
        self.assertEqual(md5(b"").hex(), "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(md5(b"abc").hex(), "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(md5(b"password").hex(),
                         "5f4dcc3b5aa765d61d8327deb882cf99")

    def test_message_digest(self):
        self.assertEqual(
            md5(b"The quick brown fox jumps over the lazy dog").hex(),
            "9e107d9d372bb6826bd81d3542a419d6")


class TestSHA(unittest.TestCase):
    def test_sha1_abc(self):
        self.assertEqual(sha1(b"abc").hex(), "a9993e364706816aba3e25717850c26c9cd0d89d")

    def test_sha256_abc(self):
        self.assertEqual(
            sha256(b"abc").hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_sha256_hello(self):
        self.assertEqual(
            sha256(b"hello").hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

    def test_sha512_abc(self):
        self.assertEqual(
            sha512(b"abc").hex(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")

    def test_sha512_hello(self):
        self.assertEqual(
            sha512(b"hello").hex(),
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7"
            "2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043")


class TestMD5Crypt(unittest.TestCase):
    def test_known_vector_openssl(self):
        self.assertEqual(md5_crypt("password", "salt1234"),
                         "$1$salt1234$HJCsv4hSeVLHo3hVyl4nh0")

    def test_crosscheck_openssl(self):
        import subprocess
        out = subprocess.run(
            ["openssl", "passwd", "-1", "-salt", "xy", "hello"],
            capture_output=True, text=True).stdout.strip()
        self.assertEqual(md5_crypt("hello", "xy"), out)


class TestShaCryptPasslib(unittest.TestCase):
    def test_sha256_rounds_5000(self):
        self.assertEqual(
            sha256_crypt("hello", "its", 5000),
            "$5$its$H5uICVlQJ7tBxsfd09UF2p9PnLVpfvAp8x7MqZzCaa8")

    def test_sha512_rounds_5000(self):
        self.assertEqual(
            sha512_crypt("hello", "its", 5000),
            "$6$its$FMASy05ZxOx5Z1EkdFJTAWGMh1uqJ4jbD.Oboo51stMbT9kiKpGF0jXXHV5kx6KE4XkhSdq2HbRWiELSDc.vM.")

    def test_rounds_prefix_omitted_at_5000(self):
        h = sha256_crypt("x", "y", 5000)
        self.assertTrue(h.startswith("$5$y$"))

    def test_rounds_prefix_added(self):
        h = sha512_crypt("x", "y", 10000)
        self.assertTrue(h.startswith("$6$rounds=10000$y$"))

    def test_reproducible_and_different_salt(self):
        self.assertEqual(sha256_crypt("p", "s", 1000), sha256_crypt("p", "s", 1000))
        self.assertNotEqual(sha256_crypt("p", "s", 1000),
                            sha256_crypt("p", "other", 1000))


class TestInternalHelpers(unittest.TestCase):
    def test_repeat_string_semantics(self):
        # passlib semantics: >= size means just truncate to size
        self.assertEqual(_repeat_string(b"abc", 5), b"abcab")
        self.assertEqual(_repeat_string(b"abc", 3), b"abc")
        self.assertEqual(_repeat_string(b"abc", 2), b"ab")
        self.assertEqual(_repeat_string(b"", 5), b"")

    def test_sha_crypt_encode_present(self):
        h = _sha_crypt_encode(b"\x2f" * 32, 5000, "sa", 32)
        self.assertTrue(h.startswith("$5$sa$"))
        self.assertEqual(len(h.split("$")[-1]), 43)  # 32-byte checksum line


if __name__ == "__main__":
    unittest.main()