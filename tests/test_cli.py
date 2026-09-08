"""Smoke tests for the CLI subcommands (offline, fast paths only)."""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_cli(*argv, timeout=120):
    env = {"PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(
        [sys.executable, "-m", "cryptocrack.cli", *argv],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=env,
    )


class TestCli(unittest.TestCase):
    def test_version(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn("cryptocrack", r.stdout)

    def test_hash_md5_hex(self):
        r = run_cli("hash", "hello", "-a", "md5")
        self.assertEqual(r.returncode, 0)
        self.assertIn("5d41402abc4b2a76b9719d911017c592", r.stdout)

    def test_crack_wordlist(self):
        r = run_cli("crack", "5f4dcc3b5aa765d61d8327deb882cf99", "-a", "md5")
        self.assertEqual(r.returncode, 0)
        self.assertIn("password", r.stdout)

    def test_crack_miss_exit_code(self):
        r = run_cli("crack", "a" * 32, "-a", "md5")
        self.assertNotEqual(r.returncode, 0)

    def test_decode_caesar(self):
        r = run_cli("decode", "Khoor Zruog", "-c", "caesar")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Hello World", r.stdout)

    def test_decode_auto_hex(self):
        r = run_cli("decode", "48656c6c6f20576f726c64", "-c", "auto")
        self.assertEqual(r.returncode, 0)
        self.assertIn("hello world", r.stdout.lower())

    def test_rsa_wiener(self):
        r = run_cli("rsa", "wiener", "--e", "2489", "--n", "11413")
        self.assertEqual(r.returncode, 0)
        self.assertIn("9", r.stdout)

    def test_rsa_fermat(self):
        r = run_cli("rsa", "fermat", "--n", "1022117")
        self.assertEqual(r.returncode, 0)
        self.assertIn("1013", r.stdout)

    def test_aes_ecb_oracle_rejects_short(self):
        # short/reserved path: no repeated blocks -> is_ecb False (exit 0)
        r = run_cli("aes", "ecb-oracle", "00112233445566778899aabbccddeeff")
        self.assertEqual(r.returncode, 0)
        self.assertIn("is_ecb", r.stdout)

    def test_hygiene_password(self):
        r = run_cli("hygiene", "Tr0ub4dor&3")
        self.assertEqual(r.returncode, 0)
        self.assertIn("strong", r.stdout)


if __name__ == "__main__":
    unittest.main()