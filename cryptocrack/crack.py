"""Wordlist + rules hash cracking engine.

Supports:
- Wordlist attack (MD5, SHA1, SHA256, NTLM via pure-python MD4)
- Rule-based mutations (leet-speak, append digits, case mutations)
- Mask attack
- MD5-crypt / SHA-256-crypt / SHA-512-crypt verification
- Performance stats
"""
import time
import string
from itertools import product as iter_product

from .primitives import md5, sha1, sha256, sha512, md4, md5_crypt, sha256_crypt, sha512_crypt


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _ntlm_hash(password: str) -> bytes:
    """NTLM = MD4(UTF-16LE(password))."""
    return md4(password.encode("utf-16-le"))


def _hash_func(algo: str):
    """Return a function that hashes a password with the given algorithm."""
    mapping = {
        "md5": lambda p: md5(p.encode()),
        "sha1": lambda p: sha1(p.encode()),
        "sha256": lambda p: sha256(p.encode()),
        "sha512": lambda p: sha512(p.encode()),
        "md4": lambda p: md4(p.encode()),
        "ntlm": _ntlm_hash,
    }
    return mapping.get(algo.lower())


def _parse_crypt_config(hash_str: str) -> tuple[int, str]:
    """Return (rounds, salt) for a $5$/$6$ crypt hash, handling rounds=."""
    parts = hash_str.split("$")
    # $5$[rounds=N$]salt$checksum  ->  ['', '5', 'rounds=N', 'salt', 'checksum']
    if len(parts) >= 4 and parts[2].startswith("rounds="):
        rounds = int(parts[2][len("rounds="):])
        salt = parts[3]
    else:
        rounds = 5000
        salt = parts[2]
    return rounds, salt


def _verify_crypt_hash(password: str, hash_str: str) -> bool:
    """Verify a password against a unix crypt-style hash."""
    if hash_str.startswith("$1$"):
        salt = hash_str.split("$")[2]
        return md5_crypt(password, salt) == hash_str
    if hash_str.startswith("$5$"):
        rounds, salt = _parse_crypt_config(hash_str)
        return sha256_crypt(password, salt, rounds) == hash_str
    if hash_str.startswith("$6$"):
        rounds, salt = _parse_crypt_config(hash_str)
        return sha512_crypt(password, salt, rounds) == hash_str
    return False


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _rule_identity(word: str):
    return [word]


def _rule_lower(word: str):
    return [word.lower()]


def _rule_upper(word: str):
    return [word.upper()]


def _rule_capitalize(word: str):
    return [word.capitalize()]


def _rule_leet(word: str):
    """Common leet-speak substitutions."""
    leet_map = {
        "a": ["4", "@"], "e": ["3"], "i": ["1", "!"],
        "o": ["0"], "s": ["5", "$"], "t": ["7"],
        "l": ["1"], "b": ["8"], "g": ["9"],
    }
    results = [word]
    for ch, replacements in leet_map.items():
        new = []
        for w in results:
            for rep in replacements:
                new.append(w.replace(ch, rep))
        results.extend(new)
    return list(set(results))


def _rule_append_digits(word: str, max_digits: int = 4):
    """Append digits 0-9999."""
    results = []
    for i in range(10 ** max_digits):
        d = str(i).zfill(1) if i < 10 else str(i)
        if len(d) <= max_digits:
            results.append(word + d)
    return results


def _rule_prepend_digits(word: str):
    results = []
    for i in range(10000):
        results.append(str(i) + word)
    return results


def _rule_append_symbols(word: str):
    symbols = ["!", "@", "#", "$", "%", "&", "*"]
    return [word + s for s in symbols]


def _rule_case_variants(word: str):
    """Generate all case variants (up to 8 chars)."""
    if len(word) > 8:
        return [word]
    variants = set()
    for combo in iter_product([0, 1], repeat=len(word)):
        variant = "".join(
            c.upper() if bit else c.lower()
            for c, bit in zip(word, combo)
        )
        variants.add(variant)
    return list(variants)


ALL_RULES = {
    "identity": _rule_identity,
    "lower": _rule_lower,
    "upper": _rule_upper,
    "capitalize": _rule_capitalize,
    "leet": _rule_leet,
    "append_digits": _rule_append_digits,
    "prepend_digits": _rule_prepend_digits,
    "append_symbols": _rule_append_symbols,
    "case": _rule_case_variants,
}

DEFAULT_RULE_ORDER = ["identity", "lower", "upper", "capitalize", "leet", "case", "append_digits", "append_symbols"]


# ---------------------------------------------------------------------------
# Mask attack
# ---------------------------------------------------------------------------

MASK_CHARS = {
    "?l": string.ascii_lowercase,
    "?u": string.ascii_uppercase,
    "?d": string.digits,
    "?s": "!@#$%^&*()_+-=[]{}|;:,.<>?",
    "?a": string.ascii_letters + string.digits + "!@#$%^&*()",
}


def expand_mask(mask: str, max_length: int = 6) -> list[str]:
    """Expand a mask like '?l?u?d' into candidate strings."""
    # Parse mask into segments
    segments = []
    i = 0
    while i < len(mask):
        if i + 1 < len(mask) and mask[i:i+2] in MASK_CHARS:
            segments.append(MASK_CHARS[mask[i:i+2]])
            i += 2
        else:
            segments.append(mask[i])
            i += 1

    # For small masks, expand fully
    total = 1
    for s in segments:
        total *= len(s)
    if total > 1_000_000:
        return []
    return ["".join(combo) for combo in iter_product(*segments)]


# ---------------------------------------------------------------------------
# Main crack engine
# ---------------------------------------------------------------------------

class CrackResult:
    def __init__(self, cracked: bool, password: str = "", algo: str = "",
                 method: str = "", attempts: int = 0, elapsed: float = 0.0):
        self.cracked = cracked
        self.password = password
        self.algo = algo
        self.method = method
        self.attempts = attempts
        self.elapsed = elapsed

    def stats(self) -> dict:
        rate = self.attempts / self.elapsed if self.elapsed > 0 else 0
        return {
            "cracked": self.cracked,
            "password": self.password,
            "algo": self.algo,
            "method": self.method,
            "attempts": self.attempts,
            "elapsed_s": round(self.elapsed, 4),
            "rate": round(rate, 1),
        }


def crack_wordlist(target_hash: str, wordlist: list[str], algo: str = "md5",
                   rules: list[str] | None = None, hashcat_mode: int = 0,
                   crypt_hash: str = "") -> CrackResult:
    """Crack a hash using wordlist + rules."""
    t0 = time.time()
    attempts = 0
    rules = rules or DEFAULT_RULE_ORDER

    if crypt_hash:
        # For crypt-style hashes, verify the full hash string
        for word in wordlist:
            attempts += 1
            if _verify_crypt_hash(word, crypt_hash):
                return CrackResult(True, word, algo, "wordlist", attempts, time.time() - t0)
        return CrackResult(False, "", algo, "wordlist", attempts, time.time() - t0)

    hash_fn = _hash_func(algo)
    if hash_fn is None:
        return CrackResult(False, "", algo, "wordlist", 0, 0.0)

    target_bytes = bytes.fromhex(target_hash)

    for rule_name in rules:
        rule_fn = ALL_RULES.get(rule_name, _rule_identity)
        for word in wordlist:
            candidates = rule_fn(word)
            for cand in candidates:
                attempts += 1
                h = hash_fn(cand)
                if h == target_bytes:
                    return CrackResult(True, cand, algo, f"wordlist+{rule_name}", attempts, time.time() - t0)

    return CrackResult(False, "", algo, "wordlist", attempts, time.time() - t0)


def crack_mask(target_hash: str, mask: str, algo: str = "md5",
               hashcat_mode: int = 0) -> CrackResult:
    """Crack a hash using a mask pattern."""
    t0 = time.time()
    candidates = expand_mask(mask)
    attempts = 0
    hash_fn = _hash_func(algo)
    target_bytes = bytes.fromhex(target_hash)

    for cand in candidates:
        attempts += 1
        h = hash_fn(cand)
        if h == target_bytes:
            return CrackResult(True, cand, algo, f"mask:{mask}", attempts, time.time() - t0)

    return CrackResult(False, "", algo, f"mask:{mask}", attempts, time.time() - t0)


def crack(target_hash: str, wordlist: list[str], algo: str = "md5",
          rules: list[str] | None = None, mask: str | None = None,
          hashcat_mode: int = 0, crypt_hash: str = "") -> CrackResult:
    """High-level crack: try wordlist+rules first, then mask if provided."""
    result = crack_wordlist(target_hash, wordlist, algo, rules, hashcat_mode, crypt_hash)
    if result.cracked:
        return result

    if mask:
        result = crack_mask(target_hash, mask, algo, hashcat_mode)
        if result.cracked:
            return result

    return CrackResult(False, "", algo, "exhausted", result.attempts, result.elapsed)
