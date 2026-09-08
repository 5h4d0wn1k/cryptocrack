"""Hash identification and classification.

Identifies common hash types from hex/base64 input strings.
Returns hashcat mode hints and algorithm metadata.
"""
import base64
import re
import hashlib


# Hashcat mode numbers for each hash type
HASHCAT_MODES = {
    "MD5": 0,
    "SHA-1": 100,
    "SHA-256": 1400,
    "SHA-512": 1700,
    "NTLM": 1000,
    "MD5-crypt ($1$)": 500,
    "SHA-256-crypt ($5$)": 7400,
    "SHA-512-crypt ($6$)": 1800,
    "bcrypt ($2a$/$2b$/$2y$)": 3200,
    "Argon2": 0,
}

# length -> possible hash types (hex)
HEX_LENGTHS = {
    32: ["MD5"],
    40: ["SHA-1"],
    56: ["SHA-224", "RIPEMD-160"],
    64: ["SHA-256"],
    96: ["SHA-384"],
    128: ["SHA-512"],
}


def _clean_hex(h: str) -> str:
    """Strip common prefixes/suffixes and return pure hex if possible."""
    h = h.strip()
    # Remove common prefixes
    for prefix in ["0x", "\\x"]:
        if h.startswith(prefix):
            h = h[len(prefix):]
    # Check if it's valid hex
    try:
        int(h, 16)
        return h
    except ValueError:
        return ""


def _try_base64_decode(h: str) -> bytes | None:
    """Try to base64-decode the hash string."""
    try:
        return base64.b64decode(h)
    except Exception:
        return None


def _hashcat_mode_hint(hash_type: str) -> dict:
    """Return a dict with hashcat mode info."""
    mode = HASHCAT_MODES.get(hash_type, 0)
    return {
        "hashcat_mode": mode,
        "hashcat_mode_name": hash_type,
        "john_format": hash_type,
    }


def identify_hash(hash_string: str) -> dict:
    """Identify a hash from its string representation.

    Returns dict with keys:
        - type: str (identified hash type)
        - hex: str (cleaned hex, if applicable)
        - base64_decoded: bytes | None
        - hashcat: dict (hashcat mode hints)
        - confidence: str ("high" | "medium" | "low")
    """
    h = hash_string.strip()
    result = {
        "type": "UNKNOWN",
        "hex": "",
        "base64_decoded": None,
        "hashcat": {"hashcat_mode": 0, "hashcat_mode_name": "UNKNOWN", "john_format": "unknown"},
        "confidence": "low",
    }

    # --- Check for crypt-style prefixes ---
    if h.startswith("$1$") and not h.startswith("$10$"):
        result["type"] = "MD5-crypt ($1$)"
        result["confidence"] = "high"
        result["hashcat"] = _hashcat_mode_hint("MD5-crypt ($1$)")
        return result

    if h.startswith("$5$"):
        result["type"] = "SHA-256-crypt ($5$)"
        result["confidence"] = "high"
        result["hashcat"] = _hashcat_mode_hint("SHA-256-crypt ($5$)")
        return result

    if h.startswith("$6$"):
        result["type"] = "SHA-512-crypt ($6$)"
        result["confidence"] = "high"
        result["hashcat"] = _hashcat_mode_hint("SHA-512-crypt ($6$)")
        return result

    if re.match(r"^\$2[aby]\$", h):
        result["type"] = "bcrypt ($2a$/$2b$/$2y$)"
        result["confidence"] = "high"
        result["hashcat"] = _hashcat_mode_hint("bcrypt ($2a$/$2b$/$2y$)")
        return result

    if re.match(r"^\$argon2[id]+\$", h):
        result["type"] = "Argon2"
        result["confidence"] = "high"
        result["hashcat"] = _hashcat_mode_hint("Argon2")
        return result

    # --- NTLM (32 hex, often uppercase) ---
    cleaned = _clean_hex(h)
    if len(cleaned) == 32:
        result["hex"] = cleaned
        result["type"] = "NTLM"
        result["confidence"] = "medium"  # could also be MD5
        result["hashcat"] = _hashcat_mode_hint("NTLM")
        return result

    # --- Hex-length-based identification ---
    if cleaned:
        result["hex"] = cleaned
        length = len(cleaned)
        if length in HEX_LENGTHS:
            candidates = HEX_LENGTHS[length]
            if length == 32:
                result["type"] = "MD5"
                result["confidence"] = "high"
                result["hashcat"] = _hashcat_mode_hint("MD5")
            elif length == 40:
                result["type"] = "SHA-1"
                result["confidence"] = "high"
                result["hashcat"] = _hashcat_mode_hint("SHA-1")
            elif length == 64:
                result["type"] = "SHA-256"
                result["confidence"] = "high"
                result["hashcat"] = _hashcat_mode_hint("SHA-256")
            elif length == 128:
                result["type"] = "SHA-512"
                result["confidence"] = "high"
                result["hashcat"] = _hashcat_mode_hint("SHA-512")
            else:
                result["type"] = candidates[0]
                result["confidence"] = "low"
            return result

    # --- Try base64 ---
    decoded = _try_base64_decode(h)
    if decoded:
        result["base64_decoded"] = decoded
        dl = len(decoded)
        if dl == 16:
            result["type"] = "MD5 (base64)"
            result["confidence"] = "medium"
            result["hashcat"] = _hashcat_mode_hint("MD5")
        elif dl == 20:
            result["type"] = "SHA-1 (base64)"
            result["confidence"] = "medium"
            result["hashcat"] = _hashcat_mode_hint("SHA-1")
        elif dl == 32:
            result["type"] = "SHA-256 (base64)"
            result["confidence"] = "medium"
            result["hashcat"] = _hashcat_mode_hint("SHA-256")
        elif dl == 64:
            result["type"] = "SHA-512 (base64)"
            result["confidence"] = "medium"
            result["hashcat"] = _hashcat_mode_hint("SHA-512")
        return result

    return result


def identify_all(hash_strings: list[str]) -> list[dict]:
    """Identify a list of hashes."""
    return [identify_hash(h) for h in hash_strings]
