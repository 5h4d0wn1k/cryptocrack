"""Automated cipher detection and decoding."""
import base64
import re
from collections import Counter
from urllib.parse import unquote

_ENGLISH_FREQ = {
    " ": 0.13, "e": 0.127, "t": 0.091, "a": 0.082, "o": 0.075,
    "i": 0.070, "n": 0.067, "s": 0.063, "h": 0.061, "r": 0.060,
    "d": 0.043, "l": 0.040, "u": 0.028, "c": 0.028, "m": 0.024,
}

_ENGLISH_BIGRAMS = {
    'th': 2.71, 'he': 2.33, 'in': 2.03, 'er': 1.78, 'an': 1.61,
    're': 1.41, 'on': 1.41, 'at': 1.35, 'en': 1.31, 'nd': 1.18,
    'ti': 1.15, 'es': 1.11, 'or': 1.08, 'te': 1.05, 'of': 1.04,
    'ed': 1.00, 'is': 0.97, 'it': 0.96, 'al': 0.93, 'ar': 0.92,
    'st': 0.89, 'nt': 0.89, 'to': 0.86, 'ng': 0.84, 'se': 0.83,
    'ha': 0.80, 'le': 0.77, 've': 0.75, 'ou': 0.74, 'as': 0.72,
    'de': 0.71, 'ra': 0.69, 'ro': 0.69, 'ri': 0.68, 'li': 0.68,
    'la': 0.67, 'wh': 0.67, 'ta': 0.66,
}


_COMMON_WORDS = (
    " alone ", " also ", " been ", " done ", " first ", " from ", " good ",
    " have ", " hello ", " home ", " know ", " last ", " like ", " many ",
    " more ", " most ", " near ", " night", " people ", " right ", " some ",
    " that ", " them ", " then ", " there ", " these ", " thing ", " this ",
    " time ", " well ", " were ", " what ", " when ", " where ", " which ",
    " will ", " with ", " word ", " would ", " world ", " years ", " your ",
    " the ", " and ", " for ", " you ", " not ", " are ",
)


def _english_score(text: str) -> float:
    """Score text by English unigram + bigram frequencies.

    Bigrams with space/space-weighting handle short messages where
    unigram analysis alone cannot disambiguate a Caesar shift. A small
    embedded common-word list adds a strong n-gram prior on short demos
    without shipping external dictionaries.
    """
    if not text:
        return 0.0
    score = 0.0
    bad = 0
    for i in range(len(text) - 1):
        score += _ENGLISH_BIGRAMS.get(text[i:i + 2].lower(), 0.0)
    score += text.count(" ") * 3.0
    for ch in text:
        o = ord(ch)
        if o < 32 and ch not in "\n\t\r":
            bad += 1
        else:
            score += 0.4 * _ENGLISH_FREQ.get(ch.lower(), 0.0)
    padded = " " + text.lower() + " "
    for word in _COMMON_WORDS:
        if word in padded:
            score += 2.0
    return score - bad * 5.0

def caesar_bruteforce(ciphertext):
    results = []
    for shift in range(26):
        decoded = ""
        for ch in ciphertext:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                decoded += chr((ord(ch) - base - shift) % 26 + base)
            else:
                decoded += ch
        results.append((shift, decoded, _english_score(decoded)))
    return sorted(results, key=lambda x: -x[2])

def vigenere_decrypt(ciphertext, key):
    result = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[ki % len(key)].upper()) - ord('A')
            result.append(chr((ord(ch) - base - k) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)

def xor_single_byte(data: bytes):
    """Crack a single-byte XOR by English frequency scoring."""
    best = (0, "", 0.0)
    for key in range(256):
        decrypted = bytes([b ^ key for b in data])
        text = decrypted.decode("latin-1")
        if any(ord(c) < 32 and c not in "\n\t\r" for c in text):
            continue
        score = _english_score(text)
        if score > best[2]:
            best = (key, text, score)
    return best

def xor_repeating_key(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def transpose_rows(ciphertext, n_cols):
    n_rows = len(ciphertext) // n_cols
    result = [""] * n_rows
    idx = 0
    for col in range(n_cols):
        for row in range(n_rows):
            if idx < len(ciphertext):
                result[row] += ciphertext[idx]
                idx += 1
    return "".join(result)

def substitution_frequency_analysis(ciphertext):
    english_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    freq = Counter(c.upper() for c in ciphertext if c.isalpha())
    cipher_order = [ch for ch, _ in freq.most_common()]
    mapping = {}
    for i, ch in enumerate(cipher_order):
        if i < len(english_order):
            mapping[ch] = english_order[i]
            mapping[ch.lower()] = english_order[i].lower()
    result = []
    for ch in ciphertext:
        result.append(mapping.get(ch, ch))
    return "".join(result), mapping

def hex_decode(s):
    try:
        return bytes.fromhex(s.replace(" ", "")).decode('latin-1')
    except Exception:
        return None

def base64_decode(s):
    import base64
    try:
        return base64.b64decode(s).decode('latin-1')
    except Exception:
        return None

def url_decode(s):
    from urllib.parse import unquote
    return unquote(s)

def is_probably_base64(s):
    import re
    return bool(re.match(r'^[A-Za-z0-9+/]+={0,2}$', s.strip()))

def is_hex_string(s):
    return all(c in '0123456789abcdefABCDEF' for c in s.replace(' ', ''))

def auto_decode(s):
    results = {}
    s = s.strip()
    if is_hex_string(s):
        decoded = hex_decode(s)
        if decoded:
            results['hex'] = decoded
    if is_probably_base64(s) and len(s) > 4:
        decoded = base64_decode(s)
        if decoded and decoded.isprintable():
            results['base64'] = decoded
    if '%' in s:
        results['url'] = url_decode(s)
    return results if results else {'raw': s}

def detect_ecb(ciphertext, block_size=16):
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    seen = {}
    for i, b in enumerate(blocks):
        if b in seen:
            return True, seen[b], i
        seen[b] = i
    return False, -1, -1
