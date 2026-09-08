"""Automated cipher detection and decoding."""
import string
from collections import Counter

def caesar_bruteforce(ciphertext):
    results = []
    for shift in range(26):
        decoded = ""
        for ch in ciphertext:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                decoded += chr((ord(ch) - base + shift) % 26 + base)
            else:
                decoded += ch
        score = sum(1 for c in decoded if c in ' ETAOINSHRDLCUMWFGYPBVKJXQZ')
        results.append((shift, decoded, score))
    return results

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

def xor_single_byte(data):
    best = (0, "", 0.0)
    freq_expected = {' ': 0.15, 'e': 0.13, 't': 0.09, 'a': 0.08, 'o': 0.075, 'n': 0.07, 'i': 0.065, 's': 0.06}
    for key in range(256):
        decrypted = bytes([b ^ key for b in data])
        text = decrypted.decode('latin-1')
        printable_ratio = sum(1 for c in text if c in string.printable) / max(len(text), 1)
        score = 0
        freq = Counter(c.lower() for c in text if c.isalpha())
        total = sum(freq.values()) or 1
        for ch, exp in freq_expected.items():
            score += min(freq.get(ch, 0) / total, exp * 2)
        final = score * printable_ratio
        if final > best[2]:
            best = (key, text, final)
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
