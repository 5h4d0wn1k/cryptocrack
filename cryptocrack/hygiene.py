"""Credential hygiene analyzer - entropy, password strength, key validation."""
import math
import re
from collections import Counter

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

def charset_analysis(s):
    has_upper = bool(re.search(r'[A-Z]', s))
    has_lower = bool(re.search(r'[a-z]', s))
    has_digit = bool(re.search(r'[0-9]', s))
    has_special = bool(re.search(r'[^A-Za-z0-9]', s))
    return {"upper": has_upper, "lower": has_lower, "digit": has_digit, "special": has_special}

def password_strength(password):
    ent = shannon_entropy(password)
    charset = charset_analysis(password)
    score = 0
    score += min(len(password) * 4, 40)
    score += 10 if charset["upper"] else 0
    score += 10 if charset["lower"] else 0
    score += 10 if charset["digit"] else 0
    score += 15 if charset["special"] else 0
    if len(password) >= 12: score += 10
    if len(password) >= 16: score += 10
    if re.search(r'(.)\1{2,}', password): score -= 15
    if re.match(r'^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()): score -= 20
    score = max(0, min(100, score))
    if score >= 80: level = "strong"
    elif score >= 60: level = "moderate"
    elif score >= 40: level = "weak"
    else: level = "very_weak"
    return {"score": score, "level": level, "entropy": round(ent, 2), "charset": charset, "length": len(password)}

def check_common_password(password):
    common = {
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
        "dragon", "login", "princess", "football", "shadow", "sunshine", "trustno1",
        "iloveyou", "batman", "access", "hello", "charlie", "letmein", "welcome",
        "password1", "admin", "1234567", "12345", "123456789", "1234", "1234567890",
        "password123", "admin123", "root", "toor", "pass", "test", "guest", "master",
    }
    return password.lower() in common

def validate_key_hex(hex_string):
    errors = []
    warnings = []
    hex_clean = hex_string.replace(" ", "").replace(":", "").replace("0x", "")
    try:
        key_bytes = bytes.fromhex(hex_clean)
    except ValueError:
        return {"valid": False, "errors": ["Invalid hex string"], "warnings": []}
    if len(key_bytes) not in (16, 24, 32):
        errors.append(f"Invalid key length: {len(key_bytes)} bytes (expected 16, 24, or 32)")
    entropy = shannon_entropy(hex_clean)
    if entropy < 3.0:
        warnings.append(f"Low entropy: {entropy:.2f} bits/char")
    freq = Counter(key_bytes)
    most_common_count = freq.most_common(1)[0][1]
    if most_common_count > len(key_bytes) * 0.4:
        warnings.append("Key has repeated bytes - may indicate weak generation")
    is_all_same = len(set(key_bytes)) == 1
    if is_all_same:
        errors.append("All bytes identical - key is critically weak")
    return {
        "valid": len(errors) == 0,
        "hex_length": len(hex_clean),
        "byte_length": len(key_bytes),
        "entropy": round(entropy, 2),
        "unique_bytes": len(set(key_bytes)),
        "errors": errors,
        "warnings": warnings,
    }

def analyze_password_batch(passwords):
    results = []
    for pw in passwords:
        strength = password_strength(pw)
        strength["is_common"] = check_common_password(pw)
        results.append({"password": pw, "analysis": strength})
    return results

def credential_report(passwords, keys=None):
    report = {
        "password_analysis": analyze_password_batch(passwords),
        "summary": {},
    }
    strengths = [r["analysis"]["score"] for r in report["password_analysis"]]
    report["summary"]["total_passwords"] = len(passwords)
    report["summary"]["avg_strength"] = round(sum(strengths) / len(strengths), 1) if strengths else 0
    report["summary"]["weak_count"] = sum(1 for s in strengths if s < 40)
    report["summary"]["common_count"] = sum(1 for r in report["password_analysis"] if r["analysis"]["is_common"])
    if keys:
        report["key_analysis"] = [validate_key_hex(k) for k in keys]
        report["summary"]["invalid_keys"] = sum(1 for k in report["key_analysis"] if not k["valid"])
    return report
