"""RSA attack implementations.

All attacks use mathematically-correct implementations against crafted
vulnerabilities (small keys, close primes, small e, common modulus).
Each attack includes an explanation of when it applies in the real world.
"""
import random
import math
from fractions import Fraction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _modinv(a: int, m: int) -> int:
    """Extended Euclidean algorithm for modular inverse."""
    if _gcd(a, m) != 1:
        return 0
    g, x, _ = _extended_gcd(a, m)
    return x % m


def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = _extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def _continued_fractions(n: int, d: int) -> list[int]:
    """Compute continued fraction representation of n/d."""
    cf = []
    while d:
        q = n // d
        cf.append(q)
        n, d = d, n - q * d
    return cf


def _convergents(cf: list[int]):
    """Generate convergents of a continued fraction."""
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    for a in cf:
        h_new = a * h_curr + h_prev
        k_new = a * k_curr + k_prev
        yield h_new, k_new
        h_prev, h_curr = h_curr, h_new
        k_prev, k_curr = k_curr, k_new


def _is_prime_miller_rabin(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_rsa_key(p: int, q: int) -> dict:
    """Generate RSA key components from given primes."""
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = _modinv(e, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "phi": phi}


def rsa_encrypt(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


def rsa_decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


# ===========================================================================
# Attack 1: Wiener's Attack  (small private exponent d)
# ===========================================================================

def wiener_attack(e: int, n: int) -> dict:
    """Wiener's attack: recover d when d < n^0.25.

    Uses continued fraction expansion of e/n.
    Real-world applicability: RSA keys with intentionally small d
    for encryption speed (historical; defeated by Wiener 1990).
    """
    cf = _continued_fractions(e, n)
    convs = list(_convergents(cf))

    for k, d in convs:
        if k == 0 or d == 0:
            continue
        # Check if this (k, d) is valid
        phi_approx = (e * d - 1) // k
        if phi_approx <= 0:
            continue

        # Try to factor n using phi = (p-1)(q-1) = n - (p+q) + 1
        # s = p + q = n - phi + 1
        s = n - phi_approx + 1
        # p, q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant >= 0:
            sqrt_disc = int(math.isqrt(discriminant))
            if sqrt_disc * sqrt_disc == discriminant:
                p = (s + sqrt_disc) // 2
                q = (s - sqrt_disc) // 2
                if p * q == n and p > 1 and q > 1:
                    return {
                        "success": True,
                        "d": d,
                        "p": p,
                        "q": q,
                        "message": "Wiener: d recovered via continued fractions",
                        "when_used": "Small d (< n^0.25); historical weak RSA keys",
                    }
    return {"success": False, "message": "Wiener attack failed: d not small enough"}


# ===========================================================================
# Attack 2: Fermat Factorization  (close primes)
# ===========================================================================

def fermat_factor(n: int, max_iter: int = 1_000_000) -> dict:
    """Fermat factorization: factor n when p and q are close.

    Real-world applicability: Randomly generated RSA keys with
    insufficient entropy or incorrectly seeded PRNG producing
    close prime factors.
    """
    a = math.isqrt(n) + 1
    b2 = a * a - n

    for _ in range(max_iter):
        b = math.isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            if p * q == n and p > 1 and q > 1:
                return {
                    "success": True,
                    "p": p,
                    "q": q,
                    "iterations": _ + 1,
                    "message": "Fermat: factored n (close primes)",
                    "when_used": "Primes close together; weak PRNG, incorrect key generation",
                }
        a += 1
        b2 = a * a - n

    return {"success": False, "message": "Fermat failed: primes too far apart"}


# ===========================================================================
# Attack 3: Hastad Broadcast Attack  (same e, different n)
# ===========================================================================

def _crt(a_list: list[int], m_list: list[int]) -> int:
    """Chinese Remainder Theorem for a system of congruences.
    x ≡ a_i (mod m_i) for all i."""
    M = 1
    for m in m_list:
        M *= m

    x = 0
    for a_i, m_i in zip(a_list, m_list):
        Mi = M // m_i
        yi = _modinv(Mi, m_i)
        x += a_i * Mi * yi
    return x % M


def hastad_broadcast(e: int, moduli: list[int], ciphertexts: list[int]) -> dict:
    """Hastad's broadcast attack: same plaintext encrypted with same small e
    to different public keys.

    Requires e == len(moduli) (3 for e=3).
    Real-world applicability: Same message sent to multiple recipients
    with e=3 (e.g., early RSA implementations in some embedded devices).
    """
    if len(moduli) != e:
        return {"success": False, "message": f"Need exactly {e} ciphertexts for e={e}"}

    # CRT to combine ciphertexts
    combined = _crt(ciphertexts, moduli)

    # Take e-th root
    root = round(combined ** (1.0 / e))
    # Verify
    if root ** e == combined:
        return {
            "success": True,
            "plaintext": root,
            "message": f"Hastad: recovered plaintext via CRT + e-th root",
            "when_used": "Same plaintext, small e, multiple recipients",
        }

    # Try integer root extraction
    root = _integer_nth_root(combined, e)
    if root is not None and pow(root, e) == combined:
        return {
            "success": True,
            "plaintext": root,
            "message": f"Hastad: recovered plaintext via CRT + integer root",
            "when_used": "Same plaintext, small e, multiple recipients",
        }

    return {"success": False, "message": "Hastad attack failed: root not exact"}


def _integer_nth_root(n: int, e: int) -> int | None:
    """Compute integer e-th root of n, or None if not a perfect power."""
    if n < 0:
        return None
    if n == 0:
        return 0

    # Newton's method
    x = 1 << ((n.bit_length() + e - 1) // e)
    while True:
        y = ((e - 1) * x + n // (x ** (e - 1))) // e
        if y >= x:
            return x
        x = y


# ===========================================================================
# Attack 4: Small-e Root Attack
# ===========================================================================

def small_e_root(ciphertext: int, e: int, n: int, padding_known: bool = True) -> dict:
    """When e is small (e.g., 3) and plaintext^e < n (no padding),
    just take the e-th root.

    Real-world applicability: Raw RSA without OAEP/PKCS#1 padding;
    small messages (< n^(1/e)).
    """
    root = _integer_nth_root(ciphertext, e)
    if root is not None and pow(root, e, n) == ciphertext:
        return {
            "success": True,
            "plaintext": root,
            "message": f"Small-e root: m^e < n, direct root extraction",
            "when_used": "Small e, no padding (raw RSA), message << n",
        }
    return {"success": False, "message": "Not a direct root (probably padded)"}


# ===========================================================================
# Attack 5: Common Modulus Attack
# ===========================================================================

def common_modulus(c1: int, c2: int, e1: int, e2: int, n: int) -> dict:
    """Common modulus attack: same n, two different e values.

    Requires gcd(e1, e2) = 1.
    Real-world applicability: Key reuse with different exponents;
    historical attack on some smart card implementations.
    """
    g, s1, s2 = _extended_gcd(e1, e2)
    if g != 1:
        return {"success": False, "message": "gcd(e1,e2) != 1, attack not applicable"}

    # m = c1^s1 * c2^s2 mod n
    # Handle negative exponents
    if s1 < 0:
        c1_inv = _modinv(c1, n)
        if c1_inv == 0:
            return {"success": False, "message": "c1 not invertible mod n"}
        m = pow(c1_inv, -s1, n) * pow(c2, s2, n) % n
    elif s2 < 0:
        c2_inv = _modinv(c2, n)
        if c2_inv == 0:
            return {"success": False, "message": "c2 not invertible mod n"}
        m = pow(c1, s1, n) * pow(c2_inv, -s2, n) % n
    else:
        m = pow(c1, s1, n) * pow(c2, s2, n) % n

    return {
        "success": True,
        "plaintext": m,
        "message": "Common modulus: m recovered",
        "when_used": "Same n with two different public exponents",
    }


# ===========================================================================
# Attack 6: Chosen-Message / CPA Check
# ===========================================================================

def chosen_message_cpa_check(e: int, n: int, oracle_encrypt, oracle_decrypt) -> dict:
    """Demonstrate that a deterministic textbook RSA is CPA-vulnerable.
    Encrypt 0 and 1; show that encrypting the same message always
    gives the same ciphertext (deterministic = not IND-CPA secure).

    Real-world: textbook RSA without padding is NOT semantically secure.
    This is why PKCS#1 v1.5 and OAEP exist.
    """
    c0 = oracle_encrypt(0)
    c1 = oracle_encrypt(1)
    c0_2 = oracle_encrypt(0)

    deterministic = (c0 == c0_2)
    encrypted_zero = (c0 == 0)
    encrypted_one = (c1 == 1 % n)

    return {
        "deterministic": deterministic,
        "encrypted_zero_is_zero": encrypted_zero,
        "encrypted_one_is_one": encrypted_one,
        "message": "Textbook RSA is deterministic — NOT IND-CPA secure. Use OAEP.",
        "when_used": "All textbook RSA without padding; need for OAEP/PKCS#1",
    }
