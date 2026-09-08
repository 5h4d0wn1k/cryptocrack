"""Correlation Power Analysis on synthetic AES-XTS leakage traces.

The trace model is honest and self-consistent, NOT a claim of real
hardware captures:

- XTS uses key K = K1 || K2 (two 16-byte halves).
- Per 128-bit sector, the tweak is T = AES_K2(sector_number) and block j
  uses T * alpha^j (multiply by x in GF(2^128), poly 0x87).
- Each 16-byte data block P_j is whitened: state = P_j ^ T_j.
- We model a single known power leakage point: the Hamming weight of the
  FIRST SubBytes output, SBOX[state ^ K1], polluted with Gaussian noise.

This is the textbook first-order CPA setup: a known plaintext/tweak line
leaking through the S-box. The attack recovers K1 byte-by-byte by
correlating predicted Hamming weights against the leaked samples.
"""
import os
import math
import random

from .aes_attacks import aes_encrypt_block, _SBOX


def _hw(x: int) -> int:
    """Hamming weight of a byte."""
    x = x - ((x >> 1) & 0x55555555)
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333)
    x = (x + (x >> 4)) & 0x0F0F0F0F
    return x & 0xFF


def _alpha_mul(t: bytes) -> bytes:
    """Multiply a 16-byte tweak by alpha (x) in GF(2^128) per XTS."""
    b = bytearray(t)
    carry = 0
    for i in range(15, -1, -1):
        new_carry = b[i] >> 7
        b[i] = ((b[i] << 1) & 0xFF) | carry
        carry = new_carry
    if carry:
        b[15] ^= 0x87
    return bytes(b)


def xts_tweak_block(sector_number: int, key2: bytes) -> bytes:
    """Base tweak for a sector: AES_K2(12-byte LE sector || zero bytes)."""
    block = (sector_number & 0xFFFFFFFFFFFFFFFFFFFFFFFF).to_bytes(16, "little")
    return aes_encrypt_block(block, key2)


def generate_synthetic_traces(n_traces: int = 200, secret_key: bytes | None = None,
                              sector_number: int | None = None, n_blocks: int = 1):
    """Generate synthetic XTS first-SubBytes leakage traces.

    Returns (traces, secret_key) where each trace is
    (plaintext_block, tweak_block, leakage[16 floats]) for the first
    ciphertext block's 16 byte positions.
    """
    if secret_key is None:
        secret_key = os.urandom(32)
    if len(secret_key) != 32:
        raise ValueError("XTS key must be 32 bytes (K1 || K2)")
    k1, k2 = secret_key[:16], secret_key[16:]

    traces = []
    for _ in range(n_traces):
        if sector_number is None:
            sector = random.getrandbits(96)
        else:
            sector = sector_number & 0xFFFFFFFFFFFFFFFFFFFFFFFF
        base_tweak = xts_tweak_block(sector, k2)
        if n_blocks > 1:
            raise ValueError("n_blocks > 1 not supported; single-block XTS model")
        tweak = base_tweak
        pt = os.urandom(16)
        leakage = []
        for byte_idx in range(16):
            sbox_out = _SBOX[pt[byte_idx] ^ tweak[byte_idx] ^ k1[byte_idx]]
            noise = random.gauss(0, 1.5)
            leakage.append(_hw(sbox_out) + noise)
        traces.append((pt, tweak, leakage))
    return traces, secret_key


def cpa_attack(traces, n_bytes: int = 16) -> tuple[bytes, list[float]]:
    """Recover XTS data key K1 from synthetic leakage traces.

    For each byte position, test all 256 candidate key bytes and pick the
    one whose predicted Hamming weight best correlates (Pearson, absolute)
    with the leaked samples.
    """
    best_key = [0] * n_bytes
    best_corr = [0.0] * n_bytes
    n = len(traces)

    for byte_idx in range(n_bytes):
        leakages = [tr[2][byte_idx] for tr in traces]
        mean_l = sum(leakages) / n
        sd_l = math.sqrt(sum((l - mean_l) ** 2 for l in leakages) / n)
        sd_l = sd_l or 1e-10

        max_corr = 0.0
        best_guess = 0
        for k_guess in range(256):
            preds = [
                _hw(_SBOX[pt[byte_idx] ^ tw[byte_idx] ^ k_guess])
                for pt, tw, _ in traces
            ]
            mean_p = sum(preds) / n
            cov = sum((p - mean_p) * (l - mean_l) for p, l in zip(preds, leakages)) / n
            sd_p = math.sqrt(sum((p - mean_p) ** 2 for p in preds) / n) or 1e-10
            corr = abs(cov / (sd_p * sd_l))
            if corr > max_corr:
                max_corr = corr
                best_guess = k_guess
        best_key[byte_idx] = best_guess
        best_corr[byte_idx] = max_corr
    return bytes(best_key), best_corr


_DEMO_KEY = (
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
)


def run_demo(n_traces: int = 300) -> dict:
    """Full synthetic XTS-CPA demonstration with a fixed demo key."""
    secret = bytes(_DEMO_KEY)
    traces, _ = generate_synthetic_traces(n_traces, secret_key=secret)
    recovered, correlations = cpa_attack(traces)
    k1 = secret[:16]
    return {
        "scheme": "AES-XTS (synthetic first-SubBytes leakage model)",
        "secret_key_k1": k1.hex(),
        "recovered_k1": recovered.hex(),
        "success": recovered == k1,
        "n_traces": n_traces,
        "key_bytes_recovered": sum(a == b for a, b in zip(recovered, k1)),
        "avg_correlation": round(sum(correlations) / len(correlations), 4),
        "message": "CPA recovered the XTS data key K1 from the leakage model"
        if recovered == k1 else "CPA failed to recover K1",
    }