"""Correlation Power Analysis on synthetic AES-XTS traces."""
import random
import math
import struct

def _aes_sbox():
    sbox = [0]*256
    p = 1
    for i in range(1, 256):
        p = (p ^ (p << 1)) & 0xFF
        if p & 0x80: p ^= 0x1B
        p &= 0xFF
        sbox[p] = i if i != 1 else 0
    sbox[0] = 0x63
    return sbox

SBOX = _aes_sbox()

def _hw(x):
    x = x - ((x >> 1) & 0x55555555)
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333)
    x = (x + (x >> 4)) & 0x0F0F0F0F
    x += x >> 8
    x += x >> 16
    return x & 0xFF

def _hamming_distance(a, b):
    return _hw(a ^ b)

def generate_synthetic_traces(n_traces=200, secret_key=None):
    if secret_key is None:
        secret_key = bytes([random.randint(0, 255) for _ in range(16)])
    traces = []
    for _ in range(n_traces):
        pt = bytes([random.randint(0, 255) for _ in range(16)])
        leakage = []
        for byte_idx in range(16):
            sbox_out = SBOX[pt[byte_idx] ^ secret_key[byte_idx]]
            hw = _hw(sbox_out)
            noise = random.gauss(0, 1.5)
            leakage.append(hw + noise)
        traces.append((pt, leakage))
    return traces, secret_key

def cpa_attack(traces, n_bytes=16):
    best_key = [0] * n_bytes
    best_corr = [0.0] * n_bytes
    for byte_idx in range(n_bytes):
        max_corr = 0
        best_guess = 0
        for k_guess in range(256):
            predictions = []
            leakages = []
            for pt, leakage in traces:
                sbox_out = SBOX[pt[byte_idx] ^ k_guess]
                predictions.append(_hw(sbox_out))
                leakages.append(leakage[byte_idx])
            n = len(predictions)
            mean_p = sum(predictions) / n
            mean_l = sum(leakages) / n
            cov = sum((p - mean_p) * (l - mean_l) for p, l in zip(predictions, leakages)) / n
            std_p = math.sqrt(sum((p - mean_p) ** 2 for p in predictions) / n) or 1e-10
            std_l = math.sqrt(sum((l - mean_l) ** 2 for l in leakages) / n) or 1e-10
            corr = abs(cov / (std_p * std_l))
            if corr > max_corr:
                max_corr = corr
                best_guess = k_guess
        best_key[byte_idx] = best_guess
        best_corr[byte_idx] = max_corr
    return bytes(best_key), best_corr

def run_demo(n_traces=300):
    secret = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41])
    traces, _ = generate_synthetic_traces(n_traces, secret_key=secret)
    recovered, correlations = cpa_attack(traces)
    return {
        "secret_key": secret.hex(),
        "recovered_key": recovered.hex(),
        "success": recovered == secret,
        "n_traces": n_traces,
        "avg_correlation": sum(correlations) / len(correlations),
        "message": "CPA successfully recovered AES key" if recovered == secret else "CPA failed",
    }
