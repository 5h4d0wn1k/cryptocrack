# Metrics

All numbers are measured on this machine (Linux, Python 3.13, pure-python
implementations; openssl 3.x and passlib 1.7.4 used only as external ground
truth during development). Timings are wall-clock from the live demo.

## Test suite

| Metric | Value |
|---|---|
| Total tests | 97 |
| Result | all passing, stable over repeated runs |
| Suite wall time | ~2 min (dominated by pure-python sha-crypt + localhost padding oracle) |
| Coverage | primitives, AES, RSA, crack engine, CLI smoke, decode, hygiene, DH, CPA |

## Rust-python hash fidelity

| Primitive | Validation source | Result |
|---|---|---|
| MD4 | RFC 1320 + PyCryptodome cross-check (incl. 1,000,000×"a") | pass |
| MD5 | RFC 1321 vectors | pass |
| SHA-1 / SHA-256 / SHA-512 | hashlib sweep (random lengths) | bytes-identical |
| md5_crypt | `openssl passwd -1` (multiple salts) | match |
| sha256_crypt / sha512_crypt | passlib 1.7.4 round-trips incl. `rounds=N` | match |
| AES-128/192/256 | FIPS-197 known-answer (both directions) | match |

## Attack success (live demo, fixtures)

| Attack | Fixture | Result |
|---|---|---|
| Wiener (`wiener_attack`) | e=2489, n=11413 | recovered d=9 |
| Fermat (`fermat_factor`) | p,q close, n=1022117 | factored to 1013×1009 |
| Hastad broadcast, e=3 | three 44-bit moduli | recovered m |
| small-e root, e=3 | m=14, n=3233 (no wrap) | recovered 14 |
| Common-modulus | e1=17,e2=19,n=101×113 | recovered m |
| Padding oracle | 2-block CBC via localhost TCP | full plaintext |
| ECB detection | repeated-block ECB vs CBC | detected / not detected |
| CBC bitflip | byte 0 of block 0 | flipped plaintext byte |
| XTS-CPA | synthetic first-SubBytes HW leakage, σ=1.5 | 16/16 key bytes, avg corr ~0.68-0.70 |
| DH MITM (RFC 3526 group 14) | simulated | two distinct derived keys |

## Throughput (honest pure-python numbers, measured)

| Operation | Rate |
|---|---|
| md4 | ~8.4k/s |
| md5 | ~5.5k/s |
| sha256 | ~1.4k/s |
| sha512 | ~1.1k/s |
| AES-128 block | ~2.9k/s |
| md5_crypt (1000 rounds) | ~8.5/s |
| sha256_crypt (1000 rounds) | ~1.2/s |
| sha256_crypt (5000 rounds) | ~4.1s per hash |
| sha512_crypt (5000 rounds) | ~4.1s per hash |
| padding oracle | ~256 localhost round-trips per byte (~8s per block) |
| XTS-CPA key byte | ~0.05s with 300 traces |

Note: single-hash times are reported per hash because the pure-python cost
makes "/s" misleading for sha-crypt variants. These numbers are the honest
cost of the "no external crypto dependency" design.

## CLI

- `python3 -m cryptocrack demo` — full proof run, exit 0, JSON to stdout.
- `python3 -m cryptocrack --version` — 1.0.0.
- Subcommands: hash, crack, rsa, aes, decode, hygiene, demo.