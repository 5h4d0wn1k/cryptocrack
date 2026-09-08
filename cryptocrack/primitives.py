"""Pure-python cryptographic hash primitives. All implementations follow published
specs and are validated against known test vectors.

Standards referenced:
- MD5: RFC 1321
- SHA-1: FIPS 180-4
- SHA-256: FIPS 180-4
- MD4: RFC 1320 (needed for NTLM)
- MD5-crypt: FreeBSD md5crypt (Drepper spec)
- SHA-256/512-crypt: crypt(3) man-page, Drepper "SHA-crypt" specification
"""
import struct

_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _rotr32(x: int, n: int) -> int:
    return (x >> n | x << (32 - n)) & _MASK32


def _rotr64(x: int, n: int) -> int:
    return (x >> n | x << (64 - n)) & _MASK64


def _pad(msg: bytes, block: int, length_field: str = ">Q") -> bytes:
    ml = len(msg) * 8
    msg += b"\x80"
    while len(msg) % block != (block - 8):
        msg += b"\x00"
    msg += struct.pack(length_field, ml)
    return msg


# ===========================================================================
# MD5  (RFC 1321)
# ===========================================================================

_MD5_K = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]

_MD5_S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]


def _md5_compress(h: list[int], block: bytes) -> list[int]:
    M = list(struct.unpack("<16I", block))
    a, b, c, d = h

    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d) & _MASK32
            g = i
        elif i < 32:
            f = (d & b) | (~d & c) & _MASK32
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | ~d & _MASK32)
            g = (7 * i) % 16

        f = (f + a + _MD5_K[i] + M[g]) & _MASK32
        a = d
        d = c
        c = b
        b = (b + _rotl32(f, _MD5_S[i])) & _MASK32

    return [(h[0] + a) & _MASK32, (h[1] + b) & _MASK32,
            (h[2] + c) & _MASK32, (h[3] + d) & _MASK32]


def md5(msg: bytes) -> bytes:
    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    msg = _pad(msg, 64, "<Q")
    for i in range(0, len(msg), 64):
        h = _md5_compress(h, msg[i:i+64])
    return struct.pack("<4I", *h)


# ===========================================================================
# MD4  (RFC 1320 — needed for NTLM)
# ===========================================================================

_MD4_S = [
    3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19,
    3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13,
    3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15,
]


def _md4_compress(h, block):
    X = list(struct.unpack("<16I", block))
    a, b, c, d = h

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    # Round 1: X[i]
    for i in range(16):
        a = _rotl32((a + F(b, c, d) + X[i]) & _MASK32, _MD4_S[i])
        a, b, c, d = d, a, b, c

    # Round 2: X[0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15]
    for i in range(16):
        k = (i % 4) * 4 + i // 4
        a = _rotl32((a + G(b, c, d) + X[k] + 0x5A827999) & _MASK32, _MD4_S[16 + i])
        a, b, c, d = d, a, b, c

    # Round 3: X[0,8,4,12, 2,10,6,14, 1,9,5,13, 3,11,7,15]
    _r3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
    for i in range(16):
        k = _r3[i]
        a = _rotl32((a + H(b, c, d) + X[k] + 0x6ED9EBA1) & _MASK32, _MD4_S[32 + i])
        a, b, c, d = d, a, b, c

    return [(h[0] + a) & _MASK32, (h[1] + b) & _MASK32,
            (h[2] + c) & _MASK32, (h[3] + d) & _MASK32]


def md4(msg: bytes) -> bytes:
    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    msg = _pad(msg, 64, "<Q")
    for i in range(0, len(msg), 64):
        h = _md4_compress(h, msg[i:i+64])
    return struct.pack("<4I", *h)


# ===========================================================================
# SHA-1  (FIPS 180-4)
# ===========================================================================

def _sha1_compress(h, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        t = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
        w.append((t << 1 | t >> 31) & _MASK32)
    a, b, c, d, e = h
    for i in range(80):
        if i < 20:
            f = (b & c) | (~b & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        t = (_rotl32(a, 5) + f + e + k + w[i]) & _MASK32
        e = d; d = c; c = _rotl32(b, 30); b = a; a = t
    return [(h[i] + v) & _MASK32 for i, v in enumerate([a, b, c, d, e])]


def sha1(msg: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = _pad(msg, 64, ">Q")
    for i in range(0, len(msg), 64):
        h = _sha1_compress(h, msg[i:i+64])
    return struct.pack(">5I", *h)


# ===========================================================================
# SHA-256  (FIPS 180-4)
# ===========================================================================

_SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_SHA256_H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


def _sha256_compress(h, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = (_rotr32(w[i-15], 7) ^ _rotr32(w[i-15], 18) ^ (w[i-15] >> 3))
        s1 = (_rotr32(w[i-2], 17) ^ _rotr32(w[i-2], 19) ^ (w[i-2] >> 10))
        w.append((w[i-16] + s0 + w[i-7] + s1) & _MASK32)
    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (hh + S1 + ch + _SHA256_K[i] + w[i]) & _MASK32
        S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK32
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK32, c, b, a, (t1 + t2) & _MASK32
    return [(h[i] + v) & _MASK32 for i, v in enumerate([a, b, c, d, e, f, g, hh])]


def sha256(msg: bytes) -> bytes:
    h = list(_SHA256_H0)
    msg = _pad(msg, 64, ">Q")
    for i in range(0, len(msg), 64):
        h = _sha256_compress(h, msg[i:i+64])
    return struct.pack(">8I", *h)


# ===========================================================================
# SHA-512 (minimal — for sha-512-crypt)
# ===========================================================================

_SHA512_K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]

_SHA512_H0 = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]


def _sha512_compress(h, block):
    w = list(struct.unpack(">16Q", block))
    for i in range(16, 80):
        s0 = _rotr64(w[i-15], 1) ^ _rotr64(w[i-15], 8) ^ (w[i-15] >> 7)
        s1 = _rotr64(w[i-2], 19) ^ _rotr64(w[i-2], 61) ^ (w[i-2] >> 6)
        w.append((w[i-16] + s0 + w[i-7] + s1) & _MASK64)
    a, b, c, d, e, f, g, hh = h
    for i in range(80):
        S1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
        ch = (e & f) ^ (~e & g)
        t1 = (hh + S1 + ch + _SHA512_K[i] + w[i]) & _MASK64
        S0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK64
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK64, c, b, a, (t1 + t2) & _MASK64
    return [(h[i] + v) & _MASK64 for i, v in enumerate([a, b, c, d, e, f, g, hh])]


def sha512(msg: bytes) -> bytes:
    h = list(_SHA512_H0)
    ml = len(msg) * 8
    padded = msg + b"\x80"
    while len(padded) % 128 != 112:
        padded += b"\x00"
    padded += (ml).to_bytes(16, "big")
    for i in range(0, len(padded), 128):
        h = _sha512_compress(h, padded[i:i+128])
    return struct.pack(">8Q", *h)


# ===========================================================================
# MD5-crypt  (FreeBSD md5crypt / Drepper spec)
# Reference: https://akkadia.org/drepper/MD5-crypt.html
# ===========================================================================

def md5_crypt(password: str, salt: str) -> str:
    """MD5-crypt per the FreeBSD/Drepper spec. Salt up to 8 chars is used as-is."""
    magic = b"$1$"
    p = password.encode("utf-8")
    s = salt.encode("utf-8")
    itoa = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    # Digest B = MD5(P + S + P)
    db = md5(p + s + p)

    # Digest A = MD5(P + magic + S + repeat(db, len(P)) + altbits)
    a_ctx = p + magic + s
    i = len(p)
    while i > 0:
        a_ctx += db[:min(16, i)]
        i -= 16
    i = len(p)
    while i > 0:
        a_ctx += b"\x00" if i & 1 else p[:1]
        i >>= 1
    da = md5(a_ctx)

    # Digest C: 1000 rounds
    dc = da
    for r in range(1000):
        ctx = p if r & 1 else dc
        if r % 3:
            ctx += s
        if r % 7:
            ctx += p
        ctx += dc if r & 1 else p
        dc = md5(ctx)

    # Encode: transpose then little-endian hash64
    transpose = (12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11)
    t = bytes(dc[i] for i in transpose)

    def _h64(src: bytes) -> str:
        out = []
        i = 0
        n = len(src)
        while i + 2 < n:
            v1, v2, v3 = src[i], src[i + 1], src[i + 2]
            out.append(itoa[v1 & 0x3f])
            out.append(itoa[((v2 & 0x0f) << 2) | (v1 >> 6)])
            out.append(itoa[((v3 & 0x03) << 4) | (v2 >> 4)])
            out.append(itoa[v3 >> 2])
            i += 3
        if i < n:
            v1 = src[i]
            out.append(itoa[v1 & 0x3f])
            if i + 1 < n:
                v2 = src[i + 1]
                out.append(itoa[((v2 & 0x0f) << 2) | (v1 >> 6)])
                out.append(itoa[v2 >> 4])
            else:
                out.append(itoa[v1 >> 6])
        return "".join(out)

    return "$1$" + salt + "$" + _h64(t)


# ===========================================================================
# SHA-256-crypt  (Drepper spec)
# Reference: https://akkadia.org/drepper/SHA-crypt.html
# ===========================================================================

def _repeat_string(src: bytes, size: int) -> bytes:
    """Cycle `src` to exactly `size` bytes (passlib repeat_string semantics)."""
    if size == 0 or not src:
        return b""
    if len(src) >= size:
        return src[:size]
    out = src
    while len(out) < size:
        out += src
    return out[:size]


def _sha_crypt_core(password: bytes, salt: bytes, rounds: int, hashfn, digest_len: int) -> bytes:
    """SHA-crypt core per Drepper spec (shared by SHA-256/512-crypt).

    Structure (see akkadia.org/drepper/SHA-crypt.html and passlib sha2_crypt):
      A:   da  = H(P + S + repeat(H(P+S+P), len(P)) + bits(P))
      P:   dp  = repeat(H(P*len(P)), len(P))
      S:   ds  = H(S * (16 + da[0]))[:len(S)]
      C:   for i in 0..rounds-1:
               ctx = dp if i odd else dc
               if i%3: ctx += ds
               if i%7: ctx += dp
               ctx += dc if i odd else dp
               dc = H(ctx)
    """
    p_len = len(password)
    s_len = len(salt)

    # Digest B = H(P + S + P)
    db = hashfn(password + salt + password)

    # Digest A — build the buffer incrementally by hand (stateless hashfn)
    da_buf = password + salt + _repeat_string(db, p_len)
    i = p_len
    while i:
        da_buf += db if i & 1 else password
        i >>= 1
    da = hashfn(da_buf)

    # Digest P
    dp = _repeat_string(hashfn(password * p_len), p_len)

    # Digest S
    ds = hashfn(salt * (16 + da[0]))[:s_len]

    # Digest C rounds
    dc = da
    for i in range(rounds):
        ctx = dp if i & 1 else dc
        if i % 3:
            ctx += ds
        if i % 7:
            ctx += dp
        ctx += dc if i & 1 else dp
        dc = hashfn(ctx)

    return dc


def _sha_crypt_encode(digest: bytes, rounds: int, salt: str, digest_len: int) -> str:
    """Encode sha-crypt digest via transpose + little-endian hash64."""
    itoa = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    _T256 = (
        20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5,
        25, 15, 26, 16, 6, 17, 7, 27, 8, 28, 18, 29, 19, 9, 30, 31,
    )
    _T512 = (
        42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26,
        5, 47, 48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52,
        31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15,
        16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
    )

    tmap = _T256 if digest_len == 32 else _T512
    t = bytes(digest[i] for i in tmap)

    def _h64(src: bytes) -> str:
        out = []
        i = 0
        n = len(src)
        while i + 2 < n:
            v1, v2, v3 = src[i], src[i + 1], src[i + 2]
            out.append(itoa[v1 & 0x3f])
            out.append(itoa[((v2 & 0x0f) << 2) | (v1 >> 6)])
            out.append(itoa[((v3 & 0x03) << 4) | (v2 >> 4)])
            out.append(itoa[v3 >> 2])
            i += 3
        if i < n:
            v1 = src[i]
            out.append(itoa[v1 & 0x3f])
            if i + 1 < n:
                v2 = src[i + 1]
                out.append(itoa[((v2 & 0x0f) << 2) | (v1 >> 6)])
                out.append(itoa[v2 >> 4])
            else:
                out.append(itoa[v1 >> 6])
        return "".join(out)

    encoded = _h64(t)
    prefix = "$5$" if digest_len == 32 else "$6$"
    if rounds == 5000:
        return f"{prefix}{salt}${encoded}"
    return f"{prefix}rounds={rounds}${salt}${encoded}"


def sha256_crypt(password: str, salt: str, rounds: int = 5000) -> str:
    if rounds < 1000 or rounds > 999999999:
        rounds = max(1000, min(999999999, rounds))
    p = password.encode("utf-8")
    s = salt.encode("utf-8")
    result = _sha_crypt_core(p, s, rounds, sha256, 32)
    return _sha_crypt_encode(result, rounds, salt, 32)


def sha512_crypt(password: str, salt: str, rounds: int = 5000) -> str:
    if rounds < 1000 or rounds > 999999999:
        rounds = max(1000, min(999999999, rounds))
    p = password.encode("utf-8")
    s = salt.encode("utf-8")
    result = _sha_crypt_core(p, s, rounds, sha512, 64)
    return _sha_crypt_encode(result, rounds, salt, 64)


# ===========================================================================
# BCrypt / Argon2 identification (structural only)
# ===========================================================================

def is_bcrypt_hash(h: str) -> bool:
    return h.startswith(("$2a$", "$2b$", "$2y$")) and len(h) == 60


def is_argon2_hash(h: str) -> bool:
    return h.startswith(("$argon2i$", "$argon2d$", "$argon2id$"))


# ===========================================================================
# Utility: hash a string with any algorithm
# ===========================================================================

_HASHFN = {
    "md5": md5,
    "sha1": sha1,
    "sha256": sha256,
    "sha512": sha512,
    "md4": md4,
}


def hash_str(msg: bytes, algo: str) -> bytes:
    """Hash bytes with the given algorithm. Returns raw bytes."""
    if algo in _HASHFN:
        return _HASHFN[algo](msg)
    raise ValueError(f"Unknown hash algorithm: {algo}")
