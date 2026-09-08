"""AES attack implementations.

- Padding oracle attack (byte-by-byte recovery via a localhost oracle)
- CBC bitflip (alter IV to modify decrypted plaintext)
- ECB detection (identical ciphertext blocks)
"""
import os
import socket
import threading
import time
import secrets
from .primitives import md5


# ---------------------------------------------------------------------------
# AES primitives (ECB / CBC modes — no padding oracle leakage here,
# the oracle *is* the server that tells us PKCS7 valid/invalid)
# ---------------------------------------------------------------------------

# S-box and inverse
_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

_XTIME = lambda a: ((a << 1) ^ 0x11b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _mix_single(a):
    return _XTIME(a) ^ (_XTIME(a) ^ a) ^ a ^ a  # simplified


def _sub_bytes(state):
    return [_SBOX[b] for b in state]


def _shift_rows(s):
    return [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]


def _add_round_key(state, rk):
    return [a ^ b for a, b in zip(state, rk)]


def _key_expansion(key: bytes, nr: int = 10) -> list[list[int]]:
    """Expand AES key into round keys."""
    nk = len(key) // 4
    w = list(key)

    i = nk
    while i < 4 * (nr + 1):
        temp = w[(i-1)*4:i*4]
        if i % nk == 0:
            temp = [(_SBOX[b]) for b in [temp[1], temp[2], temp[3], temp[0]]]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        prev = w[(i-nk)*4:(i-nk+1)*4]
        w.extend(a ^ b for a, b in zip(prev, temp))
        i += 1

    round_keys = []
    for r in range(nr + 1):
        round_keys.append(w[r*16:(r+1)*16])
    return round_keys


def _mix_columns(s):
    r = [0] * 16
    for c in range(4):
        i = c * 4
        a = s[i:i+4]
        r[i]   = _XTIME(a[0]) ^ (_XTIME(a[1]) ^ a[1]) ^ a[2] ^ a[3]
        r[i+1] = a[0] ^ _XTIME(a[1]) ^ (_XTIME(a[2]) ^ a[2]) ^ a[3]
        r[i+2] = a[0] ^ a[1] ^ _XTIME(a[2]) ^ (_XTIME(a[3]) ^ a[3])
        r[i+3] = (_XTIME(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _XTIME(a[3])
    return r


def _inv_mix_columns(s):
    r = [0] * 16
    for c in range(4):
        i = c * 4
        a = s[i:i+4]
        # multiply by inverse mix columns matrix
        r[i]   = _mul(0x0e,a[0]) ^ _mul(0x0b,a[1]) ^ _mul(0x0d,a[2]) ^ _mul(0x09,a[3])
        r[i+1] = _mul(0x09,a[0]) ^ _mul(0x0e,a[1]) ^ _mul(0x0b,a[2]) ^ _mul(0x0d,a[3])
        r[i+2] = _mul(0x0d,a[0]) ^ _mul(0x09,a[1]) ^ _mul(0x0e,a[2]) ^ _mul(0x0b,a[3])
        r[i+3] = _mul(0x0b,a[0]) ^ _mul(0x0d,a[1]) ^ _mul(0x09,a[2]) ^ _mul(0x0e,a[3])
    return r


def _mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _inv_shift_rows(s):
    return [
        s[0], s[13], s[10], s[7],
        s[4], s[1], s[14], s[11],
        s[8], s[5], s[2], s[15],
        s[12], s[9], s[6], s[3],
    ]


_INV_SBOX = [0]*256
for _i in range(256):
    _INV_SBOX[_SBOX[_i]] = _i


def _inv_sub_bytes(s):
    return [_INV_SBOX[b] for b in s]


def aes_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt a single 16-byte AES block."""
    nr = {16: 10, 24: 12, 32: 14}[len(key)]
    rk = _key_expansion(key, nr)
    state = list(plaintext[:16])
    state = _add_round_key(state, rk[0])
    for r in range(1, nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, rk[r])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, rk[nr])
    return bytes(state)


def aes_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt a single 16-byte AES block."""
    nr = {16: 10, 24: 12, 32: 14}[len(key)]
    rk = _key_expansion(key, nr)
    state = list(ciphertext[:16])
    state = _add_round_key(state, rk[nr])
    for r in range(nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, rk[r])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, rk[0])
    return bytes(state)


# ---------------------------------------------------------------------------
# PKCS7 padding
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def pkcs7_valid(data: bytes) -> bool:
    if not data or len(data) % 16 != 0:
        return False
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return False
    return data[-pad_len:] == bytes([pad_len] * pad_len)


# ---------------------------------------------------------------------------
# CBC mode
# ---------------------------------------------------------------------------

def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt with AES-CBC. Returns (ciphertext, iv)."""
    if iv is None:
        iv = os.urandom(16)
    plaintext = pkcs7_pad(plaintext)
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    prev = iv
    ct = b""
    for block in blocks:
        xored = bytes(a ^ b for a, b in zip(prev, block))
        encrypted = aes_encrypt_block(xored, key)
        ct += encrypted
        prev = encrypted
    return ct, iv


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt with AES-CBC. Returns plaintext with PKCS7 padding still present."""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    prev = iv
    pt = b""
    for block in blocks:
        decrypted = aes_decrypt_block(block, key)
        pt += bytes(a ^ b for a, b in zip(prev, decrypted))
        prev = block
    return pt


# ---------------------------------------------------------------------------
# Attack 1: Padding Oracle
# ---------------------------------------------------------------------------

class PaddingOracle:
    """A localhost padding oracle server. Connects via TCP."""

    def __init__(self, key: bytes, port: int = 0):
        self.key = key
        self.port = port or (9000 + secrets.randbelow(1000))
        self.server = None
        self._thread = None

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", self.port))
        self.server.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self.server.settimeout(5)
        try:
            while True:
                try:
                    conn, _ = self.server.accept()
                except socket.timeout:
                    return
                except OSError:
                    return
                with conn:
                    data = conn.recv(65536)
                    if len(data) < 16:
                        conn.send(b"0")
                        continue
                    iv = data[:16]
                    ct = data[16:]
                    try:
                        decrypted = cbc_decrypt(ct, self.key, iv)
                        valid = pkcs7_valid(decrypted)
                        conn.send(b"1" if valid else b"0")
                    except Exception:
                        conn.send(b"0")
        except OSError:
            pass

    def oracle(self, iv: bytes, ct: bytes) -> bool:
        """Send IV+CT to oracle, return True if padding is valid."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(("127.0.0.1", self.port))
            s.send(iv + ct)
            resp = s.recv(1)
            return resp == b"1"
        except Exception:
            return False
        finally:
            s.close()

    def stop(self):
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        return cbc_encrypt(plaintext, self.key)

    def get_real_plaintext(self) -> bytes:
        return b"This is secret!"


def padding_oracle_attack(oracle_fn, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext byte-by-byte using the padding oracle.

    This is the Vaudenay padding oracle attack.
    oracle_fn(iv, ct) -> True/False (padding valid).
    """
    block_size = 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted = b""

    for block_idx in range(len(blocks)):
        block = blocks[block_idx]
        intermediate = [0] * block_size

        for byte_pos in range(block_size - 1, -1, -1):
            pad_val = block_size - byte_pos
            prefix = bytes([intermediate[i] ^ pad_val for i in range(byte_pos + 1, block_size)])

            found = False
            for guess in range(256):
                test_iv = bytes([0] * byte_pos + [guess] + list(prefix))
                if oracle_fn(test_iv, block):
                    # Verify it's not a false positive for the last byte
                    if byte_pos == block_size - 1:
                        # Flip byte_pos-1 to confirm
                        verify_iv = bytes([0] * (byte_pos - 1) + [intermediate[byte_pos - 1] ^ pad_val] + [guess] + list(prefix[1:]))
                        if not oracle_fn(verify_iv, block):
                            continue
                    intermediate[byte_pos] = guess ^ pad_val
                    found = True
                    break
            if not found:
                break

        decrypted += bytes(intermediate)
    return decrypted


# ---------------------------------------------------------------------------
# Attack 2: CBC Bitflip
# ---------------------------------------------------------------------------

def cbc_bitflip(iv: bytes, ciphertext: bytes, key: bytes,
                target_pos: int, new_byte: int) -> tuple[bytes, bytes]:
    """Flip a byte in the IV to alter the corresponding plaintext byte.

    In CBC, decrypting block[0] = AES-Dec(ct[0]) XOR iv.
    So flipping iv[target_pos] flips plaintext[target_pos].

    Returns (modified_iv, ciphertext).
    """
    # Recover the original IV's effect: we need to know what the original
    # plaintext byte was. In practice, we know the plaintext structure.
    # Here we demonstrate: flip iv[pos] by delta to change pt[pos].
    original_iv = bytearray(iv)
    original_iv[target_pos] ^= new_byte
    return bytes(original_iv), ciphertext


def cbc_bitflip_with_known_pt(iv: bytes, ciphertext: bytes, key: bytes,
                               current_pt_byte: int, desired_pt_byte: int,
                               position: int) -> bytes:
    """Flip IV byte at `position` to change plaintext from current to desired."""
    delta = current_pt_byte ^ desired_pt_byte
    new_iv = bytearray(iv)
    new_iv[position] ^= delta
    return bytes(new_iv)


# ---------------------------------------------------------------------------
# Attack 3: ECB Detection
# ---------------------------------------------------------------------------

def detect_ecb(ciphertext: bytes, block_size: int = 16) -> dict:
    """Detect if ciphertext was encrypted with ECB by finding repeated blocks."""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    seen = {}
    duplicates = []
    for i, block in enumerate(blocks):
        if block in seen:
            duplicates.append((seen[block], i))
        else:
            seen[block] = i

    return {
        "is_ecb": len(duplicates) > 0,
        "block_size": block_size,
        "num_blocks": len(blocks),
        "duplicate_pairs": duplicates,
        "unique_blocks": len(seen),
    }
