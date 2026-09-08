"""CLI entry point for cryptocrack.

All subcommands are offline: they run against locally crafted fixtures
(no external services, no secrets, exit 0 on success).
"""
import argparse
import json
import sys

from . import __version__


# ---------------------------------------------------------------------------
# demo: end-to-end proof that every stage works
# ---------------------------------------------------------------------------

def cmd_demo(args):
    from . import primitives, hashes, crack, rsa_attacks, aes_attacks, dh_mitm, decode, cpa, hygiene
    from .primitives import md4, md5, sha1, sha256, sha512, md5_crypt, sha256_crypt, sha512_crypt
    import math
    import random

    results = {}

    # --- hash primitives: fixed known-answer vectors ---------------------
    assert md5(b"password").hex() == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert sha1(b"abc").hex() == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert sha256(b"hello").hex() == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert sha512(b"hello").hex() == "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
    assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    results["primitives"] = "md4, md5, sha1, sha256, sha512 vectors OK"

    # --- unix crypt variants (pure python, validated vs openssl/passlib) --
    assert md5_crypt("password", "salt1234") == "$1$salt1234$HJCsv4hSeVLHo3hVyl4nh0"
    assert sha256_crypt("hello", "its", 5000) == "$5$its$H5uICVlQJ7tBxsfd09UF2p9PnLVpfvAp8x7MqZzCaa8"
    assert sha512_crypt("hello", "its", 5000) == "$6$its$FMASy05ZxOx5Z1EkdFJTAWGMh1uqJ4jbD.Oboo51stMbT9kiKpGF0jXXHV5kx6KE4XkhSdq2HbRWiELSDc.vM."
    results["crypt_variants"] = "md5/sha256/sha512-crypt vectors OK"

    # --- AES (FIPS-197 known answer) ------------------------------------
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes_attacks.aes_encrypt_block(pt, key).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert aes_attacks.aes_decrypt_block(
        bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"), key).hex() == pt.hex()
    results["aes"] = "FIPS-197 AES-128 encrypt/decrypt OK"

    # --- hash identification ---------------------------------------------
    # 32-hex digests are ambiguous: md5 and NTLM have identical lengths,
    # so the honest classifier reports both with medium confidence.
    h = hashes.identify_hash(md5(b"password").hex())
    assert h["type"] in ("MD5", "NTLM") and h["confidence"] == "medium", h
    h1 = hashes.identify_hash(sha1(b"password").hex())
    assert h1["type"] == "SHA-1" and h1["confidence"] == "high", h1
    results["identify_md5"] = f"32-hex -> {h['type']} (md5/ntlm ambiguous, {h['confidence']})"
    results["identify_sha1"] = f"40-hex -> {h1['type']} ({h1['confidence']})"

    # --- wordlist + mask cracking ----------------------------------------
    wl = ["password", "secret", "horse", "correcthorse", "P@ssw0rd"]
    r = crack.crack(md5(b"correcthorse2024").hex(), wl, "md5")
    assert r.cracked and r.password == "correcthorse2024", r.password
    results["crack_wordlist_rules"] = f"{r.password!r} via {r.method} ({r.attempts} attempts)"

    r = crack.crack_mask(md5(b"cat9").hex(), "?l?l?l?d", "md5")
    assert r.cracked and r.password == "cat9", r.password
    results["crack_mask"] = f"{r.password!r} via {r.method}"

    crypt_t = sha256_crypt("secret", "abcd", 1000)
    r = crack.crack("", wl, "sha256", crypt_hash=crypt_t)
    assert r.cracked and r.password == "secret", r.password
    results["crack_sha256crypt"] = f"{r.password!r} via rounds=1000 $5$ hash"

    # --- RSA attacks ------------------------------------------------------
    p, q = 1009, 1013
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = rsa_attacks._modinv(e, phi)
    f = rsa_attacks.fermat_factor(n, max_iter=1_000_000)
    assert f["success"] and sorted([f["p"], f["q"]]) == [p, q]
    results["rsa_fermat"] = f"{n} -> {p},{q}"

    c = pow(14, 3, n)          # 14^3 = 2744 < n: no wraparound, perfect cube
    s = rsa_attacks.small_e_root(c, 3, n)
    assert s["success"] and s["plaintext"] == 14, s
    results["rsa_small_e"] = "e=3 root extraction OK"

    w = rsa_attacks.wiener_attack(e=2489, n=11413)
    assert w["success"] and w["d"] == 9, w
    results["rsa_wiener"] = "wiener continued-fraction d=9 recovered"

    random.seed(1)
    msg = 123456789
    moduli, cts = [], []
    # each modulus must exceed m^3 so the e-th power never wraps: use 44-bit primes
    while len(moduli) < 3:
        pp = random.randint(3, 10**13)
        if rsa_attacks._is_prime_miller_rabin(pp, 40):
            qq = random.randint(3, 10**13)
            if rsa_attacks._is_prime_miller_rabin(qq, 40):
                mm = pp * qq
                if mm > msg**3 and math.gcd(3, (pp - 1) * (qq - 1)) == 1:
                    moduli.append(mm)
                    cts.append(pow(msg, 3, mm))
    hb = rsa_attacks.hastad_broadcast(3, moduli, cts)
    assert hb["success"] and hb["plaintext"] == msg, hb
    results["rsa_hastad"] = "e=3 broadcast CRT recovery of ciphertext"

    # --- AES attack demos --------------------------------------------------
    pad_oracle = aes_attacks.PaddingOracle(key)
    pad_oracle.start()
    ct, iv = pad_oracle.encrypt(b"FLAG{demo-of-padding-oracle}")
    try:
        recovered = aes_attacks.padding_oracle_attack(pad_oracle.oracle, iv, ct)
        pt_blocks = []
        prev = iv
        for i in range(0, len(ct), 16):
            blk = ct[i:i + 16]
            interm = recovered[i:i + 16]
            pt_blocks.append(bytes(a ^ b for a, b in zip(prev, interm)))
            prev = blk
        got = aes_attacks.pkcs7_unpad(b"".join(pt_blocks))
        assert got == b"FLAG{demo-of-padding-oracle}", got
    finally:
        pad_oracle.stop()
    results["aes_padding_oracle"] = "full plaintext recovered byte-by-byte"

    rep = aes_attacks.pkcs7_pad(b"YELLOW SUBMARINE" * 20, 16)
    ecb_ct = b"".join(aes_attacks.aes_encrypt_block(rep[i:i + 16], key)
                      for i in range(0, len(rep), 16))
    assert aes_attacks.detect_ecb(ecb_ct)["is_ecb"]
    results["aes_ecb_detect"] = "ECB mode detected from repeated blocks"

    flip_pt = b"AAAAAAAABBBBBBBB"
    f_ct, f_iv = aes_attacks.cbc_encrypt(flip_pt, key, iv=bytes(16))
    new_iv = aes_attacks.cbc_bitflip_with_known_pt(
        f_iv, f_ct[:16], key, ord("A"), ord("X"), 0)
    flipped = aes_attacks.pkcs7_unpad(aes_attacks.cbc_decrypt(f_ct, key, new_iv))
    assert flipped == b"XAAAAAAABBBBBBBB", flipped
    results["aes_cbc_bitflip"] = "first plaintext byte flipped via IV tampering"

    # --- CPA side-channel ---------------------------------------------------
    cpa_res = cpa.run_demo(200)
    assert cpa_res["success"], cpa_res
    results["cpa"] = f"{cpa_res['recovered_k1']} (K1) recovered, avg corr {cpa_res['avg_correlation']}"

    # --- DH MITM ------------------------------------------------------------
    dh = dh_mitm.simulate_dh_mitm()
    assert dh["mitm"]["different_keys"]
    results["dh_mitm"] = "MITM holds two distinct shared keys invisibly to peers"

    # --- decoding -----------------------------------------------------------
    assert decode.caesar_bruteforce("Khoor Zruog")[0][1] == "Hello World"
    xk, xt, _ = decode.xor_single_byte(bytes([ord(c) ^ 0x20 for c in "Hello World"]))
    assert xt == "Hello World"
    assert decode.vigenere_decrypt("Rijvs Uyvjn", "KEY") == "Hello World"
    assert decode.hex_decode("48656c6c6f20576f726c64") == "Hello World"
    results["decode"] = "caesar / vigenere / xor / hex OK"

    # --- credential hygiene -------------------------------------------------
    report = hygiene.credential_report(
        ["password", "Tr0ub4dor&3", "P@ssw0rd123!"])
    results["hygiene"] = report["summary"]

    print(json.dumps(results, indent=2))
    return 0


# ---------------------------------------------------------------------------
# per-command handlers
# ---------------------------------------------------------------------------

def _load_wordlist(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def cmd_hash(args):
    from .primitives import md4, md5, sha1, sha256, sha512
    from .crack import _ntlm_hash
    algos = {
        "md5": md5, "md4": md4, "sha1": sha1, "sha256": sha256, "sha512": sha512,
    }
    data = args.input.encode()
    if args.algorithm == "ntlm":
        h = _ntlm_hash(args.input).hex()
    else:
        h = algos[args.algorithm](data).hex()
    print(f"Algorithm: {args.algorithm}")
    print(f"Hash: {h}")
    return 0


def cmd_crack(args):
    from .crack import crack
    wordlist = [_load_wordlist(args.wordlist)] if args.wordlist else \
        [["password", "123456", "secret", "qwerty", "letmein", "admin",
          "Password1", "P@ssw0rd", "correcthorse", "horse", "cat9"]]
    result = crack(
        args.hash_value if not args.crypt_hash else "",
        wordlist[0],
        args.algorithm,
        mask=args.mask,
        crypt_hash=args.crypt_hash or "",
    )
    for k, v in result.stats().items():
        print(f"{k}: {v}")
    return 0 if result.cracked else 1


def cmd_rsa(args):
    from .rsa_attacks import wiener_attack, fermat_factor, small_e_root, hastad_broadcast
    n = int(args.n, 16) if args.n.startswith("0x") else int(args.n)
    if args.attack == "wiener":
        e = int(args.e, 16) if args.e.startswith("0x") else int(args.e)
        print(json.dumps(wiener_attack(e, n), default=str, indent=2))
    elif args.attack == "fermat":
        print(json.dumps(fermat_factor(n, int(args.max_iter)), indent=2))
    elif args.attack == "small-e":
        e = int(args.e)
        c = int(args.c, 16) if args.c.startswith("0x") else int(args.c)
        print(json.dumps(small_e_root(c, e, n, padding_known=not args.unknown_padding),
                         default=str, indent=2))
    elif args.attack == "hastad":
        moduli = [int(m, 16) if m.startswith("0x") else int(m) for m in args.moduli]
        cts = [int(c, 16) if c.startswith("0x") else int(c) for c in args.ciphertexts]
        e = int(args.e)
        print(json.dumps(hastad_broadcast(e, moduli, cts), default=str, indent=2))
    return 0


def cmd_aes(args):
    from .aes_attacks import (cbc_decrypt, cbc_bitflip_with_known_pt, detect_ecb,
                              PaddingOracle, padding_oracle_attack, pkcs7_unpad)
    from .decode import hex_decode
    if args.attack == "ecb-oracle":
        data = hex_decode(args.ciphertext)
        print(json.dumps(detect_ecb(data), indent=2))
    elif args.attack == "bitflip":
        ct = hex_decode(args.ciphertext)
        key = hex_decode(args.key)
        iv = hex_decode(args.iv) if args.iv else bytes(16)
        pt = pkcs7_unpad(cbc_decrypt(ct, key, iv))
        print(f"Ciphertext: {ct.hex()}")
        print(f"Plaintext:  {pt}")
    elif args.attack == "flip-byte":
        ct = bytes.fromhex(args.ciphertext)
        key = bytes.fromhex(args.key)
        iv = bytes.fromhex(args.iv) if args.iv else bytes(16)
        target_byte = ord(args.from_char)
        new_iv = cbc_bitflip_with_known_pt(
            iv, ct[:16], key, target_byte, ord(args.to_char), int(args.position))
        print(f"New IV: {new_iv.hex()}")
    elif args.attack == "padding-oracle":
        key = bytes.fromhex(args.key) if args.key else bytes(range(16))
        oracle = PaddingOracle(key)
        oracle.start()
        try:
            secret = bytes.fromhex(args.ciphertext)
        except ValueError:
            secret = args.ciphertext.encode()
        ct, iv = oracle.encrypt(secret)
        recovered = padding_oracle_attack(oracle.oracle, iv, ct)
        blocks, prev, out = [], iv, []
        for i in range(0, len(ct), 16):
            blk = ct[i:i + 16]
            interm = recovered[i:i + 16]
            out.append(bytes(a ^ b for a, b in zip(prev, interm)))
            prev = blk
        got = pkcs7_unpad(b"".join(out))
        oracle.stop()
        print(f"Recovered ({len(ct)} bytes): {got}")
    return 0


def cmd_decode(args):
    from .decode import auto_decode, caesar_bruteforce, vigenere_decrypt, xor_single_byte, hex_decode
    if args.cipher == "auto":
        results = auto_decode(args.ciphertext)
        for k, v in results.items():
            print(f"[{k}] {v}")
    elif args.cipher == "caesar":
        for shift, decoded, score in caesar_bruteforce(args.ciphertext)[:5]:
            print(f"Shift {shift:2d}: {decoded} (score {score:0.3f})")
    elif args.cipher == "vigenere":
        print(vigenere_decrypt(args.ciphertext, args.key))
    elif args.cipher == "xor":
        if args.hex:
            decoded = hex_decode(args.ciphertext)
            data = decoded.encode("latin-1") if decoded is not None else b""
        else:
            data = args.ciphertext.encode()
        key, text, score = xor_single_byte(data)
        print(f"Key 0x{key:02x} (score {score:0.3f}): {text}")
    return 0


def cmd_hygiene(args):
    from .hygiene import password_strength, credential_report
    if args.password:
        result = password_strength(args.password)
        print(f"Score: {result['score']}/100 ({result['level']})")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Length: {result['length']}")
        print(f"Charset: {result['charset']}")
    elif args.batch:
        report = credential_report(args.batch, keys=args.keys)
        print(json.dumps(report, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="cryptocrack",
        description="Offline crypto-attack suite and credential-cracker framework. "
                    "Use only on systems you own or are authorized to test.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("demo", help="Run full proof demo with assertions")

    hash_p = sub.add_parser("hash", help="Hash a string with a pure-python primitive")
    hash_p.add_argument("input", help="String to hash")
    hash_p.add_argument("-a", "--algorithm", default="sha256",
                        choices=["md5", "md4", "sha1", "sha256", "sha512", "ntlm"])

    crack_p = sub.add_parser("crack", help="Crack a hash via wordlist+rules and/or mask")
    crack_p.add_argument("hash_value", nargs="?", help="Hex digest to crack (omit for crypt hashes)")
    crack_p.add_argument("-a", "--algorithm", default="md5",
                         choices=["md5", "md4", "sha1", "sha256", "sha512", "ntlm",
                                  "md5crypt", "sha256crypt", "sha512crypt"])
    crack_p.add_argument("-w", "--wordlist", help="Path to wordlist file")
    crack_p.add_argument("-m", "--mask", help='Mask pattern, e.g. "?l?l?l?d"')
    crack_p.add_argument("--crypt-hash", help="Full unix crypt hash ($1$/$5$/$6$)")
    crack_p.add_argument("--hashcat-mode", type=int, default=0)

    rsa_p = sub.add_parser("rsa", help="RSA attacks")
    rsa_p.add_argument("attack", choices=["wiener", "fermat", "small-e", "hastad"])
    rsa_p.add_argument("--n", required=True, help="Modulus (int or 0x-hex)")
    rsa_p.add_argument("--e", default="3", help="Public exponent")
    rsa_p.add_argument("--c", default="0x0", help="Ciphertext for small-e")
    rsa_p.add_argument("--max-iter", default="1000000", help="Fermat max iterations")
    rsa_p.add_argument("--moduli", nargs="+", help="Hastad: e-th power moduli")
    rsa_p.add_argument("--ciphertexts", nargs="+", help="Hastad: ciphertexts")
    rsa_p.add_argument("--unknown-padding", action="store_true",
                       help="Mark 'unknown padding' mode for small-e")

    aes_p = sub.add_parser("aes", help="AES attacks")
    aes_p.add_argument("attack", choices=["ecb-oracle", "bitflip", "flip-byte", "padding-oracle"])
    aes_p.add_argument("ciphertext", help="Ciphertext (hex; for padding-oracle plaintext is generated locally)")
    aes_p.add_argument("--key", help="Key hex (default 000102..0f)")
    aes_p.add_argument("--iv", help="IV hex (default zeros)")
    aes_p.add_argument("--from-char", default="A", help="flip-byte: original byte")
    aes_p.add_argument("--to-char", default="X", help="flip-byte: target byte")
    aes_p.add_argument("--position", default="0", help="flip-byte: byte index in block")

    decode_p = sub.add_parser("decode", help="Decode/decode text")
    decode_p.add_argument("ciphertext", help="Text or hex input")
    decode_p.add_argument("-c", "--cipher", default="auto",
                          choices=["auto", "caesar", "vigenere", "xor"])
    decode_p.add_argument("-k", "--key", help="Key for vigenere")
    decode_p.add_argument("--hex", action="store_true", help="Input is hex for xor")

    hygiene_p = sub.add_parser("hygiene", help="Analyze credential hygiene")
    hygiene_p.add_argument("password", nargs="?", help="Password to analyze")
    hygiene_p.add_argument("--batch", nargs="+", help="Multiple passwords")
    hygiene_p.add_argument("--keys", nargs="+", help="Hex-encoded keys to check")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "demo": cmd_demo,
        "hash": cmd_hash,
        "crack": cmd_crack,
        "rsa": cmd_rsa,
        "aes": cmd_aes,
        "decode": cmd_decode,
        "hygiene": cmd_hygiene,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())