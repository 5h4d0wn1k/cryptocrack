"""CLI entry point for cryptocrack."""
import argparse
import json
import sys
from . import __version__

def cmd_demo(args):
    results = {}
    from . import primitives
    from . import hashes
    from . import crack
    from . import rsa_attacks
    from . import aes_attacks
    from . import dh_mitm
    from . import decode
    from . import cpa
    from . import hygiene
    from .primitives import md5, sha256, sha512

    test_hash = md5(b"password")
    results["md5_password"] = test_hash
    assert test_hash == "5f4dcc3b5aa765d61d8327deb882cf99", f"MD5 failed: {test_hash}"

    test_sha = sha256(b"hello")
    results["sha256_hello"] = test_sha
    assert len(test_sha) == 64, "SHA-256 length wrong"

    test_sha5 = sha512(b"hello")
    results["sha512_hello"] = test_sha5
    assert len(test_sha5) == 128, "SHA-512 length wrong"

    identified = hashes.identify_hash(test_hash)
    results["hash_identify_md5"] = identified

    from .rsa_attacks import rsa_small_e_attack, rsa_wiener_attack, rsa_fermat_factorize
    n = 3233
    e = 17
    d = 2753
    ciphertext = pow(65, e, n)
    decrypted = rsa_small_e_attack(ciphertext, e, n)
    results["rsa_small_e"] = {"ciphertext": ciphertext, "decrypted": decrypted, "original": 65}

    p = 1009
    q = 1013
    factors = rsa_fermat_factorize(p * q)
    results["rsa_fermat"] = factors
    assert sorted(factors) == [p, q], f"Fermat factorization failed"

    import random
    random.seed(42)
    plaintext = b"SECRET MESSAGE 0123456789AB"
    key = bytes(range(16))
    from .aes_attacks import aes_cbc_encrypt, aes_cbc_decrypt, pkcs7_pad, pkcs7_unpad
    iv = bytes(16)
    ct = aes_cbc_encrypt(pkcs7_pad(plaintext, 16), key, iv)
    pt = aes_cbc_decrypt(ct, key, iv)
    results["aes_cbc"] = {"ciphertext": ct.hex(), "decrypted": pt.hex()}

    cpa_result = cpa.run_demo(200)
    results["cpa"] = cpa_result
    assert cpa_result["success"], "CPA attack failed"

    dh_result = dh_mitm.simulate_dh_mitm()
    results["dh_mitm"] = dh_result
    assert dh_result["mitm"]["different_keys"], "DH MITM should produce different keys"

    hex_input = "48656c6c6f20576f726c64"
    decoded = decode.hex_decode(hex_input)
    results["hex_decode"] = decoded
    assert decoded == "Hello World", f"Hex decode failed: {decoded}"

    batch = ["password", "correcthorsebatterystaple", "Tr0ub4dor&3", "P@ssw0rd123!"]
    report = hygiene.credential_report(batch)
    results["hygiene"] = report["summary"]

    print(json.dumps(results, indent=2))
    return 0

def cmd_hash(args):
    from .primitives import hash_str
    h = hash_str(args.input, args.algorithm)
    print(f"Algorithm: {args.algorithm}")
    print(f"Hash: {h}")
    return 0

def cmd_crack(args):
    from .crack import crack_hash
    result = crack_hash(args.hash_value, args.algorithm, args.wordlist, args.mask)
    if result.cracked:
        print(f"Cracked: {result.cracked_hash}")
        print(f"Plaintext: {result.plaintext}")
        print(f"Time: {result.elapsed:.2f}s")
        print(f"Attempts: {result.attempts}")
    else:
        print("Not cracked")
        print(f"Time: {result.elapsed:.2f}s")
        print(f"Attempts: {result.attempts}")
    return 0 if result.cracked else 1

def cmd_rsa(args):
    from .rsa_attacks import rsa_wiener_attack, rsa_fermat_factorize, rsa_hastad_broadcast
    if args.attack == "wiener":
        n = int(args.n, 16) if args.n.startswith("0x") else int(args.n)
        e = int(args.e, 16) if args.e.startswith("0x") else int(args.e)
        result = rsa_wiener_attack(n, e)
        print(json.dumps(result, indent=2))
    elif args.attack == "fermat":
        n = int(args.n, 16) if args.n.startswith("0x") else int(args.n)
        factors = rsa_fermat_factorize(n)
        print(json.dumps({"p": factors[0], "q": factors[1]}))
    elif args.attack == "hastad":
        print("Hastad broadcast requires file input (not implemented in CLI)")
    return 0

def cmd_aes(args):
    if args.attack == "ecb-oracle":
        from .aes_attacks import detect_ecb_mode
        from .decode import hex_decode
        data = hex_decode(args.ciphertext)
        detected, i, j = detect_ecb_mode(data)
        print(f"ECB detected: {detected}")
        if detected:
            print(f"Duplicate blocks at positions {i} and {j}")
    elif args.attack == "bitflip":
        from .aes_attacks import aes_cbc_decrypt, pkcs7_unpad
        from .decode import hex_decode
        ct = hex_decode(args.ciphertext)
        key = hex_decode(args.key)
        iv = hex_decode(args.iv) if args.iv else bytes(16)
        pt = aes_cbc_decrypt(ct, key, iv)
        print(f"Ciphertext: {ct.hex()}")
        print(f"Decrypted (raw): {pt.hex()}")
    return 0

def cmd_decode(args):
    from .decode import auto_decode, caesar_bruteforce
    if args.cipher == "auto":
        results = auto_decode(args.ciphertext)
        for k, v in results.items():
            print(f"[{k}] {v}")
    elif args.cipher == "caesar":
        results = caesar_bruteforce(args.ciphertext)
        for shift, decoded, score in sorted(results, key=lambda x: -x[2])[:5]:
            print(f"Shift {shift:2d}: {decoded} (score {score})")
    return 0

def cmd_hygiene(args):
    from .hygiene import password_strength, credential_report
    if args.password:
        result = password_strength(args.password)
        print(f"Score: {result['score']}/100 ({result['level']})")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Length: {result['length']}")
    elif args.batch:
        report = credential_report(args.batch)
        print(json.dumps(report["summary"], indent=2))
    return 0

def main():
    parser = argparse.ArgumentParser(
        prog="cryptocrack",
        description="Crypto-attack suite and credential-cracker framework",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("demo", help="Run full demo with assertions")

    hash_p = sub.add_parser("hash", help="Hash a string")
    hash_p.add_argument("input", help="String to hash")
    hash_p.add_argument("-a", "--algorithm", default="sha256",
                        choices=["md5", "md4", "sha1", "sha256", "sha512", "ntlm"])

    crack_p = sub.add_parser("crack", help="Crack a hash")
    crack_p.add_argument("hash_value", help="Hash to crack")
    crack_p.add_argument("-a", "--algorithm", default="md5")
    crack_p.add_argument("-w", "--wordlist", help="Path to wordlist")
    crack_p.add_argument("-m", "--mask", help="Mask pattern")

    rsa_p = sub.add_parser("rsa", help="RSA attacks")
    rsa_p.add_argument("attack", choices=["wiener", "fermat", "hastad"])
    rsa_p.add_argument("--n", required=True, help="Modulus")
    rsa_p.add_argument("--e", help="Public exponent")

    aes_p = sub.add_parser("aes", help="AES attacks")
    aes_p.add_argument("attack", choices=["ecb-oracle", "bitflip", "padding-oracle"])
    aes_p.add_argument("ciphertext", help="Ciphertext hex")
    aes_p.add_argument("--key", help="Key hex")
    aes_p.add_argument("--iv", help="IV hex")

    decode_p = sub.add_parser("decode", help="Decode ciphertext")
    decode_p.add_argument("ciphertext", help="Ciphertext to decode")
    decode_p.add_argument("-c", "--cipher", default="auto",
                          choices=["auto", "caesar", "vigenere", "xor"])

    hygiene_p = sub.add_parser("hygiene", help="Analyze credential hygiene")
    hygiene_p.add_argument("password", nargs="?", help="Password to analyze")
    hygiene_p.add_argument("--batch", nargs="+", help="Multiple passwords")

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
