"""Diffie-Hellman MITM attack simulation."""
import random
from .primitives import sha256

def _is_prime_miller_rabin(n, k=30):
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def is_safe_prime(p):
    if p < 5: return False
    q = (p - 1) // 2
    return p % 2 == 1 and _is_prime_miller_rabin(p) and _is_prime_miller_rabin(q)

def validate_generator(g, p):
    """Classify a generator for a safe prime p = 2q + 1.

    Returns the actual order class: 'full' (order p-1) or 'prime-subgroup'
    (order q). RFC 3526 group 14 uses g=5 in the prime-order subgroup,
    which is the standard cryptographic choice; full-order generators
    are only needed for schemes that must not hide in a subgroup.
    """
    if g < 2 or g >= p:
        return {"valid": False, "reason": "g out of range"}
    q = (p - 1) // 2
    if pow(g, 2, p) == 1:
        return {"valid": False, "reason": "g has order 2 (only ±1 usable); not a generator"}
    if pow(g, q, p) == 1:
        return {"valid": True, "order": q, "class": "prime-subgroup",
                "reason": "g generates the order-q subgroup (RFC 3526 style)"}
    return {"valid": True, "order": p - 1, "class": "full",
            "reason": "g generates the full group of order p-1"}

def _derive_key(shared_secret):
    return sha256(str(shared_secret).encode())

def dh_exchange(p, g):
    private = random.randrange(2, p - 1)
    public = pow(g, private, p)
    return {"private": private, "public": public}

def dh_compute_shared(their_public, my_private, p):
    secret = pow(their_public, my_private, p)
    return _derive_key(secret)

class DHMITM:
    def __init__(self, p, g):
        self.p = p; self.g = g
        self.private_a = self.public_a = None
        self.private_b = self.public_b = None
        self.key_with_alice = self.key_with_bob = None

    def intercept_alice(self, alice_public):
        self.private_a = random.randrange(2, self.p - 1)
        self.public_a = pow(self.g, self.private_a, self.p)
        self.key_with_alice = _derive_key(pow(alice_public, self.private_a, self.p))
        return self.public_a

    def intercept_bob(self, bob_public):
        self.private_b = random.randrange(2, self.p - 1)
        self.public_b = pow(self.g, self.private_b, self.p)
        self.key_with_bob = _derive_key(pow(bob_public, self.private_b, self.p))
        return self.public_b

    def keys_match(self):
        return {
            "alice_key": self.key_with_alice.hex(),
            "bob_key": self.key_with_bob.hex(),
            "different_keys": self.key_with_alice != self.key_with_bob,
            "message": "MITM has two separate keys",
        }

def simulate_dh_mitm(p=None, g=5):
    if p is None:
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    alice = dh_exchange(p, g)
    bob = dh_exchange(p, g)
    mitm = DHMITM(p, g)
    fake_bob_pub = mitm.intercept_alice(alice["public"])
    fake_alice_pub = mitm.intercept_bob(bob["public"])
    key_a = dh_compute_shared(fake_bob_pub, alice["private"], p)
    key_b = dh_compute_shared(fake_alice_pub, bob["private"], p)
    return {
        "alice_key": key_a.hex(),
        "bob_key": key_b.hex(),
        "mitm": mitm.keys_match(),
        "message": "MITM intercepts and derives two separate keys",
    }
