import hashlib
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def make_key(key_hex):
    # bee.py / on_prem.py derive the aes key as sha256 of the key string
    return hashlib.sha256(key_hex.encode()).digest()


def encrypt(epoch, key_hex, payload):
    # matches on_prem.py: epoch(4) + nonce(12) + gcm ciphertext
    g = AESGCM(make_key(key_hex))
    nonce = os.urandom(12)
    return struct.pack("!I", epoch) + nonce + g.encrypt(nonce, payload, None)


# copies bee.py's key store: current / next / previous, and the lookup order
class Bee:
    def __init__(self):
        self.cur = self.cur_e = None
        self.nxt = self.nxt_e = None
        self.prev = self.prev_e = None

    def set_current(self, key, e):
        self.cur, self.cur_e = key, e

    def got_next(self, key, e):
        self.nxt, self.nxt_e = key, e

    def rotate(self, key, e):
        self.prev, self.prev_e = self.cur, self.cur_e
        self.cur, self.cur_e = key, e
        self.nxt = self.nxt_e = None

    def key_for(self, e):
        if self.cur_e == e:
            return self.cur, "current"
        if self.nxt_e == e:
            return self.nxt, "next"
        if self.prev_e == e:
            return self.prev, "previous"
        return None, None

    def decrypt(self, pkt):
        e = struct.unpack("!I", pkt[:4])[0]
        nonce, ct = pkt[4:16], pkt[16:]
        key, src = self.key_for(e)
        if key is None:
            return None, e, "no key"
        try:
            return AESGCM(make_key(key)).decrypt(nonce, ct, None), e, src
        except InvalidTag:
            return None, e, "bad key (gcm fail)"


def report(pt, e, src):
    if pt is not None:
        print(f"    epoch {e}, key={src} -> ok: {pt!r}")
    else:
        print(f"    epoch {e} -> {src} -> dropped")


def main():
    print("key rotation check (same crypto as bee.py/on_prem.py)\n")

    k1 = "aa" * 32
    k2 = "bb" * 32
    bee = Bee()
    bee.set_current(k1, 1)

    print("1. normal packet under current key (epoch 1)")
    report(*bee.decrypt(encrypt(1, k1, b"firmware-chunk-0007")))

    print("\n2. key rotates to epoch 2, late epoch-1 packet arrives")
    bee.got_next(k2, 2)     # core sends next_key early
    bee.rotate(k2, 2)       # rotation: old key becomes previous
    report(*bee.decrypt(encrypt(1, k1, b"firmware-chunk-0008")))
    print("    ^ old key kept as previous, so it still decrypts")

    print("\n3. fresh packet under new key (epoch 2)")
    report(*bee.decrypt(encrypt(2, k2, b"firmware-chunk-0009")))

    print("\n4. attacker packet with wrong key (claims epoch 2)")
    report(*bee.decrypt(encrypt(2, "ff" * 32, b"bad-payload")))
    print("    gcm tag fails -> dropped, not decrypted to garbage")

    print("\ndone. rotation keeps working, wrong key is rejected.")


if __name__ == "__main__":
    main()
