# Understanding the encryptor (on_prem.py's _run_proxy). The on-prem receives
# plaintext multicast on one port, wraps each packet in AES-256-GCM, and
# re-emits on the encrypted port (origin+1). It prepends a 4-byte epoch so the
# receiver knows which key version to use. Normally there are two multicast
# sockets; here I feed packets in directly and collect what would be sent, so
# it runs on windows. The key derivation and packet framing are on_prem.py's.

import hashlib
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def show(label, value):
    print(f"    {label:<26} {value}")


# copied from on_prem._derive_key
def derive_key(key_str):
    return hashlib.sha256(key_str.encode()).digest()


# the proxy rule, same shape core sends to on_prem via /multicastproxy
class ProxyRule:
    def __init__(self, src_group, src_port, dst_group, dst_port, key, epoch):
        self.src = (src_group, src_port)
        self.dst = (dst_group, dst_port)
        self.key = key
        self.epoch = epoch
        # on_prem builds the AESGCM once per rule (key schedule is expensive)
        self.aesgcm = AESGCM(derive_key(key))
        self.epoch_bytes = struct.pack("!I", epoch)
        self.ingress = 0
        self.egress = 0

    def process(self, plaintext_packet):
        # this is the hot loop from on_prem._run_proxy, minus the sockets
        self.ingress += 1
        nonce = os.urandom(12)
        encrypted = nonce + self.aesgcm.encrypt(nonce, plaintext_packet, None)
        wire = self.epoch_bytes + encrypted   # epoch(4) + nonce(12) + ciphertext
        self.egress += 1
        return wire, self.dst


def main():
    print("on-prem encryptor check (on_prem.py _run_proxy logic, no sockets)\n")

    # core posts this rule to on_prem: origin -> encrypted (origin+1), with a key
    rule = ProxyRule("239.0.1.1", 5200, "239.0.1.1", 5201,
                     key="ab" * 32, epoch=1)
    print("setup: proxy rule 239.0.1.1:5200 -> 239.0.1.1:5201  epoch=1\n")

    print("1. plaintext packets arrive on the origin port")
    plaintext_packets = [b"cdn-chunk-%03d" % i for i in range(3)]
    for p in plaintext_packets:
        show("received plaintext:", p)

    print("\n2. encryptor wraps each and re-emits on the encrypted port")
    emitted = []
    for p in plaintext_packets:
        wire, dst = rule.process(p)
        emitted.append(wire)
        epoch = struct.unpack("!I", wire[:4])[0]
        show(f"-> {dst[0]}:{dst[1]}", f"epoch={epoch}  {len(wire)} bytes  (was {len(p)})")

    print("\n3. the framing: epoch + nonce + ciphertext")
    w = emitted[0]
    show("epoch (4 bytes):", struct.unpack("!I", w[:4])[0])
    show("nonce (12 bytes):", w[4:16].hex()[:16] + "...")
    show("ciphertext+tag:", f"{len(w) - 16} bytes")

    print("\n4. counters, as the on-prem dashboard shows them")
    show("ingress packets:", rule.ingress)
    show("egress packets:", rule.egress)

    print("\n5. sanity: a receiver with the same key can decrypt it")
    epoch = struct.unpack("!I", emitted[0][:4])[0]
    nonce = emitted[0][4:16]
    ct = emitted[0][16:]
    recovered = AESGCM(derive_key(rule.key)).decrypt(nonce, ct, None)
    show("decrypted back to:", recovered)
    show("matches original:", recovered == plaintext_packets[0])

    print("\ndone. encryptor receives plaintext, wraps in AES-GCM with an epoch, re-emits on origin+1.")


if __name__ == "__main__":
    main()
