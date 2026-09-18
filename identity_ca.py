# Understanding how identity_ca.py is structured: it runs TWO servers. The
# bootstrap server issues the birth cert (no auth needed) and, on a second
# endpoint, issues the operational cert but only after checking with core that
# the device is subscribed. The operational server issues service certs. This
# reproduces that two-server flow and the gate, using the repo's real pki.py,
# with the http/tls between them replaced by function calls so it runs on windows.

import pki


def show(label, value):
    print(f"    {label:<26} {value}")


# --- core's subscription table (identity_ca queries this over https) ---
class Core:
    def __init__(self):
        self.subs = {}
    def add(self, s): self.subs.setdefault(s, "unsubscribed")
    def subscribe(self, s): self.subs[s] = "subscribed"
    def subscription_of(self, s): return self.subs.get(s)


# --- the bootstrap server: /getbootstrap and /getoperational ---
class BootstrapServer:
    def __init__(self, boot_ca, boot_ca_key, op_ca, op_ca_key, core):
        self.boot_ca, self.boot_ca_key = boot_ca, boot_ca_key
        self.op_ca, self.op_ca_key = op_ca, op_ca_key
        self.core = core

    def getbootstrap(self, subject):
        # no auth required. issues 30-yr identity cert, tells core device exists.
        key = pki.generate_key()
        csr = pki.make_csr(key, subject)
        cert = pki.sign_csr(csr, self.boot_ca, self.boot_ca_key, pki.BOOTSTRAP_VALIDITY_DAYS)
        self.core.add(subject)   # identity_ca -> core POST /inventory
        return cert

    def getoperational(self, subject, presented_bootstrap_cert):
        # mTLS in the real thing: caller must present a valid bootstrap cert.
        if presented_bootstrap_cert is None:
            raise PermissionError("no bootstrap cert presented")
        if not pki.cert_signed_by_ca(pki.cert_to_pem(presented_bootstrap_cert),
                                     pki.cert_to_pem(self.boot_ca)):
            raise PermissionError("bootstrap cert not signed by our bootstrap CA")
        # THE GATE: identity_ca asks core if this device is subscribed.
        sub = self.core.subscription_of(subject)
        if sub != "subscribed":
            raise PermissionError(f"not subscribed (subscription={sub})")
        key = pki.generate_key()
        csr = pki.make_csr(key, subject)
        cert = pki.sign_csr_seconds(csr, self.op_ca, self.op_ca_key, 300)
        return cert


# --- the operational server: /getsvcert (for services like core, filefan) ---
class OperationalServer:
    def __init__(self, op_ca, op_ca_key):
        self.op_ca, self.op_ca_key = op_ca, op_ca_key
    def getsvcert(self, subject):
        key = pki.generate_key()
        csr = pki.make_csr(key, subject)
        return pki.sign_server_csr(csr, self.op_ca, self.op_ca_key, pki.SVC_CERT_VALIDITY_DAYS)


def main():
    print("identity_ca two-server flow (identity_ca.py structure, real pki.py)\n")

    # startup: identity_ca creates both CAs
    boot_ca_key = pki.generate_key()
    boot_ca = pki.make_ca_cert(boot_ca_key, "EBW-BootstrapCA")
    op_ca_key = pki.generate_key()
    op_ca = pki.make_ca_cert(op_ca_key, "EBW-OperationalCA")
    core = Core()
    boot_srv = BootstrapServer(boot_ca, boot_ca_key, op_ca, op_ca_key, core)
    op_srv = OperationalServer(op_ca, op_ca_key)
    print("startup: bootstrap server + operational server, two CAs\n")

    print("1. BEE-1001 calls bootstrap server /getbootstrap (no auth)")
    b_cert = boot_srv.getbootstrap("BEE-1001")
    show("issued by:", b_cert.issuer.rfc4514_string())
    show("core inventory:", core.subscription_of("BEE-1001"))
    print("    ^ has identity, not yet subscribed")

    print("\n2. BEE-1001 calls /getoperational BEFORE being subscribed")
    try:
        boot_srv.getoperational("BEE-1001", b_cert)
        show("result:", "issued -- BUG")
    except PermissionError as e:
        show("refused:", e)

    print("\n3. operator subscribes, then /getoperational succeeds")
    core.subscribe("BEE-1001")
    op_cert = boot_srv.getoperational("BEE-1001", b_cert)
    good = pki.cert_signed_by_ca(pki.cert_to_pem(op_cert), pki.cert_to_pem(op_ca))
    show("op cert issued, signed by op CA:", good)

    print("\n4. /getoperational with a rogue bootstrap cert is refused")
    rogue_ca_key = pki.generate_key()
    rogue_ca = pki.make_ca_cert(rogue_ca_key, "EBW-RogueCA")
    rk = pki.generate_key()
    rogue_boot = pki.sign_csr(pki.make_csr(rk, "BEE-1001"), rogue_ca, rogue_ca_key, 1)
    try:
        boot_srv.getoperational("BEE-1001", rogue_boot)
        show("result:", "issued -- BUG")
    except PermissionError as e:
        show("refused:", e)

    print("\n5. operational server issues a service cert (for core, filefan, etc.)")
    svc = op_srv.getsvcert("core")
    show("service cert for 'core':", pki.cert_signed_by_ca(pki.cert_to_pem(svc), pki.cert_to_pem(op_ca)))

    print("\ndone. bootstrap server gates op certs on subscription; operational server issues service certs.")


if __name__ == "__main__":
    main()
