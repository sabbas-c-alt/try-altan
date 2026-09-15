import time
import pki


def show(label, value):
    print(f"    {label:<28} {value}")


# stand-in for core's subscription table. real core keeps this and identity_ca
# asks it over https before issuing an op cert. here it's just a dict.
class Core:
    def __init__(self):
        self.subs = {}

    def add(self, subject):
        if subject not in self.subs:
            self.subs[subject] = "unsubscribed"

    def subscribe(self, subject):
        self.subs[subject] = "subscribed"

    def status(self, subject):
        return self.subs.get(subject)


# stand-in for identity_ca. holds the two CAs and does the gate check.
class CA:
    def __init__(self, core):
        self.core = core
        self.boot_ca_key = pki.generate_key()
        self.boot_ca = pki.make_ca_cert(self.boot_ca_key, "EBW-BootstrapCA")
        self.op_ca_key = pki.generate_key()
        self.op_ca = pki.make_ca_cert(self.op_ca_key, "EBW-OperationalCA")

    def give_bootstrap(self, subject):
        k = pki.generate_key()
        csr = pki.make_csr(k, subject)
        cert = pki.sign_csr(csr, self.boot_ca, self.boot_ca_key, pki.BOOTSTRAP_VALIDITY_DAYS)
        self.core.add(subject)   # identity_ca posts to core /inventory here
        return cert

    def give_operational(self, subject, seconds=300):
        # this is the gate. only subscribed devices get through.
        s = self.core.status(subject)
        if s != "subscribed":
            raise PermissionError(f"{subject}: subscription={s}")
        k = pki.generate_key()
        csr = pki.make_csr(k, subject)
        return pki.sign_csr_seconds(csr, self.op_ca, self.op_ca_key, seconds)


def main():
    print("subscription gate check (uses repo pki.py, no network)\n")
    core = Core()
    ca = CA(core)

    print("1. two CAs")
    show("bootstrap ca:", ca.boot_ca.subject.rfc4514_string())
    show("operational ca:", ca.op_ca.subject.rfc4514_string())

    print("\n2. manufacture BEE-1001 (bootstrap cert = id only)")
    b = ca.give_bootstrap("BEE-1001")
    ok = pki.cert_signed_by_ca(pki.cert_to_pem(b), pki.cert_to_pem(ca.boot_ca))
    show("signed by:", b.issuer.rfc4514_string())
    show("bootstrap valid:", ok)
    show("core status:", core.status("BEE-1001"))

    print("\n3a. subscribe BEE-1001, then ask for op cert")
    core.subscribe("BEE-1001")
    show("core status:", core.status("BEE-1001"))
    try:
        op = ca.give_operational("BEE-1001")
        good = pki.cert_signed_by_ca(pki.cert_to_pem(op), pki.cert_to_pem(ca.op_ca))
        show("op cert granted:", good)
    except PermissionError as e:
        show("unexpected:", e)

    print("\n3b. BEE-1002 never subscribed")
    ca.give_bootstrap("BEE-1002")
    show("core status:", core.status("BEE-1002"))
    try:
        ca.give_operational("BEE-1002")
        show("result:", "op cert issued -- BUG")
    except PermissionError as e:
        show("op cert refused:", e)
    print("    ^ this is why 'bee 1002 mqtt' fails")

    print("\n4. rogue cert from an untrusted CA")
    rogue_ca_key = pki.generate_key()
    rogue_ca = pki.make_ca_cert(rogue_ca_key, "EBW-RogueCA")
    rk = pki.generate_key()
    rcsr = pki.make_csr(rk, "BEE-1001")   # steals the real name
    rogue = pki.sign_csr(rcsr, rogue_ca, rogue_ca_key, 1)
    trusted = pki.cert_signed_by_ca(pki.cert_to_pem(rogue), pki.cert_to_pem(ca.op_ca))
    show("rogue subject:", rogue.subject.rfc4514_string())
    show("rogue issuer:", rogue.issuer.rfc4514_string())
    show("trusted by our CA:", trusted)
    print("    right name, wrong signer -> rejected")

    print("\n5. expired op cert")
    core.subscribe("BEE-1003")
    short = ca.give_operational("BEE-1003", seconds=1)
    print("    issued with 1s validity, waiting 2s...")
    time.sleep(2)
    left = pki.cert_seconds_remaining(pki.cert_to_pem(short))
    show("seconds left:", round(left, 1))
    show("expired:", left <= 0)

    print("\ndone. subscribed passes, unsubscribed/rogue/expired all fail.")


if __name__ == "__main__":
    main()
