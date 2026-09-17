# The registry is the service directory: every service registers its host:port
# here and looks the others up. registry.py runs on Windows unmodified (it's
# plain HTTP, no multicast), so this talks to the REAL registry rather than a
# stub. Start Altan's registry first, then run this.

import json
import urllib.request

REG = "http://localhost:8500"


def show(label, value):
    print(f"    {label:<22} {value}")


def register(name, host, port):
    body = json.dumps({"name": name, "host": host, "port": port}).encode()
    req = urllib.request.Request(f"{REG}/register", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def lookup(name):
    with urllib.request.urlopen(f"{REG}/lookup/{name}", timeout=5) as r:
        return json.loads(r.read())


def services():
    with urllib.request.urlopen(f"{REG}/services", timeout=5) as r:
        return json.loads(r.read())


def main():
    print("registry / service discovery check (talks to Altan's real registry.py)\n")

    try:
        urllib.request.urlopen(f"{REG}/services", timeout=3)
    except Exception:
        print("ERROR: registry not reachable at localhost:8500.")
        print("Start it first in another terminal:  python registry.py")
        return

    print("1. register a few fake services")
    for name, host, port in [("core", "127.0.0.1", 9001),
                             ("filefan", "127.0.0.1", 9002),
                             ("stick-atl", "127.0.0.1", 9003)]:
        res = register(name, host, port)
        show(f"registered {name}:", res.get("status"))

    print("\n2. look one up by name")
    info = lookup("filefan")
    show("filefan is at:", f"{info['host']}:{info['port']}")

    print("\n3. list everything currently registered")
    all_svc = services()
    for name, info in sorted(all_svc.items()):
        show(name + ":", f"{info['host']}:{info['port']}")

    print("\n4. look up something that isn't registered")
    try:
        lookup("does-not-exist")
    except urllib.error.HTTPError as e:
        show("missing service:", f"HTTP {e.code} (correctly not found)")

    print("\ndone. every service finds the others through this one directory.")


if __name__ == "__main__":
    import urllib.error
    main()
