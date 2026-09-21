# Understanding the root CDN (root_cdn._do_ingest + _notify_edges). The root CDN
# fetches each file once, caches it, hashes it, then tells each edge on-prem to
# fetch that session and which multicast to send it on. Normally the fetch and
# the edge notify are http; here I read local bytes and print the notify instead
# of sending it, so it runs on windows. The session build and per-edge site
# mapping are root_cdn.py's logic.

import hashlib
import os
import secrets
import tempfile


def show(label, value):
    print(f"    {label:<24} {value}")


# --- stands in for cdn.fetch_file (file:// path) ---
def fetch_file(url, dest):
    if url.startswith("file://"):
        with open(url[7:], "rb") as f:
            data = f.read()
    else:
        import urllib.request
        with urllib.request.urlopen(url, timeout=30) as r:
            data = r.read()
    with open(dest, "wb") as f:
        f.write(data)
    return len(data)


# --- copied logic from root_cdn._do_ingest ---
def ingest(files, sites, send_at):
    session_id = secrets.token_hex(4)
    sdir = tempfile.mkdtemp(prefix=f"cdn_{session_id}_")
    cached = []
    for entry in files:
        url = entry["url"]
        name = entry["name"]
        dest = os.path.join(sdir, name)
        size = fetch_file(url, dest)
        # hash the cached bytes, same as root_cdn
        h = hashlib.sha256()
        with open(dest, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        cached.append({"name": name, "size": size, "sha256": h.hexdigest()})
        print(f"    cached '{name}' ({size} bytes, sha256={h.hexdigest()[:12]}...)")

    session = {
        "session_id": session_id,
        "files": cached,
        "sites": sites,
        "send_at": send_at,
        "state": "cached",
    }
    return session


# --- copied logic from root_cdn._notify_edges (maps edge -> its site multicast) ---
def notify_edges(session):
    sites = session["sites"]
    # build service -> site map, same as root_cdn
    service_to_site = {site["service"]: site for site in sites.values()}
    for svc, site in service_to_site.items():
        print(f"    [stub] would POST /cdn/fetch to {svc}")
        show("  session:", session["session_id"])
        show("  multicast:", f"{site['sg']}:{site['port']}")
        show("  files:", [f["name"] for f in session["files"]])
        show("  send_at:", session["send_at"])


def main():
    print("root CDN ingest + edge notify (root_cdn.py logic, no HTTP)\n")

    # make two temp files to ingest
    tmp = tempfile.mkdtemp(prefix="src_")
    files = []
    for name in ["IMG_8505.jpeg", "IMG_8549.jpeg"]:
        p = os.path.join(tmp, name)
        with open(p, "wb") as f:
            f.write(b"fake image bytes " * 40)
        files.append({"url": "file://" + p, "name": name})

    # sites come from the distribution (one on-prem site 'atl')
    sites = {"atl": {"sg": "239.0.1.1", "port": 5200,
                     "encrypted_port": 5201, "service": "on-prem-atl"}}
    print("setup: 2 files to ingest, one edge site 'atl'\n")

    print("1. root CDN fetches each file once, caches and hashes it")
    session = ingest(files, sites, send_at="2026-01-01T12:00:00Z")
    show("session id:", session["session_id"])
    show("files cached:", len(session["files"]))

    print("\n2. root CDN notifies each edge which session + multicast to use")
    notify_edges(session)
    print("    ^ each edge fetches the cached files and sends on its own multicast")

    print("\n3. why hash at ingest")
    show("hashes computed:", [f["sha256"][:12] + "..." for f in session["files"]])
    print("    ^ the root CDN caches once and serves every edge, so it fetches from")
    print("      the origin a single time no matter how many edges receive it")

    print("\ndone. root CDN caches a file once, then tells each edge which multicast to transmit it on.")


if __name__ == "__main__":
    main()
