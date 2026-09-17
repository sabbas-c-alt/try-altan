# filefan_manifest.py
# Understanding filefan's hashing + manifest step from filefan.py, without the
# CDN or MQTT. filefan hashes each file itself (not the CDN) so the same check
# works for multicast and http, then publishes a manifest telling BEEs what's
# coming. Here I compute the hashes and build the manifest, and print the mqtt
# publish instead of sending it.

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def show(label, value):
    print(f"    {label:<22} {value}")


# --- copied from filefan._compute_file_hashes (supports file:// and http/https) ---
def compute_file_hashes(files):
    hashes = {}
    for f in files:
        name = f.get("name", "")
        url = f.get("url", "")
        if not url or not name:
            continue
        try:
            if url.startswith("file://"):
                path = url[7:]
                with open(path, "rb") as fh:
                    data = fh.read()
            else:
                import urllib.request
                with urllib.request.urlopen(url, timeout=30) as r:
                    data = r.read()
            hashes[name] = hashlib.sha256(data).hexdigest()
            print(f"    hashed '{name}' ({len(data)} bytes) sha256={hashes[name][:12]}...")
        except Exception as e:
            print(f"    WARNING could not hash '{name}': {e}")
    return hashes


# --- stands in for filefan._publish_distribution_manifest (mqtt publish) ---
def build_and_publish_manifest(group, dist_id, session_id, send_at, files):
    manifest = {
        "dist_id": dist_id,
        "session_id": session_id,
        "send_at": send_at,
        "method": "core",
        "files": [{"name": f["name"]} for f in files],
    }
    dist_topic = f"filefan/groups/{group}/distributions/{dist_id}/manifest"
    group_topic = f"filefan/groups/{group}/manifest"
    print(f"    [stub] would publish manifest to {dist_topic}")
    print(f"    [stub] would publish manifest to {group_topic}")
    return manifest


def main():
    print("filefan hashing + manifest check (filefan.py logic, no CDN/MQTT)\n")

    # make three temp files so we have real bytes to hash
    tmpdir = tempfile.mkdtemp(prefix="filefan_")
    files = []
    for i, name in enumerate(["IMG_8505.jpeg", "IMG_8549.jpeg", "IMG_8552.jpeg"]):
        p = os.path.join(tmpdir, name)
        with open(p, "wb") as fh:
            fh.write(f"fake image content {i}".encode() * 50)
        files.append({"url": "file://" + p, "name": name})
    print(f"setup: 3 test files in {tmpdir}\n")

    print("1. filefan hashes each file itself (so multicast + http verify the same way)")
    hashes = compute_file_hashes(files)
    show("files hashed:", len(hashes))

    print("\n2. build + publish the distribution manifest")
    session_id = "abc123"
    manifest = build_and_publish_manifest(
        "atl-area", "fleet", session_id, "2026-01-01T12:00:00Z", files)
    show("dist_id:", manifest["dist_id"])
    show("session_id:", manifest["session_id"])
    show("method:", manifest["method"])
    show("files in manifest:", [f["name"] for f in manifest["files"]])
    print("    ^ manifest carries only file names; keys came from the site-join earlier")

    print("\n3. later, a BEE reports a receipt; filefan checks the hash it kept")
    # simulate a BEE reporting the sha256 of one file it received
    reported_name = "IMG_8505.jpeg"
    reported_hash = hashes[reported_name]        # honest BEE reports the real hash
    expected = hashes.get(reported_name)
    ok = (reported_hash == expected)
    show("BEE reported:", reported_name)
    show("hash matches expected:", ok)
    # now a tampered/forged receipt
    forged_ok = ("0" * 64 == expected)
    show("forged hash matches:", forged_ok)
    print("    ^ expected hash is never published, so a BEE can't fake a receipt")

    print("\ndone. filefan hashes files itself, publishes a name-only manifest, verifies receipts by hash.")


if __name__ == "__main__":
    main()
