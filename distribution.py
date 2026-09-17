import secrets
import time
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def show(label, value):
    print(f"    {label:<26} {value}")


# these mirror core.py's module state
groups = {}          # name -> group dict
distributions = {}   # (group, dist_id) -> dist dict
multicasts = {}      # mc_group -> multicast dict
devices = {}         # subject -> device (just to resolve group members)

MC_BASE = "239.0.1"
MC_PORT_START = 5200
KEY_LIFETIME = 20    # core default


# --- multicast address allocation (same as core._next_multicast_group/port) ---
def next_mc_group():
    used = set()
    for g in multicasts:
        parts = g.split(".")
        if parts[:3] == MC_BASE.split("."):
            used.add(int(parts[3]))
    for i in range(1, 255):
        if i not in used:
            return f"{MC_BASE}.{i}"
    raise RuntimeError("no addresses left")


def next_mc_port():
    used = set()
    for m in multicasts.values():
        used.add(m["port"])
        used.add(m.get("dest_port", m["port"] + 1))
    p = MC_PORT_START
    while p in used:
        p += 1
    return p


# --- these stand in for the network calls core makes ---
def stub_notify_encryptor(svc, mc):
    # real core does POST /multicastproxy to the on-prem here
    print(f"    [stub] would POST proxy rule to {svc}: "
          f"{mc['group']}:{mc['port']} -> {mc['dest_group']}:{mc['dest_port']} epoch={mc['current_epoch']}")


def stub_publish_site_join(group, stick, dist_id, mc):
    # real core publishes retained mqtt on core/groups/{g}/sites/{stick}/join
    print(f"    [stub] would publish core/groups/{group}/sites/{stick}/join")
    show("  key epoch:", mc["current_epoch"])
    show("  key (first 16):", mc["current_key"][:16] + "...")
    show("  encrypted sg:", f"{mc['dest_group']}:{mc['dest_port']}")


# --- group resolve (same shape as core._do_groups_resolve, onprem type) ---
def resolve_group(group_name):
    grp = groups[group_name]
    onprem_map = {}
    for s in grp.get("onprems", []):
        svc = f"on-prem-{s}"
        onprem_map[svc] = {"service": svc, "stick": s, "bees": []}
    for subject, dev in devices.items():
        for s in grp.get("onprems", []):
            if s in dev.get("sticks", []):
                onprem_map[f"on-prem-{s}"]["bees"].append(subject)
    return list(onprem_map.values())


# --- create (copied logic from core._do_create_distribution) ---
def create_distribution(group_name, dist_id, key_rotation_seconds=None):
    if group_name not in groups:
        raise ValueError(f"group '{group_name}' not found")
    if (group_name, dist_id) in distributions:
        raise ValueError(f"dist '{dist_id}' already exists")

    onprems = resolve_group(group_name)
    if not onprems:
        raise ValueError("group has no on-prem sites")

    sites = {}
    for op in onprems:
        stick = op["stick"]
        svc = op["service"]
        mc_group = next_mc_group()
        mc_port = next_mc_port()
        enc_port = mc_port + 1
        # reserve the multicast with NO key yet (epoch 0) - keys come on activate
        multicasts[mc_group] = {
            "group": mc_group, "port": mc_port,
            "dest_group": mc_group, "dest_port": enc_port,
            "identity": f"dist:{dist_id}",
            "current_key": None, "current_epoch": 0,
            "next_key": None, "next_epoch": None,
            "epoch_start": None,
            "key_lifetime_seconds": key_rotation_seconds,
            "logical_group": group_name,
        }
        sites[stick] = {"sg": mc_group, "port": mc_port,
                        "encrypted_port": enc_port, "service": svc,
                        "bees": op.get("bees", [])}

    dist = {
        "dist_id": dist_id, "group": group_name, "service": "filefan",
        "sites": sites, "key_rotation_seconds": key_rotation_seconds,
        "status": "created", "created_at": now_iso(), "activated_at": None,
    }
    distributions[(group_name, dist_id)] = dist
    return dist


# --- activate (copied logic from core._do_activate_distribution) ---
def activate_distribution(group_name, dist_id):
    dist = distributions.get((group_name, dist_id))
    if dist is None:
        raise ValueError("dist not found")
    if dist["status"] == "active":
        raise ValueError("already active")

    for stick, site in dist["sites"].items():
        mc_group = site["sg"]
        svc = site["service"]
        # generate the real key (core uses secrets.token_hex(32))
        current_key = secrets.token_hex(32)
        site["current_key"] = current_key
        site["current_epoch"] = 1

        mc = multicasts[mc_group]
        mc["current_key"] = current_key
        mc["current_epoch"] = 1
        mc["epoch_start"] = now_iso()
        mc["members"] = list(site["bees"])

        stub_notify_encryptor(svc, mc)
        stub_publish_site_join(group_name, stick, dist_id, mc)

    dist["status"] = "active"
    dist["activated_at"] = now_iso()
    return dist


# --- one rotation step (copied logic from core._run_key_rotation) ---
def rotate_once(mc_group):
    mc = multicasts[mc_group]
    old_epoch = mc["current_epoch"]
    # half-life: pre-generate next key
    mc["next_key"] = secrets.token_hex(32)
    mc["next_epoch"] = mc["current_epoch"] + 1
    show("half-life:", f"next_key ready, next_epoch={mc['next_epoch']}")
    # full rotation: promote next -> current
    mc["current_key"] = mc["next_key"]
    mc["current_epoch"] = mc["next_epoch"]
    mc["next_key"] = None
    mc["next_epoch"] = None
    mc["epoch_start"] = now_iso()
    show("rotated:", f"epoch {old_epoch} -> {mc['current_epoch']}")


def main():
    print("distribution lifecycle check (core.py logic, no network)\n")

    # setup: one device on stick 'atl', and an onprem group over 'atl'
    devices["BEE-1001"] = {"subject": "BEE-1001", "sticks": ["atl"]}
    groups["atl-area"] = {"name": "atl-area", "type": "onprem", "onprems": ["atl"]}
    print("setup: BEE-1001 on stick 'atl', group 'atl-area' over 'atl'\n")

    print("1. create distribution 'fleet' in group 'atl-area'")
    d = create_distribution("atl-area", "fleet", key_rotation_seconds=20)
    show("status:", d["status"])
    show("sites:", list(d["sites"].keys()))
    for stick, site in d["sites"].items():
        show(f"site {stick} sg:", f"{site['sg']}:{site['port']} (enc {site['encrypted_port']})")
        show(f"site {stick} key:", "none yet (keys come on activate)")

    print("\n2. activate distribution 'fleet'")
    d = activate_distribution("atl-area", "fleet")
    show("status:", d["status"])
    print("    ^ key generated, encryptor notified, site-join published")

    print("\n3. key rotation on the distribution's multicast")
    mc_group = d["sites"]["atl"]["sg"]
    rotate_once(mc_group)
    print("    ^ this is the timer-driven rotation from core's background thread")

    print("\n4. show final distribution record")
    show("dist_id:", d["dist_id"])
    show("group:", d["group"])
    show("status:", d["status"])
    show("current epoch:", multicasts[mc_group]["current_epoch"])

    print("\ndone. create reserves multicast, activate generates keys, rotation advances epoch.")


if __name__ == "__main__":
    main()
