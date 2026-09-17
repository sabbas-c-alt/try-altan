
# Understanding how core turns a group into its actual members, from core.py's
# _do_groups_resolve. A group can be defined two ways: an explicit list of BEEs,
# or a list of sticks (sites) where membership is whatever BEEs are on those
# sticks. The second kind is dynamic: attach a BEE to a stick and it joins.

def show(label, value):
    print(f"    {label:<20} {value}")


# module state, same shape as core.py
devices = {}   # subject -> {"sticks": [...]}
onprems = {}   # svc_name -> {"service", "stick"}
groups = {}    # name -> group dict


# --- copied logic from core._do_groups_resolve ---
def resolve_group(group_name):
    grp = groups[group_name]
    onprem_map = {}

    if grp["type"] == "bee":
        bees = [b for b in grp.get("bees", []) if b in devices]
        for subject in bees:
            bee_sticks = set(devices[subject].get("sticks", []))
            for svc_name, op in onprems.items():
                if op["stick"] in bee_sticks:
                    onprem_map.setdefault(svc_name, {"service": svc_name, "stick": op["stick"], "bees": []})
                    onprem_map[svc_name]["bees"].append(subject)
    else:  # onprem type
        for s in grp.get("onprems", []):
            svc = f"on-prem-{s}"
            onprem_map[svc] = {"service": svc, "stick": s, "bees": []}
        for subject, dev in devices.items():
            for s in grp.get("onprems", []):
                if s in dev.get("sticks", []):
                    if f"on-prem-{s}" in onprem_map:
                        onprem_map[f"on-prem-{s}"]["bees"].append(subject)

    onprems_list = list(onprem_map.values())
    all_bees, seen = [], set()
    for op in onprems_list:
        for b in op["bees"]:
            if b not in seen:
                all_bees.append(b)
                seen.add(b)
    return {"group": group_name, "onprems": onprems_list, "bees": all_bees}


def main():
    print("group resolution check (core.py logic, no network)\n")

    # setup: two sites, three devices
    onprems["on-prem-atl"] = {"service": "on-prem-atl", "stick": "atl"}
    onprems["on-prem-nyc"] = {"service": "on-prem-nyc", "stick": "nyc"}
    devices["BEE-1001"] = {"sticks": ["atl"]}
    devices["BEE-1002"] = {"sticks": ["atl"]}
    devices["BEE-1010"] = {"sticks": ["nyc"]}
    print("setup: BEE-1001, BEE-1002 on 'atl'; BEE-1010 on 'nyc'\n")

    print("1. onprem-type group over stick 'atl' (membership is dynamic)")
    groups["atl-area"] = {"name": "atl-area", "type": "onprem", "onprems": ["atl"]}
    r = resolve_group("atl-area")
    show("onprems:", [op["service"] for op in r["onprems"]])
    show("resolved bees:", r["bees"])
    print("    ^ any BEE attached to 'atl' is a member automatically")

    print("\n2. a new device attaches to 'atl' -> it joins with no group change")
    devices["BEE-1003"] = {"sticks": ["atl"]}
    r = resolve_group("atl-area")
    show("resolved bees:", r["bees"])
    print("    ^ BEE-1003 appeared just by being on the stick")

    print("\n3. bee-type group with an explicit list")
    groups["vip"] = {"name": "vip", "type": "bee", "bees": ["BEE-1001", "BEE-1010"]}
    r = resolve_group("vip")
    show("resolved bees:", r["bees"])
    show("onprems (via sticks):", [op["service"] for op in r["onprems"]])
    print("    ^ explicit members, and core still finds which site each is on")

    print("\ndone. onprem groups resolve dynamically by stick; bee groups use an explicit list.")


if __name__ == "__main__":
    main()
