"""NEXUS network detection kinds, in the same form as detect.py: weight, impact, MITRE reference. Deterministic.
Signals use the asset id as the 'user' so SecureShield's correlation groups them into one incident per device."""
import json
from collections import defaultdict
from . import db

KINDS = {  # weights are starting points to tune on the lab network
    "unknown_device": (3.0, 3, "T1200 Hardware Additions"),
    "device_reaches_critical": (3.5, 5, "T1021 Remote Services"),
    "new_external_destinations": (3.5, 4, "T1048 Exfiltration Over Alternative Protocol"),
    "segment_crossing": (1.5, 2, "T1046 Network Service Discovery"),
    "internal_scan": (2.5, 3, "T1046 Network Service Discovery"),
    "arp_anomaly": (4.0, 4, "T1557.002 ARP Cache Poisoning"),
    "device_gone_silent": (3.0, 4, "T1562 Impair Defenses"),
}
WINDOW = 30         # seconds (compressed for the demo)
SCAN_MIN, EXT_MIN, SILENT_AFTER = 6, 8, 60


def collect():
    if not db.meta_get("net_started"):
        return []
    from datetime import timedelta
    assets = {a["asset_id"]: a for a in db.q("select * from assets")}
    nm = lambda i: assets[i]["name"] if i in assets else i
    ev = db.q("select * from events where source like 'net%' order by ts")
    for e in ev:
        e["d"] = json.loads(e["detail"] or "{}")
    by_dev = defaultdict(list)
    for e in ev:
        by_dev[e["user"]].append(e)
    sigs = []

    def add(aid, ts, kind, title, evidence):
        w, imp, mitre = KINDS[kind]
        sigs.append(dict(user=aid, ts=ts, kind=kind, title=title, weight=w, impact=imp, mitre=mitre, evidence=evidence[:12]))

    def win(items, key):
        best, j = (0, []), 0
        for i in range(len(items)):
            while db.parse(items[i]["ts"]) - db.parse(items[j]["ts"]) > timedelta(seconds=WINDOW):
                j += 1
            n = len({key(e) for e in items[j:i + 1]})
            if n > best[0]:
                best = (n, items[j:i + 1])
        return best

    now = db.utcnow()
    for aid, a in assets.items():
        mine = by_dev.get(aid, [])
        if not a["authorized"] and not a["declared"]:
            add(aid, a["first_seen"], "unknown_device", f"New device {a['name']} ({a['ip']}) appeared and is not in any inventory",
                [e["id"] for e in mine[:3]])
        flows = [e for e in mine if e["action"] == "flow"]
        internal = [e for e in flows if e["d"]["dst"] != "EXTERNAL"]
        n, grp = win(internal, lambda e: (e["d"]["dst"], e["d"]["port"]))
        if n >= SCAN_MIN:
            add(aid, grp[-1]["ts"], "internal_scan", f"{a['name']} probed {n} distinct host/port targets within {WINDOW} seconds", [e["id"] for e in grp])
        ext = [e for e in flows if e["d"]["dst"] == "EXTERNAL"]
        n, grp = win(ext, lambda e: e["d"]["dst_ip"])
        if n >= EXT_MIN:
            before = len({e["d"]["dst_ip"] for e in ext if e["ts"] < grp[0]["ts"]})
            if before <= 3:
                add(aid, grp[-1]["ts"], "new_external_destinations",
                    f"{a['name']} contacted {n} distinct outside addresses within {WINDOW} seconds (previously {before})", [e["id"] for e in grp])
        if a["criticality"] == "critical" and a["status"] != "quarantined" and len(json.loads(a["seen_by"])) >= 2 \
                and (now - db.parse(a["last_seen"])).total_seconds() > SILENT_AFTER:
            add(aid, a["last_seen"], "device_gone_silent", f"Critical asset {a['name']} has not appeared in any source since {a['last_seen']}",
                [e["id"] for e in mine[-2:]])
    grouped = defaultdict(list)
    for c in db.q("select * from connections"):       # unauthorized or unapproved device reaching a critical asset
        s_, d_ = assets.get(c["src_asset"]), assets.get(c["dst_asset"])
        if s_ and d_ and not s_["authorized"] and d_["criticality"] == "critical":
            grouped[(c["src_asset"], c["dst_asset"])].append(c)
    for (sa, da), cs in grouped.items():
        ports = sorted(c["port"] for c in cs)
        evid = [e["id"] for e in by_dev.get(sa, []) if e["action"] == "flow" and e["d"]["dst"] == da]
        add(sa, min(c["first_seen"] for c in cs), "device_reaches_critical",
            f"Unauthorized device {nm(sa)} connected to critical asset {nm(da)} on port(s) {', '.join(map(str, ports))}", evid)
    learn = db.meta_get("net_learn_until") or ""
    seen_pairs = set()
    for e in sorted((e for e in ev if e["action"] == "flow" and e["d"]["dst"] in assets and e["user"] in assets), key=lambda e: e["ts"]):
        pair = (assets[e["user"]]["subnet"], assets[e["d"]["dst"]]["subnet"])
        if pair[0] != pair[1] and pair[0] and pair[1]:
            if e["ts"] <= learn:
                seen_pairs.add(pair)
            elif pair not in seen_pairs:
                seen_pairs.add(pair)
                add(e["user"], e["ts"], "segment_crossing", f"Traffic crossed from {pair[0]} to {pair[1]}, which never talked before", [e["id"]])
    done = set()
    for e in ev:
        if e["action"] == "arp_conflict" and (e["d"]["ip"], e["d"]["new_mac"]) not in done:
            done.add((e["d"]["ip"], e["d"]["new_mac"]))
            add(e["d"]["victim"], e["ts"], "arp_anomaly",
                f"{e['d']['ip']} is claimed by two MAC addresses ({e['d']['known_mac']} and {e['d']['new_mac']}): possible ARP spoofing", [e["id"]])
    return sigs
