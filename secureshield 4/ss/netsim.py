"""NEXUS lab network simulator. Emits the same raw scanner / sensor / flow records real discovery would, with scripted
scenarios, so the demo is repeatable on any laptop. Starts empty: nothing is discovered until NEXUS is switched on."""
import ipaddress
import json
import random
from datetime import timedelta
from . import db, discovery

NETWORKS = [  # cidr, name, vlan, authorized_for_active_scan, passive_sensor, active_scan, fragile, notes
    ("10.0.10.0/24", "Office LAN", 10, 1, 1, 1, 0, ""), ("10.0.20.0/24", "Server VLAN", 20, 1, 1, 1, 0, ""),
    ("10.0.30.0/24", "Guest Wi-Fi", 30, 0, 0, 0, 0, "no sensor on this segment"),
    ("10.0.40.0/24", "IoT VLAN", 40, 0, 1, 1, 1, "fragile devices: passive only")]
DECLARED = [("gw-01", "netops", "high", "gateway"), ("laptop-asha", "asha", "low", "laptop"), ("laptop-meena", "meena", "low", "laptop"),
            ("priyas-iphone", "priya", "low", "phone"), ("app-01", "platform", "high", "application server"),
            ("db-01", "platform", "critical", "database server"), ("cam-lobby", "facilities", "low", "camera")]
S = lambda *ps: [{"port": p, "proto": "tcp", "service": {22: "ssh", 53: "dns", 80: "http", 443: "https", 445: "microsoft-ds",
                                                          554: "rtsp", 5432: "postgresql", 8080: "http-proxy"}[p]} for p in ps]
DEVICES = {
    "gw-01": dict(ip="10.0.10.1", mac="00:00:0c:07:ac:01", vendor="Cisco", hostname="gw-01", os="Cisco IOS 15.2", ports=S(22, 53, 80, 443)),
    "laptop-asha": dict(ip="10.0.10.21", mac="f4:8e:38:aa:01:21", vendor="Dell", hostname="laptop-asha", os="Windows 11", ports=S(445), dhcp="01:f4:8e:38:aa:01:21"),
    "laptop-meena": dict(ip="10.0.10.22", mac="3c:52:82:bb:02:22", vendor="HP", hostname="laptop-meena", os="Windows 10", ports=S(445), dhcp="01:3c:52:82:bb:02:22"),
    "priyas-iphone": dict(ip="10.0.10.57", mac="da:a1:19:5c:10:57", vendor="", hostname="priyas-iphone", os="Apple iOS 17", ports=[],
                          dhcp="01:priya-phone", mdns=["_apple-mobdev2._tcp"]),
    "app-01": dict(ip="10.0.20.10", mac="00:50:56:a1:00:10", vendor="VMware", hostname="app-01", os="Linux 5.4", ports=S(22, 80, 443)),
    "db-01": dict(ip="10.0.20.20", mac="00:50:56:a1:00:20", vendor="VMware", hostname="db-01", os="Linux 5.4", ports=S(22, 5432)),
    "cam-lobby": dict(ip="10.0.40.15", mac="ac:cc:8e:12:40:15", vendor="Axis", hostname="cam-lobby", os="Linux 3.2 (embedded)", ports=S(80, 554),
                      dhcp="01:ac:cc:8e:12:40:15", mdns=["_rtsp._tcp"]),
    "rogue": dict(ip="10.0.10.99", mac="b8:27:eb:4d:09:99", vendor="Raspberry Pi", hostname="", os="Linux 5.15", ports=S(22, 8080), dhcp="01:b8:27:eb:4d:09:99"),
}
EXT = "34.117.59.81"
PROFILES = [  # src, dst, port, chance per second, bytes range
    ("laptop-asha", "app-01", 443, .30, (20e3, 400e3)), ("laptop-meena", "app-01", 443, .30, (20e3, 400e3)),
    ("laptop-asha", "gw-01", 53, .20, (200, 900)), ("laptop-meena", "gw-01", 53, .20, (200, 900)), ("priyas-iphone", "gw-01", 53, .15, (200, 900)),
    ("app-01", "db-01", 5432, .60, (50e3, 300e3)), ("app-01", "cam-lobby", 554, .12, (500e3, 1.5e6)), ("cam-lobby", "gw-01", 123, .10, (80, 200)),
    ("laptop-asha", EXT, 443, .20, (10e3, 200e3)), ("laptop-meena", EXT, 443, .20, (10e3, 200e3)), ("priyas-iphone", EXT, 443, .15, (10e3, 100e3)),
    ("cam-lobby", EXT, 443, .08, (2e3, 9e3))]
SWEEP, WARMUP = 20, 40
SCENARIOS = {
    "connect_unknown": dict(label="Connect an unknown device", expect=["unknown_device"]),
    "probe_database": dict(label="Unknown device probes the database", expect=["unknown_device", "device_reaches_critical", "internal_scan"]),
    "iot_exfil": dict(label="Camera contacts many outside addresses", expect=["new_external_destinations"]),
    "arp_spoof": dict(label="Impersonate the gateway (ARP spoof)", expect=["arp_anomaly"]),
    "phone_mac_rotate": dict(label="Phone rotates its MAC address", expect=[]),
    "lateral_move": dict(label="Laptop reaches into the IoT VLAN (new segment crossing)", expect=["segment_crossing"]),
    "db_offline": dict(label="Database server goes silent", expect=["device_gone_silent"], secs=80),
}


def seed():
    db.exmany("insert or replace into networks values (?,?,?,?,?,?,?,?)", NETWORKS)
    db.exmany("insert or replace into net_declared values (?,?,?,?)", DECLARED)


def _st():
    return json.loads(db.meta_get("net_state") or "{}")


def _save(st):
    db.meta_set("net_state", json.dumps(st))


def _dev(k, st):
    return dict(DEVICES[k], **st.get("override", {}).get(k, {}))


def _net_of(nets, ip):
    return next((n for n in nets if ipaddress.ip_address(ip) in ipaddress.ip_network(n["cidr"])), None)


def _alive(k, st, quarantined):
    d = DEVICES[k]
    return (k != "rogue" or "rogue" in st.get("joined", {})) and d["ip"] not in quarantined and k not in st.get("offline", [])


def _arp(d, ts, mac=None):
    return ("netpassive", {"ts": ts, "kind": "arp", "ip": d["ip"], "mac": mac or d["mac"]})


def _dhcp(d, ts):
    return ("netpassive", {"ts": ts, "kind": "dhcp", "ip": d["ip"], "mac": d["mac"], "hostname": d["hostname"], "dhcp_id": d["dhcp"]})


def _mdns(d, ts):
    return ("netpassive", {"ts": ts, "kind": "mdns", "ip": d["ip"], "mac": d["mac"], "hostname": d["hostname"], "mdns": d["mdns"]})


def _scan(d, ts):
    return ("netscan", {"ts": ts, "ip": d["ip"], "mac": d["mac"], "vendor": d["vendor"], "hostname": d["hostname"], "os": d["os"], "ports": d["ports"]})


def _flow(ts, src_ip, dst_ip, port, nbytes):
    return ("netflow", {"ts": ts, "src_ip": src_ip, "dst_ip": dst_ip, "port": port, "proto": "tcp", "bytes": int(nbytes)})


def _ip(x, st):
    return x if x == EXT or x[0].isdigit() else _dev(x, st)["ip"]


def _quarantined():
    return {r["ip"] for r in db.q("select ip from assets where status='quarantined'")}


def _passive_ok(d, nets):
    n = _net_of(nets, d["ip"])
    return bool(n and n["passive_sensor"])


def _scannable(d, nets):
    n = _net_of(nets, d["ip"])
    return bool(n and n["active_scan"] and n["authorized"] and not n["fragile"])


def _initial_discovery(iso):
    """What NEXUS does the moment it is switched on: one sweep of the approved ranges plus whatever passive sensors hear."""
    st, nets, q, pairs = _st(), db.q("select * from networks"), _quarantined(), []
    for k in DEVICES:
        if not _alive(k, st, q):
            continue
        d = _dev(k, st)
        if _passive_ok(d, nets):
            pairs += [_arp(d, iso)] + ([_dhcp(d, iso)] if d.get("dhcp") else []) + ([_mdns(d, iso)] if d.get("mdns") else [])
        if _scannable(d, nets):
            pairs.append(_scan(d, iso))
    discovery.ingest(pairs)


def start(rng=None, warmup=WARMUP):
    """Switch NEXUS on: initial sweep, then catch up `warmup` seconds of normal traffic so baselines exist."""
    if db.meta_get("net_started"):
        return
    if not db.q("select 1 from networks limit 1"):
        seed()
    now = db.utcnow()
    t0 = now - timedelta(seconds=warmup)
    db.meta_set("net_started", db.iso(now))
    db.meta_set("net_learn_until", db.iso(now))
    db.meta_set("net_last_tick", db.iso(t0))
    _initial_discovery(db.iso(t0))
    st, q0 = _st(), _quarantined()
    alive = {k for k in DEVICES if _alive(k, st, q0)}      # one earlier flow per normal conversation: the learned baseline never depends on luck
    discovery.ingest([_flow(db.iso(t0), _ip(src, st), _ip(dst, st), port, (lo + hi) / 2)
                      for src, dst, port, _, (lo, hi) in PROFILES if src in alive and (dst == EXT or dst in alive)])
    tick(rng, max_catchup=warmup + 5)


def stop():
    for k in ("net_started", "net_last_tick"):
        db.ex("delete from meta where key=?", (k,))


def run_scenario(name):
    st, now = _st(), db.utcnow()
    until = lambda s: db.iso(now + timedelta(seconds=s))
    if name == "connect_unknown":
        st.setdefault("joined", {})["rogue"] = db.iso(now)
    elif name == "probe_database":
        st.setdefault("joined", {}).setdefault("rogue", db.iso(now))
        st["probe_until"] = until(25)
    elif name == "iot_exfil":
        st["exfil_until"] = until(20)
    elif name == "arp_spoof":
        st.setdefault("joined", {}).setdefault("rogue", db.iso(now))
        st["spoof_until"] = until(15)
    elif name == "lateral_move":
        st["lateral_until"] = until(20)
    elif name == "db_offline":
        st["offline"] = sorted(set(st.get("offline", [])) | {"db-01"})
    elif name == "phone_mac_rotate":
        st.setdefault("override", {})["priyas-iphone"] = {"mac": "de:4b:77:20:31:09"}
        st["rotate_at"], st["rotated"] = db.iso(now), 0
    _save(st)


def tick(rng=None, max_catchup=120):
    """Advance the lab to 'now' and ingest everything the sensors would have produced. Returns records ingested."""
    if not db.meta_get("net_started"):
        return 0
    rng, now = rng or random.Random(), db.utcnow()
    t0 = db.parse(db.meta_get("net_last_tick"))
    if (now - t0).total_seconds() > max_catchup:
        t0 = now - timedelta(seconds=max_catchup)
    n = int((now - t0).total_seconds())
    if n < 1:
        return 0
    st, nets, q, pairs = _st(), db.q("select * from networks"), _quarantined(), []
    blocks = {(b["src_asset"], b["dst_asset"], b["port"]) for b in db.q("select * from net_blocks")}
    ipmap = {r["ip"]: r["asset_id"] for r in db.q("select ip, asset_id from assets")}
    dirty = False
    for i in range(1, n + 1):
        ts = t0 + timedelta(seconds=i)
        iso = db.iso(ts)
        alive = [k for k in DEVICES if _alive(k, st, q)]
        for k in alive:
            d = _dev(k, st)
            if _passive_ok(d, nets):
                if rng.random() < 1 / 15:
                    pairs.append(_arp(d, iso))
                if d.get("dhcp") and rng.random() < 1 / 45:
                    pairs.append(_dhcp(d, iso))
                if d.get("mdns") and rng.random() < 1 / 30:
                    pairs.append(_mdns(d, iso))
            if k == "rogue" and not st.setdefault("announced", {}).get("rogue"):
                pairs += [_arp(d, iso), _dhcp(d, iso)]
                st["announced"]["rogue"] = 1
                dirty = True
        if int(ts.timestamp()) % SWEEP == 0:
            pairs += [_scan(_dev(k, st), iso) for k in alive if _scannable(_dev(k, st), nets)]
        if st.get("rotate_at") and not st.get("rotated"):   # DHCP announces the new random MAC with the same client id and hostname
            d = _dev("priyas-iphone", st)
            pairs += [_dhcp(d, iso), _arp(d, iso)]
            st["rotated"] = 1
            dirty = True
        for src, dst, port, p, (lo, hi) in PROFILES:
            if src in alive and (dst == EXT or dst in alive) and rng.random() < p:
                si, di = _ip(src, st), _ip(dst, st)
                if (ipmap.get(si), ipmap.get(di), port) not in blocks:
                    pairs.append(_flow(iso, si, di, port, rng.uniform(lo, hi)))
        if "rogue" in alive and iso < st.get("probe_until", ""):
            for _ in range(2):
                dst, port = rng.choice([("app-01", 443), ("app-01", 22), ("app-01", 80), ("db-01", 5432), ("db-01", 22), ("db-01", 3306)])
                if (ipmap.get(DEVICES["rogue"]["ip"]), ipmap.get(DEVICES[dst]["ip"]), port) not in blocks:
                    pairs.append(_flow(iso, DEVICES["rogue"]["ip"], DEVICES[dst]["ip"], port, rng.uniform(100, 3000)))
        if "laptop-meena" in alive and "cam-lobby" in alive and iso < st.get("lateral_until", "") and rng.random() < .5:
            pairs.append(_flow(iso, DEVICES["laptop-meena"]["ip"], DEVICES["cam-lobby"]["ip"], 554, rng.uniform(5e4, 3e5)))
        if "cam-lobby" in alive and iso < st.get("exfil_until", ""):
            for _ in range(3):
                pairs.append(_flow(iso, DEVICES["cam-lobby"]["ip"], f"{rng.choice([45, 91, 185, 203])}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}",
                                   rng.choice([443, 8443, 4444]), rng.uniform(5e4, 5e5)))
        if "rogue" in alive and iso < st.get("spoof_until", "") and int(ts.timestamp()) % 3 == 0:
            pairs.append(("netpassive", {"ts": iso, "kind": "arp", "ip": DEVICES["gw-01"]["ip"], "mac": DEVICES["rogue"]["mac"]}))
    if dirty:
        _save(st)
    db.meta_set("net_last_tick", db.iso(t0 + timedelta(seconds=n)))
    discovery.ingest(pairs)
    return len(pairs)
