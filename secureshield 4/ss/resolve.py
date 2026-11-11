"""NEXUS entity resolution: one device, one identity. Observations from scans, passive sensors and flow records are
reconciled into the assets table. Every device-type guess is a noisy-OR of weighted evidence, and the evidence is kept."""
import ipaddress
import json
import re
from . import db

LEASE_SECS = 120
GENERIC_HOSTS = {"", "localhost", "unknown", "android", "iphone", "host", "dhcp"}
OUI = {"00:00:0c": "Cisco", "00:50:56": "VMware", "ac:cc:8e": "Axis", "3c:52:82": "HP", "f4:8e:38": "Dell",
       "b8:27:eb": "Raspberry Pi", "00:1a:2b": "Juniper"}
VENDOR = {"Cisco": ("network", "router or switch", .5), "Juniper": ("network", "router or switch", .5),
          "Axis": ("iot", "network camera", .5), "Raspberry Pi": ("iot", "single-board computer", .3),
          "VMware": ("server", "server", .3), "Dell": ("computer", "computer", .3), "HP": ("computer", "computer", .3)}
HOST_PAT = [(r"^(gw|rtr|router|sw|fw)[-_]?\d*", "network", "router or switch", .35), (r"(^|[-_])db\d*($|[-_])|sql|postgres", "server", "database server", .35),
            (r"^(app|web|srv|api)[-_]?\d*", "server", "web server", .3), (r"^cam|camera", "iot", "network camera", .4),
            (r"^(laptop|pc|desktop|ws)[-_]", "computer", "computer", .35), (r"iphone|ipad|android|pixel|galaxy", "mobile", "phone or tablet", .4),
            (r"printer|^prn", "iot", "printer", .4)]
OS_PAT = [(r"cisco ios", "network", "router or switch", .5), (r"windows", "computer", "windows machine", .5),
          (r"ios|android", "mobile", "phone or tablet", .5), (r"embedded", "iot", "embedded device", .3),
          (r"linux", "server", "server", .3), (r"mac ?os", "computer", "mac", .5)]
PORT = {22: ("server", "server", .1), 80: ("server", "web server", .25), 443: ("server", "web server", .25),
        5432: ("server", "database server", .35), 3306: ("server", "database server", .35), 1433: ("server", "database server", .35),
        53: ("network", "dns or gateway", .3), 554: ("iot", "network camera", .4), 9100: ("iot", "printer", .5),
        445: ("computer", "windows machine", .3), 3389: ("computer", "windows machine", .3), 161: ("network", "router or switch", .2)}
LISTEN = {5432: ("server", "database server", .25), 554: ("iot", "network camera", .3), 53: ("network", "dns or gateway", .24),
          443: ("server", "web server", .2)}
MDNS = {"_airplay": ("mobile", "phone or tablet", .4), "_apple-mobdev": ("mobile", "phone or tablet", .4),
        "_ipp": ("iot", "printer", .5), "_rtsp": ("iot", "network camera", .4)}
RISKY_PORTS = {21, 23, 445, 3389, 5900, 161, 3306, 1433, 5432}


def randomized(mac):
    return bool(mac) and bool(int(mac[1], 16) & 2)


def vendor_of(mac):
    if not mac:
        return ""
    return "randomized (private) address" if randomized(mac) else OUI.get(mac[:8], "")


def classify(a):
    """Noisy-OR: P(type) = 1 - prod(1 - w_i) over independent evidence for that type. Returns (dtype, role, conf, evidence)."""
    ev = []

    def add(text, t, role, w, src):
        ev.append(dict(evidence=text, supports=t, role=role, weight=w, source=src, used=False))
    v = a.get("vendor") or ""
    if v in VENDOR:
        t, r, w = VENDOR[v]
        add(f"vendor prefix {(a.get('mac') or '')[:8]} is {v}" if a.get("mac") else f"vendor is {v}", t, r, w, "mac")
    if a.get("os"):
        for pat, t, r, w in OS_PAT:
            if re.search(pat, a["os"], re.I):
                add(f"OS fingerprint: {a['os']}", t, r, w, "scan")
                break
    name = a.get("name") or ""
    if name and not name.startswith(("host-", "unknown-")):
        for pat, t, r, w in HOST_PAT:
            if re.search(pat, name, re.I):
                add(f"hostname '{name}' looks like {r}", t, r, w, "hostname")
                break
    for p in a.get("ports", []):
        if p["port"] in PORT:
            t, r, w = PORT[p["port"]]
            add(f"open port {p['port']}/{p.get('service') or 'tcp'}", t, r, w, "scan")
    for port in a.get("listens", []):
        if port in LISTEN:
            t, r, w = LISTEN[port]
            add(f"other devices connect to it on port {port}", t, r, w, "flow")
    for svc in a.get("mdns", []):
        for k, (t, r, w) in MDNS.items():
            if svc.startswith(k):
                add(f"announces mDNS service {svc}", t, r, w, "mdns")
    score = {}
    for e in ev:
        score[e["supports"]] = 1 - (1 - score.get(e["supports"], 0)) * (1 - e["weight"])
    if not score:
        return "unknown", "", 0.0, []
    best = max(score, key=score.get)
    for e in ev:
        e["used"] = e["supports"] == best
    top = max((e for e in ev if e["used"]), key=lambda e: e["weight"])
    return best, top["role"], round(min(0.99, score[best]), 2), sorted(ev, key=lambda e: (-e["used"], -e["weight"]))


def evidence_table(asset):
    return json.loads(asset.get("evidence") or "[]")


class Resolver:
    def __init__(self, c):
        self.c = c
        self.nets = [(ipaddress.ip_network(n["cidr"]), n) for n in c.execute("select * from networks").fetchall()]

    # ---- helpers
    def one(self, sql, args=()):
        r = self.c.execute(sql, args).fetchone()
        return dict(r) if r else None

    def secs(self, a, b):
        return abs((db.parse(a) - db.parse(b)).total_seconds())

    def net_of(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return next((n for net, n in self.nets if addr in net), None)

    def change(self, ts, aid, kind, old, new):
        self.c.execute("insert into changes(ts,asset_id,kind,old,new) values (?,?,?,?,?)", (ts, aid, kind, old, new))

    def asset(self, aid):
        return self.one("select * from assets where asset_id=?", (aid,))

    def by_ident(self, kind, value):
        r = self.one("select asset_id from identifiers where kind=? and value=? order by last_seen desc", (kind, value))
        return r["asset_id"] if r else None

    def has_mac(self, aid):
        return self.one("select 1 x from identifiers where asset_id=? and kind='mac'", (aid,)) is not None

    def holder(self, ip):
        r = self.one("select asset_id, last_seen from assets where ip=? order by first_seen limit 1", (ip,))
        return (r["asset_id"], r["last_seen"]) if r else (None, None)

    def temp(self, aid):
        """An auto-created asset holding only a MAC and IP: no DHCP id, no hostname, not declared. Safe to fold into another asset."""
        a = self.asset(aid)
        return bool(a) and not a["declared"] and not a["authorized"] and \
            self.one("select 1 x from identifiers where asset_id=? and kind in ('dhcp_id','hostname')", (aid,)) is None

    def merge(self, keep, drop, ts, new_mac):
        """Two assets turned out to be one device. Move everything onto `keep`, keep the history, flag for review
        because the link rests on a DHCP id or hostname, not on the hardware address."""
        old = (self.one("select value from identifiers where asset_id=? and kind='mac' order by last_seen desc", (keep,)) or {}).get("value", "")
        for t, cols in (("identifiers", ("asset_id",)), ("observations", ("asset_id",)), ("changes", ("asset_id",)), ("events", ("user",)),
                        ("connections", ("src_asset", "dst_asset"))):
            for col in cols:
                self.c.execute(f"update or ignore {t} set {col}=? where {col}=?", (keep, drop))
        for t, col in (("identifiers", "asset_id"), ("connections", "src_asset"), ("connections", "dst_asset")):
            self.c.execute(f"delete from {t} where {col}=?", (drop,))
        self.c.execute("update incidents set user=? where user=?", (keep, drop))
        a, b = self.asset(keep), self.asset(drop)
        union = lambda col: json.dumps(sorted(set(json.loads(a[col])) | set(json.loads(b[col]))))
        self.c.execute("update assets set seen_by=?, listens=?, mdns=?, first_seen=min(first_seen,?), needs_review=1 where asset_id=?",
                       (union("seen_by"), union("listens"), union("mdns"), b["first_seen"], keep))
        self.c.execute("delete from assets where asset_id=?", (drop,))
        self.change(ts, keep, "merged_duplicate", drop, f"temporary asset {drop} merged in; MAC {old} -> {new_mac} linked by DHCP id or hostname; needs review")

    def attach(self, aid, kind, value, ts):
        if not value:
            return
        if self.one("select 1 x from identifiers where asset_id=? and kind=? and value=?", (aid, kind, value)):
            self.c.execute("update identifiers set last_seen=? where asset_id=? and kind=? and value=?", (ts, aid, kind, value))
        else:
            self.c.execute("insert into identifiers values (?,?,?,?,?)", (aid, kind, value, ts, ts))

    def new_asset(self, ts, name, ip, how):
        n = (self.one("select max(cast(substr(asset_id,3) as integer)) m from assets") or {}).get("m") or 0
        aid = f"A-{n + 1:04d}"
        net = self.net_of(ip)
        self.c.execute("insert into assets(asset_id,name,dtype,role,type_conf,authorized,declared,owner,criticality,ip,subnet,vendor,os,"
                       "first_seen,last_seen) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (aid, name, "unknown", "", 0.0, 0, 0, "", "", ip, net["name"] if net else "", "", "", ts, ts))
        self.change(ts, aid, "new_asset", "", f"first seen at {ip}: {how}")
        return aid

    def by_ip(self, ip, ts, how):
        aid, _ = self.holder(ip)
        return aid or self.new_asset(ts, f"host-{ip}", ip, how)

    def match_declared(self, aid, ts):
        a = self.asset(aid)
        if a["declared"] or a["name"].startswith(("host-", "unknown-")):
            return
        d = self.one("select * from net_declared where lower(hostname)=lower(?)", (a["name"],))
        inv = self.one("select * from inventory where lower(device)=lower(?)", (a["name"],))
        if d or inv:
            self.c.execute("update assets set authorized=1, declared=1, owner=?, criticality=? where asset_id=?",
                           ((d or inv)["owner"], d["criticality"] if d else "low", aid))
            self.change(ts, aid, "matched_declared_record", "not in any inventory", f"administrator-declared as '{a['name']}'")

    def event(self, ts, src, action, aid, name, ip, resource, detail):
        n = (self.one("select max(cast(substr(id,4) as integer)) m from events") or {}).get("m") or 0
        eid = f"EV-{n + 1:05d}"
        self.c.execute("insert into events values (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (eid, ts, src, "network", action, "success", aid, name, ip, "", resource, json.dumps(detail), json.dumps(detail)))
        return eid

    def touch(self, aid, src, ts):
        a = self.asset(aid)
        by = sorted(set(json.loads(a["seen_by"])) | {src})
        self.c.execute("update assets set seen_by=?, last_seen=? where asset_id=?", (json.dumps(by), ts, aid))

    def reclassify(self, aid):
        a = self.asset(aid)
        a["ports"], a["listens"], a["mdns"] = json.loads(a["ports"]), json.loads(a["listens"]), json.loads(a["mdns"])
        a["mac"] = (self.one("select value from identifiers where asset_id=? and kind='mac' order by last_seen desc", (aid,)) or {}).get("value", "")
        t, role, conf, ev = classify(a)
        self.c.execute("update assets set dtype=?, role=?, type_conf=?, evidence=? where asset_id=?", (t, role, conf, json.dumps(ev), aid))

    # ---- one record
    def handle(self, src, raw):
        (self.flow if src == "netflow" else self.ident)(src, raw)

    def ident(self, src, raw):
        ts, ip, mac = raw["ts"], raw.get("ip", ""), (raw.get("mac") or "").lower()
        host = (raw.get("hostname") or "").split(".")[0].lower()
        host = "" if host in GENERIC_HOSTS else host
        did = raw.get("dhcp_id", "")
        aid, how, conf, weak = None, "", 1.0, False
        if mac and (x := self.by_ident("mac", mac)):
            aid, how = x, "MAC"
        elif did and (x := self.by_ident("dhcp_id", did)):
            aid, how, conf = x, "DHCP client id", 0.9
            weak = bool(mac)
        elif host and (not mac or randomized(mac)) and (x := self.by_ident("hostname", host)):
            aid, how, conf, weak = x, "hostname (weak)", 0.5, bool(mac)
        else:
            h, hts = self.holder(ip) if ip else (None, None)
            if (mac or did) and h and not self.has_mac(h) and self.secs(ts, hts) < LEASE_SECS:
                aid, how, conf = h, "IP lease (first hardware identity)", 0.8
        if aid is None:
            name = host or (f"unknown-{mac[-8:].replace(':', '')}" if mac else f"host-{ip}")
            aid = self.new_asset(ts, name, ip, f"{src} {raw.get('kind', 'scan')}")
        if aid and mac and (did or (host and randomized(mac))):     # a stronger identifier says this MAC belongs to an asset we already know
            other = (self.by_ident("dhcp_id", did) if did else None) or (self.by_ident("hostname", host) if host and randomized(mac) else None)
            if other and other != aid and self.temp(aid):
                self.merge(other, aid, ts, mac)
                aid, how, conf = other, "merged with a duplicate (DHCP id / hostname)", 0.8
        a = self.asset(aid)
        if src == "netpassive" and raw.get("kind") == "arp" and mac and ip:       # one IP claimed by two different hardware addresses
            h, hts = self.holder(ip)
            if h and h != aid and self.has_mac(h) and self.secs(ts, hts) < LEASE_SECS:
                old = self.one("select value from identifiers where asset_id=? and kind='mac' order by last_seen desc", (h,))["value"]
                self.event(ts, src, "arp_conflict", h, self.asset(h)["name"], ip, f"{old} vs {mac}",
                           {"ip": ip, "known_mac": old, "new_mac": mac, "victim": h})
                self.change(ts, h, "arp_conflict", old, f"{ip} also claimed by {mac}")
        if weak and mac and not self.by_ident("mac", mac):
            old = (self.one("select value from identifiers where asset_id=? and kind='mac' order by last_seen desc", (aid,)) or {}).get("value", "")
            self.change(ts, aid, "mac_changed", old, f"{mac} linked by {how}; needs review")
            self.c.execute("update assets set needs_review=1 where asset_id=?", (aid,))
        for kind, val in (("mac", mac), ("ip", ip), ("hostname", host), ("dhcp_id", did)):
            self.attach(aid, kind, val, ts)
        if ip and a["ip"] != ip and not (a["ip"] and self.holder(ip)[0] not in (None, aid)):
            self.change(ts, aid, "ip_changed", a["ip"], ip)
            net = self.net_of(ip)
            self.c.execute("update assets set ip=?, subnet=? where asset_id=?", (ip, net["name"] if net else "", aid))
        if host and a["name"].startswith(("host-", "unknown-")):
            self.c.execute("update assets set name=? where asset_id=?", (host, aid))
            self.change(ts, aid, "named", a["name"], host)
        vendor = raw.get("vendor") or vendor_of(mac)
        sets = {}
        if vendor:
            sets["vendor"] = vendor
        if raw.get("os"):
            sets["os"] = raw["os"]
        if "ports" in raw and src == "netscan":
            merged = {p["port"]: p for p in json.loads(a["ports"])}
            merged.update({p["port"]: p for p in raw["ports"]})
            sets["ports"] = json.dumps(sorted(merged.values(), key=lambda p: p["port"]))
        if raw.get("mdns"):
            sets["mdns"] = json.dumps(sorted(set(json.loads(a["mdns"])) | set(raw["mdns"])))
        for k, v in sets.items():
            self.c.execute(f"update assets set {k}=? where asset_id=?", (v, aid))
        self.touch(aid, src, ts)
        self.match_declared(aid, ts)
        self.reclassify(aid)
        facts = [("mac", mac), ("ip", ip), ("hostname", host), ("dhcp_id", did), ("os", raw.get("os", ""))] + \
                [("open_port", f"{p['port']}/{p['proto']} {p.get('service', '')}".strip()) for p in raw.get("ports", [])] + \
                [("mdns", s) for s in raw.get("mdns", [])]
        self.c.executemany("insert into observations(ts,source,asset_id,fact,value,confidence) values (?,?,?,?,?,?)",
                           [(ts, src, aid, f, v, conf) for f, v in facts if v])
        a = self.asset(aid)
        self.event(ts, src, raw.get("kind", "scan_result"), aid, a["name"], ip, how or "new device",
                   {"mac": mac, "hostname": host, "matched_by": how or "new asset", "ports": [p["port"] for p in raw.get("ports", [])]})

    def flow(self, src, raw):
        ts, sip, dip, port = raw["ts"], raw["src_ip"], raw["dst_ip"], int(raw["port"])
        if not self.net_of(sip):
            return
        s = self.by_ip(sip, ts, "flow record")
        d = self.by_ip(dip, ts, "flow record") if self.net_of(dip) else "EXTERNAL"
        if self.one("select 1 x from net_blocks where src_asset=? and dst_asset=? and port=?", (s, d, port)):
            return
        row = self.one("select * from connections where src_asset=? and dst_asset=? and port=?", (s, d, port))
        if row:
            self.c.execute("update connections set count=count+1, bytes=bytes+?, last_seen=? where src_asset=? and dst_asset=? and port=?",
                           (raw["bytes"], ts, s, d, port))
        else:
            self.c.execute("insert into connections values (?,?,?,?,?,?,?,?)", (s, d, port, raw.get("proto", "tcp"), 1, raw["bytes"], ts, ts))
        self.touch(s, src, ts)
        if d != "EXTERNAL":
            self.touch(d, src, ts)
            da = self.asset(d)
            ls = json.loads(da["listens"])
            if port not in ls:
                self.c.execute("update assets set listens=? where asset_id=?", (json.dumps(sorted(ls + [port])), d))
                self.reclassify(d)
        sa = self.asset(s)
        self.event(ts, src, "flow", s, sa["name"], sip, f"{d}:{port}", {"dst": d, "dst_ip": dip, "port": port, "bytes": raw["bytes"]})


def ingest(pairs):
    """pairs: [(source, raw_record)] with source in netscan / netpassive / netflow. Identification runs before flows in the same second."""
    prio = {"netscan": 0, "netpassive": 1, "netflow": 2}
    pairs = sorted(pairs, key=lambda p: (p[1]["ts"], prio[p[0]]))
    c = db.get()
    try:
        r = Resolver(c)
        for src, raw in pairs:
            r.handle(src, raw)
        c.commit()
    finally:
        c.close()
    return len(pairs)
