"""NEXUS discovery layer. Real Nmap / Scapy discovery, restricted to ranges the administrator has approved.
Everything here produces the same raw records the lab simulator emits, so real and simulated sources share one pipeline."""
import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from . import db, resolve


class ScopeError(Exception):
    pass


MAX_ADDRS = 1024        # a /22


def approved_ranges():
    return [n for n in db.q("select * from networks where authorized=1 and active_scan=1 and fragile=0")]


def check_scope(target):
    """Refuse to actively scan anything that is not inside an approved, non-fragile range, or is too large."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise ScopeError(f"'{target}' is not a valid address range")
    ok = [ipaddress.ip_network(n["cidr"]) for n in approved_ranges()]
    listing = ", ".join(str(n) for n in ok) or "none"
    if net.num_addresses > MAX_ADDRS:
        raise ScopeError(f"{net} is larger than a /22 ({MAX_ADDRS} addresses). Split it into smaller approved ranges.")
    if not any(net.version == o.version and net.subnet_of(o) for o in ok):
        raise ScopeError(f"{net} is not inside an approved, actively scannable range. Approved: {listing}.")
    return str(net)


def parse_nmap_xml(xml):
    """Nmap -oX output -> scan records (hosts that are up). Only open ports are kept."""
    out = []
    for h in ET.fromstring(xml).findall("host"):
        if (h.find("status") is None) or h.find("status").get("state") != "up":
            continue
        rec = {"ip": "", "mac": "", "vendor": "", "hostname": "", "os": "", "ports": []}
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                rec["ip"] = a.get("addr")
            elif a.get("addrtype") == "mac":
                rec["mac"], rec["vendor"] = a.get("addr").lower(), a.get("vendor", "")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            rec["hostname"] = hn.get("name", "").split(".")[0]
        om = h.find("os/osmatch")
        if om is not None:
            rec["os"] = om.get("name", "")
        for p in h.findall("ports/port"):
            if p.find("state") is not None and p.find("state").get("state") == "open":
                s = p.find("service")
                rec["ports"].append({"port": int(p.get("portid")), "proto": p.get("protocol"), "service": s.get("name") if s is not None else ""})
        out.append(rec)
    return out


def nmap_scan(target, max_rate=100, timeout=300):
    """Rate-limited Nmap service detection of an approved range. Needs the nmap binary; raises ScopeError first if out of scope."""
    target = check_scope(target)
    if not shutil.which("nmap"):
        raise RuntimeError("nmap is not installed (apt install nmap / brew install nmap)")
    xml = subprocess.run(["nmap", "-sV", "-T3", "--max-rate", str(max_rate), "-oX", "-", target],
                         capture_output=True, text=True, timeout=timeout, check=True).stdout
    ts = db.iso(db.utcnow())
    recs = [dict(r, ts=ts) for r in parse_nmap_xml(xml)]
    ingest([("netscan", r) for r in recs])
    return recs


def arp_sweep(target, timeout=3):
    """ARP sweep of an approved local range using Scapy (needs root). Returns and ingests ip/mac pairs."""
    target = check_scope(target)
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        raise RuntimeError("scapy is not installed (pip install scapy)")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target), timeout=timeout, verbose=False)
    ts = db.iso(db.utcnow())
    recs = [{"ts": ts, "kind": "arp", "ip": r.psrc, "mac": r.hwsrc.lower()} for _, r in ans]
    ingest([("netpassive", r) for r in recs])
    return recs


def packet_to_record(pkt):
    """Scapy packet (ARP, DHCP or mDNS) -> passive record, or None. Passive listening sends nothing."""
    from scapy.all import ARP, BOOTP, DHCP, DNS, IP, Ether
    ts = db.iso(db.utcnow())
    if pkt.haslayer(ARP) and pkt[ARP].psrc not in ("0.0.0.0", ""):
        return {"ts": ts, "kind": "arp", "ip": pkt[ARP].psrc, "mac": pkt[ARP].hwsrc.lower()}
    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
        opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
        host = opts.get("hostname", b"")
        host = host.decode(errors="ignore") if isinstance(host, bytes) else str(host)
        return {"ts": ts, "kind": "dhcp", "ip": opts.get("requested_addr") or pkt[BOOTP].ciaddr, "mac": pkt[Ether].src.lower(),
                "hostname": host, "dhcp_id": str(opts["client_id"]) if opts.get("client_id") else ""}
    if pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt[IP].dst == "224.0.0.251":
        names = [bytes(a.rrname).decode(errors="ignore").rstrip(".") for a in (pkt[DNS].an or [])] if pkt[DNS].an else []
        return {"ts": ts, "kind": "mdns", "ip": pkt[IP].src, "mac": pkt[Ether].src.lower(),
                "hostname": next((n.split(".")[0] for n in names if n.endswith(".local")), ""), "mdns": [n for n in names if n.startswith("_")]}
    return None


def passive_listen(iface=None, seconds=30):
    """Sniff ARP / DHCP / mDNS on an interface you are allowed to monitor (needs root). Records are ingested as they are heard."""
    try:
        from scapy.all import sniff
    except ImportError:
        raise RuntimeError("scapy is not installed (pip install scapy)")
    recs = []

    def cb(p):
        r = packet_to_record(p)
        if r and r.get("ip"):
            recs.append(r)
    sniff(iface=iface, prn=cb, store=False, timeout=seconds, filter="arp or udp port 67 or udp port 68 or udp port 5353")
    ingest([("netpassive", r) for r in recs])
    return recs


def ingest(pairs):
    return resolve.ingest(pairs)
