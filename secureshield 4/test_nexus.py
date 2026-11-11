"""NEXUS self-test: python test_nexus.py  (scope guard, Nmap parsing, resolution, detection, response, verification)"""
import os, random, tempfile
os.environ["SS_DB"] = os.path.join(tempfile.mkdtemp(), "n.db")
from ss import db, simulator, netsim, pipeline, discovery as d, graph, respond, agent

simulator.reset_empty(); db.OFFSET = 0
xml = '''<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.20.20" addrtype="ipv4"/><address addr="00:50:56:A1:00:20" addrtype="mac" vendor="VMware"/>
<hostnames><hostname name="db-01.corp" type="PTR"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="closed"/></port></ports><os><osmatch name="Linux 5.4"/></os></host><host><status state="down"/><address addr="10.0.20.99" addrtype="ipv4"/></host></nmaprun>'''
r = d.parse_nmap_xml(xml); assert len(r) == 1 and r[0]["hostname"] == "db-01" and r[0]["ports"] == [{"port": 22, "proto": "tcp", "service": "ssh"}], r
assert d.check_scope("10.0.20.0/25") == "10.0.20.0/25"
for bad in ["10.0.40.0/24", "192.168.1.0/24", "10.0.0.0/8", "10.0.30.0/24"]:
    try: d.check_scope(bad); raise SystemExit("scope guard let through " + bad)
    except d.ScopeError as e: print("REFUSED", bad)

rng = random.Random(3); netsim.start(rng)
a = db.q("select * from assets"); assert len(a) == 7 and all(x["authorized"] for x in a), "all 7 lab devices found and matched to declared records"
def run(n):
    for _ in range(n): db.OFFSET += 1; netsim.tick(rng); pipeline.analyze()
run(30); assert not pipeline.state()["incidents"], "normal traffic must raise nothing"
netsim.run_scenario("probe_database"); run(30)
inc = pipeline.state()["incidents"][0]; print(inc["title"], inc["severity"])
assert inc["severity"] >= 8 and "device_reaches_critical" in inc["signals"]
rogue = inc["user"]; assert graph.attack_paths(rogue), "attack path to db-01 expected"
rep = agent.investigate(inc["id"]); assert rep["validator"]["passed"]
assert respond.execute("quarantine_device", rogue)[0] == "blocked", "needs approval"
respond.execute("quarantine_device", rogue, "tester", inc["id"]); run(5)
ok, checks = respond.verify_incident(inc["id"]); print(checks); assert ok
assert not graph.what_if(rogue)["after"], "database must be unreachable after isolation"
print("NEXUS OK")

# ---- MAC rotation heard ARP-first must merge into one asset, flagged for review
from ss import resolve
simulator.reset_empty(); db.OFFSET = 0; rng = random.Random(3); netsim.start(rng)
n0 = db.q("select count(*) n from assets")[0]["n"]; ts = db.iso(db.utcnow()); new = "de:4b:77:20:31:09"
resolve.ingest([("netpassive", {"ts": ts, "kind": "arp", "ip": "10.0.10.57", "mac": new})])
resolve.ingest([("netpassive", {"ts": ts, "kind": "dhcp", "ip": "10.0.10.57", "mac": new, "hostname": "priyas-iphone", "dhcp_id": "01:priya-phone"})])
ph = db.q("select * from assets where name='priyas-iphone'")
assert db.q("select count(*) n from assets")[0]["n"] == n0 and len(ph) == 1 and ph[0]["needs_review"] == 1, "rotation must not create a duplicate"
print("MAC rotation merge OK")

# ---- replay: the map at an earlier moment excludes devices that appeared later
simulator.reset_empty(); db.OFFSET = 0; rng = random.Random(5); netsim.start(rng)
before = db.iso(db.utcnow())
for _ in range(3): db.OFFSET += 1; netsim.tick(rng)
netsim.run_scenario("connect_unknown")
for _ in range(10): db.OFFSET += 1; netsim.tick(rng); pipeline.analyze()
now_a, _ = graph.snapshot(); old_a, old_e = graph.snapshot(before)
assert len(now_a) == len(old_a) + 1, (len(now_a), len(old_a))
assert all(e["src_asset"] in old_a or e["src_asset"] == "EXTERNAL" for e in old_e)
assert "<svg" in graph.svg(at=before) and len(graph.snapshot(None, show=set())[0]) == 0
print("Replay + filter OK")

# ---- assistant routing: 'why' about an unknown device's own name must explain, not list unknowns
unk = db.q("select name from assets where authorized=0")[0]["name"]
title, rows = agent.net_ask(f"why was {unk} flagged")
assert title.startswith("Why"), title
print("Assistant routing OK")
