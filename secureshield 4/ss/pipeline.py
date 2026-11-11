import random
from . import db, auditor, detect, simulator, netsim


def analyze():
    gaps = auditor.run()
    detect.run(gaps)


def escalate(after_seconds=60):
    """No human acknowledged a high-severity incident in time: page the secondary contact."""
    now = db.utcnow()
    for i in db.q("select * from incidents where acked_at is null and escalated=0 and severity>=6 and status='open'"):
        if (now - db.parse(i["created"])).total_seconds() > after_seconds:
            db.ex("update incidents set escalated=1 where id=?", (i["id"],))
            db.ex("insert into actions(ts,ref,action,target,tier,approved_by,status,result) values (?,?,?,?,?,?,?,?)",
                  (db.iso(now), i["id"], "escalate", "secondary on-call", "auto", "system", "done",
                   f"No acknowledgment after {after_seconds}s: paged secondary contact"))


def live_cycle(rng=None):
    """One heartbeat of the live system: new logs arrive, everything is re-analyzed, unacknowledged incidents escalate."""
    n = simulator.tick(rng)
    analyze()
    escalate()
    return n


def net_cycle(rng=None):
    """One heartbeat of NEXUS: sensors report, assets are resolved, everything is re-analyzed."""
    n = netsim.tick(rng)
    analyze()
    escalate()
    return n


def state():
    gaps = db.q("select * from gaps order by created, id")
    sigs = detect.collect([g for g in gaps if g["status"] == "open"])
    return dict(gaps=gaps, signals=sigs, incidents=db.q("select * from incidents order by severity desc, created desc"),
                insiders=detect.insider_scores(sigs))


def _run(rng, seconds, every):
    for i in range(seconds):
        db.OFFSET += 1
        simulator.tick(rng)
        if i % every == 0:
            analyze()
            escalate()


def redteam():
    """Run every scenario on a throwaway database with a fast simulated clock, and check it was caught.
    The control run has no attack and must raise nothing."""
    orig_path, orig_off = db.DB_PATH, db.OFFSET
    db.DB_PATH = orig_path.replace(".db", "_redteam.db")
    out = []
    try:
        for name, sc in simulator.SCENARIOS.items():
            simulator.reset_empty()
            db.OFFSET, rng = 0, random.Random(7)
            _run(rng, 100, 10)
            simulator.run_scenario(name)
            _run(rng, 60, 2)
            st = state()
            found = {s["kind"] for s in st["signals"]} | {g["kind"] for g in st["gaps"] if g["status"] == "open"}
            miss = [k for k in sc["expect"] if k not in found]
            out.append({"scenario": sc["label"], "expected detections": ", ".join(sc["expect"]),
                        "result": "DETECTED" if not miss else "MISSED: " + ", ".join(miss), "incidents raised": len(st["incidents"])})
        simulator.reset_empty()
        db.OFFSET, rng = 0, random.Random(7)
        _run(rng, 160, 2)
        st = state()
        alarms = len(st["incidents"]) + len([g for g in st["gaps"] if g["status"] == "open" and g["kind"] != "coverage_ratio"])
        out.append({"scenario": "Control: normal traffic, no attack", "expected detections": "nothing",
                    "result": "NO FALSE ALARMS" if not alarms else f"FALSE ALARMS: {alarms}", "incidents raised": len(st["incidents"])})
    finally:
        db.DB_PATH, db.OFFSET = orig_path, orig_off
    return out


def _run_net(rng, seconds, every=2):
    for i in range(seconds):
        db.OFFSET += 1
        netsim.tick(rng)
        if i % every == 0:
            analyze()


def net_redteam():
    """Run every network scenario on a throwaway database with a fast simulated clock. The control run raises nothing."""
    orig_path, orig_off = db.DB_PATH, db.OFFSET
    db.DB_PATH = orig_path.replace(".db", "_netredteam.db")
    out = []
    try:
        for name, sc in netsim.SCENARIOS.items():
            simulator.reset_empty()
            db.OFFSET, rng = 0, random.Random(7)
            netsim.start(rng)
            _run_net(rng, 20, 10)
            n0 = db.q("select count(*) n from assets")[0]["n"]
            netsim.run_scenario(name)
            _run_net(rng, sc.get("secs", 45))
            st = state()
            found = {s["kind"] for s in st["signals"]}
            miss = [k for k in sc["expect"] if k not in found]
            extra = ""
            if name == "phone_mac_rotate":
                n1, rev = db.q("select count(*) n from assets")[0]["n"], db.q("select count(*) n from assets where needs_review=1")[0]["n"]
                if n1 != n0 or not rev:
                    miss = ["one device kept as one asset and flagged for review"]
                extra = f" (assets {n0} -> {n1}, flagged for review: {rev})"
            out.append({"scenario": sc["label"], "expected detections": ", ".join(sc["expect"]) or "same asset kept, flagged for review",
                        "result": ("DETECTED" if not miss else "MISSED: " + ", ".join(miss)) + extra, "incidents raised": len(st["incidents"])})
        simulator.reset_empty()
        db.OFFSET, rng = 0, random.Random(7)
        netsim.start(rng)
        _run_net(rng, 240)
        st = state()
        out.append({"scenario": "Control: normal network traffic, no attack", "expected detections": "nothing",
                    "result": "NO FALSE ALARMS" if not st["incidents"] and not st["signals"] else f"FALSE ALARMS: {len(st['signals'])} signals",
                    "incidents raised": len(st["incidents"])})
    finally:
        db.DB_PATH, db.OFFSET = orig_path, orig_off
    return out
