"""Self-test of the live engine on a simulated fast clock: python test_smoke.py"""
import os, random, tempfile, time
os.environ["SS_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
from ss import db, simulator, pipeline, agent, respond, auditor

simulator.reset_empty()
assert db.q("select count(*) n from events")[0]["n"] == 0, "must start with no logs"
pipeline.analyze(); st = pipeline.state(); assert not st["incidents"] and not [g for g in st["gaps"]], "nothing to report before any logs"
print("starts empty: 0 events, 0 incidents, 0 gaps")

t = time.time()
for r in pipeline.redteam():
    print(r["result"].ljust(24), r["scenario"], "| incidents:", r["incidents raised"])
    assert r["result"] in ("DETECTED", "NO FALSE ALARMS"), r
print(f"red-team suite took {time.time() - t:.0f}s\n")

def run(rng, secs, every=2):
    for i in range(secs):
        db.OFFSET += 1; simulator.tick(rng)
        if i % every == 0: pipeline.live_cycle(rng) if False else (pipeline.analyze(), pipeline.escalate())

db.OFFSET = 0; rng = random.Random(3)
# soak: 15 simulated minutes of normal traffic must raise nothing
simulator.reset_empty(); run(rng, 900, every=5); pipeline.analyze()
st = pipeline.state()
bad = [g for g in st["gaps"] if g["status"] == "open" and g["kind"] != "coverage_ratio"]
assert not st["incidents"] and not bad, (st["incidents"], bad)
print("soak: 15 simulated minutes,", db.q("select count(*) n from events")[0]["n"], "events kept, 0 false alarms")

# tamper flow with fix + verification
simulator.reset_empty(); db.OFFSET = 0; run(rng, 100, 10); simulator.run_scenario("tamper_silence"); run(rng, 40)
inc = pipeline.state()["incidents"][0]; print("\n", inc["title"], inc["severity"], inc["confidence"])
rep = agent.investigate(inc["id"]); print("report:", rep["mode"], "validator passed:", rep["validator"]["passed"])
print(respond.execute("retry_connector", "endpoint")[1])
print(respond.execute("reenable_audit_logging", "endpoint-connector", "tester", inc["id"])[1])
ok, checks = respond.verify_incident(inc["id"]); print(ok, checks); assert ok

# takeover flow: severity must climb while the attack unfolds
simulator.reset_empty(); db.OFFSET = 0; run(rng, 100, 10); simulator.run_scenario("account_takeover")
sev = []
for _ in range(16):
    run(rng, 2, 1); i = pipeline.state()["incidents"]; sev.append(i[0]["severity"] if i else 0)
print("\ntakeover severity over time:", sev); assert sev[-1] >= 8 and sev[0] < sev[-1]
inc = pipeline.state()["incidents"][0]; print(inc["title"], inc["severity"], inc["route"])
respond.execute("revoke_session", "meena", "tester", inc["id"]); run(rng, 20)
ok, checks = respond.verify_incident(inc["id"]); print(ok, checks); assert ok
print(agent.hunt("who queried the AI about salaries this week?")[0])
n = [a["result"] for a in db.q("select result from actions where action='notify'")]; print("alerts sent:", n)
print("ALL GOOD")
