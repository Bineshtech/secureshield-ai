import json
import os
import random
from collections import Counter
from datetime import timedelta
import pandas as pd
import streamlit as st
from ss import agent, auditor, db, detect, graph, netmap, netsim, pipeline, resolve, respond, simulator

st.set_page_config(page_title="SecureShield AI", page_icon="🛡️", layout="wide")

if not db.q("select 1 from users limit 1"):
    simulator.reset_empty()          # company config only: NO logs exist until the stream is switched on
for k, v in (("net_path", None), ("verify", {}), ("msg", None), ("seen", {}), ("seen_gaps", set()), ("rng", random.Random())):
    st.session_state.setdefault(k, v)

LEVELS = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}


def level(sev):
    return 3 if sev >= 8 else 2 if sev >= 6 else 1 if sev >= 3 else 0


def refresh():
    try:
        st.rerun(scope="fragment")
    except st.errors.StreamlitAPIException:
        st.rerun()


# ------------------------------------------------------------------ sidebar (static controls)
with st.sidebar:
    st.title("🛡️ SecureShield AI")
    key = st.text_input("Anthropic API key (optional)", type="password", value=os.environ.get("ANTHROPIC_API_KEY", ""))
    if key:
        os.environ["ANTHROPIC_API_KEY"] = key
    st.caption("Claude investigation agent: ON" if agent.have_llm() else "Template mode (no API key). Everything works; reports use the built-in writer.")
    st.divider()
    live = st.toggle("🔴 Live log stream", key="live",
                     help="Starts the simulated company. Logs stream in about 3 per second and every feature updates from them.")
    st.caption("No logs exist until you switch this on.")
    def do_reset():
        simulator.reset_empty()
        st.session_state.update(live=False, net_live=False, net_path=None, verify={}, seen={}, seen_gaps=set(), msg="Reset. Stream is off and no logs exist.")
        st.session_state.pop("rt", None)

    st.toggle("🌐 NEXUS network discovery", key="net_live",
              help="Switches on the lab network: initial sweep of approved ranges, passive listening, flow records, live map.")
    st.caption("NEXUS finds devices and connections. No devices exist until you switch this on.")
    st.button("🗑️ Reset (stream off, no logs)", width="stretch", on_click=do_reset)
    st.divider()
    st.subheader("Inject an attack")
    st.caption("Attacks unfold in real time inside the live traffic. Wait about 90 seconds after starting before injecting the volume-drop attack, so there is a baseline.")
    for name, sc in simulator.SCENARIOS.items():
        if st.button(sc["label"], key=f"sc_{name}", width="stretch", disabled=not live):
            simulator.run_scenario(name)
            st.session_state["msg"] = f"Attack started: {sc['label']}. Watch the alerts."
    st.divider()
    st.subheader("NEXUS lab scenarios")
    for name, sc in netsim.SCENARIOS.items():
        if st.button(sc["label"], key=f"ns_{name}", width="stretch", disabled=not st.session_state.get("net_live")):
            netsim.run_scenario(name)
            st.session_state["msg"] = f"Network scenario started: {sc['label']}. Watch the map."
    st.divider()
    if st.button("🧪 Run NEXUS network test suite", width="stretch"):
        with st.spinner("Running network scenarios on a fast simulated clock (separate database)..."):
            st.session_state["nrt"] = pipeline.net_redteam()
    if st.button("🧪 Run full red-team test suite", width="stretch"):
        with st.spinner("Running all scenarios on a fast simulated clock (separate database)..."):
            st.session_state["rt"] = pipeline.redteam()


# ------------------------------------------------------------------ alerts
def alerts(incs, open_gaps):
    seen = st.session_state["seen"]
    toasts = []
    for i in incs:
        lv = level(i["severity"])
        if i["status"] == "open" and lv >= 2 and lv > seen.get(i["id"], 0):
            toasts.append(("🚨" if lv == 3 else "⚠️", f"{LEVELS[lv]} THREAT: {i['title']} (severity {i['severity']}/10)"))
        seen[i["id"]] = max(seen.get(i["id"], 0), lv)
    for g in open_gaps:
        if g["severity"] >= 3 and g["id"] not in st.session_state["seen_gaps"]:
            toasts.append(("🕳️", f"Visibility gap: {g['detail']}"))
            st.session_state["seen_gaps"].add(g["id"])
    for icon, text in toasts[:3]:
        st.toast(text, icon=icon)
    hot = [i for i in incs if i["status"] == "open" and i["severity"] >= 6]
    for i in sorted(hot, key=lambda x: -x["severity"])[:3]:
        lv = level(i["severity"])
        tag = "  📟 ESCALATED to secondary on-call" if i["escalated"] else ("  ✅ acknowledged" if i["acked_at"] else "")
        (st.error if lv == 3 else st.warning)(
            f"**{'🚨' if lv == 3 else '⚠️'} {LEVELS[lv]} THREAT  |  {i['title']}**  \nSeverity {i['severity']}/10, confidence {i['confidence']:.0%}. "
            f"Delivered via: {i['route']}.{tag}  Open the **Incidents** tab to investigate and respond.")
    for g in [g for g in open_gaps if g["severity"] >= 4][:2]:
        st.warning(f"**🕳️ VISIBILITY GAP  |  {g['kind'].replace('_', ' ').upper()}**  \n{g['detail']}  See the **Coverage auditor** tab.")


def graph_dot(inc):
    ids = [e for e in json.loads(inc["evidence"]) if e.startswith("EV-")]
    evs = db.q(f"select * from events where id in ({','.join('?' * len(ids))})", ids) if ids else []
    edges, u = Counter(), inc["user"]
    for e in evs:
        if e["device"]:
            edges[(u, "dev:" + e["device"], "uses")] += 1
        if e["ip"]:
            edges[(u, "ip:" + e["ip"], "from")] += 1
            if e["country"]:
                edges[("ip:" + e["ip"], "geo:" + e["country"], "")] += 1
        if e["category"] in ("file", "repo"):
            edges[(u, "res:" + e["resource"], e["action"])] += 1
        if e["category"] == "ai_prompt":
            edges[(u, "ai:" + e["resource"], "prompts")] += 1
    colors = {"dev": "#cfe8ff", "ip": "#ffe3b3", "geo": "#ffc9c9", "res": "#d7f5d0", "ai": "#e6d4ff"}
    lines = ["digraph G { rankdir=LR; node [shape=box, style=filled, fontname=Helvetica, fontsize=10]; edge [fontsize=9];",
             f'"{u}" [fillcolor="#ffffff", shape=ellipse, penwidth=2];']
    for (a, b, lab), n in list(edges.items())[:30]:
        for node in (a, b):
            if node != u:
                lines.append(f'"{node}" [label="{node.split(":", 1)[1]}", fillcolor="{colors[node.split(":", 1)[0]]}"];')
        lines.append(f'"{a}" -> "{b}" [label="{(lab + " x" + str(n)) if lab and n > 1 else lab}"];')
    return "\n".join(lines) + "}"


def render_actions(items, key, ref):
    for i, a in enumerate(items):
        cols = st.columns([4, 1])
        tier = {"auto": "🟢 AUTO", "approve": "🟡 NEEDS APPROVAL", "human": "🔴 HUMAN ONLY"}[a["tier"]]
        cols[0].markdown(f"**{respond.ACTIONS[a['action']][1]}** `{a['target']}`  \n{tier}: {a['reason']}")
        label = {"auto": "Run", "approve": "Approve & run", "human": "Hand to human"}[a["tier"]]
        if cols[1].button(label, key=f"{key}_{i}_{a['action']}"):
            status, result = respond.execute(a["action"], a["target"], "operator" if a["tier"] == "approve" else None, ref)
            st.session_state["msg"] = f"{respond.ACTIONS[a['action']][1]}: {status}. {result}"
            refresh()


def device_card(who):
    """Identity, evidence, owner, services, history and connections for one asset (used by the Live Map and Assets tabs)."""
    a = db.q("select * from assets where asset_id=?", (who,))[0]
    st.markdown(f"**{a['name']}**: {a['dtype']} / {a['role'] or 'role unknown'}, identification confidence **{a['type_conf']:.0%}**. "
               f"First seen {a['first_seen']}, last seen {a['last_seen']}. Declared: {'yes, owner ' + a['owner'] if a['declared'] else 'no (not in any inventory)'}.")
    c1, c2 = st.columns(2)
    with c1:
        st.caption("Evidence behind the type guess (noisy-OR; unused evidence supports a different type)")
        ev = resolve.evidence_table(a)
        st.dataframe(pd.DataFrame(ev), hide_index=True, width="stretch") if ev else st.caption("No evidence yet.")
        st.caption("Identifiers")
        st.dataframe(pd.DataFrame(db.q("select kind, value, first_seen, last_seen from identifiers where asset_id=?", (who,))), hide_index=True, width="stretch")
    with c2:
        st.caption("History (changes)")
        st.dataframe(pd.DataFrame(db.q("select ts, kind, old, new from changes where asset_id=? order by id desc limit 20", (who,))), hide_index=True, width="stretch")
        st.caption("Open services (observed by scan)")
        st.dataframe(pd.DataFrame(json.loads(a["ports"])), hide_index=True, width="stretch") if json.loads(a["ports"]) else st.caption("None observed.")
        st.caption("Connections")
        st.dataframe(pd.DataFrame(db.q("select src_asset, dst_asset, port, count, bytes from connections where src_asset=? or dst_asset=?", (who, who))), hide_index=True, width="stretch")


# ------------------------------------------------------------------ the live dashboard
@st.fragment(run_every=2 if (st.session_state.get("live") or st.session_state.get("net_live")) else None)
def dashboard():
    if st.session_state.get("net_live"):
        netsim.start(st.session_state["rng"])           # first switch-on: initial sweep + warm-up; afterwards just catches up
        netsim.tick(st.session_state["rng"])            # sensors report -> assets are resolved
    if st.session_state.get("live"):
        pipeline.live_cycle(st.session_state["rng"])    # new logs arrive -> everything is re-analyzed
    elif st.session_state.get("net_live"):
        pipeline.analyze()
        pipeline.escalate()
    S = pipeline.state()
    incs, gaps = S["incidents"], S["gaps"]
    open_gaps = [g for g in gaps if g["status"] == "open"]
    now = db.utcnow()
    total = db.q("select count(*) n from events where source not like 'net%'")[0]["n"]
    net_on = bool(db.meta_get("net_started"))
    last10 = db.q("select count(*) n from events where ts>?", (db.iso(now - timedelta(seconds=10)),))[0]["n"]

    if st.session_state["msg"]:
        st.success(st.session_state["msg"])
        st.session_state["msg"] = None
    st.title("SecureShield AI")
    st.caption(("🔴 LIVE" if st.session_state.get("live") else "⏸ STREAM OFF") +
               f"   |   {now.strftime('%H:%M:%S')} UTC   |   Simulated company. Detection windows are compressed to seconds for the demo.")
    if total == 0 and not net_on:
        st.info("**Waiting for logs.** Nothing has been generated yet. Switch on **🔴 Live log stream** in the sidebar and watch every tab fill from the incoming logs.")

    alerts(incs, open_gaps)

    open_incs = [i for i in incs if i["status"] == "open"]
    c = st.columns(6)
    c[0].metric("Events ingested", total)
    c[1].metric("Events / second", f"{last10 / 10:.1f}")
    c[2].metric("Coverage score", f"{auditor.coverage_score()}/100" if total else "-")
    if net_on:
        na = db.q("select count(*) n, sum(authorized=0) u, sum(status='quarantined') q from assets")[0]
        d = st.columns(4)
        d[0].metric("Devices on the map", na["n"])
        d[1].metric("Unknown (unauthorized)", na["u"] or 0)
        d[2].metric("Quarantined", na["q"] or 0)
        d[3].metric("Blind subnets", len([g for g in open_gaps if g["kind"] == "net_blind_subnet"]))
    c[3].metric("Threat level", LEVELS[level(max([i["severity"] for i in open_incs], default=0))] if open_incs else ("CLEAR" if total else "-"))
    c[4].metric("Open incidents", len(open_incs))
    c[5].metric("Open visibility gaps", len(open_gaps))

    tabs = st.tabs(["Overview", "Incidents", "Coverage auditor", "AI security", "Insider risk", "Threat hunt", "Compliance",
                    "🗺️ Live Map", "Assets", "Unknown devices", "Attack path", "Network coverage", "Ask NEXUS"])

    # ---------------- overview
    with tabs[0]:
        left, right = st.columns([3, 2])
        with left:
            st.subheader("Live event feed")
            st.dataframe(pd.DataFrame(db.q("select ts, source, user, action, status, resource from events order by ts desc limit 14")),
                         hide_index=True, width="stretch")
        with right:
            st.subheader("Log source health")
            st.dataframe(pd.DataFrame(auditor.source_health()), hide_index=True, width="stretch")
        if "nrt" in st.session_state:
            st.subheader("NEXUS network test results")
            st.dataframe(pd.DataFrame(st.session_state["nrt"]), hide_index=True, width="stretch")
        if "rt" in st.session_state:
            st.subheader("Red-team test results")
            st.dataframe(pd.DataFrame(st.session_state["rt"]), hide_index=True, width="stretch")
        st.subheader("Incidents")
        if incs:
            st.dataframe(pd.DataFrame([{"id": i["id"], "title": i["title"], "severity": i["severity"], "confidence": f"{i['confidence']:.0%}",
                                        "status": i["status"], "delivery": i["route"], "acknowledged": bool(i["acked_at"]),
                                        "escalated": bool(i["escalated"])} for i in incs]), hide_index=True, width="stretch")
        else:
            st.caption("No incidents.")
        st.subheader("Alert and action log")
        acts = db.q("select ts, ref, action, target, tier, approved_by, status, result from actions order by id desc limit 15")
        st.dataframe(pd.DataFrame(acts), hide_index=True, width="stretch") if acts else st.caption("Nothing yet.")

    # ---------------- incidents
    with tabs[1]:
        if not incs:
            st.info("No incidents. Inject an attack from the sidebar (try 1, 2 or 3) and watch it build here.")
        else:
            pick = st.selectbox("Incident", [i["id"] for i in incs],
                                format_func=lambda x: next(f"{i['id']}: {i['title']}  [{i['status']}, severity {i['severity']}]" for i in incs if i["id"] == x))
            inc = next(i for i in incs if i["id"] == pick)
            c = st.columns(5)
            c[0].metric("Severity", f"{inc['severity']}/10")
            c[1].metric("Confidence", f"{inc['confidence']:.0%}")
            c[2].metric("Impact", f"{inc['impact']}/10")
            c[3].metric("Urgency", f"{round(inc['severity'] * inc['confidence'], 1)}/10")
            c[4].metric("Status", inc["status"].upper())
            st.caption(f"Delivery: {inc['route']}   |   MITRE: {', '.join(json.loads(inc['mitre']))}")
            if not inc["acked_at"]:
                if st.button("✅ Acknowledge (stops escalation)", key="ack"):
                    db.ex("update incidents set acked_at=? where id=?", (db.iso(db.utcnow()), pick))
                    refresh()
            else:
                st.caption(f"Acknowledged at {inc['acked_at']}")
            left, right = st.columns([1, 1])
            with left:
                st.subheader("Why these signals were linked")
                st.dataframe(pd.DataFrame([{"signal": s["kind"], "weight": s["weight"], "what we saw": s["title"]} for s in json.loads(inc["signals"])]),
                             hide_index=True, width="stretch")
            with right:
                st.subheader("Entity graph")
                st.graphviz_chart(graph_dot(inc), width="stretch")
            st.subheader("Investigation report")
            if st.button("🧠 Run AI investigation", key="inv", type="primary"):
                with st.spinner("Agent is gathering evidence and writing the case..."):
                    agent.investigate(pick)
                refresh()
            if inc["report"]:
                rep, v = json.loads(inc["report"]), json.loads(inc["report"])["validator"]
                if len(json.loads(inc["evidence"])) > rep.get("evidence_count", 0):
                    st.warning("This incident has grown since the report was written. Run the AI investigation again to include the new evidence.")
                st.caption(f"Written by: {'Claude' if rep['mode'] == 'claude' else 'built-in template writer'}   |   "
                           f"Evidence validator: {'PASSED, every claim cites real evidence' if v['passed'] else 'FAILED'}")
                if v.get("llm_report_blocked"):
                    st.warning("The validator blocked the AI-written report and used the safe template instead: " + "; ".join(v["llm_report_blocked"]))
                st.markdown(f"**Summary.** {rep['summary']}")
                st.markdown(f"**Likely cause.** {rep['cause']}")
                st.markdown(f"**Impact.** {rep['impact']}")
                st.markdown(f"**What we cannot see.** {rep['visibility']}")
                st.markdown(f"**Confidence.** {rep['confidence_note']}")
                with st.expander("Findings with evidence IDs"):
                    for f in rep["findings"]:
                        st.markdown(f"- {f['claim']}  \n  `{', '.join(f['evidence'][:8])}{' ...' if len(f['evidence']) > 8 else ''}`")
                with st.expander("Timeline"):
                    if rep["timeline"]:
                        st.dataframe(pd.DataFrame(rep["timeline"]).drop(columns=["evidence"], errors="ignore"), hide_index=True, width="stretch")
                with st.expander("Verification plan"):
                    st.markdown("\n".join(f"- {x}" for x in rep["verification_plan"]))
            st.subheader("Recommended actions (the agent proposes, you decide)")
            render_actions(respond.recommend(inc), f"inc_{pick}", pick)
            if st.button("🔍 Verify the fix", key="ver"):
                st.session_state["verify"][pick] = respond.verify_incident(pick)
                refresh()
            if pick in st.session_state["verify"]:
                ok, checks = st.session_state["verify"][pick]
                (st.success if ok else st.warning)("Verified: incident resolved." if ok else "Not verified yet. Remaining checks:")
                for label, passed in checks:
                    st.markdown(f"{'✅' if passed else '❌'} {label}")
            mine = db.q("select ts, action, target, tier, approved_by, status, result from actions where ref=? order by id", (pick,))
            if mine:
                st.caption("Action log for this incident")
                st.dataframe(pd.DataFrame(mine), hide_index=True, width="stretch")

    # ---------------- coverage
    with tabs[2]:
        st.subheader("Can the agent see everything it should?")
        st.dataframe(pd.DataFrame(auditor.source_health()), hide_index=True, width="stretch")
        inv = pd.DataFrame(db.q("select device, owner, has_agent from inventory"))
        inv["has_agent"] = inv["has_agent"].map({1: "yes", 0: "NO"})
        with st.expander(f"Device inventory ({(inv['has_agent'] == 'NO').sum()} of {len(inv)} without endpoint agent)"):
            st.dataframe(inv, hide_index=True, width="stretch")
        st.subheader("Open gaps and what they hide")
        if not open_gaps:
            st.success("No visibility gaps." if total else "Waiting for logs.")
        for g in open_gaps:
            ex = auditor.explain(g)
            with st.expander(f"{g['id']}  {g['kind'].replace('_', ' ').upper()}: {g['detail']}", expanded=g["kind"] in ("stale_source", "config_posture", "volume_drop", "field_drift")):
                st.markdown(f"**Likely cause ({ex['confidence']:.0%} confidence).** {ex['cause']}")
                st.markdown(f"**Risk.** {ex['risk']}")
                if ex["blind"]:
                    st.markdown("**Detections that are blind right now:** " + ", ".join(ex["blind"]))
                render_actions(respond.recommend_gap(g, ex), f"gap_{g['id']}", g["id"])
                if st.button("🔍 Verify the fix", key=f"vg_{g['id']}"):
                    st.session_state["msg"] = respond.verify_gap(g["id"])[1]
                    refresh()
        done = [g for g in gaps if g["status"] == "resolved"]
        if done:
            st.caption("Resolved and verified: " + "; ".join(f"{g['kind']} {g['target']} at {g['resolved_at']}" for g in done))

    # ---------------- AI security
    with tabs[3]:
        st.subheader("AI usage and abuse")
        rows = []
        for e in db.q("select * from events where category='ai_prompt' order by ts desc"):
            p = json.loads(e["detail"])["prompt"]
            f = detect.classify_prompt(p)
            if f:
                rows.append({"time": e["ts"], "user": e["user"], "policy": e["status"], "flags": ", ".join(sorted(f)), "prompt (redacted)": detect.redact(p)})
        n_all = db.q("select count(*) n from events where category='ai_prompt'")[0]["n"]
        st.caption(f"{n_all} prompts seen so far. Layer 1 flags suspicious phrasing; layer 2 scores the SEQUENCE per user and links it to logins and downloads. "
                   "One refused request alone is only informational.")
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch") if rows else st.info("No suspicious prompts so far.")
        st.subheader("Shadow AI")
        sh = [g for g in open_gaps if g["kind"] == "shadow_ai"]
        if sh:
            for g in sh:
                who = Counter(e["user"] for e in db.q("select user from events where source='proxy' and resource=?", (g["target"],)))
                st.warning(g["detail"] + ". Users: " + ", ".join(f"{u} ({n})" for u, n in who.items()))
        else:
            st.success("No unsanctioned AI services seen.")
        st.caption("Prompt text is shown redacted. In a real deployment, prompt content sits in a restricted vault with logged, reason-based access.")

    # ---------------- insider
    with tabs[4]:
        st.subheader("Explainable insider and identity risk")
        st.caption("Weak signals accumulate and decay with a 24-hour half-life. A VPN alone barely moves the score. Humans decide on any action concerning a person.")
        ins = S["insiders"]
        if ins:
            df = pd.DataFrame([{"user": u, "risk score": d["score"]} for u, d in ins.items()]).sort_values("risk score", ascending=False)
            st.bar_chart(df.set_index("user"))
            who = st.selectbox("Why was this person scored?", df["user"])
            st.dataframe(pd.DataFrame([{"signal": k, "decayed points": v} for k, v in ins[who]["components"].items()]), hide_index=True, width="stretch")
        else:
            st.info("No risk signals for anyone right now.")

    # ---------------- hunt
    with tabs[5]:
        st.subheader("Ask in plain English")
        q = st.text_input("Question", key="hq_in", placeholder="who queried the AI about salaries?")
        cols = st.columns(3)
        for col, exq in zip(cols, ["who queried the AI about salaries", "who cloned repositories", "show downloads by meena"]):
            col.button(exq, key="hx_" + exq, on_click=lambda e=exq: st.session_state.__setitem__("hq_in", e))
        rerun = st.button("🔄 Search again with the newest logs", key="hq_btn")
        if q and (rerun or st.session_state.get("hq_last") != q):
            st.session_state["hq_res"], st.session_state["hq_last"] = agent.hunt(q), q
        if q and "hq_res" in st.session_state:
            ans, rows, flt = st.session_state["hq_res"]
            st.markdown(f"**{ans}**")
            st.caption(f"Search filter used: {flt}")
            if rows:
                st.dataframe(pd.DataFrame(rows)[["id", "ts", "source", "user", "action", "status", "resource", "detail"]], hide_index=True, width="stretch")

    # ---------------- compliance
    with tabs[6]:
        st.subheader("Executive summary and compliance evidence")
        acts = db.q("select * from actions where action not in ('notify') order by id")
        md = ["# SecureShield AI: Security Posture Report", f"Generated: {now.strftime('%Y-%m-%d %H:%M')} UTC (simulated data)", "",
              "## Executive summary", f"- Events analyzed: {total}", f"- Coverage score: **{auditor.coverage_score() if total else 'n/a'}/100**",
              f"- Incidents: {len(incs)} total, {len([i for i in incs if i['status'] == 'resolved'])} resolved and verified",
              f"- Open visibility gaps: {len(open_gaps)}", "", "## Incidents"]
        md += [f"- **{i['id']}** {i['title']} (severity {i['severity']}/10, confidence {i['confidence']:.0%}, status {i['status']})" for i in incs] or ["- None"]
        md += ["", "## Visibility gaps (stated openly)"] + ([f"- {g['kind']}: {g['detail']}" for g in open_gaps] or ["- None"])
        md += ["", "## Human oversight log"] + ([f"- {a['ts']} {a['action']} on {a['target']}: {a['status']} (tier {a['tier']}, approved by {a['approved_by'] or 'n/a'})" for a in acts] or ["- No actions taken"])
        md += ["", "## Privacy controls", "- Metadata first; prompt text is redacted and access-restricted", "- No automated action against any employee; humans decide",
               "- Scope: company-managed tools and accounts only", "- Legal review and employee notice are required before deployment (e.g. India DPDP Act)"]
        text = "\n".join(md)
        st.markdown(text)
        st.download_button("⬇️ Download report (.md)", text, file_name="secureshield_report.md")

    # ================================================================== NEXUS tabs
    sigs = S["signals"]
    nets_empty = "Switch on **🌐 NEXUS network discovery** in the sidebar. Nothing is on the map until discovery runs."
    # ---------------- live map
    with tabs[7]:
        if not net_on:
            st.info(nets_empty)
        else:
            st.subheader("Live network map")
            all_assets = db.q("select * from assets order by asset_id")
            assets_ = {a["asset_id"]: a for a in all_assets}
            risk_ = {r["asset_id"]: r["risk"] for r in graph.risk_table(sigs)}
            f1, f2, f3, f4, f5 = st.columns(5)
            ftype = f1.multiselect("Type", sorted({a["dtype"] for a in all_assets}), key="mf_type")
            fsub = f2.multiselect("Subnet", sorted({a["subnet"] for a in all_assets if a["subnet"]}), key="mf_sub")
            fauth = f3.selectbox("Authorization", ["all", "unknown only", "authorized only"], key="mf_auth")
            frisk = f4.slider("Minimum risk", 0.0, 10.0, 0.0, 0.5, key="mf_risk")
            fq = f5.text_input("Search name or IP", key="mf_q")
            show = {k for k, a in assets_.items()
                    if (not ftype or a["dtype"] in ftype) and (not fsub or a["subnet"] in fsub)
                    and (fauth == "all" or (fauth == "unknown only") == (not a["authorized"]))
                    and risk_.get(k, 0) >= frisk and (not fq or fq.lower() in f"{a['name']} {a['ip']}".lower())}
            moments = db.q("select ts, asset_id, kind from changes where kind in ('new_asset','quarantined','approved') order by id")
            labels = {}
            for m in moments:
                nm_ = assets_[m["asset_id"]]["name"] if m["asset_id"] in assets_ else m["asset_id"]
                labels[f"{m['ts'][11:19]}  {m['kind'].replace('_', ' ')}: {nm_}"] = m["ts"]
            keys = list(labels) + ["Live (now)"]
            at_label = st.select_slider("Replay: drag back to see the map as it was when each device appeared", options=keys, value="Live (now)", key="map_at")
            at = labels.get(at_label)
            sel_box, map_box = st.container(), st.container()      # the dropdown is shown above the map but created after the click is read
            cur = st.session_state.get("map_pick", "(none)")
            if cur not in assets_:
                cur = st.session_state["map_pick"] = "(none)"
            path = None
            if cur != "(none)" and not at:
                path = next(iter(graph.attack_paths(cur).values()), None)
            snap_assets, _ = graph.snapshot(at, show)
            if at:
                st.warning(f"Replaying the network as it was at {at}. Showing {len(snap_assets)} devices. Quarantine and approval flags shown are current, not historical.")
            with map_box:
                if st.toggle("Classic static map (fallback)", key="map_classic"):
                    st.markdown(f'<img src="{graph.svg_data_uri(sigs=sigs, path=path, selected=None if cur == "(none)" else cur, at=at, show=show)}" style="width:100%">',
                                unsafe_allow_html=True)
                    click = None
                else:
                    click = netmap.render(key="nexus_map", sigs=sigs, path=path, selected=None if cur == "(none)" else cur, at=at, show=show, height=560)
            if click and click.get("ts") != st.session_state.get("map_click_ts"):       # a node was clicked on the map -> open its device card
                st.session_state["map_click_ts"] = click["ts"]
                if click.get("node") in assets_ and click["node"] != cur:
                    st.session_state["map_pick"] = click["node"]
                    refresh()
            with sel_box:
                pick = st.selectbox("Selected device (click a node on the map, or choose here)", ["(none)"] + list(assets_), key="map_pick",
                                    format_func=lambda x: x if x == "(none)" else f"{assets_[x]['name']} ({assets_[x]['ip']})")
            st.caption(f"{len(snap_assets)} of {len(assets_)} devices shown. Drag nodes, scroll to zoom, hover for details, click to open the card. "
                       "New devices animate in; a pulsing ring marks a device with an active alert.")
            if pick != "(none)":
                st.markdown("#### Device card")
                device_card(pick)
    # ---------------- assets
    with tabs[8]:
        if not net_on:
            st.info(nets_empty)
        else:
            risk = {r["asset_id"]: r for r in graph.risk_table(sigs)}
            rows = [{"id": a["asset_id"], "name": a["name"], "ip": a["ip"], "type": a["dtype"], "role": a["role"], "confidence": f"{a['type_conf']:.0%}",
                     "authorized": "yes" if a["authorized"] else "NO", "owner": a["owner"], "criticality": a["criticality"], "subnet": a["subnet"],
                     "risk": risk[a["asset_id"]]["risk"], "seen by": ", ".join(json.loads(a["seen_by"])), "status": a["status"],
                     "review": "yes" if a["needs_review"] else ""} for a in db.q("select * from assets order by asset_id")]
            f1, f2, f3 = st.columns(3)
            ftype = f1.multiselect("Type", sorted({r["type"] for r in rows}))
            fsub = f2.multiselect("Subnet", sorted({r["subnet"] for r in rows}))
            fq = f3.text_input("Search name or IP")
            rows = [r for r in rows if (not ftype or r["type"] in ftype) and (not fsub or r["subnet"] in fsub) and (not fq or fq.lower() in f"{r['name']} {r['ip']}".lower())]
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
            if rows:
                who = st.selectbox("Device card", [r["id"] for r in rows], format_func=lambda x: next(f"{r['name']} ({r['ip']})" for r in rows if r["id"] == x))
                device_card(who)
    # ---------------- unknown devices
    with tabs[9]:
        if not net_on:
            st.info(nets_empty)
        else:
            unk = db.q("select * from assets where authorized=0 order by first_seen desc")
            if not unk:
                st.success("Every device on the map is authorized.")
            for a in unk:
                with st.expander(f"❓ {a['name']}  {a['ip']}  |  {a['dtype']} {a['type_conf']:.0%}  |  {a['status']}", expanded=a["status"] == "active"):
                    st.markdown(f"First seen {a['first_seen']} in **{a['subnet']}**, seen by {', '.join(json.loads(a['seen_by']))}. Vendor: {a['vendor'] or 'unknown'}. Not in the inventory.")
                    render_actions([dict(action="approve_device", tier="approve", target=a["asset_id"], reason="Only if you know this device"),
                                    dict(action="quarantine_device", tier="approve", target=a["asset_id"], reason="Cut it off while you investigate")], f"unk_{a['asset_id']}", a["asset_id"])
    # ---------------- attack path
    with tabs[10]:
        if not net_on:
            st.info(nets_empty)
        else:
            st.subheader("What could a compromised device reach?")
            assets_ = {a["asset_id"]: a for a in db.q("select * from assets")}
            src = st.selectbox("Start from", list(assets_), key="ap_src", format_func=lambda x: f"{assets_[x]['name']} ({assets_[x]['ip']})")
            ap = graph.attack_paths(src)
            if ap:
                for tgt, p in ap.items():
                    st.error(f"Potential path to critical asset: **{' → '.join(assets_[i]['name'] for i in p)}**")
                st.caption("A potential path shows what a compromised device could reach. It is not proof that anyone did.")
                tgt = next(iter(ap))
                cut = st.multiselect("What-if: isolate these devices", [i for i in assets_ if i != src], key="ap_cut", format_func=lambda x: assets_[x]["name"])
                if cut:
                    w = graph.what_if(src, remove_nodes=cut)
                    left = [assets_[k]["name"] for k in w["after"]]
                    (st.warning if left else st.success)("Still reachable: " + ", ".join(left) if left else "No critical asset stays reachable.")
                netmap.render(key="nexus_map_ap", sigs=sigs, path=ap[tgt], selected=src, height=460)
            else:
                st.success("No critical asset is reachable from this device through observed connections.")
            st.subheader("Context-aware risk (exposure × criticality of what it reaches × confidence)")
            st.dataframe(pd.DataFrame(graph.risk_table(sigs)).drop(columns=["asset_id"]), hide_index=True, width="stretch")
    # ---------------- network coverage
    with tabs[11]:
        if not net_on:
            st.info(nets_empty)
        else:
            st.subheader("What NEXUS cannot see")
            st.dataframe(pd.DataFrame(auditor.net_coverage()), hide_index=True, width="stretch")
            for g in [g for g in open_gaps if g["kind"] in ("net_blind_subnet", "net_passive_only")]:
                ex = auditor.explain(g)
                with st.expander(f"{g['kind'].replace('_', ' ').upper()}: {g['detail']}", expanded=g["kind"] == "net_blind_subnet"):
                    st.markdown(f"**Risk.** {ex['risk']}")
                    render_actions(respond.recommend_gap(g, ex), f"ng_{g['id']}", g["id"])
            single = db.q("select name, seen_by from assets")
            one = [x["name"] for x in single if len(json.loads(x["seen_by"])) == 1]
            if one:
                st.caption("Devices seen by only one source (lower confidence): " + ", ".join(one))
    # ---------------- ask nexus
    with tabs[12]:
        st.subheader("Ask about the network")
        st.caption("Answers come from fixed queries over stored data, so every answer points to real rows.")
        cols = st.columns(4)
        for col, exq in zip(cols, ["show all unknown devices", "which devices can reach db-01", "what changed today", "list all devices"]):
            col.button(exq, key="nx_" + exq, on_click=lambda e=exq: st.session_state.__setitem__("nq", e))
        nq = st.text_input("Question", key="nq")
        if nq:
            title, rows = agent.net_ask(nq)
            st.markdown(f"**{title}**")
            if rows:
                st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


dashboard()
