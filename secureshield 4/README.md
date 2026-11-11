# SecureShield AI: live prototype

A security agent that connects logs from many tools, checks its own blind spots, explains incidents with cited
evidence, and asks a human before acting. The company and all logs are simulated.

**The app starts completely empty.** No logs exist until you switch on the live stream.

## Run on a Mac (Terminal)

    cd secureshield
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    streamlit run app.py

Optional, for the real Claude investigation agent: `export ANTHROPIC_API_KEY="sk-ant-..."` before starting, or paste
the key in the sidebar. Without a key everything works; reports use a built-in template writer.

If you used an earlier version, delete the old `secureshield.db` file. This version uses `secureshield_live.db`.

## How the live demo works

- Switch on **Live log stream**. Logs from 7 sources stream in (about 3 per second). Every tab recomputes every 2 seconds.
- **Inject an attack** with the sidebar buttons. Attacks unfold log by log in real time inside the normal traffic,
  so you watch severity climb and alerts fire.
- Alerts: toast pop-ups, red/yellow banners across the top, delivery routing (page / ticket / digest), and automatic
  escalation to a secondary on-call if nobody acknowledges within 60 seconds.
- Time is compressed for the demo: "a source is silent" means seconds, not hours.

## Demo script (about 5 minutes)

1. Open the app: empty, "Waiting for logs".
2. Switch on the stream. Event feed and source health fill in. Coverage score appears.
3. Wait about 90 seconds (builds the baseline), then click attack 1 (account takeover).
   Within about 20 seconds: medium, then high, then CRITICAL banner and toast. Open Incidents, run the AI investigation,
   approve "Revoke sessions", click "Verify the fix".
4. Click attack 2 (admin disables logging). A visibility-gap warning appears at once, then about 15 seconds later endpoint
   logs go silent and the incident turns critical. In Coverage auditor, "Retry connector" FAILS and explains why;
   approve "Re-enable audit logging", then verify.
5. Attack 3 (insider) and 4 (honeytoken). Insider risk tab shows why each score is what it is.
6. Threat hunt: "who queried the AI about salaries".
7. "Run full red-team test suite": all 8 scenarios detected, control run has zero false alarms.
8. Reset returns to empty with the stream off.

## Project map

    app.py              live dashboard (Streamlit fragment refreshing every 2 s)
    ss/simulator.py     empty start, live traffic, real-time attack scripts, faults
    ss/normalize.py     raw vendor logs -> one schema
    ss/auditor.py       coverage, freshness, volume drop, field drift, config posture, shadow AI, cause analysis
    ss/detect.py        rules, baselines, correlation into incidents, insider score, MITRE mapping
    ss/agent.py         Claude investigation agent, evidence validator, natural-language hunt
    ss/respond.py       auto / approve / human-only actions, verification
    ss/pipeline.py      live cycle, escalation, red-team suite
    test_smoke.py       self-test on a fast simulated clock (about 30 seconds)

## Honest scope

Real: normalization, detection rules, correlation, coverage auditor, tiered response and verification logic,
evidence validator, prompt-injection handling, Claude integration, alerting and escalation.
Simulated: the log sources (no real vendor connectors), the response actions (they change simulated data), and the
compressed timescale. Logs older than 40 minutes are discarded to keep the demo fast.
Not built (future scope): off-hours baselines, AI-agent governance inventory, real connectors, multi-tenant isolation.

---

# NEXUS: Network Asset Discovery and Mapping (added on top of SecureShield)

NEXUS finds every device, resolves each to one identity, draws a live map of connections, flags unknown devices and
odd behaviour, scores risk by what a device can reach, and hands incidents to the existing SecureShield agent,
validator and approval-gated response. Everything runs offline on one laptop with a scripted lab network.

## Run the demo

    streamlit run app.py

1. Sidebar: switch on **🌐 NEXUS network discovery**. The map fills with 7 lab devices, each with a type and confidence.
2. **Network coverage** tab: Guest Wi-Fi is reported as BLIND (no sensor, no approved scan); the IoT VLAN is passive only.
3. Click **Connect an unknown device**: a red `?` node appears and an alert fires. **Assets** tab > device card shows
   when it appeared, how it was identified, the evidence, and that it is not in the inventory.
4. Click **Unknown device probes the database**: `device_reaches_critical` and `internal_scan` fire, severity goes critical.
5. **Attack path** tab: unknown device → db-01 highlighted. **What-if** removes a device and recomputes what stays reachable.
6. Click **Camera contacts many outside addresses**: baseline rule fires; the report says it is unusual, not that it is hacked.
7. **Incidents** tab: run the AI investigation (cited evidence, validated). Approve **Quarantine device**, then **Verify the fix**
   (device quarantined, no new traffic observed, database no longer reachable).
8. Extras: **ARP spoof** scenario, **Phone rotates its MAC** (one asset kept, flagged for review), **Ask NEXUS** tab.

Tests: `python test_nexus.py` (NEXUS), `python test_smoke.py` (original SecureShield), or the sidebar button
**Run NEXUS network test suite** (every scenario + a control run that must raise nothing).

## New and changed files

| File | Role |
|---|---|
| `ss/netsim.py` | Lab network simulator, scripted scenarios, networks and declared devices seed |
| `ss/discovery.py` | Real Nmap XML parsing, rate-limited `nmap_scan`, Scapy `arp_sweep` / `passive_listen`, **scope guard** (`check_scope`) |
| `ss/resolve.py` | Entity resolution (MAC, DHCP id, hostname, IP lease), noisy-OR identification confidence with stored evidence |
| `ss/graph.py` | Connection graph, attack paths, what-if, context-aware risk, offline SVG map |
| `ss/netdetect.py` | Network rule kinds with MITRE references (`unknown_device`, `device_reaches_critical`, `new_external_destinations`, `segment_crossing`, `internal_scan`, `arp_anomaly`, `device_gone_silent`) |
| `ss/detect.py`, `auditor.py`, `agent.py`, `respond.py`, `pipeline.py`, `db.py`, `app.py` | Extended: network signals feed incidents; blind-subnet gaps; assistant query tools; approve / quarantine / block actions with verification; new tabs |

## Real discovery (owned or written-permission networks only)

    from ss import db, discovery
    discovery.nmap_scan("10.0.20.0/24")        # refused unless inside an approved, non-fragile range (max /22)
    discovery.passive_listen("en0", 30)        # ARP / DHCP / mDNS; sends nothing; needs root + scapy

Approved ranges live in the `networks` table. Scans are rate-limited (`--max-rate 100`, `-T3`).

## Honest limits

- Demo data is simulated: it shows the pipeline, not real-world accuracy. Detection weights are starting values.
- Identity can still fail: if an ARP packet with a never-seen random MAC arrives before the DHCP/hostname packet, a temporary
  duplicate asset is created (no merge step yet). Declared records match by hostname only.
- Attack paths show what a device could reach through observed connections, not proof of an attack. Path search is a
  plain breadth-first search (no NetworkX/Neo4j needed).
- Quarantine and block change simulated state only; real enforcement needs switch or firewall integration and policy.
- Built beyond Phase 2: **time-slider replay** and **map filters** (type, subnet, authorization, minimum risk, search) on the Live Map, with a device card for the selected node; duplicate assets from phone MAC rotation are **merged** (history kept, flagged for review); two more lab scenarios (lateral movement into the IoT VLAN, database going silent) so every detection rule has a test.
- Not built (Phase 3): SNMP/LLDP topology, cloud discovery, SIEM export, roles, digital-twin comparison. Map nodes are chosen with a selector, not clicked (the map is an embedded SVG image).
- Test: `python test_smoke.py && python test_nexus.py` (all pass); the sidebar buttons run the full red-team and NEXUS network suites.

## Interactive live map (NEXUS)
The Live Map tab and the Attack path tab use a clickable component (`ss/netmap.py` + `ss/netmap_frontend/index.html`, plain canvas, no external libraries, works offline).
- Drag nodes (positions survive the 2-second refresh; double-click or "Fit" resets), scroll to zoom, hover for a tooltip, click to open the device card.
- New devices pop in with a burst ring; an unknown device is a red `?` node with a banner; a device with an active alert pulses (red = high, amber = medium); new connections send a packet along the edge.
- "Classic static map (fallback)" toggle keeps the old SVG.
- Browser test: `pip install playwright && playwright install chromium && python browser_test/e2e_netmap.py` (replays frames recorded from the real pipeline into the component).
