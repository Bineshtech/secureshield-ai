SecureShield AI + NEXUS

A simple AI security prototype. It collects logs from many tools, finds attacks, maps the devices on a network, explains what happened, and asks a human before taking action.

All logs, devices and attacks in the demo are simulated.

HOW it Works

Collects logs from 7 different sources and converts them into one format.
Checks itself to find blind spots, such as a tool that stopped sending logs.
Detects attacks (account takeover, insider threat, disabled logging, decoy file touched) and groups alerts into incidents.
Finds devices on the network, draws a live map, and flags unknown devices.
Explains incidents with evidence from the logs (AI-written reports using Claude, optional).
Responds safely: a human approves each action, then the app verifies the fix worked.

How we built it
Part	What we used
Language	Python
Dashboard	Streamlit
Storage	SQLite
AI reports	Claude API (optional, has a built-in fallback)
Network discovery	Nmap and Scapy (only on approved networks)
Live map	Plain HTML canvas, works offline

Flow: raw logs → normalize → detect and correlate → incident → AI explanation → human approval → response → verify
