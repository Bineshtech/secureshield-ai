"""Interactive NEXUS map: a small bidirectional Streamlit component (plain HTML canvas, no external libraries, works offline).
Python decides WHAT is on the map (nodes, edges, risk colours, which devices have an active alert); the browser keeps the picture
alive between the 2-second refreshes: it keeps dragged positions, animates devices that appear, and pulses a node while it has an
active alert. Clicking a node sends its id back to Python so the app can open the device card."""
import math
import os
from . import db, graph

COL_X, ROW_Y = 270, 100          # layout grid in map units (the browser fits the view to the window)
_component = None


def _declare():
    global _component
    if _component is None:
        import streamlit.components.v1 as components
        _component = components.declare_component("nexus_netmap", path=os.path.join(os.path.dirname(__file__), "netmap_frontend"))
    return _component


def _slots(assets):
    """Stable layout slot per device: column = subnet (ordered by VLAN), row = order of first appearance.
    New devices always take the next free row, so they never land on top of devices that are already drawn."""
    vlan = {n["name"]: n["vlan"] for n in db.q("select name, vlan from networks")}
    cols = sorted({a["subnet"] or "unplaced" for a in assets.values()}, key=lambda c: (vlan.get(c, 99), c))
    rows = {c: 0 for c in cols}
    pos = {}
    for a in sorted(assets.values(), key=lambda a: (a["first_seen"], a["asset_id"])):
        c = a["subnet"] or "unplaced"
        pos[a["asset_id"]] = (cols.index(c) * COL_X, rows[c] * ROW_Y)
        rows[c] += 1
    return cols, pos, rows


def build(sigs=None, path=None, selected=None, at=None, show=None, height=560):
    """Everything the browser needs, as plain JSON. Pure function of the database: easy to test."""
    full, _ = graph.load()
    vis_assets, vis_edges = graph.snapshot(at, show)
    risk = {r["asset_id"]: r for r in graph.risk_table(sigs)}
    cols, pos, rows = _slots(full)
    alerts = {}
    for s in sigs or []:
        alerts.setdefault(s["user"], []).append(s)

    nodes = []
    for aid, a in vis_assets.items():
        r = risk.get(aid, {"risk": 0})
        quarantined = a["status"] == "quarantined"
        sig = [] if quarantined else alerts.get(aid, [])
        unauth = not a["authorized"]
        fill = "#9aa0a6" if quarantined else "#d64545" if unauth else graph.COL(r["risk"])
        pulse = None
        if sig:
            pulse = "high" if unauth or any(s["impact"] >= 4 for s in sig) else "medium"
        x, y = pos.get(aid, (0, 0))
        kinds = sorted({s["kind"] for s in sig})
        nodes.append(dict(
            id=aid, label=a["name"], type=a["dtype"], x=x, y=y, fill=fill, border="#b000b0" if unauth else "#444",
            size={"critical": 26, "high": 22}.get(a["criticality"], 18), unauth=unauth, quarantined=quarantined, pulse=pulse, alerts=kinds,
            tip=dict(name=a["name"], ip=a["ip"], type=a["dtype"], conf=round(a["type_conf"] or 0, 2), role=a["role"], subnet=a["subnet"],
                     risk=r["risk"], auth=bool(a["authorized"]), owner=a["owner"], status=a["status"], alerts=kinds)))
    ext_x = len(cols) * COL_X
    if any(e["dst_asset"] == "EXTERNAL" for e in vis_edges):
        nodes.append(dict(id="EXTERNAL", label="Internet", type="external", x=ext_x, y=ROW_Y, fill="#cfd4da", border="#888", size=22, unauth=False,
                          quarantined=False, pulse=None, alerts=[],
                          tip=dict(name="Internet", ip="", type="external", conf=1, role="", subnet="Outside", risk=0, auth=True, owner="", status="active", alerts=[])))
    ids = {n["id"] for n in nodes}

    pair = {}
    for e in vis_edges:
        s, d = e["src_asset"], e["dst_asset"]
        if s in ids and d in ids and s != d:
            p = pair.setdefault((s, d), dict(bytes=0, count=0, ports=set()))
            p["bytes"] += e["bytes"]; p["count"] += e["count"]; p["ports"].add(e["port"])
    hl = set(zip(path, path[1:])) if path else set()
    names = {n["id"]: n["label"] for n in nodes}
    edges = []
    for (s, d), p in pair.items():
        red = (s, d) in hl
        edges.append(dict(id=f"{s}>{d}", src=s, dst=d, red=red, dashed=p["count"] <= 1, curved=(d, s) in pair,
                          width=round(1 + min(4, math.log10(p["bytes"] + 1) / 2) + (1.5 if red else 0), 1),
                          title=f"{names[s]} → {names[d]}", ports=", ".join(str(x) for x in sorted(p["ports"])), count=p["count"], bytes=p["bytes"]))

    height_units = max(rows.values() or [1]) * ROW_Y
    columns = [dict(label=c, x=i * COL_X, h=height_units) for i, c in enumerate(cols)]
    if "EXTERNAL" in ids:
        columns.append(dict(label="Outside", x=ext_x, h=height_units))
    return dict(nodes=nodes, edges=edges, columns=columns, selected=selected, height=height, colw=COL_X)


def render(key="nexus_map", height=560, **kw):
    """Draw the map. Returns {'node': asset_id, 'ts': ms} when the user clicks a node, otherwise None."""
    return _declare()(key=key, default=None, **build(height=height, **kw))
