"""NEXUS network intelligence: connection graph, attack paths, what-if isolation, context-aware risk, offline SVG map.
Pure Python (breadth-first search), so it runs offline with no graph database."""
import base64
import json
import math
from collections import deque
from . import db, resolve

CRIT_W = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


def load():
    assets = {a["asset_id"]: a for a in db.q("select * from assets")}
    edges = db.q("select * from connections")
    return assets, edges


def adjacency(assets, edges, remove_nodes=(), remove_edges=()):
    """Directed graph of observed connections. Quarantined devices and removed nodes/edges do not carry traffic."""
    gone = set(remove_nodes) | {k for k, a in assets.items() if a["status"] == "quarantined"}
    rm = {(s, d) for s, d in remove_edges}
    adj = {}
    for e in edges:
        s, d = e["src_asset"], e["dst_asset"]
        if s in gone or d in gone or (s, d) in rm or d == "EXTERNAL":
            continue
        adj.setdefault(s, set()).add(d)
    return adj


def reach(src, adj):
    """Everything reachable from src with the shortest path to each: {asset_id: [path]}."""
    paths, q = {src: [src]}, deque([src])
    while q:
        n = q.popleft()
        for m in sorted(adj.get(n, ())):
            if m not in paths:
                paths[m] = paths[n] + [m]
                q.append(m)
    return paths


def attack_paths(src, assets=None, edges=None, remove_nodes=(), remove_edges=()):
    """Potential routes from a (possibly compromised) device to assets tagged critical. Not proof of an attack."""
    if assets is None:
        assets, edges = load()
    if src in set(remove_nodes) or (src in assets and assets[src]["status"] == "quarantined"):
        return {}
    r = reach(src, adjacency(assets, edges, remove_nodes, remove_edges))
    return {k: v for k, v in r.items() if k != src and k in assets and assets[k]["criticality"] == "critical"}


def what_if(src, remove_nodes=(), remove_edges=()):
    """Which critical assets stay reachable from src before and after removing a node or edge (e.g. isolating a device)."""
    assets, edges = load()
    before, after = attack_paths(src, assets, edges), attack_paths(src, assets, edges, remove_nodes, remove_edges)
    return dict(before=before, after=after, cut=sorted(set(before) - set(after)))


def reachable_from(src):
    assets, edges = load()
    return {k: v for k, v in reach(src, adjacency(assets, edges)).items() if k != src}


def who_can_reach(target):
    assets, edges = load()
    adj = adjacency(assets, edges)
    return sorted(s for s in assets if s != target and target in reach(s, adj))


def risk_table(sigs=None):
    """risk = exposure x criticality of reachable assets x evidence confidence, each factor shown (0-10)."""
    assets, edges = load()
    adj = adjacency(assets, edges)
    nsig = {}
    for s in sigs or []:
        nsig[s["user"]] = nsig.get(s["user"], 0) + 1
    rows = []
    for aid, a in assets.items():
        ports = json.loads(a["ports"])
        risky = sum(1 for p in ports if p["port"] in resolve.RISKY_PORTS)
        exposure = min(1.0, 0.15 + 0.04 * len(ports) + 0.08 * risky + (0.35 if not a["authorized"] else 0) + 0.2 * min(2, nsig.get(aid, 0)))
        r = reach(aid, adj) if a["status"] != "quarantined" else {aid: [aid]}
        crit = max([CRIT_W.get(assets[k]["criticality"], 0.1) for k in r if k in assets] or [0.1])
        conf = 0.5 + 0.5 * (a["type_conf"] or 0)
        rows.append(dict(asset_id=aid, name=a["name"], exposure=round(exposure, 2), reach_criticality=crit, confidence=round(conf, 2),
                         risk=round(10 * exposure * crit * conf, 1), reaches=len(r) - 1,
                         critical_reachable=sorted(k for k in r if k != aid and k in assets and assets[k]["criticality"] == "critical")))
    return sorted(rows, key=lambda r: -r["risk"])


COL = lambda r: "#d64545" if r >= 5 else "#e8a33d" if r >= 2.5 else "#3a9d5d"


def snapshot(at=None, show=None):
    """The map as it was at time `at` (ISO string; None = now): only assets and connections first seen by then.
    `show` optionally limits it to a set of asset ids. Status flags (quarantine) are current, not historical."""
    assets, edges = load()
    if at:
        assets = {k: a for k, a in assets.items() if a["first_seen"] <= at}
        edges = [e for e in edges if e["first_seen"] <= at]
    if show is not None:
        assets = {k: a for k, a in assets.items() if k in show}
    return assets, edges


def svg(sigs=None, path=None, selected=None, width=960, height=520, at=None, show=None):
    """Offline SVG map: shape by type, colour by risk, dashed magenta outline = unauthorized, size = criticality,
    edge width = traffic volume, dashed edge = seen only once, red edge = highlighted attack path."""
    assets, edges = snapshot(at, show)
    risk = {r["asset_id"]: r for r in risk_table(sigs)}
    cols = {}
    for a in sorted(assets.values(), key=lambda a: (a["subnet"] or "~")):
        cols.setdefault(a["subnet"] or "unplaced", []).append(a)
    vlan = {n["name"]: n["vlan"] for n in db.q("select name, vlan from networks")}
    order = sorted(cols, key=lambda c: vlan.get(c, 99))
    pos, ncols = {}, len(order) + 1
    for ci, c in enumerate(order):
        n = len(cols[c])
        for i, a in enumerate(cols[c]):
            pos[a["asset_id"]] = (90 + ci * (width - 180) / max(1, ncols - 1), 70 + (i + .5) * (height - 110) / n)
    pos["EXTERNAL"] = (width - 90, height / 2)
    hl = set(zip(path, path[1:])) if path else set()
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" font-family="Helvetica,Arial,sans-serif">',
         '<defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#888"/></marker>'
         '<marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#d64545"/></marker></defs>',
         f'<rect width="{width}" height="{height}" fill="#fafafa" rx="8"/>']
    for ci, c in enumerate(order):
        x = 90 + ci * (width - 180) / max(1, ncols - 1)
        o.append(f'<text x="{x}" y="24" text-anchor="middle" font-size="13" fill="#555" font-weight="bold">{c}</text>')
    o.append(f'<text x="{width - 90}" y="24" text-anchor="middle" font-size="13" fill="#555" font-weight="bold">Outside</text>')
    pair = {}
    for e in edges:
        if e["src_asset"] in pos and e["dst_asset"] in pos and e["src_asset"] != e["dst_asset"]:
            p = pair.setdefault((e["src_asset"], e["dst_asset"]), dict(bytes=0, count=0, ports=[]))
            p["bytes"] += e["bytes"]; p["count"] += e["count"]; p["ports"].append(e["port"])
    for (s, d), p in pair.items():
        (x1, y1), (x2, y2) = pos[s], pos[d]
        dx, dy = x2 - x1, y2 - y1
        L = math.hypot(dx, dy) or 1
        ox, oy = -dy / L * 5 * (1 if (d, s) in pair and s > d else 0), dx / L * 5 * (1 if (d, s) in pair and s > d else 0)
        sh = 24 / L
        a1, b1, a2, b2 = x1 + dx * sh + ox, y1 + dy * sh + oy, x2 - dx * sh + ox, y2 - dy * sh + oy
        red = (s, d) in hl
        w = 1 + min(4, math.log10(p["bytes"] + 1) / 2) + (1.5 if red else 0)
        o.append(f'<line x1="{a1:.0f}" y1="{b1:.0f}" x2="{a2:.0f}" y2="{b2:.0f}" stroke="{"#d64545" if red else "#999"}" stroke-width="{w:.1f}" '
                 f'{"stroke-dasharray=\"5 4\" " if p["count"] <= 1 else ""}opacity="{1 if red else .6}" marker-end="url(#{"ah" if red else "ar"})"><title>{s} to {d} ports {sorted(set(p["ports"]))}, {p["count"]} flows, {p["bytes"]} bytes</title></line>')
    for aid, (x, y) in pos.items():
        if aid == "EXTERNAL":
            o.append(f'<circle cx="{x}" cy="{y}" r="22" fill="#eee" stroke="#999"/><text x="{x}" y="{y + 4}" text-anchor="middle" font-size="11">Internet</text>')
            continue
        a, r = assets[aid], risk[aid]
        sz = {"critical": 24, "high": 20}.get(a["criticality"], 16)
        stroke, dash = ("#b000b0", ' stroke-dasharray="4 3"') if not a["authorized"] else ("#333", "")
        fill = "#bbb" if a["status"] == "quarantined" else COL(r["risk"])
        sw = 4 if aid == selected else 2
        t = a["dtype"]
        if t == "server":
            shape = f'<rect x="{x - sz}" y="{y - sz * .8}" width="{2 * sz}" height="{1.6 * sz}" rx="4"'
        elif t == "network":
            shape = f'<polygon points="{x},{y - sz * 1.2} {x + sz * 1.2},{y} {x},{y + sz * 1.2} {x - sz * 1.2},{y}"'
        elif t == "iot":
            shape = f'<polygon points="{x},{y - sz} {x + sz},{y + sz * .8} {x - sz},{y + sz * .8}"'
        elif t == "mobile":
            shape = f'<rect x="{x - sz * .6}" y="{y - sz}" width="{sz * 1.2}" height="{2 * sz}" rx="6"'
        else:
            shape = f'<circle cx="{x}" cy="{y}" r="{sz}"'
        tip = f'{a["name"]} | {a["dtype"]} {a["type_conf"]:.0%} | risk {r["risk"]} | {"authorized" if a["authorized"] else "UNAUTHORIZED"} | {a["status"]}'
        o.append(f'<g>{shape} fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{dash}/><title>{tip}</title></g>')
        o.append(f'<text x="{x}" y="{y + sz + 16}" text-anchor="middle" font-size="11" fill="#222">{a["name"]}{" ✖" if a["status"] == "quarantined" else ""}</text>')
        if not a["authorized"]:
            o.append(f'<text x="{x}" y="{y + 4}" text-anchor="middle" font-size="13" font-weight="bold" fill="white">?</text>')
    o.append('<g font-size="10" fill="#444"><text x="12" y="%d">shape = type | colour = risk (green/amber/red) | dashed magenta outline + ? = unauthorized | '
             'edge width = traffic | dashed edge = seen once | red = attack path | grey ✖ = quarantined</text></g></svg>' % (height - 10))
    return "".join(o)


def svg_data_uri(**kw):
    return "data:image/svg+xml;base64," + base64.b64encode(svg(**kw).encode()).decode()
