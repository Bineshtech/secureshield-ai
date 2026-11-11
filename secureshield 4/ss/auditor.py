"""Self-monitoring: what SHOULD be reporting vs what IS. Deterministic checks, no AI needed."""
import hashlib
import json
import re
from datetime import timedelta
from . import db

DEPENDS = {"endpoint": ["malware/process detection", "verifying that a login comes from a known managed device"],
           "identity": ["login anomaly detection", "new-country and new-device detection"],
           "cloud": ["mass-download and external-share detection", "honeytoken alerts", "audit-change detection"],
           "ai_assistant": ["prompt-abuse and credential-extraction detection"],
           "devplatform": ["mass repository clone detection"],
           "vpn": ["anonymizer/VPN detection"], "proxy": ["shadow-AI discovery"]}
SANCTIONED_AI = {"corp-assistant.corp.example"}
AI_DOMAIN = re.compile(r"(gpt|llm|copilot|-ai|ai-|chatbot|chat\.)", re.I)


def _gid(kind, target):
    return "GAP-" + hashlib.md5(f"{kind}|{target}".encode()).hexdigest()[:6].upper()


def _log_checks(now):
    cur = []   # (kind, target, detail, since, severity)
    t20, t80, t60 = db.iso(now - timedelta(seconds=20)), db.iso(now - timedelta(seconds=80)), db.iso(now - timedelta(seconds=60))
    for s in db.q("select * from sources"):
        n, last = s["name"], s["last_seen"]
        if not last:
            continue    # source has not connected yet
        age = (now - db.parse(last)).total_seconds()
        if age > s["thresh_seconds"]:
            cur.append(("stale_source", n, f"{n} has sent no logs for {age:.0f}s (expected at least every {s['thresh_seconds']:.0f}s)", last, 4))
            continue
        recent = db.q("select count(*) c from events where source=? and ts>?", (n, t20))[0]["c"]
        first = db.q("select min(ts) m from events where source=?", (n,))[0]["m"]
        prev = db.q("select since from gaps where kind='volume_drop' and target=? and status='open'", (n,))
        end = db.parse(prev[0]["since"]) if prev else now - timedelta(seconds=20)   # baseline freezes while a drop is open
        span = min(300.0, (end - db.parse(first)).total_seconds()) if first else 0
        if span >= 40:      # need enough history; the baseline never learns from the outage itself
            base = db.q("select count(*) c from events where source=? and ts>? and ts<=?", (n, db.iso(end - timedelta(seconds=span)), db.iso(end)))[0]["c"]
            rr, rb = recent / 20, base / span
            if rb >= 0.1 and rr < 0.3 * rb:
                cur.append(("volume_drop", n, f"{n} log volume dropped {100 * (1 - rr / rb):.0f}% ({rr * 60:.0f}/min now vs {rb * 60:.0f}/min normally)", db.iso(end), 3))
        if n != "endpoint":
            e60 = db.q("select ts, user from events where source=? and ts>?", (n, t60))
            empties = [e for e in e60 if not e["user"]]
            if len(e60) >= 5 and len(empties) / len(e60) > 0.25:
                cur.append(("field_drift", n, f"{len(empties)} of {len(e60)} {n} events in the last minute have an empty user field (possible schema change)",
                            min(e["ts"] for e in empties), 3))
    # configuration posture: security controls turned off and never turned back on
    state = {}
    for e in db.q("select * from events where category='config' order by ts"):
        if e["action"] in ("audit_logging_disabled", "mfa_disabled"):
            state[e["resource"]] = e
        elif e["action"] in ("audit_logging_enabled", "mfa_reset"):
            state.pop(e["resource"], None)
    for res, e in state.items():
        cur.append(("config_posture", res, f"{e['action'].replace('_', ' ')} on {res} by {e['user']} at {e['ts']} and not re-enabled", e["ts"], 4))
    # endpoint coverage ratio
    inv = db.q("select * from inventory")
    missing = [d["device"] for d in inv if not d["has_agent"]]
    if missing:
        cur.append(("coverage_ratio", "endpoint-agent", f"{len(missing)} of {len(inv)} devices have no endpoint agent ({', '.join(missing)})", "", 2))
    # shadow AI
    blocked = {e["resource"] for e in db.q("select resource from events where action='domain_blocked'")}
    doms = {}
    for e in db.q("select user, resource from events where source='proxy'"):
        d = e["resource"]
        if d not in SANCTIONED_AI and d not in blocked and AI_DOMAIN.search(d):
            doms.setdefault(d, []).append(e["user"])
    for d, us in doms.items():
        if len(us) < 3:
            continue
        cur.append(("shadow_ai", d, f"{len(us)} requests from {len(set(us))} users to unsanctioned AI service {d}", "", 3))
    return cur


def net_checks(now):
    """NEXUS: say what the network sensors cannot see. Absence of evidence must not be read as safety."""
    if not db.meta_get("net_started"):
        return []
    cur = []
    for n in db.q("select * from networks"):
        if not n["passive_sensor"] and not n["active_scan"]:
            cur.append(("net_blind_subnet", n["cidr"], f"{n['name']} ({n['cidr']}) has no sensor and no approved scan: devices there cannot be seen", "", 4))
        elif not (n["active_scan"] and n["authorized"]) or n["fragile"]:
            cur.append(("net_passive_only", n["cidr"], f"{n['name']} ({n['cidr']}) is watched passively only (no active scans); silent devices may be missed", "", 1))
    return cur


def net_coverage():
    """Rows for the Network coverage tab: per subnet, what sees it, and how many devices were found there."""
    rows = []
    for n in db.q("select * from networks order by vlan"):
        cnt = db.q("select count(*) c from assets where subnet=?", (n["name"],))[0]["c"]
        how = [x for x, on in (("passive sensor", n["passive_sensor"]), ("approved active scan", n["active_scan"] and n["authorized"] and not n["fragile"])) if on]
        rows.append({"subnet": n["cidr"], "name": n["name"], "seen by": ", ".join(how) or "NOTHING", "devices found": cnt,
                     "status": "BLIND" if not how else "PARTIAL (passive only)" if len(how) == 1 else "OK", "note": n["notes"]})
    return rows


def run():
    now = db.utcnow()
    if not db.q("select 1 from events limit 1"):
        return db.q("select * from gaps order by created, id")     # nothing has streamed yet: nothing to audit
    cur = []
    if db.q("select 1 from events where source not like 'net%' limit 1"):
        cur += _log_checks(now)
    cur += net_checks(now)
    ids = set()
    for kind, target, detail, since, sev in cur:
        gid = _gid(kind, target)
        ids.add(gid)
        if db.q("select 1 from gaps where id=?", (gid,)):
            was = db.q("select status, since from gaps where id=?", (gid,))[0]
            db.ex("update gaps set detail=?, since=?, status='open', resolved_at=NULL where id=?",
                  (detail, was["since"] if was["status"] == "open" else since, gid))
        else:
            db.ex("insert into gaps values (?,?,?,?,?,?,?,?,?)", (gid, kind, target, detail, since, db.iso(now), "open", None, sev))
    for g in db.q("select id from gaps where status='open'"):
        if g["id"] not in ids:
            db.ex("update gaps set status='resolved', resolved_at=? where id=?", (db.iso(now), g["id"]))
    return db.q("select * from gaps order by created, id")


def coverage_score():
    """0-100: healthy sources (40%), agent coverage (30%), security controls on (30%)."""
    gaps = [g for g in db.q("select * from gaps where status='open'")]
    n_src = len(db.q("select * from sources"))
    bad = {g["target"] for g in gaps if g["kind"] in ("stale_source", "volume_drop", "field_drift")}
    inv = db.q("select * from inventory")
    ratio = sum(d["has_agent"] for d in inv) / max(1, len(inv))
    cfg = len([g for g in gaps if g["kind"] == "config_posture"])
    return round(100 * (0.4 * (n_src - len(bad)) / max(1, n_src) + 0.3 * ratio + 0.3 * (1 - min(1, cfg * 0.5))))


def source_health():
    now, out = db.utcnow(), []
    open_gaps = {g["target"]: g for g in db.q("select * from gaps where status='open'") if g["kind"] in ("stale_source", "volume_drop", "field_drift")}
    for s in db.q("select * from sources"):
        n, last = s["name"], s["last_seen"]
        c = db.q("select count(*) c from events where source=? and ts>?", (n, db.iso(now - timedelta(seconds=60))))[0]["c"]
        g = open_gaps.get(n)
        status = ("WAITING FOR FIRST LOG" if not last else "OK" if not g else
                  {"stale_source": "SILENT", "volume_drop": "VOLUME DROP", "field_drift": "BAD FIELDS"}[g["kind"]])
        out.append({"source": n, "seconds_since_last_event": int((now - db.parse(last)).total_seconds()) if last else None,
                    "events_last_minute": c, "status": status})
    return out


def explain(g):
    """Cause analysis for a gap: tampering vs ordinary connector failure, plus what we are now blind to."""
    out = dict(cause="", risk="", blind=[], confidence=0.5, tamper=False)
    k, t = g["kind"], g["target"]
    if k in ("stale_source", "volume_drop"):
        out["blind"] = DEPENDS.get(t, [])
        since = db.parse(g["since"]) if g["since"] else None
        near = [e for e in db.q("select * from events where action='audit_logging_disabled'")
                if since and abs((db.parse(e["ts"]) - since).total_seconds()) <= 9000]
        if near:
            e = near[0]
            login = db.q("select * from events where user=? and action='login' and ts<=? order by ts desc limit 1", (e["user"], e["ts"]))
            extra = f" The same account logged in moments earlier from device '{login[0]['device']}'." if login else ""
            out.update(cause=f"Possible tampering: {e['user']} disabled audit logging on {e['resource']} at {e['ts']}, "
                             f"and {t} logs stopped right after.{extra}", confidence=0.6, tamper=True,
                       risk="An attacker or insider may be hiding their activity. Treat as a security incident until proven otherwise.")
        else:
            out.update(cause=f"Most likely a technical failure (expired token, broken connector or network issue). No security change was found near the time {t} went quiet.",
                       confidence=0.55, risk="No malicious sign found, but while this source is blind, related attacks would be missed.")
    elif k == "field_drift":
        out.update(cause=f"The vendor probably changed the log format for {t} (a field was renamed). Raw events still contain the user name under a different key.",
                   confidence=0.7, risk="Events cannot be linked to people, so correlation and insider scoring are blind for this source.",
                   blind=["user-level correlation", "insider risk scoring"])
    elif k == "config_posture":
        out.update(cause="A security control was turned off and never turned back on.", confidence=0.8,
                   risk="Logging or authentication protection is weakened.", blind=["audit trail for this system"])
    elif k == "coverage_ratio":
        out.update(cause="These devices were never enrolled in endpoint protection.", confidence=0.9,
                   risk="Activity on these devices is invisible, and logins from them cannot be verified.", blind=DEPENDS["endpoint"])
    elif k == "net_blind_subnet":
        out.update(cause="No passive sensor listens on this segment and no scan is approved for it.", confidence=0.9,
                   risk="Any device here, including an unknown one, is invisible. Absence of devices on the map is not evidence that none exist.",
                   blind=["device discovery", "connections from this subnet"])
    elif k == "net_passive_only":
        out.update(cause="Fragile or unapproved range: NEXUS listens but does not probe.", confidence=0.9,
                   risk="Devices that stay silent on the wire will not be found, and open services are not enumerated.", blind=["silent devices", "service inventory"])
    elif k == "shadow_ai":
        out.update(cause="Staff are using an AI service the company does not log or control.", confidence=0.7,
                   risk="Sensitive data may be pasted into an unmonitored tool.", blind=["what data left through this AI service"])
    return out
