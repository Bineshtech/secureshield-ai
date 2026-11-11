"""Tiered response: auto / approve / human-only. Every action is logged, and every fix is verified afterwards."""
import json
from . import db, simulator, pipeline, detect
from .normalize import ingest_many

ACTIONS = {
    "retry_connector": ("auto", "Retry the log connector"),
    "open_ticket": ("auto", "Open a ticket"),
    "revoke_session": ("approve", "Revoke the user's active sessions"),
    "reset_mfa": ("approve", "Force MFA re-enrollment"),
    "reenable_audit_logging": ("approve", "Re-enable audit logging on the connector"),
    "deploy_endpoint_agent": ("approve", "Deploy endpoint agent to unmonitored devices"),
    "fix_parser_mapping": ("approve", "Update the parser mapping for the changed log format"),
    "block_domain": ("approve", "Block the unsanctioned AI domain at the proxy"),
    "approve_device": ("approve", "Approve this device as authorized"),
    "quarantine_device": ("approve", "Quarantine the device (cut it off the network)"),
    "block_connection": ("approve", "Block one connection (source > destination:port)"),
    "disable_account": ("human", "Disable the account"),
    "change_user_access": ("human", "Change user access rights"),
}
NET_KINDS = {"unknown_device", "device_reaches_critical", "new_external_destinations", "segment_crossing", "internal_scan", "arp_anomaly", "device_gone_silent"}
CONTAIN_KINDS = {"new_country_login", "credential_prompts", "mass_download", "mass_clone", "external_share", "honeytoken"}


def _apply(action, target):
    now = db.iso(db.utcnow())
    if action == "approve_device":
        a = db.q("select * from assets where asset_id=?", (target,))[0]
        db.ex("update assets set authorized=1, status='active', needs_review=0 where asset_id=?", (target,))
        db.ex("insert into changes(ts,asset_id,kind,old,new) values (?,?,?,?,?)", (now, target, "approved", "unauthorized", "approved by administrator"))
        return "done", f"{a['name']} ({a['ip']}) is now marked authorized."
    if action == "quarantine_device":
        a = db.q("select * from assets where asset_id=?", (target,))[0]
        db.ex("update assets set status='quarantined' where asset_id=?", (target,))
        db.ex("insert into changes(ts,asset_id,kind,old,new) values (?,?,?,?,?)", (now, target, "quarantined", "active", "cut off by administrator"))
        return "done", f"{a['name']} ({a['ip']}) quarantined. In the lab this stops its traffic; real enforcement needs switch or firewall integration."
    if action == "block_connection":
        src, rest = target.split(">")
        dst, port = rest.split(":")
        db.ex("insert or replace into net_blocks values (?,?,?,?)", (src, dst, int(port), now))
        db.ex("delete from connections where src_asset=? and dst_asset=? and port=?", (src, dst, int(port)))
        return "done", f"Connection {src} to {dst}:{port} blocked."
    if action == "retry_connector":
        if db.q("select 1 from gaps where status='open' and kind='config_posture' and target=?", (f"{target}-connector",)):
            return "failed", (f"The {target} connector is reachable, but audit logging is disabled on it, so no data is produced. "
                              "Re-enable audit logging first.")
        simulator.resume(target)
        return "done", f"{target} connector restarted; new events are arriving."
    if action == "reenable_audit_logging":
        ingest_many([("cloud", {"timestamp": now, "principal": "sysadmin", "operation": "AuditLoggingEnabled", "object": target, "ip": "103.77.12.9"})])
        simulator.resume(target.replace("-connector", ""))
        return "done", f"Audit logging re-enabled on {target}; log flow resumed."
    if action == "revoke_session":
        ingest_many([("identity", {"eventTime": now, "actor": target, "outcome": "REVOKED", "app": "sso", "client": {}})])
        return "done", f"All active sessions for {target} were revoked."
    if action == "reset_mfa":
        ingest_many([("cloud", {"timestamp": now, "principal": "sysadmin", "operation": "MFAReset", "object": target, "ip": ""})])
        return "done", f"MFA reset for {target}; re-enrollment required at next login."
    if action == "deploy_endpoint_agent":
        new = db.q("select device, owner from inventory where has_agent=0")
        db.ex("update inventory set has_agent=1 where has_agent=0")
        ingest_many([("endpoint", {"ts": now, "host": d["device"], "user": d["owner"], "event": "heartbeat", "proc": "agent"}) for d in new])
        return "done", f"Endpoint agent deployed to {len(new)} devices; they now report in."
    if action == "fix_parser_mapping":
        fixed = 0
        for e in db.q("select id, raw from events where source='devplatform' and user=''"):
            who = json.loads(e["raw"]).get("author", "")
            if who:
                db.ex("update events set user=? where id=?", (who, e["id"]))
                fixed += 1
        db.ex("delete from faults where source=?", (target,))
        return "done", f"Parser now maps 'author' to user; {fixed} events re-normalized from raw evidence."
    if action == "block_domain":
        ingest_many([("cloud", {"timestamp": now, "principal": "sysadmin", "operation": "BlockDomain", "object": target, "ip": ""})])
        return "done", f"{target} blocked at the proxy."
    return "done", "Ticket created."


def execute(action, target, approved_by=None, ref=""):
    tier = ACTIONS[action][0]
    if tier == "human":
        status, result = "handed_to_human", "The agent is not allowed to do this. A task was created for a human decision."
    elif tier == "approve" and not approved_by:
        status, result = "blocked", "Needs human approval."
    else:
        status, result = _apply(action, target)
    db.ex("insert into actions(ts,ref,action,target,tier,approved_by,status,result) values (?,?,?,?,?,?,?,?)",
          (db.iso(db.utcnow()), ref, action, target, tier, approved_by or "", status, result))
    pipeline.analyze()
    return status, result


def recommend(inc):
    kinds = {s["kind"] for s in json.loads(inc["signals"])}
    u, out = inc["user"], []

    def add(a, t, why):
        if not any(o["action"] == a and o["target"] == t for o in out):
            out.append(dict(action=a, tier=ACTIONS[a][0], target=t, reason=why))

    if kinds & {"new_country_login", "credential_prompts", "mass_download", "honeytoken"}:
        add("revoke_session", u, "Cut off the possibly stolen session")
        add("reset_mfa", u, "Force MFA re-enrollment so the attacker's device cannot return")
    if kinds & {"mass_clone", "external_share"}:
        add("revoke_session", u, "Stop ongoing access while a human reviews")
        add("change_user_access", u, "Review repository and sharing rights")
    if kinds & {"audit_logging_disabled", "log_silence_after_change"}:
        for s in json.loads(inc["signals"]):
            if s["kind"] == "audit_logging_disabled":
                res = db.q("select resource from events where id=?", (s["evidence"][0],))[0]["resource"]
                add("reenable_audit_logging", res, "Restore the audit trail the attacker may have switched off")
    if kinds & NET_KINDS:
        a = db.q("select * from assets where asset_id=?", (u,))
        if a:
            add("quarantine_device", u, "Cut the device off while a human reviews it")
            if not a[0]["authorized"]:
                add("approve_device", u, "Only if the device is known and expected (it will leave the unknown list)")
            for c in db.q("select * from connections where src_asset=?", (u,)):
                d = db.q("select * from assets where asset_id=?", (c["dst_asset"],))
                if d and d[0]["criticality"] == "critical" and not a[0]["authorized"]:
                    add("block_connection", f"{u}>{c['dst_asset']}:{c['port']}", f"Stop {a[0]['name']} reaching {d[0]['name']} on port {c['port']}")
    laptop = simulator.USERS.get(u, {}).get("device")
    if laptop and db.q("select 1 from inventory where device=? and has_agent=0", (laptop,)):
        add("deploy_endpoint_agent", "all-missing", f"{laptop} has no endpoint agent, so this device cannot be verified")
    add("open_ticket", inc["id"], "Track the investigation")
    if inc["severity"] >= 8 and not kinds & NET_KINDS:
        add("disable_account", u, "Account disablement is a human-only decision")
    return out


def recommend_gap(g, ex):
    k, t = g["kind"], g["target"]
    if k in ("stale_source", "volume_drop"):
        out = [("retry_connector", t, "Try restarting the connector first")]
        if ex["tamper"]:
            out.append(("reenable_audit_logging", f"{t}-connector", "Audit logging was disabled; restore it"))
        else:
            out.append(("open_ticket", g["id"], "Ask the system owner to renew the token or fix the connector"))
    elif k == "config_posture":
        out = [("reenable_audit_logging", t, "Turn the control back on")]
    elif k in ("net_blind_subnet", "net_passive_only"):
        out = [("open_ticket", g["id"], "Ask network owners to place a sensor or approve scanning of this range")]
    elif k == "field_drift":
        out = [("fix_parser_mapping", t, "Map the renamed field and re-normalize from raw evidence")]
    elif k == "coverage_ratio":
        out = [("deploy_endpoint_agent", "all-missing", "Enroll the unmonitored devices")]
    elif k == "shadow_ai":
        out = [("open_ticket", g["id"], "Notify the owners"), ("block_domain", t, "Block until the tool is reviewed")]
    else:
        out = []
    return [dict(action=a, tier=ACTIONS[a][0], target=tg, reason=r) for a, tg, r in out]


def verify_gap(gid):
    pipeline.analyze()
    g = db.q("select * from gaps where id=?", (gid,))
    ok = bool(g) and g[0]["status"] == "resolved"
    return ok, ("Re-check passed: the gap is gone and data is flowing." if ok else "Re-check FAILED: the gap is still open.")


def verify_incident(iid):
    pipeline.analyze()
    inc = db.q("select * from incidents where id=?", (iid,))
    if not inc:
        return True, [("Incident no longer present after re-analysis", True)]
    inc = inc[0]
    evid, kinds, checks = json.loads(inc["evidence"]), {s["kind"] for s in json.loads(inc["signals"])}, []
    if kinds & NET_KINDS:
        return _verify_network(inc, kinds)
    for gid in [i for i in evid if i.startswith("GAP-")]:
        g = db.q("select * from gaps where id=?", (gid,))[0]
        checks.append((f"{g['kind']} on {g['target']} is {g['status']}", g["status"] == "resolved"))
    for s in json.loads(inc["signals"]):
        if s["kind"] == "audit_logging_disabled":
            res = db.q("select resource from events where id=?", (s["evidence"][0],))[0]["resource"]
            src = res.replace("-connector", "")
            off = db.q("select 1 from gaps where status='open' and kind='config_posture' and target=?", (res,))
            silent = db.q("select 1 from gaps where status='open' and target=? and kind in ('stale_source','volume_drop')", (src,))
            checks.append((f"Audit logging is on again for {res}", not off))
            checks.append((f"{src} logs are flowing again", not silent))
    if kinds & CONTAIN_KINDS:
        rev = db.q("select ts from actions where action='revoke_session' and target=? and status='done' order by ts desc limit 1", (inc["user"],))
        checks.append(("Sessions for the account were revoked", bool(rev)))
        if rev:
            home = db.q("select country from users where user=?", (inc["user"],))[0]["country"]
            owned = {d["device"] for d in db.q("select device from inventory where owner=?", (inc["user"],))}
            later = [e for e in db.q("select country, device from events where user=? and action='login' and ts>?", (inc["user"], rev[0]["ts"]))
                     if (e["country"] and e["country"] != home) or (e["device"] and e["device"] not in owned)]
            checks.append(("No suspicious logins (new country or unknown device) since revocation", not later))
        gaps = [g for g in db.q("select * from gaps where status='open'")]
        others = sorted({s["user"] for s in detect.collect(gaps) if s["user"] != inc["user"] and s["kind"] in kinds & CONTAIN_KINDS})
        checks.append(("No other account shows the same pattern" + (f" (found: {', '.join(others)})" if others else ""), not others))
    ok = bool(checks) and all(c[1] for c in checks)
    if ok:
        db.ex("update incidents set status='resolved' where id=?", (iid,))
    return ok, checks


def _verify_network(inc, kinds):
    """Did the action work? Check that the device really disappeared from observation, not just that a button was pressed."""
    from . import graph
    aid = inc["user"]
    a = db.q("select * from assets where asset_id=?", (aid,))
    acts = db.q("select ts, action from actions where target=? and status='done' and action in ('quarantine_device','approve_device') order by id desc limit 1", (aid,))
    checks = []
    if not acts:
        checks.append(("A containment or approval action was taken for this device", False))
    elif acts[0]["action"] == "approve_device":
        checks.append(("Device is now authorized (the administrator confirmed it is known)", bool(a and a[0]["authorized"])))
    else:
        checks.append(("Device is quarantined", bool(a and a[0]["status"] == "quarantined")))
        later = db.q("select count(*) n from events where user=? and source in ('netflow','netpassive') and ts>?", (aid, acts[0]["ts"]))[0]["n"]
        checks.append((f"No traffic observed from the device since the action ({later} new records)", later == 0))
        reach = graph.reachable_from(aid) if a and a[0]["status"] != "quarantined" else {}
        crit = [k for k in reach if db.q("select 1 from assets where asset_id=? and criticality='critical'", (k,))]
        checks.append(("No critical asset is reachable from the device any more", not crit))
    if "arp_anomaly" in kinds:
        checks.append(("ARP conflict: quarantine the second MAC's device to clear it", bool(acts)))
    ok = bool(checks) and all(c[1] for c in checks)
    if ok:
        db.ex("update incidents set status='resolved' where id=?", (inc["id"],))
    return ok, checks
