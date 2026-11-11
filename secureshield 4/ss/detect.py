"""Deterministic detection + correlation. The AI never decides what is an incident; rules and baselines do."""
import hashlib
import json
import re
from collections import defaultdict
from datetime import timedelta
from . import db, netdetect

# kind: (weight, impact, MITRE ATT&CK / ATLAS reference)
KINDS = {
    "new_country_login": (2.5, 3, "T1078 Valid Accounts"),
    "new_device": (1.2, 1, "T1078 Valid Accounts"),
    "anonymizer_vpn": (0.8, 1, "T1090 Proxy"),
    "credential_prompts": (3.5, 4, "T1555 Credentials from Password Stores"),
    "ai_data_extraction": (2.0, 3, "T1213 Data from Information Repositories"),
    "jailbreak_attempt": (1.5, 1, "AML.T0054 LLM Jailbreak"),
    "agent_injection": (2.0, 1, "AML.T0051 LLM Prompt Injection"),
    "secret_in_prompt": (2.0, 3, "T1552 Unsecured Credentials"),
    "role_mismatch_access": (2.0, 3, "T1213 Data from Information Repositories"),
    "mass_download": (3.5, 5, "T1530 Data from Cloud Storage"),
    "mass_clone": (3.0, 4, "T1213.003 Code Repositories"),
    "external_share": (3.0, 5, "T1567 Exfiltration Over Web Service"),
    "honeytoken": (6.0, 3, "T1078 Valid Accounts (decoy touched)"),
    "audit_logging_disabled": (4.0, 5, "T1562.008 Disable or Modify Cloud Logs"),
    "mfa_disabled": (3.0, 4, "T1556 Modify Authentication Process"),
    "log_silence_after_change": (4.0, 4, "T1562 Impair Defenses"),
}
KINDS.update(netdetect.KINDS)       # NEXUS network kinds share the same correlation and incident logic
F = re.I
PATTERNS = {
    "cred": re.compile(r"(password|credential|api key|secret|token|vault|admin access|service account)", F),
    "extract": re.compile(r"(export|dump|list|summarize).{0,40}(customer|salary|salaries|employee|payroll|records)", F),
    "jailbreak": re.compile(r"(ignore (all |any )?(previous|prior) instructions|pretend you are|developer mode|bypass (the )?polic)", F),
    "agent_inj": re.compile(r"(security agent|mark (this|the) incident|false positive|do not alert|don't alert)", F),
    "secret": re.compile(r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|password\s*[:=]\s*\S+)", F),
}


def classify_prompt(text):
    return {k for k, p in PATTERNS.items() if p.search(text or "")}


def redact(text):
    return PATTERNS["secret"].sub("[REDACTED-SECRET]", text or "")


def route(sev):
    return ("PAGE on-call (critical)" if sev >= 8 else "Ticket + chat alert (high)" if sev >= 6
            else "Ticket (medium)" if sev >= 3 else "Weekly digest (low)")


def _best_window(items, val, minutes=60):
    best = (0, [])
    for i in range(len(items)):
        t0, tot, grp = db.parse(items[i]["ts"]), 0, []
        for j in range(i, len(items)):
            if db.parse(items[j]["ts"]) - t0 > timedelta(minutes=minutes):
                break
            tot += val(items[j])
            grp.append(items[j])
        if tot > best[0]:
            best = (tot, grp)
    return best


def collect(gaps=None):
    gaps = gaps or []
    ev = db.q("select * from events where source not like 'net%' order by ts")
    for e in ev:
        e["detail"] = json.loads(e["detail"] or "{}")
    users = {u["user"]: u for u in db.q("select * from users")}
    inv = {d["device"]: d for d in db.q("select * from inventory")}
    sigs = []

    def add(user, ts, kind, title, evidence):
        w, imp, mitre = KINDS[kind]
        sigs.append(dict(user=user, ts=ts, kind=kind, title=title, weight=w, impact=imp, mitre=mitre, evidence=evidence))

    by_user = defaultdict(list)
    for e in ev:
        by_user[e["user"]].append(e)
    for u, es in by_user.items():
        if u not in users:
            continue
        home, role = users[u]["country"], users[u]["role"]
        for e in es:
            if e["action"] == "login" and e["status"] == "success":
                if e["country"] and e["country"] != home:
                    add(u, e["ts"], "new_country_login", f"Successful login from {e['country']} (usual country: {home})", [e["id"]])
                d = inv.get(e["device"])
                if e["device"] and (d is None or d["owner"] != u):
                    add(u, e["ts"], "new_device", f"Login from unrecognized device '{e['device']}'", [e["id"]])
            if e["action"] == "vpn_connect" and e["detail"].get("anonymizer"):
                add(u, e["ts"], "anonymizer_vpn", "VPN connection through an anonymizer service", [e["id"]])
        pr = [e for e in es if e["category"] == "ai_prompt"]
        flags = {e["id"]: classify_prompt(e["detail"].get("prompt", "")) for e in pr}
        bad = [e for e in pr if flags[e["id"]]]
        cred = [e for e in pr if "cred" in flags[e["id"]]]
        if len(cred) >= 3 and sum(e["status"] == "blocked" for e in cred) >= 2:
            span = int((db.parse(bad[-1]["ts"]) - db.parse(bad[0]["ts"])).total_seconds() // 60)
            add(u, bad[-1]["ts"], "credential_prompts",
                f"{len(bad)} suspicious prompts in {span} min ({sum(e['status'] == 'blocked' for e in bad)} blocked by policy); {len(cred)} sought credentials",
                [e["id"] for e in bad])
        for flag, kind, label in [("extract", "ai_data_extraction", "prompts seeking bulk sensitive data"),
                                  ("jailbreak", "jailbreak_attempt", "prompts with instruction-override phrasing"),
                                  ("agent_inj", "agent_injection", "prompt text trying to instruct the security agent (injection attempt)"),
                                  ("secret", "secret_in_prompt", "prompts containing pasted secrets")]:
            hit = [e for e in pr if flag in flags[e["id"]]]
            if hit:
                add(u, hit[-1]["ts"], kind, f"{len(hit)} {label}", [e["id"] for e in hit])
        mism = [e for e in es if e["action"] == "file_read" and
                ((e["resource"].startswith("hr/") and role != "hr") or (e["resource"].startswith("finance/") and role != "finance"))]
        if mism:
            add(u, mism[-1]["ts"], "role_mismatch_access", f"Accessed {len(mism)} resource(s) outside role '{role}' (e.g. {mism[-1]['resource']})", [e["id"] for e in mism])
        tot, grp = _best_window([e for e in es if e["action"] == "file_download"], lambda e: e["detail"].get("bytes", 0))
        if tot >= 300e6:
            add(u, grp[-1]["ts"], "mass_download", f"{tot / 1e6:.0f} MB downloaded in {len(grp)} files within 60 minutes", [e["id"] for e in grp])
        n, grp = _best_window([e for e in es if e["action"] == "clone"], lambda e: 1)
        if n >= 8:
            add(u, grp[-1]["ts"], "mass_clone", f"{int(n)} repositories cloned within 60 minutes", [e["id"] for e in grp])
        sh = [e for e in es if e["action"] == "external_share"]
        if sh:
            add(u, sh[-1]["ts"], "external_share", f"{len(sh)} external share(s) to personal storage, {sum(e['detail'].get('bytes', 0) for e in sh) / 1e6:.0f} MB", [e["id"] for e in sh])
        ht = [e for e in es if e["resource"].startswith("honeytoken/")]
        if ht:
            add(u, ht[0]["ts"], "honeytoken", f"Decoy file '{ht[0]['resource']}' was opened (no legitimate reason exists)", [e["id"] for e in ht])
        for e in es:
            if e["action"] in ("audit_logging_disabled", "mfa_disabled"):
                add(u, e["ts"], e["action"], f"{e['action'].replace('_', ' ').capitalize()} on {e['resource']}", [e["id"]])
    # a source going silent right after a privileged change is treated as a possible attack
    cfg = [s for s in sigs if s["kind"] == "audit_logging_disabled"]
    evmap = {e["id"]: e for e in ev}
    for g in gaps:
        if g["kind"] in ("stale_source", "volume_drop") and g["since"]:
            for s in cfg:
                if abs((db.parse(s["ts"]) - db.parse(g["since"])).total_seconds()) <= 9000:
                    res = evmap[s["evidence"][0]]["resource"]
                    gid = [g["id"]] + [x["id"] for x in gaps if x["kind"] == "config_posture" and x["target"] == res]
                    add(s["user"], s["ts"], "log_silence_after_change",
                        f"{g['target']} logs went silent right after audit logging was disabled ({g['detail']})", gid + s["evidence"])
    sigs += netdetect.collect()
    return sorted(sigs, key=lambda s: s["ts"])


def insider_scores(sigs):
    """Explainable per-user risk: weak signals accumulate, then decay with a 24h half-life."""
    now, out = db.utcnow(), {}
    for s in sigs:
        age = max(0, (now - db.parse(s["ts"])).total_seconds() / 3600)
        d = out.setdefault(s["user"], {"score": 0, "components": {}})
        d["components"][s["kind"]] = round(d["components"].get(s["kind"], 0) + s["weight"] * 0.5 ** (age / 24), 2)
    for d in out.values():
        d["score"] = round(min(10, sum(d["components"].values())), 1)
    return out


def _title(user, kinds):
    if kinds & set(netdetect.KINDS):
        a = (db.q("select name, ip from assets where asset_id=?", (user,)) or [{"name": user, "ip": ""}])[0]
        who = f"{a['name']} ({a['ip']})"
        if "arp_anomaly" in kinds:
            return f"Possible ARP spoofing against {who}"
        if "device_reaches_critical" in kinds:
            return f"Unauthorized device {who} reaching a critical asset"
        if "new_external_destinations" in kinds:
            return f"Unusual outbound connections from {who}"
        if "unknown_device" in kinds:
            return f"Unknown device on the network: {who}"
        if "device_gone_silent" in kinds:
            return f"Critical asset {who} went silent"
        return f"Suspicious network behaviour: {who}"
    if "honeytoken" in kinds:
        return f"Honeytoken touched by {user}"
    if "log_silence_after_change" in kinds:
        return "Audit logging disabled, then log source went silent (possible tampering)"
    if "new_country_login" in kinds or ("new_device" in kinds and kinds & {"credential_prompts", "mass_download"}):
        return f"Possible account compromise: {user}"
    if kinds & {"mass_clone", "external_share"}:
        return f"Possible insider data exfiltration: {user}"
    return f"Suspicious multi-signal activity: {user}"


def run(gaps):
    open_gaps = [g for g in gaps if g["status"] == "open"]
    sigs = collect(open_gaps)
    old = {i["id"]: i for i in db.q("select * from incidents")}
    evmap = {e["id"]: e for e in db.q("select id, source from events")}
    users = {u["user"]: u for u in db.q("select * from users")}
    inv = {d["device"]: d for d in db.q("select * from inventory")}
    stale = {g["target"] for g in open_gaps if g["kind"] in ("stale_source", "volume_drop")}
    by = defaultdict(list)
    for s in sigs:
        by[s["user"]].append(s)
    now, rows, notes = db.iso(db.utcnow()), [], []
    for user, ss in by.items():
        clusters, cur = [], [ss[0]]
        for s in ss[1:]:
            if db.parse(s["ts"]) - db.parse(cur[-1]["ts"]) <= timedelta(hours=3):
                cur.append(s)
            else:
                clusters.append(cur)
                cur = [s]
        clusters.append(cur)
        for cl in clusters:
            kinds = {s["kind"] for s in cl}
            total = sum(s["weight"] for s in cl)
            if total < 3.0 and "honeytoken" not in kinds:
                continue
            iid = "INC-" + hashlib.md5(f"{user}|{cl[0]['ts']}".encode()).hexdigest()[:6].upper()
            evid = list(dict.fromkeys(i for s in cl for i in s["evidence"]))
            srcs = {evmap[i]["source"] for i in evid if i in evmap}
            conf = 0.25 + 0.12 * len(srcs) + 0.01 * len(cl) + (0.30 if "honeytoken" in kinds else 0)
            laptop = users.get(user, {}).get("device")
            if (laptop and laptop in inv and not inv[laptop]["has_agent"]) or "endpoint" in stale:
                conf -= 0.10   # blind spot lowers confidence
            sev = min(10, round(total, 1))
            o = old.get(iid, {})
            rows.append((iid, user, o.get("created", now), _title(user, kinds), sev, round(max(0.15, min(0.95, conf)), 2),
                         min(10, round(0.6 * sum(s["impact"] for s in cl), 1)), o.get("status", "open"),
                         json.dumps(sorted({s["mitre"] for s in cl})), json.dumps(evid), json.dumps(cl), o.get("report"),
                         o.get("acked_at"), o.get("escalated", 0), route(sev)))
            lvl = lambda x: 3 if x >= 8 else 2 if x >= 6 else 1 if x >= 3 else 0
            if iid not in old:
                notes.append((now, iid, "notify", user, "auto", "system", "done", f"Delivered via: {route(sev)}"))
            elif lvl(sev) > lvl(o["severity"]):
                notes.append((now, iid, "notify", user, "auto", "system", "done", f"Severity rose {o['severity']} -> {sev}. Delivered via: {route(sev)}"))
    db.ex("delete from incidents")
    db.exmany("insert into incidents values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    db.exmany("insert into actions(ts,ref,action,target,tier,approved_by,status,result) values (?,?,?,?,?,?,?,?)", notes)
    return rows
