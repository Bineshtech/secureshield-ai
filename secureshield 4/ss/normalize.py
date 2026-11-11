"""Layer 1: every vendor's raw log format -> one common schema (OCSF-inspired). Raw evidence is preserved."""
import json
from . import db


def _u(email):
    return (email or "").split("@")[0]


def n_identity(r):
    c = r.get("client", {})
    out = r["outcome"].upper()
    return dict(ts=r["eventTime"], category="authentication",
                action="session_revoked" if out == "REVOKED" else "login",
                status={"SUCCESS": "success", "FAILURE": "failure", "REVOKED": "revoked"}.get(out, out.lower()),
                user=r.get("actor", ""), device=c.get("device", ""), ip=c.get("ip", ""), country=c.get("geo", ""),
                resource=r.get("app", ""), detail={})


def n_vpn(r):
    return dict(ts=r["time"], category="network", action="vpn_connect", status="success", user=r.get("username", ""),
                device=r.get("device", ""), ip=r.get("src_ip", ""), country=r.get("country", ""), resource="vpn",
                detail={"anonymizer": bool(r.get("anonymizer"))})


CLOUD_OPS = {
    "FileRead": ("file", "file_read"), "FileDownload": ("file", "file_download"),
    "ExternalShare": ("file", "external_share"), "AuditLoggingDisabled": ("config", "audit_logging_disabled"),
    "AuditLoggingEnabled": ("config", "audit_logging_enabled"), "MFADisabled": ("config", "mfa_disabled"),
    "MFAReset": ("config", "mfa_reset"), "BlockDomain": ("config", "domain_blocked"),
}


def n_cloud(r):
    cat, act = CLOUD_OPS[r["operation"]]
    return dict(ts=r["timestamp"], category=cat, action=act, status="success", user=r.get("principal", ""), device="",
                ip=r.get("ip", ""), country=r.get("geo", ""), resource=r.get("object", ""),
                detail={"bytes": r.get("bytes", 0)})


def n_endpoint(r):
    return dict(ts=r["ts"], category="process", action=r["event"], status="success", user=r.get("user", ""),
                device=r.get("host", ""), ip="", country="", resource=r.get("proc", ""), detail={})


def n_ai(r):
    return dict(ts=r["created_at"], category="ai_prompt", action="prompt", status=r["policy"], user=_u(r.get("user_email")),
                device="", ip="", country="", resource=r.get("tool", ""), detail={"prompt": r["prompt"]})


def n_dev(r):
    return dict(ts=r["when"], category="repo", action=r["verb"], status="success", user=r.get("who", ""), device="",
                ip="", country="", resource=r.get("repo", ""), detail={"size_mb": r.get("size_mb", 0)})


def n_proxy(r):
    return dict(ts=r["time"], category="web", action="http_request", status="success", user=r.get("user", ""),
                device="", ip="", country="", resource=r["domain"], detail={"bytes": r.get("bytes", 0)})


NORMALIZERS = {"identity": n_identity, "vpn": n_vpn, "cloud": n_cloud, "endpoint": n_endpoint,
               "ai_assistant": n_ai, "devplatform": n_dev, "proxy": n_proxy}


def ingest_many(pairs):
    """pairs: [(source, raw_dict)]. Normalizes and stores. Returns new event ids."""
    c = db.get()
    try:
        n = c.execute("select max(cast(substr(id,4) as integer)) m from events").fetchone()["m"] or 0
        rows = []
        for source, raw in pairs:
            n += 1
            e = NORMALIZERS[source](raw)
            rows.append((f"EV-{n:05d}", e["ts"], source, e["category"], e["action"], e["status"], e["user"], e["device"],
                         e["ip"], e["country"], e["resource"], json.dumps(e["detail"]), json.dumps(raw)))
        c.executemany("insert into events values (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        latest = {}
        for r in rows:
            latest[r[2]] = max(latest.get(r[2], ""), r[1])
        for src, ts in latest.items():
            c.execute("update sources set last_seen=? where name=? and (last_seen is null or last_seen<?)", (ts, src, ts))
        c.commit()
        return [r[0] for r in rows]
    finally:
        c.close()
