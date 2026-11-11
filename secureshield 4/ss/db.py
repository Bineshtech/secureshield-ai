"""SQLite storage + time helpers."""
import os
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = os.environ.get("SS_DB", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secureshield_live.db"))
OFFSET = 0          # simulated clock shift in seconds; only the red-team test suite changes it
_READY = set()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, ts TEXT, source TEXT, category TEXT, action TEXT, status TEXT,
  user TEXT, device TEXT, ip TEXT, country TEXT, resource TEXT, detail TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS ix_ev ON events(source, ts);
CREATE INDEX IF NOT EXISTS ix_ts ON events(ts);
CREATE TABLE IF NOT EXISTS users(user TEXT PRIMARY KEY, role TEXT, country TEXT);
CREATE TABLE IF NOT EXISTS inventory(device TEXT PRIMARY KEY, owner TEXT, has_agent INTEGER);
CREATE TABLE IF NOT EXISTS sources(name TEXT PRIMARY KEY, thresh_seconds REAL, last_seen TEXT);
CREATE TABLE IF NOT EXISTS gaps(id TEXT PRIMARY KEY, kind TEXT, target TEXT, detail TEXT, since TEXT, created TEXT,
  status TEXT, resolved_at TEXT, severity INTEGER);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, user TEXT, created TEXT, title TEXT, severity REAL,
  confidence REAL, impact REAL, status TEXT, mitre TEXT, evidence TEXT, signals TEXT, report TEXT, acked_at TEXT,
  escalated INTEGER DEFAULT 0, route TEXT);
CREATE TABLE IF NOT EXISTS actions(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, ref TEXT, action TEXT, target TEXT,
  tier TEXT, approved_by TEXT, status TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS scheduled(id INTEGER PRIMARY KEY AUTOINCREMENT, due TEXT, kind TEXT, source TEXT, payload TEXT);
CREATE TABLE IF NOT EXISTS faults(source TEXT PRIMARY KEY, mode TEXT, keep REAL, since TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS assets(asset_id TEXT PRIMARY KEY, name TEXT, dtype TEXT, role TEXT, type_conf REAL, authorized INTEGER DEFAULT 0,
  declared INTEGER DEFAULT 0, owner TEXT, criticality TEXT, ip TEXT, subnet TEXT, vendor TEXT, os TEXT, needs_review INTEGER DEFAULT 0,
  first_seen TEXT, last_seen TEXT, status TEXT DEFAULT 'active', seen_by TEXT DEFAULT '[]', ports TEXT DEFAULT '[]',
  listens TEXT DEFAULT '[]', mdns TEXT DEFAULT '[]', evidence TEXT DEFAULT '[]');
CREATE TABLE IF NOT EXISTS identifiers(asset_id TEXT, kind TEXT, value TEXT, first_seen TEXT, last_seen TEXT, PRIMARY KEY(kind, value, asset_id));
CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, source TEXT, asset_id TEXT, fact TEXT, value TEXT, confidence REAL);
CREATE TABLE IF NOT EXISTS connections(src_asset TEXT, dst_asset TEXT, port INTEGER, proto TEXT, count INTEGER, bytes INTEGER,
  first_seen TEXT, last_seen TEXT, PRIMARY KEY(src_asset, dst_asset, port));
CREATE TABLE IF NOT EXISTS networks(cidr TEXT PRIMARY KEY, name TEXT, vlan INTEGER, authorized INTEGER, passive_sensor INTEGER,
  active_scan INTEGER, fragile INTEGER, notes TEXT);
CREATE TABLE IF NOT EXISTS net_declared(hostname TEXT PRIMARY KEY, owner TEXT, criticality TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS changes(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, asset_id TEXT, kind TEXT, old TEXT, new TEXT);
CREATE TABLE IF NOT EXISTS net_blocks(src_asset TEXT, dst_asset TEXT, port INTEGER, ts TEXT, PRIMARY KEY(src_asset, dst_asset, port));
"""


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=OFFSET)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def get():
    if not os.path.exists(DB_PATH):
        _READY.discard(DB_PATH)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA synchronous=OFF")
    if DB_PATH not in _READY:
        c.executescript(SCHEMA)
        _READY.add(DB_PATH)
    return c


def q(sql, args=()):
    c = get()
    try:
        return [dict(r) for r in c.execute(sql, args).fetchall()]
    finally:
        c.close()


def ex(sql, args=()):
    c = get()
    try:
        c.execute(sql, args)
        c.commit()
    finally:
        c.close()


def exmany(sql, seq):
    c = get()
    try:
        c.executemany(sql, list(seq))
        c.commit()
    finally:
        c.close()


def meta_get(k):
    r = q("select value from meta where key=?", (k,))
    return r[0]["value"] if r else None


def meta_set(k, v):
    ex("insert or replace into meta values (?,?)", (k, v))


def reset():
    _READY.discard(DB_PATH)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    get().close()
