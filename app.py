#!/usr/bin/env python3
"""
Handover Advice -> Acumatica Sales Shipments
--------------------------------------------
Drop a Dachser handover-advice PDF, review the matched sales orders, and create
(unconfirmed) shipments in Acumatica. A person does the final Confirm in
Acumatica, since confirming triggers invoicing / revenue recognition.

Mirrors the PO-Receipts tool: OAuth (Auth Code + PKCE), preview -> confirm,
read-back verification, reconciliation certificate, run-history log. Runs on
Render (always-on) alongside the receipts tool. Config via env vars.

Most containers on a real advice do NOT list PO#s in the text (often only one
container out of many does) -- see containers_to_pos(). Each container's POs
are resolved via Acumatica PO Receipts: container -> PurchaseReceipt -> Sand+Fog's
internal PO# -> that PO's VendorRef (where the retail PO text lives) -> match
against Sales Orders. Optional env overrides: RECEIPT_CONTAINER_FIELD /
RECEIPT_CONTAINER_VIEW (skip auto-discovery), RECEIPT_LOOKBACK_DAYS (default 180).
"""
import os, re, json, time, base64, hashlib, hmac, secrets, datetime, threading, csv, io
import urllib.parse, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

PACIFIC = ZoneInfo("America/Los_Angeles")  # dashboard/log display only -- stored timestamps stay UTC

try:
    import pdfplumber
except ImportError:
    pdfplumber = None

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------- Config ----------------
def cfg(k, d=""):
    return os.environ.get(k, d)

CFG = {
    "base_url":        cfg("ACU_BASE_URL", "https://sandandfog.acumatica.com").rstrip("/"),
    "tenant":          cfg("ACU_TENANT"),
    "client_id":       cfg("ACU_CLIENT_ID"),
    "client_secret":   cfg("ACU_CLIENT_SECRET"),
    "app_password":    cfg("APP_PASSWORD"),
    "public_url":      cfg("PUBLIC_URL", "http://localhost:8400").rstrip("/"),
    "warehouse":       cfg("WAREHOUSE_ID", ""),
    "container_field": cfg("SHIP_CONTAINER_FIELD", ""),
    "api_version":     cfg("ACU_API_VERSION", "20.200.001"),
}
# Optional per-user logins for attribution: APP_USERS="abby@x.com:pw,brenda@x.com:pw"
CFG["users"] = {}
for _pair in cfg("APP_USERS", "").split(","):
    if ":" in _pair:
        _u, _p = _pair.split(":", 1)
        if _u.strip():
            CFG["users"][_u.strip()] = _p.strip()
PORT = int(cfg("PORT", cfg("WEBSITES_PORT", "8400")))
TOKEN_DIR = cfg("TOKEN_DIR", HERE)
TOKEN_PATH = os.path.join(TOKEN_DIR, "ship_token.json")
PKCE_PATH = os.path.join(TOKEN_DIR, "ship_pkce.json")
RUNS_PATH = os.path.join(TOKEN_DIR, "ship_runs.jsonl")
SHIPDATES_PATH = os.path.join(TOKEN_DIR, "po_shipdates.json")  # {po: 'YYYY-MM-DD'} NRT pickup dates, pushed by the daily sync
CONTAINERDATES_PATH = os.path.join(TOKEN_DIR, "container_dates.json")  # {container: 'YYYY-MM-DD'} NRT pickup (email) dates, pushed by the daily sync
WATCHLIST_PATH = os.path.join(TOKEN_DIR, "maersk_watchlist.json")  # {container: {pos, port_of_loading, receipt_no, vessel, status, date_added, ...}}
WATCHLIST_SLA_DAYS = int(cfg("WATCHLIST_SLA_DAYS", "45"))  # containers watching longer than this without a Load-on event are flagged, not silently left open
LEDGER_PATH = os.path.join(TOKEN_DIR, "container_ledger.json")  # {master_token: {containers: {container: pickup_date}, status, first_seen, last_updated}} -- see po_completeness()
LEDGER_SLA_DAYS = int(cfg("LEDGER_SLA_DAYS", "45"))  # masters stuck waiting/partial longer than this surface in /agent/summary for human review
AGENTLOG_PATH = os.path.join(TOKEN_DIR, "agent_log.jsonl")  # one row per agent DECISION (not per LLM turn) -- the mailbox-agent's human-reviewable audit trail
INGEST_DIR = os.path.join(TOKEN_DIR, "ingest_queue")  # Power Automate pushes raw emails here (one JSON file each); the agent cron job drains it
AUTOSHIP_TOKEN = cfg("AUTOSHIP_TOKEN", "")  # separate, write-capable token for /autoship -- keep distinct from STATUS_TOKEN (read-only)
FCR_TOKEN = cfg("FCR_TOKEN", "") or AUTOSHIP_TOKEN  # token for /parsefcr (read-only parse, no Acumatica writes); falls back to AUTOSHIP_TOKEN if not set separately
MAERSK_TOKEN = cfg("MAERSK_TOKEN", "") or FCR_TOKEN  # token for /checkmaersk and the watch-list endpoints (no Acumatica writes -- /autoship is the only endpoint that creates real records)
AGENT_TOKEN = cfg("AGENT_TOKEN", "") or MAERSK_TOKEN  # token the mailbox-agent uses for /agent/log and /ingest/list|delete; falls back to MAERSK_TOKEN if not set separately
INGEST_TOKEN = cfg("INGEST_TOKEN", "") or AGENT_TOKEN  # token Power Automate uses to POST /ingest; falls back to AGENT_TOKEN if not set separately
SHIPMENT_WEBHOOK_URL = cfg("SHIPMENT_WEBHOOK_URL", "")  # Power Automate "When an HTTP request is received" trigger URL -- see notify_shipment_created()
REDIRECT_URI = CFG["public_url"] + "/callback"
COOKIE_SECRET = (CFG["app_password"] or "dev").encode() + b"::ship"
SESSIONS = {}
_PKCE = {}   # in-memory PKCE state (primary); disk is a backup
ENTITY = f"/entity/Default/{CFG['api_version']}"

# ---------------- login rate limiting ----------------
_LOGIN_ATTEMPTS = {}      # ip -> [timestamps of recent failed logins]
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SEC = 600    # look back 10 minutes
LOGIN_LOCKOUT_SEC = 900   # lock out for 15 minutes once tripped

def _login_blocked(ip):
    now = time.time()
    attempts = [t for t in _LOGIN_ATTEMPTS.get(ip, []) if now - t < LOGIN_WINDOW_SEC]
    _LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS and (now - attempts[-1]) < LOGIN_LOCKOUT_SEC

def _record_login_failure(ip):
    _LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())

# ---------------- helpers ----------------
def b64url(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

def save_json(path, obj):
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f: json.dump(obj, f)
    except Exception: pass

def load_json(path):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return None

# ThreadingHTTPServer means two requests can genuinely run this process's code at the same
# instant. save_json()/load_json() themselves are just single-file I/O -- the actual risk is
# a caller doing load -> mutate one key -> save: if two threads both load the old state before
# either saves, whichever saves last silently wins, dropping the other thread's update. A
# single RLock (reentrant so a locked function calling another locked function can't
# self-deadlock) around each such read-modify-write critical section closes that. Does NOT
# cover WATCHLIST_PATH (Maersk/FCR is out of scope for now) or TOKEN_PATH (see _TOKEN_LOCK
# below instead -- deliberately a SEPARATE lock, not this one).
_JSON_LOCK = threading.RLock()

# access_token()'s refresh path makes a real network call to Acumatica's OAuth endpoint
# (_token_request, up to a 60s timeout) while holding this lock. Kept separate from
# _JSON_LOCK on purpose: if it shared that lock, one slow token refresh would stall every
# unrelated ledger/ingest/shipdates write for the whole duration of the network call.
_TOKEN_LOCK = threading.RLock()

# ---------------- Maersk watch-list (state store for the local checker script) ----------------
# Render can't reliably reach maersk.com itself (Akamai blocks the cloud/datacenter IP range
# it deploys from -- confirmed live: browser launches fine, page load times out). So the
# actual page-check runs from a local script on a normal network instead; this app just
# holds the shared state (what's being watched, what's resolved) the same way it already
# holds po_shipdates.json/container_dates.json, so everything stays centrally auditable.
def watchlist_add(container, pos=None, port_of_loading=None, receipt_no=None, vessel=None, source=None):
    """Idempotent -- re-adding an already-watched container updates its fields (e.g. a
    corrected FCR re-send) rather than creating a duplicate entry."""
    container = (container or "").strip().upper()
    if not container:
        return None
    wl = load_json(WATCHLIST_PATH) or {}
    existing = wl.get(container, {})
    entry = {
        "pos": pos if pos is not None else existing.get("pos", []),
        "port_of_loading": port_of_loading or existing.get("port_of_loading"),
        "receipt_no": receipt_no or existing.get("receipt_no"),
        "vessel": vessel or existing.get("vessel"),
        "source": source or existing.get("source"),
        "status": existing.get("status", "watching"),
        "date_added": existing.get("date_added", datetime.datetime.now(datetime.timezone.utc).isoformat()),
    }
    wl[container] = entry
    save_json(WATCHLIST_PATH, wl)
    return entry

def watchlist_resolve(container, status, note=None, ship_date=None):
    container = (container or "").strip().upper()
    wl = load_json(WATCHLIST_PATH) or {}
    if container not in wl:
        return None
    wl[container]["status"] = status
    wl[container]["resolved_date"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if note: wl[container]["note"] = note
    if ship_date: wl[container]["ship_date"] = ship_date
    save_json(WATCHLIST_PATH, wl)
    return wl[container]

def watchlist_check_sla():
    """Flip 'watching' entries past WATCHLIST_SLA_DAYS to 'alert' in place -- a container
    that never shows a Load-on event shouldn't just sit silent forever. Runs on every
    /watchlist/list call so the local checker always sees current status, no separate cron."""
    wl = load_json(WATCHLIST_PATH) or {}
    now = datetime.datetime.now(datetime.timezone.utc)
    changed = False
    for container, entry in wl.items():
        if entry.get("status") != "watching":
            continue
        try:
            added = datetime.datetime.fromisoformat(entry["date_added"])
        except Exception:
            continue
        if (now - added).days > WATCHLIST_SLA_DAYS:
            entry["status"] = "alert"
            entry["alert_reason"] = f"no Load-on event found after {WATCHLIST_SLA_DAYS} days"
            changed = True
    if changed:
        save_json(WATCHLIST_PATH, wl)
    return wl

# ---------------- container ledger (Phase 2 / Tier 2: split-PO shipment completeness) ----------------
# Tracks per-master pickup dates across however many NRT events it takes, so a PO whose
# containers arrive via separate receipts (see master_multi_receipt_flags' docstring) can
# still be shipped once -- at the LATEST recorded pickup date -- rather than refused forever.
# Same JSON-on-persistent-disk pattern as the Maersk watch-list above.
def ledger_record(master_token, container, pickup_date, email_received_at=None):
    """Idempotent upsert -- a duplicate/resent NRT email for a container already in the
    ledger just re-writes the same date, harmless. Always called BEFORE any shipment
    decision, so the ledger reflects reality even if the completeness check or the
    shipment-creation loop below it fails partway through.

    email_received_at (optional): the triggering NRT email's own received timestamp,
    stored alongside pickup_date -- Parker's request, 2026-08-05, so a human can see the
    ACTUAL email that proved a container was confirmed, not just the date this automation
    recorded, without having to separately cross-check Outlook for every shipment. Kept as
    a parallel dict rather than replacing containers[container]'s existing bare-date value
    -- that shape is read by /lookup, /container-status, and the anomaly ledger_entry
    note, all of which expect a plain date string."""
    if not master_token or not container:
        return None
    with _JSON_LOCK:
        data = load_json(LEDGER_PATH) or {}
        entry = data.setdefault(master_token, {"containers": {}, "status": "waiting",
                                                "first_seen": pickup_date, "last_updated": pickup_date})
        entry["containers"][container] = pickup_date
        if email_received_at:
            entry.setdefault("email_received", {})[container] = email_received_at
        entry["last_updated"] = pickup_date
        save_json(LEDGER_PATH, data)
        return entry

def ledger_set_status(master_token, status, note=None, reset_first_seen=False):
    """reset_first_seen (default False, preserves the normal SLA-clock behavior): pass True
    only when a master is genuinely starting a NEW waiting period, not continuing an old
    one -- e.g. the stale-ledger-verification case in process_manual, where a master
    previously marked 'shipped' turns out to have no live shipment anymore (deleted after
    being found erroneous) and is reset to 'waiting'. Without this, ledger_check_sla()
    would measure from the ORIGINAL first_seen date -- possibly months ago -- and could
    immediately flag a master that just re-entered 'waiting' today as stuck for months,
    a false alarm (not a missed one, but still wrong)."""
    with _JSON_LOCK:
        data = load_json(LEDGER_PATH) or {}
        if master_token not in data:
            return None
        data[master_token]["status"] = status
        if note:
            data[master_token]["note"] = note
        if reset_first_seen:
            data[master_token]["first_seen"] = time.strftime("%Y-%m-%d")
        save_json(LEDGER_PATH, data)
        return data[master_token]

def ledger_latest_date(master_token):
    """Latest confirmed pickup date across every container this master's OWN receipts say
    it depends on -- sourced primarily from confirmed_pickup_containers() (the permanent
    agent_log.jsonl record, see its docstring for why), not just this master's own
    container_ledger.json entry, which can be missing a real confirmation if Acumatica's
    receipt didn't exist yet at the moment that container's NRT trigger fired. Also folds
    in the ledger entry's own dates (belt-and-suspenders -- covers anything recorded by a
    path that doesn't log to agent_log.jsonl, e.g. a manual /autoship test)."""
    dates = []
    expected = expected_containers_for_master(master_token)
    dates.extend(d for c, d in confirmed_pickup_containers().items() if c in expected)
    data = load_json(LEDGER_PATH) or {}
    dates.extend((data.get(master_token) or {}).get("containers", {}).values())
    return max(dates) if dates else None

def ledger_stamp_checked(master_token):
    """Records WHEN a live PO-completeness check last actually ran for this master --
    distinct from last_updated (which tracks container pickup dates, not live-check time).
    Lets /splits show a cached, zero-API-call view by default with an honest 'as of' time,
    rather than needing a live call just to know how stale the cache is."""
    with _JSON_LOCK:
        data = load_json(LEDGER_PATH) or {}
        if master_token in data:
            data[master_token]["last_checked"] = time.strftime("%Y-%m-%d %H:%M:%S")
            save_json(LEDGER_PATH, data)

def ledger_entry(master_token):
    return (load_json(LEDGER_PATH) or {}).get(master_token)

def ledger_check_sla():
    """Flag masters stuck 'waiting'/'partial' past LEDGER_SLA_DAYS -- mirrors
    watchlist_check_sla(). Runs opportunistically (from /agent/summary), no separate cron
    needed for the flagging itself (the recheck job below is separate and IS cron-driven,
    since it has to actually retry the completeness check, not just flag staleness)."""
    data = load_json(LEDGER_PATH) or {}
    stale = []
    for token, entry in data.items():
        if entry.get("status") not in ("waiting", "partial"):
            continue
        try:
            first = datetime.date.fromisoformat((entry.get("first_seen") or "")[:10])
        except Exception:
            continue
        if (datetime.date.today() - first).days > LEDGER_SLA_DAYS:
            stale.append({"master": token, "status": entry["status"],
                          "days_waiting": (datetime.date.today() - first).days,
                          "containers": sorted(entry.get("containers", {}).keys())})
    return stale

def parse_multipart(body, boundary):
    """Minimal multipart/form-data parser (replaces the removed stdlib `cgi`).
    Returns {name: bytes} for file parts and {name: str} for text parts.
    For file parts, also stashes the original filename under "_fn_<name>" (used
    for the run-history log so it shows what document was processed)."""
    fields = {}
    for part in body.split(b"--" + boundary):
        if not part or part.strip() in (b"", b"--"): continue
        if b"\r\n\r\n" not in part: continue
        head, data = part.split(b"\r\n\r\n", 1)
        head_s = head.decode("utf-8", "ignore")
        m = re.search(r'name="([^"]+)"', head_s)
        if not m: continue
        name = m.group(1)
        if data.endswith(b"\r\n"): data = data[:-2]
        if 'filename="' in head_s:
            fn = re.search(r'filename="([^"]*)"', head_s)
            fields["_fn_" + name] = (fn.group(1) if fn else "") or ""
            fields[name] = data
        else:
            fields[name] = data.decode("utf-8", "ignore")
    return fields

# ---------------- OAuth (Auth Code + PKCE; state persisted to disk) ----------------
def build_authorize_url():
    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    state = b64url(secrets.token_bytes(16))
    _PKCE["verifier"] = verifier; _PKCE["state"] = state
    save_json(PKCE_PATH, {"verifier": verifier, "state": state})
    q = {"response_type": "code", "client_id": CFG["client_id"], "redirect_uri": REDIRECT_URI,
         # openid+profile requested so the token/userinfo actually carries a username claim --
         # without them Acumatica's identity endpoints return nothing to identify who's
         # connected, which is why the "Connected as ..." banner silently showed no user.
         "scope": "api offline_access openid profile", "code_challenge": challenge,
         "code_challenge_method": "S256", "state": state,
         "prompt": "login"}  # force the Acumatica login prompt so it never silently reuses a personal SSO session
    return CFG["base_url"] + "/identity/connect/authorize?" + urllib.parse.urlencode(q)

def _token_request(data):
    req = urllib.request.Request(CFG["base_url"] + "/identity/connect/token",
                                 data=urllib.parse.urlencode(data).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
        raise RuntimeError(f"HTTP {e.code} from token endpoint -> {body}")

def _detect_user(tok):
    """Best-effort: figure out which Acumatica user the token belongs to, for the
    'Connected as ...' banner. Tries the JWT payload, then the userinfo endpoint.
    Returns None if it can't tell (banner then just says 'Connected')."""
    at = tok.get("access_token", "")
    try:
        parts = at.split(".")
        if len(parts) >= 2:
            pad = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(pad.encode()))
            for k in ("preferred_username", "username", "unique_name", "name", "email", "sub"):
                if payload.get(k): return str(payload[k])[:60]
    except Exception: pass
    try:
        req = urllib.request.Request(CFG["base_url"] + "/identity/connect/userinfo",
                                     headers={"Authorization": "Bearer " + at})
        with urllib.request.urlopen(req, timeout=20) as r:
            info = json.loads(r.read())
            for k in ("preferred_username", "name", "email", "sub"):
                if info.get(k): return str(info[k])[:60]
    except Exception: pass
    return None

def connected_user():
    return (load_json(TOKEN_PATH) or {}).get("_user")

def exchange_code(code):
    pk = _PKCE if _PKCE.get("verifier") else (load_json(PKCE_PATH) or {})
    tok = _token_request({"grant_type": "authorization_code", "code": code,
                          "redirect_uri": REDIRECT_URI, "client_id": CFG["client_id"],
                          "client_secret": CFG["client_secret"], "code_verifier": pk.get("verifier", "")})
    tok["obtained"] = time.time(); tok["_user"] = _detect_user(tok); save_json(TOKEN_PATH, tok); return tok

def refresh_token(tok):
    new = _token_request({"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                          "client_id": CFG["client_id"], "client_secret": CFG["client_secret"]})
    new["obtained"] = time.time()
    new.setdefault("refresh_token", tok["refresh_token"])
    new["_user"] = tok.get("_user") or _detect_user(new)
    save_json(TOKEN_PATH, new); return new

def access_token():
    # Locked end-to-end so two near-simultaneous requests with an expired token can't both
    # decide to refresh at once. Without this, both would load the same (still old, both see
    # it as expired) token and each call refresh_token() with the SAME refresh_token value --
    # many OAuth providers rotate/invalidate a refresh_token on use, so the second call could
    # fail outright (that request then gets "not connected"), and even if the provider allows
    # reuse, whichever save_json() finishes last wins, silently discarding the other's result.
    # Re-loading fresh AFTER acquiring the lock (not reusing whatever was loaded before it)
    # means a thread that had to wait sees the OTHER thread's already-completed refresh and
    # skips redoing it.
    with _TOKEN_LOCK:
        tok = load_json(TOKEN_PATH)
        if not tok: return None
        if time.time() - tok.get("obtained", 0) > tok.get("expires_in", 3600) - 120:
            try: tok = refresh_token(tok)
            except Exception: return None
        return tok.get("access_token")

def api(method, path, body=None, token=None):
    token = token or access_token()
    if not token: return 0, {"error": "not connected"}
    url = (CFG["base_url"] + path).replace(" ", "%20")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode(); headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read().decode()
            try: return r.status, json.loads(raw)
            except Exception: return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw
    except Exception as e:
        return 0, {"error": str(e)}

def api_with_headers(method, path, body=None, token=None):
    """Like api(), but also returns response headers (lowercased keys) -- needed to follow
    the `Location` header Acumatica gives back for LONG-RUNNING actions (e.g. CreateShipment).
    A 202 from the initial POST means "accepted, still processing", not "done"; the caller
    must poll Location until it stops returning 202."""
    token = token or access_token()
    if not token: return 0, {"error": "not connected"}, {}
    url = (CFG["base_url"] + path).replace(" ", "%20")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode(); headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read().decode()
            try: parsed = json.loads(raw)
            except Exception: parsed = raw
            return r.status, parsed, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try: parsed = json.loads(raw)
        except Exception: parsed = raw
        return e.code, parsed, {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        return 0, {"error": str(e)}, {}

# ---------------- container -> PO resolution (Acumatica PO Receipts) ----------------
# The old handover-advice PDF path this was originally built alongside only listed PO#s
# for a container "sometimes" -- that manual-upload flow is gone (Parker's call, 2026-08-06:
# the mailbox agent replaced it entirely), but Acumatica remains the reliable source either
# way: the PO-receipts tool tags
# each PurchaseReceipt with the container number, and each receipt line carries
# Sand+Fog's own internal PO# (POOrderNbr). That internal PO's VendorRef field
# is where the retail PO text ("MS 117256", "TJX 117261") actually lives -- it's
# the same field the PO-receipts tool itself searches when matching a packing
# list to a PO. So: container -> PurchaseReceipt -> internal PO# -> VendorRef ->
# extract retail PO digits -> match against Sales Orders exactly as before.
#
# Server-side filtering on the container custom field is deliberately avoided --
# unproven on this tenant (see the substringof-500 note for SalesOrder). Instead
# this fetches a bounded, date-limited set of receipts using only proven
# standard-field filters, then matches container/PO values client-side.
_RCPT_CONTAINER_FIELD = {"field": None, "view": None, "checked": False}
_RECEIPTS_CACHE = {"rows": None, "ts": 0}
RECEIPTS_TTL = 600  # 10 min, same as the open-orders cache
RECEIPT_LOOKBACK_DAYS = int(cfg("RECEIPT_LOOKBACK_DAYS", "180"))

def _fetch_all_pages(path, page_size=500, max_pages=10):
    """GET with $top/$skip paging, capped at max_pages as a safety limit. Returns
    (rows, ok) -- ok=False means the loop broke early because of an API error/bad
    response, NOT because it legitimately ran out of data. Callers must not treat an
    empty result as "this really is everything" when ok is False -- see
    load_recent_receipts()'s cache-skip logic, added after finding the same "cached a
    transient failure as a confirmed empty result" bug class in
    discover_receipt_container_field()."""
    rows = []
    ok = True
    sep = "&" if "?" in path else "?"
    for page in range(max_pages):
        q = f"{path}{sep}$top={page_size}&$skip={page * page_size}"
        st, data = api("GET", q)
        if st != 200 or not isinstance(data, list):
            ok = False
            break
        rows.extend(data)
        if len(data) < page_size:
            break
    return rows, ok

def discover_receipt_container_field():
    """Find the container-number custom/UDF field on PurchaseReceipt -- the
    PO-receipts tool writes this same field (mirrors its own discovery logic).

    FIXED 2026-07-29 (real bug caught in audit, not yet observed live): `checked` used to
    be set to True BEFORE the schema API call ran, unconditionally -- so a single
    transient failure (timeout, 5xx, rate-limit) on whichever call happened to be the
    first one after a deploy/restart would permanently cache "field not found" for the
    rest of that process's life. Every downstream caller (load_recent_receipts, and
    everything built on it -- process_manual, /diag, /splits, /lookup) would
    silently stop resolving ANY container until the next restart, with no error message
    pointing to why. Now only caches "not found" once a real 200 response actually said
    so -- a transient failure just retries on the next call instead."""
    if _RCPT_CONTAINER_FIELD["checked"]:
        return _RCPT_CONTAINER_FIELD["field"], _RCPT_CONTAINER_FIELD["view"]
    env_f = cfg("RECEIPT_CONTAINER_FIELD")
    if env_f:
        _RCPT_CONTAINER_FIELD.update(field=env_f, view=cfg("RECEIPT_CONTAINER_VIEW", "Document"), checked=True)
        return _RCPT_CONTAINER_FIELD["field"], _RCPT_CONTAINER_FIELD["view"]
    st, data = api("GET", f"{ENTITY}/PurchaseReceipt/$adHocSchema")
    if st != 200 or not isinstance(data, dict):
        return None, None  # transient failure -- NOT cached, retry next call
    _RCPT_CONTAINER_FIELD["checked"] = True  # a real answer came back -- safe to cache now, found or not
    for view, fields in (data.get("custom") or {}).items():
        for fname, meta in fields.items():
            label = ((meta or {}).get("displayName") or "") + " " + fname
            if re.search(r"contain|ctnr|cont(\.|\s)*no", label, re.I) and not re.search(r"\beta\b|arriv|estimat", label, re.I):
                _RCPT_CONTAINER_FIELD.update(field=fname, view=view)
                return fname, view
    return None, None

def load_recent_receipts(force=False):
    """Fetch recent PurchaseReceipts (bounded to RECEIPT_LOOKBACK_DAYS) with the
    container attribute + the receipt's own VendorRef header. Cached briefly.

    LEAN: the retail order lives right on the receipt's VendorRef header
    (e.g. "M2626 124940" -> 124940), so we do NOT $expand=Details or make a
    separate PO lookup -- that pulled every line item of thousands of receipts
    and hung the page. Header-only + $custom for the container = small + fast."""
    now = time.time()
    if not force and _RECEIPTS_CACHE["rows"] is not None and now - _RECEIPTS_CACHE["ts"] < RECEIPTS_TTL:
        return _RECEIPTS_CACHE["rows"]
    field, view = discover_receipt_container_field()
    if not field:
        return []
    cutoff = (datetime.date.today() - datetime.timedelta(days=RECEIPT_LOOKBACK_DAYS)).isoformat()
    # Date filter uses the OData datetimeoffset literal (datetimevalue is rejected). No
    # $expand, no $select -- VendorRef is a top-level field returned by default; the
    # container attribute comes via $custom.
    path = (f"{ENTITY}/PurchaseReceipt?$filter=Date ge datetimeoffset'{cutoff}T00:00:00Z'"
            f"&$custom={view}.{field}")
    # The list comes back oldest-first (ascending ReceiptNbr) and $orderby is IGNORED by this
    # endpoint, so the receipts we care about (recent pickups = highest ReceiptNbr) are at the
    # END. Page through the WHOLE date-bounded window -- the Date filter caps the total, so
    # paging stops naturally when a short page arrives; max_pages is just a runaway guard. Rows
    # are header-only now, so deep paging is cheap. (Was max_pages=6 -> capped at 3000 -> missed
    # everything recent.)
    data, fetch_ok = _fetch_all_pages(path, page_size=500, max_pages=40)
    rows = []
    for r in data:
        cont = ((r.get("custom") or {}).get(view, {}).get(field) or {}).get("value")
        if not cont:
            continue
        # One receipt's container attribute can list SEVERAL containers (confirmed). Parse
        # each ISO container token (4 letters + 6-7 digits) so a single-container query
        # matches a multi-container receipt and callers can flag the ~3% split case.
        conts = [m.upper() for m in re.findall(r"[A-Z]{4}\d{6,7}", cont.upper())] or [cont.strip().upper()]
        rows.append({"containers": conts, "container_raw": cont.strip(),
                     "receipt_nbr": (r.get("ReceiptNbr") or {}).get("value"),
                     "vendor_ref": (r.get("VendorRef") or {}).get("value") or ""})
    # Same bug class as discover_receipt_container_field(): don't cache a suspicious
    # empty result caused by an API failure as though it were a confirmed "zero receipts"
    # answer -- that would make every container look unresolved for the full 10-minute
    # TTL. A genuinely empty page-1 response (fetch_ok=True) is still cached normally; a
    # partial-but-nonempty result from a later page failing mid-pagination is also cached
    # (better than nothing, and it'll refresh again after the TTL either way).
    if fetch_ok or rows:
        _RECEIPTS_CACHE.update(rows=rows, ts=now, raw_total=len(data))
    return rows

def containers_to_pos(containers):
    """Resolve each container to its retail PO#(s) via Acumatica: container -> the PO
    Receipt(s) carrying it -> the retail order digits in that receipt's VendorRef header.
    Returns {container: [po, ...]}; an empty list means it didn't resolve (no receipt yet,
    or no order digits in the VendorRef) -- callers flag these rather than silently drop."""
    containers = [c.strip().upper() for c in containers if c]
    if not containers:
        return {}
    receipts = load_recent_receipts()
    by_container = {}
    for r in receipts:
        for c in r["containers"]:
            pos = by_container.setdefault(c, set())
            for n in _extract_order_tokens(r.get("vendor_ref")):
                pos.add(n)
    return {c: sorted(by_container.get(c, [])) for c in containers}

def container_scope(container):
    """Classify a single container for the NRT port-pickup path (returns (scope, pos)):
      - 'out_of_scope': every PO Receipt carrying it is 3PL-marked (MMX/4006/AMAZON/HG...)
        -> revenue is recognized at the 3PL, not at port; skip QUIETLY, not an exception.
      - 'in_scope': at least one in-scope order token (6-digit master or 8-9 digit Ecomm).
      - 'unresolved': a receipt exists but carries no in-scope token, OR no receipt found
        -> genuinely needs human review."""
    container = (container or "").strip().upper()
    receipts = [r for r in load_recent_receipts() if container in r.get("containers", [])]
    pos = sorted({n for r in receipts for n in _extract_order_tokens(r.get("vendor_ref"))})
    if pos:
        return "in_scope", pos
    if receipts and all(_is_3pl_vendor_ref(r.get("vendor_ref")) for r in receipts):
        return "out_of_scope", []
    return "unresolved", []

def master_multi_receipt_flags(containers):
    """For each queried container, True if picking it up doesn't imply the whole PO/SO is
    available to ship -- either of two cases:
      (a) same-receipt split: its PO Receipt also lists OTHER containers (one packing-list
          upload covering several containers for the same PO) -- the original check.
      (b) cross-receipt split: its resolved master/Ecomm token ALSO appears on a DIFFERENT
          PO Receipt (a PO whose containers arrived via SEPARATE packing-list uploads, each
          producing its own receipt that looks like a normal single-container order in
          isolation). Confirmed real: packing-list-acumatica's create_receipt() always PUTs
          a brand-new PurchaseReceipt with no lookup against an existing one for the same
          PO, so a cross-upload split leaves no trace on any single receipt's container
          field -- only a same-master-different-receipt match reveals it.
    Either case means the NRT auto-ship path refuses and flags for a human rather than
    shipping items that may still be afloat elsewhere. Pure client-side check over the
    already-cached load_recent_receipts() -- no new Acumatica calls.
    Known remaining gap (needs the PO-completeness check, not this function): a sibling
    container whose receipt doesn't exist in Acumatica AT ALL yet (still in transit / its
    packing list not yet processed) has nothing here to detect."""
    receipts = load_recent_receipts()
    token_receipts = {}
    for r in receipts:
        for tok in _extract_order_tokens(r.get("vendor_ref")):
            token_receipts.setdefault(tok, set()).add(r["receipt_nbr"])
    flags = {}
    for c in [x.strip().upper() for x in containers if x]:
        own = [r for r in receipts if c in r.get("containers", [])]
        own_receipt_nbrs = {r["receipt_nbr"] for r in own}
        same_receipt_multi = any(len(r["containers"]) > 1 for r in own)
        _, tokens = container_scope(c)
        cross_receipt_split = any(token_receipts.get(tok, set()) - own_receipt_nbrs for tok in tokens)
        flags[c] = same_receipt_multi or cross_receipt_split
    return flags

def resolve_pos_from_container(container):
    """All distinct internal Purchase Orders behind a container's receipt(s) -- usually
    one, but a container can appear on more than one receipt (confirmed real: e.g. two
    masters resolving to the same DC off one container, seen in production). Targeted,
    bounded $expand=Details fetch per receipt (NOT the header-only bulk cache) to read
    POOrderNbr/POOrderType. Returns a list, one entry per receipt: (po_type, po_nbr) if
    that receipt's Details agree on a single PO, else None -- a None means "couldn't
    resolve," which callers must treat as incomplete (fail closed), never skipped."""
    container = (container or "").strip().upper()
    receipts = [r for r in load_recent_receipts() if container in r.get("containers", [])]
    found = []
    for r in receipts:
        flt = urllib.parse.quote(f"ReceiptNbr eq '{r['receipt_nbr']}'")
        st, d = api("GET", f"{ENTITY}/PurchaseReceipt?$filter={flt}&$expand=Details")
        if st != 200 or not isinstance(d, list) or not d:
            found.append(None)
            continue
        details = d[0].get("Details") or []
        po_nbrs = {(dd.get("POOrderNbr") or {}).get("value") for dd in details if dd.get("POOrderNbr")}
        po_types = {(dd.get("POOrderType") or {}).get("value") for dd in details if dd.get("POOrderType")}
        if len(po_nbrs) == 1 and po_nbrs != {None}:
            found.append(((next(iter(po_types)) if po_types else None), next(iter(po_nbrs))))
        else:
            found.append(None)
    return found

def resolve_pos_by_master(container):
    """Per-master pairing of a container's receipts to their internal Purchase Orders --
    same targeted $expand=Details fetch as resolve_pos_from_container(), but keyed by the
    master/Ecomm token from each receipt's OWN VendorRef instead of returned as one flat
    list. Needed because a single pickup event can resolve to SEVERAL unrelated masters at
    once (confirmed real, 2026-07-27: container ONEU9300392 sits on 5 separate receipts,
    one per master, 141970/378306/645410/645411/645399) -- gating them as one aggregate
    unit wrongly held back 4 masters that were fully ready just because a 5th (645399,
    waiting on sibling container FSCU5863132) wasn't. Returns {master_token: (po_type,
    po_nbr) or None}; None means that receipt's Details didn't resolve to exactly one PO
    -- fail closed for that master only, not its siblings."""
    container = (container or "").strip().upper()
    receipts = [r for r in load_recent_receipts() if container in r.get("containers", [])]
    out = {}
    for r in receipts:
        tokens = _extract_order_tokens(r.get("vendor_ref"))
        if not tokens:
            continue
        flt = urllib.parse.quote(f"ReceiptNbr eq '{r['receipt_nbr']}'")
        st, d = api("GET", f"{ENTITY}/PurchaseReceipt?$filter={flt}&$expand=Details")
        ref = None
        if st == 200 and isinstance(d, list) and d:
            details = d[0].get("Details") or []
            po_nbrs = {(dd.get("POOrderNbr") or {}).get("value") for dd in details if dd.get("POOrderNbr")}
            po_types = {(dd.get("POOrderType") or {}).get("value") for dd in details if dd.get("POOrderType")}
            if len(po_nbrs) == 1 and po_nbrs != {None}:
                ref = ((next(iter(po_types)) if po_types else None), next(iter(po_nbrs)))
        for tok in tokens:
            out[tok] = ref
    return out

def po_completeness(po_type, po_nbr):
    """Is this Purchase Order fully received? Checks each Detail line's own `Completed`
    flag (Acumatica computes this directly from received-vs-ordered qty per line) rather
    than the header Status string.

    FIXED 2026-07-22 (real false-negative found in production): originally checked
    Status == 'Completed' only. But a PO that finishes receiving and later gets closed
    out (e.g. once billing/period-close wraps up) moves on to Status 'Closed' -- a LATER
    terminal status on this tenant, not an alternate one. Real confirmed case: PO 008174
    (container SEKU9013424) was fully received (Open Quantity 0 in Acumatica's own
    Purchase Orders export) but sat at Status 'Closed', so the old check wrongly left it
    'waiting' forever -- there's no future event that would ever move a Closed PO back to
    'Completed', so this wasn't just slow, it would never have shipped.

    Checking each line's own Completed flag is correct regardless of which terminal
    status string the header ends up showing -- and, unlike just also accepting 'Closed'
    outright, still correctly refuses a PO that was closed EARLY, before being fully
    received (Closed does not always mean fully received; a per-line Completed=false
    does reliably mean not received, so this is the safer signal to gate on either way).

    Exact eq filter, never substringof (500s on this tenant). FAILS CLOSED: any lookup
    error, a PO with no Detail lines, or an unreadable Completed flag is treated as NOT
    complete -- never silently 'ready to ship' on an ambiguous read."""
    if not po_nbr:
        return False, {"error": "no PO number"}
    flt = urllib.parse.quote(f"OrderNbr eq '{po_nbr}'")
    st, d = api("GET", f"{ENTITY}/PurchaseOrder?$filter={flt}&$expand=Details")
    if st != 200 or not isinstance(d, list) or not d:
        return False, {"error": f"PO lookup failed (status {st})", "po": po_nbr}
    status = (d[0].get("Status") or {}).get("value")
    details = d[0].get("Details") or []
    if not details:
        return False, {"error": "PO has no Detail lines to check", "po": po_nbr, "po_status": status}
    all_complete = all(bool((line.get("Completed") or {}).get("value")) for line in details)
    return all_complete, {"po": po_nbr, "po_status": status}

def expected_containers_for_master(master_token):
    """Every container Acumatica's OWN receipts say belongs to this master -- the union
    across every receipt whose VendorRef resolves to this master, regardless of how many
    separate uploads it took (mirrors the /diag po_completeness_probe pattern)."""
    containers = set()
    for r in load_recent_receipts():
        if master_token in _extract_order_tokens(r.get("vendor_ref")):
            containers.update(r.get("containers") or [])
    return containers

def confirmed_pickup_containers():
    """The definitive record of which containers have genuinely sent an 'Available for
    Pickup' NRT trigger, and the ship_date the agent recorded for each -- derived from
    agent_log.jsonl (append-only, permanent) rather than from any one master's own
    container_ledger.json entry.

    Why this has to be the source of truth rather than the ledger: container_ledger.json
    only ever gets a container recorded under whichever master(s) container_scope()
    happened to resolve to AT THE MOMENT the NRT trigger fired (see process_manual). If
    Acumatica had no receipt yet linking that container to any master at that instant --
    real confirmed case, 2026-07-24: FBIU5266985 triggered before receipts 007316-007324
    (which tie it to 9 masters) existed -- the resolved-token list was empty, so
    ledger_record() never ran, and the confirmation was silently dropped, permanently,
    since "Available for Pickup" only fires once per container. Scanning the permanent log
    instead means a real confirmation is never lost to Acumatica receipt timing, and
    every currently-stuck case gets picked up automatically the next time this is called --
    no manual backfill needed, it's recomputed fresh from data already on disk.

    Filters on action_taken == "create_shipment" (the tool was actually invoked), NOT
    classification == "nrt_available_for_pickup". Real bug caught 2026-07-28 testing this
    fix live: agent.py's own system prompt tells the agent to classify a genuine
    "Available for Pickup" email as nrt_waiting_on_containers whenever create_shipment
    comes back waiting_on_containers=true -- which is the COMMON case for any container in
    one of these multi-master groups, not the exception. Filtering on classification
    excluded almost every real trigger except the rare one that shipped immediately;
    action_taken is set unconditionally whenever the tool was called (see agent.py
    run_tool()'s create_shipment branch), regardless of what finish() classified it as.

    Local file read only, no live Acumatica calls. Returns {container: latest ship_date}."""
    out = {}
    for r in agent_log_read(limit=0):
        if r.get("action_taken") != "create_shipment":
            continue
        args = r.get("tool_args") or {}
        c = (args.get("container") or "").strip().upper()
        d = args.get("ship_date")
        if not c or not d:
            continue
        if c not in out or d > out[c]:
            out[c] = d
    return out

def containers_confirmed_available(master_token, current_container=None):
    """Has EVERY container Acumatica's receipts say belongs to this master ALSO been
    individually confirmed 'Available for Pickup' (or later) by its own NRT email --
    not just "the Purchase Order shows fully received in Acumatica"?

    Real incident, 2026-07-23/24 (Light Forever / L26US-051, then MRKU5545922 /
    MSGU9216100): a multi-container consolidated PO's underlying Purchase Order can show
    fully RECEIVED in Acumatica -- a warehouse-side fact, driven by whenever the packing
    list got processed into a receipt -- while one or more of its OWN containers have
    never sent an "Available for Pickup" NRT email at all. Confirmed real: MRKU5545922
    had ZERO NRT status emails ever, while its sibling MSGU9216100 had a complete, normal
    progression (Available -> Scheduled -> Picked Up -> Empty) -- and a shipment was
    created for POs depending on MRKU5545922 anyway, because ONE container's confirmation
    was enough to satisfy the (PO-receiving-only) gate. Revenue recognition is anchored to
    the port-pickup event (an NRT fact), not the warehouse-receiving event (an Acumatica
    fact) -- both must hold, not just the PO's own Status. Parker's rule, stated directly:
    a shipment must not be created until ALL of a PO's containers show Available for
    Pickup (or later).

    "Confirmed" = present in confirmed_pickup_containers() -- the permanent agent_log.jsonl
    record of every real NRT trigger, NOT container_ledger.json's per-master dict. Real bug
    found 2026-07-28: FBIU5266985 sent a genuine "Available for Pickup" email on 2026-07-24,
    correctly processed by the agent -- but at that moment Acumatica had NO receipt yet
    linking it to any master (those receipts, tying it to 9 masters, weren't created until
    ~2026-07-27/28). With zero resolved master tokens, ledger_record()'s "for token in
    resolved" loop ran zero times -- the confirmation was silently dropped, permanently,
    since that email never fires twice. Once those receipts appeared, all 9 masters
    correctly expected FBIU5266985 but could never see it confirmed. Deriving from the
    permanent log instead means a real confirmation is never lost to Acumatica receipt
    timing, and needs no manual backfill -- see confirmed_pickup_containers()'s docstring.

    current_container (FIXED 2026-08-03, real incidents: MRKU5545922 and GCXU5545290):
    the container whose NRT trigger is being processed THIS call must count as confirmed
    even though its own agent_log.jsonl entry doesn't exist yet -- log_run() only writes
    that entry at the END of process_manual(), well after this completeness check runs.
    Without this, a container's OWN first-ever trigger always saw itself as unconfirmed
    (confirmed_pickup_containers() can only see PAST entries), so any master whose only
    remaining gap was this exact confirmation stayed incorrectly "waiting" until some LATER
    event re-evaluated it -- a sibling's own trigger, or the recheck job, whichever came
    first. Both real cases resolved themselves on the next recheck, but cost up to a day's
    delay on orders that were actually ready to ship the whole time.
    Returns (all_confirmed, missing_containers, expected_containers)."""
    expected = expected_containers_for_master(master_token)
    confirmed = expected & set(confirmed_pickup_containers().keys())
    if current_container:
        confirmed = confirmed | (expected & {current_container.strip().upper()})
    missing = expected - confirmed
    return (not missing), sorted(missing), sorted(expected)

# ---------------- matching ----------------
_OPEN_ORDERS = {"rows": None, "ts": 0}
OPEN_TTL = 600   # cache open sales orders for 10 min

def load_open_orders(force=False):
    """Fetch all OPEN sales orders once (no slow 'contains' scan — just a Status
    filter), cache them, and reuse. Turns N table scans into one bounded fetch.

    FIXED 2026-08-05 (real bug, caught via /container-status showing "no Sales Order
    matched yet" for masters that plainly had shipped): this used a single unpaginated
    api() call -- fine while the open-order count stayed under Acumatica's default page
    size, but silently truncated once it didn't, with no error, just a quietly incomplete
    result cached for the full 10-minute TTL. Paginated the same proven way
    load_recent_receipts() already does."""
    now = time.time()
    if not force and _OPEN_ORDERS["rows"] is not None and now - _OPEN_ORDERS["ts"] < OPEN_TTL:
        return _OPEN_ORDERS["rows"]
    q = (f"{ENTITY}/SalesOrder?$filter=Status eq 'Open'"
         f"&$select=OrderType,OrderNbr,CustomerOrder,CustomerID,Status")
    # Larger page size than the 500 default (2026-08-05, cutting round-trips): if the
    # tenant caps $top lower server-side, OData clamps it silently rather than erroring, so
    # this is a safe thing to try without verifying a hard limit first.
    data, fetch_ok = _fetch_all_pages(q, page_size=2000, max_pages=20)
    rows = []
    for so in data:
        g = lambda k: (so.get(k) or {}).get("value")
        rows.append({"order_type": g("OrderType"), "order_nbr": g("OrderNbr"),
                     "cust_order": g("CustomerOrder") or "", "customer": g("CustomerID"),
                     "status": g("Status")})
    if fetch_ok or rows:
        _OPEN_ORDERS["rows"] = rows
        _OPEN_ORDERS["ts"] = now
    return rows

# Retail POs are a 6-digit MASTER number. In Acumatica each master is split into one
# Sales Order per DC (distribution center); the DC is a short numeric prefix on the
# CustomerOrder, so master 124940 appears as 06124940, 07124940, 01124940, ... (1 DC =
# 1 SO = 1 invoice). Matching the master to open orders MUST be an anchored suffix with a
# <=2-digit numeric DC prefix -- NOT a loose substring. A plain `master in cust_order`
# also hits mid-string (master 124940 matches 12494055, whose real master is 494055),
# which would ship the wrong customer. Anchoring to <DC><master>$ eliminates that.
# Matching MULTIPLE open orders for one master is EXPECTED (all DCs ship together) --
# it is not an ambiguity to flag.
DC_PREFIX_MAXLEN = 2  # DC-code length in front of the 6-digit master (S+F order scheme)

# Markers that flag a 3PL-bound receipt: those units are recognized at the 3PL LATER,
# not at port pickup, so they are OUT OF SCOPE for this project and must never match a
# sales order. Word-boundary matched against the VendorRef so they don't false-hit inside
# a longer order number. NOTE: "HG" here is the 3PL HomeGoods flow -- in-scope HomeGoods
# DC orders arrive with a 6-digit master, not an "HG" marker.
THREEPL_MARKERS = ("MMX", "AMAZON", "HG", "4003", "4006", "4007")
_THREEPL_RE = re.compile(r"(?<![A-Z0-9])(?:" + "|".join(THREEPL_MARKERS) + r")(?![A-Z0-9])")

def _is_3pl_vendor_ref(vendor_ref):
    return bool(_THREEPL_RE.search((vendor_ref or "").upper()))

def _extract_order_tokens(vendor_ref):
    """In-scope order numbers from a receipt VendorRef header: a 6-digit MASTER (DC-split,
    fans out to every DC order) or an 8-9 digit Ecomm number (exact, one order). Returns []
    for 3PL / out-of-scope refs so they never match a sales order."""
    if _is_3pl_vendor_ref(vendor_ref):
        return []
    return re.findall(r"\b(\d{6}|\d{8,9})\b", vendor_ref or "")

def _co_matches_master(cust_order, token):
    """token = an order number pulled from a receipt VendorRef. A 6-digit MASTER matches
    every DC-split order (<=2-digit numeric DC prefix + master, or the bare master). An
    8-9 digit Ecomm number matches its order EXACTLY (Ecomm is not DC-split)."""
    if cust_order == token:
        return True  # exact: Ecomm 8-9 digit, or a bare master with no DC prefix (Costco)
    if len(token) == 6 and cust_order.endswith(token):
        prefix = cust_order[:-len(token)]
        return prefix.isdigit() and 1 <= len(prefix) <= DC_PREFIX_MAXLEN
    return False

def find_sales_orders_batch(pos):
    """Match every retail-PO master against the cached open-order list locally (instant).
    One master normally matches SEVERAL open orders -- one per DC -- and that is expected;
    they ship and invoice together. See _co_matches_master for why this is an anchored
    suffix match (<DC><master>$) rather than a substring test."""
    orders = load_open_orders()
    results = {p: [] for p in pos}
    for o in orders:
        co = o["cust_order"]
        if not co:
            continue
        for p in pos:
            if _co_matches_master(co, p):
                results[p].append(o)
    return results

_ALL_ORDERS = {"rows": None, "ts": 0}
ALL_ORDERS_TTL = 3600  # non-open orders barely change -- hourly is plenty, unlike the 10-min open cache

def load_all_orders(force=False):
    """Every sales order regardless of status -- a separate, longer-lived cache from
    load_open_orders(), used ONLY as a fallback (see find_fulfilled_sales_orders) when a
    master has zero OPEN matches. Real case, 2026-07-29: the missed-trigger-backfill fix
    worked through a large backlog of old NRT emails at once, and MANY of the masters it
    tried to ship turned out to be legacy orders Parker's team had already fulfilled
    (manually, before this automation existed) -- 'no open sales order' flagged every one
    of them as needing review, even though nothing was actually wrong. Same shape as
    load_open_orders(), just without the Status filter.

    FIXED 2026-08-05 (real bug, caught via /container-status showing "no Sales Order
    matched yet" for masters that plainly had shipped): a single unpaginated api() call
    over EVERY sales order regardless of status -- the company's entire order history --
    was always going to hit Acumatica's default page-size truncation eventually, silently
    and with no error. Every caller of this function (find_fulfilled_sales_orders,
    find_any_sales_orders_batch, the stale-ledger check in process_manual) was reading a
    quietly incomplete result for up to an hour at a time. Paginated the same proven way
    load_recent_receipts() already does."""
    now = time.time()
    if not force and _ALL_ORDERS["rows"] is not None and now - _ALL_ORDERS["ts"] < ALL_ORDERS_TTL:
        return _ALL_ORDERS["rows"]
    select = "$select=OrderType,OrderNbr,CustomerOrder,CustomerID,Status"
    # Parker's ask, 2026-08-05: bound this to the last 6 months instead of the whole
    # order history -- RequestDate is the field this tenant's own "Container SO Lookup" GI
    # displays as "Requested On" (confirmed real data, not a guess at the API field name).
    # FAILS OPEN, not closed, on this specific filter: if RequestDate turns out to be the
    # wrong field (400 on page 0), fall back to the unfiltered fetch rather than silently
    # returning nothing for the rest of this cache cycle -- that exact silent-empty failure
    # is what caused today's "no Sales Order matched yet" incident in the first place.
    cutoff = (datetime.date.today() - datetime.timedelta(days=182)).isoformat()
    filtered_q = (f"{ENTITY}/SalesOrder?$filter=RequestDate ge datetimeoffset'{cutoff}T00:00:00Z'"
                  f"&{select}")
    data, fetch_ok = _fetch_all_pages(filtered_q, page_size=2000, max_pages=75)
    if not fetch_ok and not data:
        data, fetch_ok = _fetch_all_pages(f"{ENTITY}/SalesOrder?{select}", page_size=2000, max_pages=75)
    rows = []
    for so in data:
        g = lambda k: (so.get(k) or {}).get("value")
        rows.append({"order_type": g("OrderType"), "order_nbr": g("OrderNbr"),
                     "cust_order": g("CustomerOrder") or "", "customer": g("CustomerID"),
                     "status": g("Status")})
    if fetch_ok or rows:
        _ALL_ORDERS["rows"] = rows
        _ALL_ORDERS["ts"] = now
    return rows

FULFILLED_SO_STATUSES = {"Completed", "Closed", "Shipping"}  # already has a shipment; not just non-open
# "Shipping" confirmed real, 2026-07-31 (masters 362040/041/044/045/328810): Acumatica flips a
# Sales Order's own status to "Shipping" the moment ANY shipment is created against it -- well
# before that shipment is confirmed/invoiced (Completed/Closed). Without it here, an order in
# this perfectly normal in-progress state matched NEITHER the open-orders search (order is no
# longer "Open") NOR the old two-value fulfilled check -- read as "no open sales order," a false
# exception for an order that's actually fine, and kept the ledger stuck on "partial" forever
# (every /ledger/recheck re-hit the same false negative). Still deliberately NOT "anything
# non-Open" -- Cancelled/Voided/Hold etc. remain correctly excluded, see this function's
# docstring below.

def find_fulfilled_sales_orders(pos):
    """For masters with zero OPEN matches: is there an order instead that already has a
    shipment against it -- Completed/Closed (fully invoiced), or Shipping (a shipment exists
    but isn't confirmed/invoiced yet -- see FULFILLED_SO_STATUSES)? Distinguishes 'already
    handled before/outside this automation' (no action needed, not a real problem) from a
    genuine gap (no sales order exists at all, which DOES need a human). Only meaningfully
    called on that rare fallback path, not the normal hot path.

    Deliberately an ALLOW-list (Completed/Closed only), not "anything non-Open" -- real bug
    caught 2026-07-29 before it shipped: the first version treated Cancelled/Voided orders
    the same as genuinely fulfilled ones. A cancelled order means the SALE was abandoned,
    not that goods shipped -- calling that "no action needed" could mask a real problem
    (goods physically arrived with no valid order left to ship them against). Anything not
    in this allow-list (Cancelled, Voided, Credit Hold, Back Order, Pending Approval, ...)
    correctly falls through to "genuinely needs review" instead."""
    orders = [o for o in load_all_orders() if o["status"] in FULFILLED_SO_STATUSES]
    results = {p: [] for p in pos}
    for o in orders:
        co = o["cust_order"]
        if not co:
            continue
        for p in pos:
            if _co_matches_master(co, p):
                results[p].append(o)
    return results

def find_any_sales_orders_batch(pos):
    """Same DC-anchored match as find_sales_orders_batch(), but over EVERY order regardless
    of status -- for the one place that genuinely needs "does an order for this master exist
    at all, in any state" rather than "is it open" or "is it done": the stale-ledger
    verification in process_manual() (does a real shipment still exist for a master the
    ledger claims is already 'shipped'?). Using the open-only search there missed a Shipping-
    or Completed/Closed-status order (see FULFILLED_SO_STATUSES's docstring for the real
    Shipping-status incident) -- the master WAS genuinely still shipped, but the narrower
    open-only search found nothing, wrongly read as "ledger stale," and bounced the master
    back to 'waiting' for no reason every time that check ran."""
    orders = load_all_orders()
    results = {p: [] for p in pos}
    for o in orders:
        co = o["cust_order"]
        if not co:
            continue
        for p in pos:
            if _co_matches_master(co, p):
                results[p].append(o)
    return results

# ---------------- shipment creation (validate via /diag first) ----------------
def _latest_shipment_for_order(order_type, order_nbr, retries=3, delay=1.0):
    """Find the most recent real Shipment for an order, right after CreateShipment's
    long-running action reports done. FIXED (2026-07-13): originally filtered the Shipment
    entity with `substringof(...)`, which this tenant returns a 500 for -- confirmed via a
    real run where two shipments (017236/017237) genuinely existed in Acumatica but this
    lookup reported "not found" every single time, even after retrying, because the query
    itself was broken, not merely racing Acumatica's indexing. Use the same GET-by-key +
    $expand=Shipments pattern _order_pipeline() already uses successfully on this tenant
    instead. Small retry kept only for genuine propagation lag, not as the primary fix."""
    for attempt in range(retries):
        st, d = api("GET", f"{ENTITY}/SalesOrder/{order_type}/{order_nbr}?$expand=Shipments")
        if st == 200 and isinstance(d, dict):
            # Real shipment records carry a ShipmentNbr; credit-memo/auto-issue rows don't.
            ship_recs = [s for s in (d.get("Shipments") or []) if _sh_field(s, "ShipmentNbr")]
            if ship_recs:
                sh = ship_recs[-1]
                # Also capture the record's own system "id" GUID -- Acumatica's contract API
                # identifies a record for UPDATE by this id, not by the natural key
                # (ShipmentNbr); every entity sub-record carries it for free, no extra call.
                return {"shipment_nbr": _sh_field(sh, "ShipmentNbr"), "id": sh.get("id")}
        if attempt < retries - 1:
            time.sleep(delay)
    return None

def _failure_reason(order_type, order_nbr, raw_error=None):
    """When CreateShipment fails, look at the order to give a human reason
    instead of Acumatica's generic 'Operation failed' stack trace.

    raw_error (FIXED 2026-08-03, real incident: 17+ orders across masters 036239/039837/
    039839/041000 all failed with Acumatica's own "does not contain any items planned for
    shipment on '<date>'" error, while every check below -- Hold, CreditHold, existing
    shipment, Status -- came back clean, so this function fell all the way through to its
    generic fallback and reported "backordered or no stock," which actively misled the
    investigation into checking inventory that was never the problem. The real cause: the
    order's own Scheduled Shipment date was later than the requested ship_date, so Acumatica
    correctly refused to plan anything for the earlier date. Checked here, after the specific
    ground-truth checks above (which read the order's actual current state) but before the
    generic fallback, so a real Hold/CreditHold/Status finding still wins if present."""
    try:
        st, d = api("GET", f"{ENTITY}/SalesOrder/{order_type}/{order_nbr}?$expand=Shipments")
    except Exception:
        return None
    if st != 200 or not isinstance(d, dict):
        return None
    g = lambda k: (d.get(k) or {}).get("value")
    if g("Hold"): return "Order is On Hold in Acumatica"
    if g("CreditHold"): return "Customer is on Credit Hold"
    shs = d.get("Shipments") or []
    if any((s.get("ShipmentNbr") or {}).get("value") for s in shs):
        return "A shipment already exists for this order"
    stt = g("Status")
    if stt and stt != "Open":
        return f"Order status is '{stt}' — not shippable"
    if raw_error and "does not contain any items planned for shipment" in str(raw_error):
        return ("Order's Scheduled Shipment date is later than the requested ship date -- "
                "Acumatica won't plan a shipment before an order's own scheduled date. "
                "Check/update the Scheduled Shipment field on this Sales Order.")
    return "Nothing available to ship (backordered or no stock in the ship-from warehouse)"


def set_shipment_date_and_container(shipment_id, ship_nbr, date=None, container_ref=None, attempt_put=True):
    """PUT ShipmentDate (and the container custom field) onto an EXISTING shipment, then
    read it back to verify the date actually stuck.

    2026-07-14: earlier attempts identified the record by its NATURAL key (ShipmentNbr) --
    either in the URL path (every variant 500'd identically: "Invalid uri structure",
    misrouted into EntityController.PutFile) or in the JSON body of a bare-collection PUT
    (Acumatica read the absence of an "id" as "no existing record" and attempted an INSERT
    of a new blank shipment -- caught safely that time by a required-field validation error,
    but not something to keep testing against production). Acumatica's contract API
    identifies a record for UPDATE by its internal system "id" GUID, not the natural key --
    GET-by-natural-key is a convenience for reads only. Looking a shipment's id up directly
    by ShipmentNbr also proved unreliable three different ways (URL-path key, $select=id,
    an exact-filter list query all failed differently) -- shipment_id must instead come from
    _latest_shipment_for_order()'s $expand=Shipments read via the parent order, which is
    proven to work. Never invented or left empty, since an empty/missing id in the body is
    exactly the condition that caused the earlier accidental-insert attempt.

    2026-07-22: the PUT itself is confirmed to always fail (500, wrong id-space -- the id
    from SalesOrder's Shipments sub-view isn't the Shipment entity's own id) -- every real
    create_shipment run since 2026-07-14 has hit this, it just went unnoticed because the
    date happened to match "today" anyway. attempt_put=False (used by create_shipment's
    automated path) skips the PUT and its guaranteed-failure round-trip entirely, keeping
    only the verification read -- one fewer wasted Acumatica call per shipment, which
    matters when a single /autoship call fans out to several DC orders in one request and
    the extra round-trips were stacking up toward real request-timeout risk. /fixshipdate
    (a human explicitly asking to correct a date) still attempts the real PUT via the
    default attempt_put=True, since that's the entire point of calling it by hand."""
    out = {}
    if not shipment_id:
        out["ship_date_put_error"] = "no shipment id available -- refusing to PUT without one (would risk an insert, not an update)"
        return out
    if attempt_put:
        update = {"id": shipment_id}
        if date: update["ShipmentDate"] = {"value": date}
        if container_ref and CFG["container_field"]:
            update.setdefault("custom", {}).setdefault("Document", {})[CFG["container_field"]] = \
                {"type": "CustomStringField", "value": container_ref}
        if len(update) > 1:  # more than just the id -- something to actually change
            pst, presp = api("PUT", f"{ENTITY}/Shipment", update)
            if pst not in (200, 204):
                out["ship_date_put_status"] = pst
                out["ship_date_put_error"] = presp if isinstance(presp, str) else json.dumps(presp)[:500]
    vst, vdata = api("GET", f"{ENTITY}/Shipment/{ship_nbr}?$select=ShipmentDate")
    actual = ((vdata.get("ShipmentDate") or {}).get("value") or "")[:10] \
        if vst == 200 and isinstance(vdata, dict) else None
    out["ship_date_verified"] = bool(date) and actual == date
    if date and actual and actual != date:
        out["ship_date_actual"] = actual
    return out

def _sync_scheduled_shipment_date(order_type, order_nbr, target_date):
    """Acumatica's CreateShipment refuses to plan anything for a date EARLIER than the
    Sales Order's own Requested On field (SOOrder.RequestDate on the DAC; confirmed via
    live Inspect Element on 2026-08-03 -- Data Class SOOrder, Data Field RequestDate). The
    literal error is "does not contain any items planned for shipment on '<date>'", which
    has nothing to do with stock -- see _failure_reason()'s docstring. Confirmed real,
    2026-08-03: 17+ orders across masters 036239/039837/039839/041000/041016/041017 all
    failed this way. RequestedOn gets set to an original lead-time estimate at order
    creation; when the container arrives faster than that estimate, the order is genuinely
    ready before its own pre-set schedule catches up.

    UNVERIFIED against this tenant: the JSON field name used below (RequestedOn) is
    Acumatica's standard default-endpoint name for this DAC field, but this tenant's PUT
    behavior has surprised this codebase before (see set_shipment_date_and_container's
    docstring -- Shipment required an internal id, not its natural key, and every
    key-format guess failed a different way). Test this against one real stuck order
    before trusting it at scale.

    Fail-soft by design: any failure here (wrong field name, permission, network) is
    swallowed and logged in the return dict, never raised -- create_shipment() proceeds to
    attempt CreateShipment regardless, so worst case is the same already-handled failure,
    not a new one."""
    try:
        st, d = api("GET", f"{ENTITY}/SalesOrder/{order_type}/{order_nbr}?$select=RequestedOn")
        if st != 200 or not isinstance(d, dict):
            return {"requested_on_sync": f"GET failed (status {st})"}
        current = ((d.get("RequestedOn") or {}).get("value") or "")[:10]
        if not current or not target_date or current <= target_date:
            return None  # already fine, or nothing usable to compare -- leave it alone
        pst, presp = api("PUT", f"{ENTITY}/SalesOrder",
                          {"OrderType": {"value": order_type}, "OrderNbr": {"value": order_nbr},
                           "RequestedOn": {"value": target_date}})
        out = {"requested_on_was": current, "requested_on_target": target_date,
               "requested_on_synced": pst in (200, 204)}
        if pst not in (200, 204):
            out["requested_on_put_error"] = presp if isinstance(presp, str) else json.dumps(presp)[:300]
        return out
    except Exception as e:
        return {"requested_on_sync_error": str(e)}

def create_shipment(order_type, order_nbr, container_ref=None, ship_date=None, po=None):
    # ship_date is required by the caller (process_manual hard-stops before this
    # point if it's missing, unless dry_run) -- no more silent fallback to a synced
    # date or to "today". po is accepted for logging only.
    # NOTE: the ShipmentDate action PARAMETER below is NOT reliably honored by Acumatica --
    # confirmed via a real run where the resulting shipment came back dated "today" despite
    # this parameter. Kept here in case it helps in some configs, but the real mechanism is
    # the corrective PUT + verification read further down, right after the shipment exists.
    date = ship_date
    sync_result = _sync_scheduled_shipment_date(order_type, order_nbr, date) if date else None
    params = {}
    if date: params["ShipmentDate"] = {"value": date}
    if CFG["warehouse"]: params["WarehouseID"] = {"value": CFG["warehouse"]}
    body = {"entity": {"OrderType": {"value": order_type}, "OrderNbr": {"value": order_nbr}}, "parameters": params}
    st, resp, headers = api_with_headers("POST", f"{ENTITY}/SalesOrder/CreateShipment", body)
    res = {"order": f"{order_type} {order_nbr}", "invoke_status": st, "ship_date": date}
    if sync_result:
        res["scheduled_shipment_sync"] = sync_result

    # CreateShipment is a LONG-RUNNING action: 202 + Location means "accepted, still
    # processing", not "done". Poll Location until it stops returning 202 -- otherwise a
    # 202 gets reported as success even when the action goes on to fail with a business
    # rule (e.g. "no items are available for shipment"), which is exactly what happened
    # before this fix: a real failure was logged as created=true.
    location = headers.get("location")
    if st == 202 and location:
        poll_path = location.replace(CFG["base_url"], "") if location.startswith("http") else location
        for _ in range(15):  # ~15s max; a single-order action normally finishes in 1-3s
            time.sleep(1)
            st, resp, _ = api_with_headers("GET", poll_path)
            if st != 202:
                break
        else:
            # Before giving up as "unclear, check manually": is a shipment actually there
            # despite the slow/unresponsive poll? Real case, 2026-07-29 (SZLU9831203): this
            # branch always reported ambiguous even when a shipment plausibly existed,
            # forcing a manual Acumatica check every single time a poll ran long --
            # _latest_shipment_for_order() is the SAME proven check used for the normal
            # success path two lines below; it was just never tried here.
            ship = _latest_shipment_for_order(order_type, order_nbr, retries=1, delay=0)
            if ship:
                res.update(created=True, verified=True, shipment_nbr=ship.get("shipment_nbr"),
                           note="Acumatica's action didn't finish polling within 15s, but a "
                                "shipment was confirmed to exist on a direct check.")
                res.update(set_shipment_date_and_container(ship.get("id"), ship.get("shipment_nbr"),
                                                             date, container_ref, attempt_put=False))
            else:
                res.update(created=False, verified=False,
                           error="Acumatica did not finish processing within 15s (still 202), and no "
                                 "shipment was found on a direct check -- check manually.")
            return res

    res["created"] = st in (200, 204)
    if res["created"]:
        ship = _latest_shipment_for_order(order_type, order_nbr)
        res["shipment_nbr"] = ship.get("shipment_nbr") if ship else None
        if ship:
            # attempt_put=False: the PUT is confirmed to always fail here (wrong id-space) --
            # skip it in this automated path to save a guaranteed-wasted round-trip per
            # order, which matters when one /autoship call fans out to several DC orders.
            res.update(set_shipment_date_and_container(ship.get("id"), ship.get("shipment_nbr"),
                                                         date, container_ref, attempt_put=False))
        res["verified"] = bool(ship)
        if not ship:
            # Acumatica's action reported done, but no shipment can be found for this
            # order -- don't claim success on an outcome we can't actually verify.
            res["created"] = False
            res["error"] = "action completed but no resulting shipment was found for this order"
    else:
        res["error"] = resp if isinstance(resp, str) else json.dumps(resp)[:500]
        res["reason"] = _failure_reason(order_type, order_nbr, raw_error=res["error"])
    return res

# ---------------- run log ----------------
def log_run(entry):
    try:
        os.makedirs(TOKEN_DIR, exist_ok=True)
        entry["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(RUNS_PATH, "a") as f: f.write(json.dumps(entry) + "\n")
    except Exception: pass

def _render_shipment_email_html(event):
    """Pre-built, email-safe HTML for the shipment-created notification -- sent as-is in
    the webhook payload (`email_body_html`) so the Power Automate flow just drops ONE
    dynamic-content token into the email body, instead of building/styling a table itself.
    Deliberately NOT the dashboard's own CSS (custom properties, flexbox) -- email clients
    (especially Outlook desktop's Word rendering engine) need inline styles and table-based
    layout, no external/embedded stylesheet reliance. Colors match the dashboard's design
    tokens by value (sand/paper/stone/taupe/moss/rust) so this still reads as the same
    product, not a mismatched bolt-on."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    orders = event.get("orders") or []
    rows_html = "".join(
        f'<tr>'
        f'<td style="padding:8px 10px;border-bottom:1px solid #ddd5c4;font-size:13px">{esc(o.get("po"))}</td>'
        f'<td style="padding:8px 10px;border-bottom:1px solid #ddd5c4;font-size:13px">{esc(o.get("order"))}</td>'
        f'<td style="padding:8px 10px;border-bottom:1px solid #ddd5c4;font-size:13px">{esc(o.get("customer"))}</td>'
        f'<td style="padding:8px 10px;border-bottom:1px solid #ddd5c4;font-size:13px;font-weight:600">{esc(o.get("shipment_nbr"))}</td>'
        f'</tr>'
        for o in orders)
    table_html = (
        '<table style="width:100%;border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif">'
        '<tr style="background:#efece3;text-align:left">'
        '<th style="padding:8px 10px;font-size:12px;color:#7d7363;text-transform:uppercase;letter-spacing:.03em">Master PO</th>'
        '<th style="padding:8px 10px;font-size:12px;color:#7d7363;text-transform:uppercase;letter-spacing:.03em">Order</th>'
        '<th style="padding:8px 10px;font-size:12px;color:#7d7363;text-transform:uppercase;letter-spacing:.03em">Customer</th>'
        '<th style="padding:8px 10px;font-size:12px;color:#7d7363;text-transform:uppercase;letter-spacing:.03em">Shipment #</th>'
        f'</tr>{rows_html}</table>') if orders else ""
    meta_rows = "".join(
        f'<tr><td style="padding:2px 0;color:#7d7363;font-size:13px;width:150px;vertical-align:top">{label}</td>'
        f'<td style="padding:2px 0;color:#38352f;font-size:13px">{esc(value) if value else "&mdash;"}</td></tr>'
        for label, value in [
            ("Container", event.get("container")),
            ("Ship date", event.get("ship_date")),
            ("Email received", event.get("email_received_at")),
            ("Source", event.get("source")),
            ("Acumatica user", event.get("acumatica_user")),
        ])
    still_waiting = event.get("still_waiting_masters")
    waiting_html = (
        f'<div style="margin-top:14px;padding:10px 14px;background:#e9f0f1;color:#5d7682;'
        f'border-radius:8px;font-size:13px">Still waiting on: {esc(", ".join(still_waiting))}</div>'
    ) if still_waiting else ""
    anomalies = event.get("anomalies")
    anomalies_html = (
        '<div style="margin-top:10px;padding:10px 14px;background:#f9ece3;color:#b0653a;'
        'border-radius:8px;font-size:13px">&#9888; Needs review:<br>' +
        "<br>".join(esc(a.get("note")) for a in anomalies) + '</div>'
    ) if anomalies else ""
    created_count = event.get("created_count") or 0
    plural = "" if created_count == 1 else "s"
    return (
        '<div style="font-family:Segoe UI,Arial,sans-serif;max-width:640px;margin:0 auto;'
        'background:#fbf9f5;border:1px solid #ddd5c4;border-radius:12px;overflow:hidden">'
        f'<div style="background:#5a7d5a;color:#fbf9f5;padding:16px 20px;font-size:16px;font-weight:600">'
        f'&#10003; {created_count} shipment{plural} created</div>'
        f'<div style="padding:16px 20px">'
        f'<table style="width:100%;margin-bottom:16px">{meta_rows}</table>'
        f'{table_html}{waiting_html}{anomalies_html}'
        f'</div>'
        f'<div style="padding:12px 20px;border-top:1px solid #ddd5c4;font-size:11px;color:#7d7363">'
        f'Full history: {esc(CFG.get("public_url"))}/history</div>'
        '</div>'
    )

def notify_shipment_created(event):
    """Fire a real-time notification the moment shipments are actually created (created>0
    only -- waiting/anomaly/no-op outcomes don't fire this, they're covered by the daily
    digest and the CSV export instead). POSTs to a Power Automate 'When an HTTP request is
    received' trigger URL (SHIPMENT_WEBHOOK_URL) -- that flow formats and sends the actual
    email/Teams message under Parker's own O365 login, same philosophy as the existing
    daily digest (this app never touches email credentials directly).

    Includes a pre-rendered `email_body_html` field (see _render_shipment_email_html) so
    the Power Automate flow's email body is just ONE dynamic-content token, not a hand-
    built table/expression -- avoids the exact fragility already hit once building the
    daily-digest flow (a complex expression typed directly into the Body broke rendering;
    see the Notification Flow Guide's 'Power Automate lessons learned'). The raw structured
    fields (container, orders, etc.) stay in the payload too, for a Teams adaptive card or
    any other consumer that wants the data instead of pre-built HTML.

    Best-effort, fire-and-forget: a notification failure must NEVER affect the real
    shipment-creation result the caller already has in hand -- caught and swallowed here,
    logged to stdout only (visible in Render logs if it's ever needed for debugging)."""
    if not SHIPMENT_WEBHOOK_URL:
        return
    try:
        payload = dict(event)
        payload["email_body_html"] = _render_shipment_email_html(event)
        req = urllib.request.Request(
            SHIPMENT_WEBHOOK_URL, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=15)
    except Exception as e:
        print(f"[notify_shipment_created] webhook call failed (non-fatal): {e}")

def history(limit=200):
    """Every non-dry-run process runs through here permanently (ship_runs.jsonl
    on the persistent disk) -- nothing is ever deleted from the file itself.
    `limit` only caps how many rows a given caller wants back."""
    out = []
    try:
        with open(RUNS_PATH) as f:
            out = [json.loads(l) for l in f if l.strip()]
    except Exception: pass
    out = list(reversed(out))
    return out[:limit] if limit else out

# Columns for the CSV/Excel export -- one row per shipment outcome, covering successes
# AND flagged/exceptions (see export_history_rows()). Fixed order/set so the export has a
# stable shape run to run, regardless of which optional fields a given row happens to have.
EXPORT_COLUMNS = ["ts", "status", "source", "container", "master_po", "order", "customer",
                   "shipment_nbr", "created", "ship_date", "email_received_at",
                   "acumatica_user", "reason", "note"]

def export_history_rows(limit=0):
    """Flatten history() into one row per shipment/order OUTCOME for the CSV/Excel export
    -- covers successes (created/already_fulfilled/partial/failed/no_matches, one row per
    matched order, from the `orders` list) AND flagged/exception outcomes (out_of_scope/
    unresolved/anomaly/waiting), which only exist as RUN-level fields with no per-order
    breakdown -- those get one summary row for the whole event instead. Requires the
    logging-gap fix (every process_manual() outcome now reaches log_run(), not just ones
    that get to the creation loop) to actually be complete; before that fix, recheck-
    triggered waiting/exception outcomes were invisible to this export entirely.
    Local file read only, no live Acumatica calls."""
    rows = []
    for run in history(limit=limit):
        base = {"ts": run.get("ts"), "status": run.get("status"),
                "source": run.get("document") or run.get("user") or "",
                "container": run.get("containers"), "acumatica_user": run.get("acumatica_user"),
                "ship_date": run.get("ship_date"), "email_received_at": run.get("email_received_at")}
        orders = run.get("orders") or []
        if orders:
            for o in orders:
                rows.append({**base, "master_po": o.get("po"), "order": o.get("order"),
                             "customer": o.get("customer"), "shipment_nbr": o.get("shipment_nbr"),
                             "created": bool(o.get("created")), "reason": o.get("reason"), "note": None})
        else:
            note = run.get("note")
            anomalies = run.get("anomalies")
            if anomalies:
                anomaly_text = "; ".join(a.get("note", "") for a in anomalies if a.get("note"))
                note = f"{note} -- {anomaly_text}" if note else anomaly_text
            rows.append({**base, "master_po": None, "order": None, "customer": None,
                         "shipment_nbr": None, "created": False, "reason": None, "note": note})
    return rows

def _flagged_row_masters(r):
    """Every master/PO token an already-flagged agent_log row's OWN stored tool_result
    named at decision time (from data.rows, or data.anomalies) -- pure local read of data
    already on the row, no live call. Used by _find_later_success() to match a later
    resolving run by shared master, not just by container name.

    FIXED 2026-08-03, real incident: an anomaly response (reason=pickup_after_already_
    shipped, e.g. master 642058's siblings SEGU9247979/SZLU9148202/TTNU8872610) stores its
    master token(s) under data.anomalies (each entry: {"master": ..., "note": ...,
    "ledger_entry": ...}), not data.rows -- rows is only populated on the normal
    completeness-gate response shape. Without reading anomalies too, this always returned
    an empty set for anomaly-flagged rows, so _find_later_success() fell back to
    container-only matching -- which is exactly the match that fails for a sibling
    container that was never personally the trigger of the later successful run (see
    container_ship_history()'s docstring for the same underlying pattern). Genuinely
    unresolved anomalies (no later run ever shows the master shipped) are unaffected --
    this only lets ALREADY-resolved ones surface as "Resolved on retry" instead of sitting
    flagged forever."""
    data = ((r or {}).get("tool_result") or {}).get("data") or {}
    from_rows = {row.get("po") for row in (data.get("rows") or []) if row.get("po")}
    from_anomalies = {a.get("master") for a in (data.get("anomalies") or []) if a.get("master")}
    return from_rows | from_anomalies

def _find_later_success(container, after_ts, hist_rows, master_tokens=None):
    """Did a LATER run (e.g. a manual retry after a timeout exception) succeed for this
    same container? agent_log.jsonl is append-only by design (a permanent record of what
    the agent decided at the time) -- a retry never edits an old flagged row, it just adds
    a new one to ship_runs.jsonl. Without this check, a resolved exception sits flagged
    forever, which reads as an open problem long after it's actually been fixed. Pure
    local-file lookup (history() reads ship_runs.jsonl) -- no live Acumatica calls, cheap
    to run per row on every page render.

    "Success" is EITHER a real shipment created (status=='ok' and created), OR every
    RELEVANT PO in that later run resolving to already_fulfilled (see
    find_fulfilled_sales_orders()) -- real gap found 2026-07-29: an "already fulfilled"
    outcome has created=0/status='no_matches' (nothing to create, it's already done), so
    without this it would never show as resolved even after a fresh recheck correctly
    recognized it -- old flagged rows from before that fix deployed would stay flagged
    forever despite nothing being wrong.

    master_tokens (optional): the master tokens THIS flagged row's own tool_result already
    named (via _flagged_row_masters) -- matches a later run by shared master, not just by
    container name, since a multi-master group's resolving event may be triggered by a
    DIFFERENT sibling container than the one this row named. Real case, 2026-07-29:
    TCLU8945399/KKFU8019382/TGBU9728306 shared masters with siblings (BSIU9862220,
    TCLU9773571, TCLU9422089...) that resolved via a different container in the same
    recheck run -- container-only matching left them flagged forever even though their
    masters were genuinely fine."""
    if not container or not after_ts:
        return None
    master_tokens = master_tokens or set()
    for h in hist_rows:
        if h.get("ts", "") <= after_ts:
            continue
        h_orders = h.get("orders") or []
        h_masters = {o.get("po") for o in h_orders if o.get("po")}
        # Exact token match, not a bare substring check -- see container_ship_history()'s
        # comment for why `container in "..."` risks a false match against a sibling
        # container ref in the same run.
        h_containers = {c.strip() for c in (h.get("containers") or "").split(",") if c.strip()}
        by_container = container in h_containers
        by_master = bool(master_tokens) and bool(master_tokens & h_masters)
        if not (by_container or by_master):
            continue
        if h.get("status") == "ok" and h.get("created"):
            return h
        relevant = [o for o in h_orders if o.get("po") in master_tokens] if by_master and not by_container else h_orders
        if relevant and all(str(o.get("reason") or "").startswith("already fulfilled") for o in relevant):
            return h
    return None

def container_ship_history(container):
    """Has a shipment already been created off THIS container? For the mailbox-agent to
    call on every NRT status email, not just "Available for Pickup" triggers.

    Real incident, 2026-07-23: NRT sent a genuine "Available for Pickup" email for
    TRHU7302491/KKFU8060560, which correctly triggered create_shipment (30 shipments
    created, exactly as designed) -- then NRT sent a CONTRADICTORY "Scheduled for
    Pickup" email for the SAME containers 45 minutes later, walking the status backward.
    That second email correctly wasn't a trigger, so the agent logged "no action" -- but
    had no way to know a shipment had just been created off what turned out to be a
    premature/erroneous notice from NRT itself. Nothing here was wrong: the resolution
    chain, the completeness gate, and the LLM's reading of both emails were all accurate
    to what NRT actually sent -- the source system contradicted itself.

    This makes that contradiction visible in real time instead of requiring someone to
    notice it days later by cross-referencing exports by hand: the agent checks this for
    EVERY email regardless of status, and if a shipment already exists for this container
    while the CURRENT status has moved backward, that's flagged as an exception. Checks
    the permanent history file, not just the current batch, so it also catches the
    correction arriving in a LATER cron cycle, not only the same one. Local file read
    only, no live Acumatica calls.

    FIXED 2026-08-03, real incident: master 642058's own 5 containers (SZLU9148202,
    KKFU6781146, SEGU9247979, TTNU8872610, TCLU1353206) arrived as 5 separate real NRT
    events over ~2 days -- only the LAST one to arrive actually completed the master's
    confirmed-container set and triggered creation, so only THAT container's literal
    string ended up in a successful run's own "containers" field (which is just the single
    container parameter that happened to trigger process_manual, not every container
    involved). The other 4 -- equally real, equally part of the same already-shipped
    order -- always read shipped=false against the OLD exact-trigger check below, forever,
    since they were never personally the one that triggered a successful run. That falsely
    tripped the missed-trigger-backfill logic days later when NRT sent their NEXT
    lifecycle-stage email ("Scheduled for Pickup"), re-firing create_shipment for containers
    that had already done their job. Checking the newer "all_confirmed_containers" field
    (every container actually confirmed for whichever master(s) shipped in that run, not
    just the trigger) fixes this going forward; the exact-trigger check below stays as a
    fallback for older log entries recorded before this field existed."""
    if not container:
        return {"shipped": False}
    for h in history(limit=0):
        all_confirmed = h.get("all_confirmed_containers")
        if all_confirmed and container in all_confirmed:
            return {"shipped": True, "ts": h.get("ts"),
                    "master_pos": sorted({o.get("po") for o in (h.get("orders") or []) if o.get("po")})}
        # Fallback for log entries recorded before all_confirmed_containers existed --
        # exact token match against the ", "-joined trigger field (see process_manual()'s
        # container_ref), not a bare substring check -- `container in "..."` would also
        # match if this container's ref happened to be a literal substring of a sibling
        # container's ref in the same run (e.g. a shorter/malformed ref folded into a
        # longer valid one), producing a false "already shipped" positive.
        run_containers = {c.strip() for c in (h.get("containers") or "").split(",") if c.strip()}
        if container in run_containers and h.get("status") == "ok" and h.get("created"):
            return {"shipped": True, "ts": h.get("ts"),
                    "master_pos": sorted({o.get("po") for o in (h.get("orders") or []) if o.get("po")})}
    return {"shipped": False}

# ---------------- agent decision log ----------------
# The mailbox-agent (separate Claude Agent SDK service) posts ONE row per decision it
# makes about a mailbox item -- not per LLM turn. This is its durable, human-reviewable
# audit trail, kept on the same persistent disk as everything else so there's one place
# to look. It ALSO doubles as the idempotency check: the agent logs a row (with the
# source message_id) BEFORE calling any write tool, so a crash between "called /autoship"
# and "marked the email handled in Graph" is recoverable -- the next run sees the row and
# doesn't double-act. append-only; nothing is ever deleted.
_AGENTLOG_FIELDS = ("run_id", "source_mailbox", "message_id", "subject", "message_date",
                    "classification", "action_taken", "tool_args", "tool_result",
                    "rationale", "mode", "exception_flag", "exception_reason")

def agent_log(entry):
    """Append one decision row. Server stamps 'ts'. Returns the stored row."""
    row = {k: entry.get(k) for k in _AGENTLOG_FIELDS}
    row["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(TOKEN_DIR, exist_ok=True)
        with open(AGENTLOG_PATH, "a") as f:
            f.write(json.dumps(row) + "\n")
    except Exception:
        pass
    return row

def agent_log_read(limit=200, exceptions_only=False, pickup_only=False, created_only=False, message_id=None):
    """Newest-first. exceptions_only filters to flagged rows for quick review; pickup_only
    (the dashboard's default view, per Parker's request 2026-07-27) drops the routine NRT
    noise -- Scheduled/Picked up/Empty-returned status emails, non-NRT mail, skipped/
    ambiguous ones -- keeping only genuine "Available for pickup" triggers PLUS anything
    flagged for review (an exception should never be hidden just because the email that
    caused it wasn't itself a pickup trigger).

    nrt_late_pickup_confirmation (FIXED 2026-08-06, real feedback: a batch of these showing
    "No action needed" read as pure noise on the dashboard) is a DIFFERENT case from the
    other classifications this filters out -- it's the missed-trigger-backfill path, which
    sometimes creates a genuinely new shipment for a container whose first-stage "Available
    for Pickup" email was never seen. Only keep it when it actually did something
    (_row_created_shipment or flagged); drop it when the shipment already existed and
    nothing happened, same as the rest of the routine-noise classifications.

    created_only (Parker's request, 2026-08-05) keeps ONLY rows that actually created a
    real shipment -- no No-action-needed, no Needs-review, nothing else. message_id returns
    every row for one source email (the idempotency lookup), bypassing every other filter."""
    out = []
    try:
        with open(AGENTLOG_PATH) as f:
            out = [json.loads(l) for l in f if l.strip()]
    except Exception:
        pass
    if message_id is not None:
        return [r for r in out if r.get("message_id") == message_id]
    out = list(reversed(out))
    if exceptions_only:
        out = [r for r in out if r.get("exception_flag")]
    elif created_only:
        out = [r for r in out if _row_created_shipment(r)]
    elif pickup_only:
        out = [r for r in out if r.get("exception_flag")
                                 or r.get("classification") == "nrt_available_for_pickup"
                                 or (r.get("classification") == "nrt_late_pickup_confirmation"
                                     and _row_created_shipment(r))]
    return out[:limit] if limit else out

def agent_summary(hours=24):
    """Roll up the last `hours` of agent decisions for the notification digest:
    counts, the flagged-exception list (flat rows, ready for Power Automate's
    'Create HTML table'), plus queue depth and last-decision time so the digest
    also reveals job-silence (agent stopped) or a backing-up queue."""
    def _epoch(r):
        try:
            return time.mktime(time.strptime(r.get("ts", ""), "%Y-%m-%d %H:%M:%S"))
        except Exception:
            return 0.0
    all_rows = agent_log_read(limit=0)  # newest-first, all rows
    cutoff = time.time() - hours * 3600
    rows = [r for r in all_rows if _epoch(r) >= cutoff]
    by_class = {}
    # prepared: every create_shipment call regardless of outcome -- kept exactly as before
    # for existing consumers (the digest email may key on this). shipped/waiting/flagged/
    # no_action are a NEW, mutually exclusive partition of every row, in the same priority
    # order _status_pill() already uses for the per-row pill (exception first, then
    # trigger-vs-not, then waiting-vs-shipped) -- so the dashboard's KPI tiles sum to
    # `decisions` exactly and never disagree with what an individual row's own pill shows.
    prepared = shipped = waiting = flagged = no_action = 0
    exceptions = []
    for r in rows:
        c = r.get("classification") or "unknown"
        by_class[c] = by_class.get(c, 0) + 1
        is_prepared = r.get("action_taken") == "create_shipment"
        if is_prepared:
            prepared += 1
        if r.get("exception_flag"):
            flagged += 1
            exceptions.append({
                "when": r.get("ts"), "subject": (r.get("subject") or "")[:80],
                "classification": c, "reason": r.get("exception_reason") or "(none)",
                "message_id": r.get("message_id") or "",
            })
        elif not is_prepared:
            no_action += 1
        else:
            data = ((r.get("tool_result") or {}).get("data")) or {}
            if data.get("waiting_on_containers"):
                waiting += 1
            else:
                shipped += 1
    live = sum(1 for r in rows if r.get("mode") == "live")
    if not rows:
        mode = "n/a"
    elif live == 0:
        mode = "shadow"
    elif live == len(rows):
        mode = "live"
    else:
        mode = "mixed"

    last_decision_at = all_rows[0].get("ts") if all_rows else None
    # Agent-health flag -- same staleness threshold the dashboard uses, computed once here
    # so a notification flow can branch on one field instead of doing its own date math.
    if not last_decision_at:
        agent_health = "no_activity"
    else:
        try:
            agent_health = "stale" if (time.time() - _epoch(all_rows[0])) / 3600 > 6 else "ok"
        except Exception:
            agent_health = "ok"

    # Real shipment-creation runs in this window that either failed technically or ran
    # under an unexpected Acumatica identity -- distinct from exception_flag, which only
    # covers cases the agent's own judgment recognized as ambiguous. A run can look fine to
    # the agent (it called /autoship) but still fail on Acumatica's side, or succeed under
    # the wrong account -- this catches both, so it's not invisible until someone happens
    # to check /history.
    exp_user = os.environ.get("EXPECTED_ACU_USER", "").strip()
    run_issues = []
    for h in history(limit=0):
        try:
            if time.mktime(time.strptime(h.get("ts", ""), "%Y-%m-%d %H:%M:%S")) < cutoff:
                continue
        except Exception:
            continue
        acu = h.get("acumatica_user") or ""
        identity_mismatch = bool(exp_user and acu and exp_user.lower() not in acu.lower())
        if h.get("status") in ("failed", "partial") or identity_mismatch:
            run_issues.append({
                "when": h.get("ts"), "containers": h.get("containers") or "",
                "status": h.get("status") or "", "acumatica_user": acu or "(unknown)",
                "identity_mismatch": identity_mismatch,
            })

    return {
        "window_hours": hours,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "decisions": len(rows),
        "shipments_prepared": prepared,   # in shadow these are "would-be"; see mode -- unchanged, existing consumers may key on this
        "shipped": shipped,                # NEW: of `prepared`, the ones that actually shipped (or were already fulfilled)
        "waiting": waiting,                 # NEW: of `prepared`, still waiting on sibling containers
        "flagged": flagged,
        "no_action": no_action,
        "mode": mode,
        "by_classification": by_class,
        "exceptions": exceptions,
        "queue_depth": len(ingest_list()),
        "last_decision_at": last_decision_at,
        "agent_health": agent_health,
        "run_issues": run_issues,
        # Masters stuck "waiting"/"partial" (Purchase Order not yet fully received) past
        # LEDGER_SLA_DAYS -- not time-windowed like the fields above, this is current state,
        # not a window count, since a stuck master isn't tied to any one day's decisions.
        "ledger_stale": ledger_check_sla(),
    }

# ---------------- ingest queue (Power Automate push -> agent pull) ----------------
# The Graph app-only approach was blocked (Global Admin wouldn't grant tenant-wide
# Mail.Read). Instead a Power Automate flow, running under the user's own O365 login,
# PUSHES each new NRT/FCR email (metadata + body + any attachments, base64) to /ingest.
# Those land here as one JSON file per email on the persistent disk; the mailbox-agent
# cron job drains them on its schedule. This keeps the agent a scheduled batch job and
# decouples it from Power Automate's timing -- if the agent is down or mid-run, items
# just wait in the queue. Dedup is by the email's internetMessageId so a Power Automate
# retry can't enqueue the same message twice while it's still waiting.
def ingest_enqueue(payload):
    # Locked end-to-end (the dedup scan AND the write): two Power Automate retries landing
    # on separate threads at the same instant could otherwise both pass the "not found yet"
    # scan before either had written its file, enqueuing the same email twice.
    with _JSON_LOCK:
        os.makedirs(INGEST_DIR, exist_ok=True)
        msg_id = (payload.get("message_id") or "").strip()
        if msg_id:
            for fn in os.listdir(INGEST_DIR):
                if not fn.endswith(".json"):
                    continue
                existing = load_json(os.path.join(INGEST_DIR, fn)) or {}
                if existing.get("message_id") == msg_id:
                    return existing.get("id"), True  # already queued -> idempotent no-op
        item_id = base64.urlsafe_b64encode(hashlib.sha256(
            (msg_id or repr(payload.get("subject"))).encode()).digest()).decode().rstrip("=")[:20]
        item = dict(payload)
        item["id"] = item_id
        item["enqueued_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_json(os.path.join(INGEST_DIR, item_id + ".json"), item)
        return item_id, False

def ingest_list():
    out = []
    try:
        for fn in sorted(os.listdir(INGEST_DIR)):
            if fn.endswith(".json"):
                item = load_json(os.path.join(INGEST_DIR, fn))
                if item:
                    out.append(item)
    except Exception:
        pass
    return out

def ingest_delete(item_id):
    """Agent calls this after it has fully processed an item (logged its decision +
    called any tools). Returns True if a file was removed."""
    path = os.path.join(INGEST_DIR, os.path.basename(item_id) + ".json")
    try:
        os.remove(path)
        return True
    except Exception:
        return False

def _fmt_ts(ts):
    """Display-only: server stores naive UTC 'YYYY-MM-DD HH:MM:SS' (time.strftime with no
    tzinfo) -- convert to Pacific (DST-aware) and a plain 12-hour clock for anything shown
    on screen. Never used for parsing/sorting/staleness math -- those keep operating on the
    stored UTC string untouched."""
    if not ts or " " not in ts:
        return ts or ""
    try:
        dt = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
        local = dt.astimezone(PACIFIC)
        return local.strftime("%m/%d/%Y %I:%M %p %Z").replace(" 0", " ")
    except Exception:
        return ts

# What the agent's classification enum (agent.py) actually means, in plain English --
# shown as the "Email status" column instead of the raw enum, plus a legend under the
# table. Plain text only, no embedded HTML entities -- every use of this is esc()'d, so an
# entity like &middot; would double-escape and show up as literal text on screen.
CLASSIFICATION_LABELS = {
    "nrt_available_for_pickup": "Available for pickup",
    "nrt_late_pickup_confirmation": "Available for pickup",
    "nrt_waiting_on_containers": "Waiting on containers",
    "nrt_other_status": "Just a status update",
    "not_nrt": "Not an NRT email",
    "ambiguous": "Ambiguous",
    "skip": "Skipped",
}
# A small muted explanation shown under the primary label in the decision-log table only
# (not folded into the label itself as a parenthetical, and not used in aggregate/chip
# views, where nrt_late_pickup_confirmation correctly merges into plain "Available for
# pickup" -- see CLASSIFICATION_LABELS above). Keyed by the raw classification string.
CLASSIFICATION_SUBTEXT = {
    "nrt_late_pickup_confirmation": "caught after the fact",
}
CLASSIFICATION_LEGEND = ("<b>Email status:</b> what the agent decided this email was about &mdash; "
    "<b>Available for pickup</b> is the shipment trigger; the others result in no shipment.")

# Staff-plain override for the dashboard's Needs-review table (Parker's feedback,
# 2026-08-10: the agent's own free-text exception_reason -- however it happens to
# paraphrase a given case -- can drift into internal jargon a staff member wouldn't know
# how to act on). Keyed by process_manual's own machine-readable `reason` code (stable,
# not LLM-authored), read from the row's stored tool_result -- falls back to the agent's
# exception_reason for any case not covered here yet. Expand this as new confusing cases
# come up rather than trying to cover every possible reason up front.
REASON_STAFF_MESSAGES = {
    "unresolved_container": "This container isn't linked to a Purchase Order in Acumatica yet. "
        "Check whether the packing list for this container has been entered -- if it has, the PO "
        "number on that receipt may be missing or entered incorrectly.",
    "pickup_after_already_shipped": "This order already shipped, but a new pickup notice just came "
        "in for it -- possibly a duplicate email from the carrier, or a container that wasn't "
        "accounted for the first time. Worth a quick look to confirm nothing extra needs to ship.",
}

def _friendly_classification(c):
    return CLASSIFICATION_LABELS.get(c, c or "&mdash;")

def _classification_cell(c, esc):
    """Email-status table cell: primary label plus an optional small muted secondary line
    (e.g. a pickup confirmed from a later status email, not the original trigger) -- kept
    as its own line rather than jammed into the label as a parenthetical qualifier."""
    label = esc(_friendly_classification(c))
    sub = CLASSIFICATION_SUBTEXT.get(c)
    return f'{label}<span class=status-sub>{esc(sub)}</span>' if sub else label

# The run-history "user" field is either a real app-login username (manual PDF upload) or
# an "auto:<source>" tag (an automated trigger -- the live agent, or a manual API test).
# Label the automated ones plainly instead of showing the raw tag.
RUN_SOURCE_LABELS = {"nrt": "Automated &middot; NRT agent", "maersk-fcr": "Automated &middot; Maersk/FCR",
                     "test": "Automated &middot; manual test", "preview": "Automated &middot; preview"}

def _friendly_run_source(user_val):
    if not user_val:
        return "&mdash;"
    if user_val.startswith("auto:"):
        src = user_val.split(":", 1)[1]
        return RUN_SOURCE_LABELS.get(src, f"Automated &middot; {src}" if src != "unknown" else "Automated")
    return user_val

def _row_severity(r):
    """The single severity bucket a decision row belongs in -- drives both the status pill
    and the row's left-edge stripe color, so the two never disagree. One of: 'rust' (needs
    review), 'fog' (shadow/waiting), 'moss' (shipped), 'neutral' (no action)."""
    if r.get("exception_flag"):
        return "rust"
    if r.get("action_taken") == "create_shipment":
        if r.get("mode") != "live":
            return "fog"
        data = (r.get("tool_result") or {}).get("data") or {}
        if data.get("waiting_on_containers"):
            return "fog"
        if data.get("created"):
            return "moss"
    return "neutral"

def _row_created_shipment(r):
    """True only for a decision row that actually resulted in a real, live shipment
    creation -- exactly the "Shipment created" branch of _status_pill(), factored out so
    the /agent/log created-only filter (Parker's request, 2026-08-05: a view with just
    created shipments, no No-action-needed/Needs-review noise) can't drift out of sync
    with what the pill itself shows."""
    if r.get("exception_flag") or r.get("mode") != "live" or r.get("action_taken") != "create_shipment":
        return False
    return bool(((r.get("tool_result") or {}).get("data") or {}).get("created"))

def _status_pill(r):
    """One colored badge that says, at a glance, what happened -- replaces the separate
    raw Action/Mode text columns. Derived from fields already on every decision row:
    exception_flag (needs a human), action_taken (create_shipment vs none), mode (shadow
    vs live), and -- for live create_shipment calls -- the actual tool_result.data, so a
    waiting_on_containers=true outcome (Phase 2 completeness gate) isn't mislabeled as a
    success just because the tool was CALLED; nothing was actually created."""
    if r.get("exception_flag"):
        return '<span class="pill rust">&#9888; Needs review</span>'
    if r.get("action_taken") == "create_shipment":
        if r.get("mode") != "live":
            return '<span class="pill fog">&#9678; Would create &middot; shadow</span>'
        if _row_created_shipment(r):
            return '<span class="pill moss">&#10003; Shipment created</span>'
        data = (r.get("tool_result") or {}).get("data") or {}
        if data.get("waiting_on_containers"):
            return '<span class="pill fog">&#8987; Waiting on containers</span>'
    return '<span class=pill>No action needed</span>'

def _fmt_kv(d, esc):
    """Flat dict -> 'Key: value &middot; Key2: value2' instead of a raw JSON dump -- used
    for the tool call args/result in the decision log's Detail column. Falls back to a
    plain escaped string for a non-dict (e.g. a bare error string) or None."""
    if d is None:
        return None
    if not isinstance(d, dict):
        return esc(str(d))
    parts = []
    for k, v in d.items():
        if v is None or v == "":
            continue
        label = k.replace("_", " ").strip().capitalize()
        val = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        parts.append(f"{label}: {esc(val)}")
    return " &middot; ".join(parts) if parts else None

def _friendly_shipment_result(tool_result, esc):
    """Plain-English rendering of a create_shipment tool_result, for the decision log's
    Detail column -- replaces a raw JSON dump of process_manual's response (which nests
    dicts/lists that _fmt_kv would otherwise show as literal JSON text) with the same
    sentences a person would use to describe what happened. Internal debug fields (HTTP
    status codes, the ship-date-correction PUT's stack trace, dry_run/confidence flags)
    are deliberately omitted -- nothing here needs them to understand the outcome."""
    if not isinstance(tool_result, dict):
        return None
    data = tool_result.get("data")
    if not isinstance(data, dict):
        return _fmt_kv(tool_result, esc)  # unexpected shape -- fall back rather than hide it
    if data.get("waiting_on_containers"):
        detail = [d for d in (data.get("completeness_detail") or []) if isinstance(d, dict)]
        total = len(detail)
        # Count the actual `complete` boolean the per-master gate loop already computed
        # (per-line Completed check) -- NOT the raw header po_status string. A PO that's
        # genuinely fully received can still show header status "Closed" (a later terminal
        # status on this tenant, see po_completeness()'s docstring), so comparing po_status
        # to the literal string "Completed" undercounts real completions. Real case,
        # 2026-07-27: container ONEU9300392's 5 underlying POs were all genuinely complete
        # (Completed=true on every Detail line, billed and closed) but this display showed
        # "0 of 5 received in full" -- purely cosmetic; the actual gate below wasn't fooled.
        received = sum(1 for d in detail if d.get("complete"))
        counts = (f"<div class=sub>{received} of {total} purchase orders received in full &mdash; "
                  f'<a href=/splits>see Split orders</a> for the breakdown.</div>') if total else ""
        gaps = data.get("container_gaps") or {}
        if gaps:
            missing = sorted({c for g in gaps.values() for c in (g.get("missing_containers") or [])})
            counts += (f"<div class=sub>Still waiting on NRT pickup confirmation for: "
                       f"{esc(', '.join(missing))}.</div>")
        return ("Waiting on the rest of this order to arrive &mdash; no shipment created yet; "
                "it'll ship automatically once every container is in." + counts)
    if data.get("out_of_scope"):
        return "Skipped &mdash; this container is 3PL-bound, not tracked here."
    if data.get("needs_review"):
        return f"Needs a person to look at this &mdash; {esc(str(data.get('note') or data.get('reason') or ''))}"
    rows = data.get("rows") or []
    created_lines, fulfilled_lines, other_lines = [], [], []
    for row in rows:
        res = row.get("result") or {}
        po = esc(str(row.get("po") or ""))
        order = esc(str(res.get("order") or ""))
        if res.get("created"):
            already = " (already existed)" if res.get("already_existed") else ""
            created_lines.append(
                f"Order {order} (Master PO {po}) &rarr; Shipment {esc(str(res.get('shipment_nbr') or '?'))}, "
                f"dated {esc(str(res.get('ship_date') or ''))}{already}")
        elif row.get("already_fulfilled"):
            # Distinct from a genuine flag -- see find_fulfilled_sales_orders()'s docstring.
            # Kept visually separate so a mixed result (some genuinely flagged, some just
            # already done) doesn't read as "all of these need review."
            fulfilled_lines.append(f"Master PO {po} &mdash; {esc(str(row.get('note') or ''))}")
        elif order or po:
            reason = res.get("reason") or res.get("error") or row.get("note") or "not created"
            other_lines.append(f"Order {order} (Master PO {po}) &mdash; {esc(str(reason))}")
    parts = []
    if not rows:
        note = data.get("note") or data.get("reason")
        if note:
            parts.append(esc(str(note)))
    else:
        if created_lines:
            parts.append("<br>".join(created_lines))
        if fulfilled_lines:
            parts.append(('<div class=sub style="color:var(--taupe)">' if created_lines or other_lines else "")
                          + "<br>".join(fulfilled_lines) + ("</div>" if created_lines or other_lines else ""))
        if other_lines:
            parts.append(("<br>" if created_lines or fulfilled_lines else "") + "<br>".join(other_lines))
    # Some sibling master(s) in this same pickup event shipped above (or matched, above);
    # these are still gated on their own -- see the per-master gate comment in
    # process_manual (real case: ONEU9300392 -> 645399 waiting on FSCU5863132 while its
    # 4 sibling masters shipped in the same event).
    still_waiting = data.get("still_waiting_masters") or []
    if still_waiting:
        gaps = data.get("container_gaps") or {}
        missing = sorted({c for tok in still_waiting
                           for c in (gaps.get(tok, {}).get("missing_containers") or [])})
        note2 = f"<div class=sub>Still waiting on master(s) {esc(', '.join(still_waiting))}"
        if missing:
            note2 += f" &mdash; missing NRT pickup confirmation for: {esc(', '.join(missing))}"
        note2 += ".</div>"
        parts.append(note2)
    return "".join(parts) if parts else None

_CONTAINER_IN_SUBJECT = re.compile(r"Container\s*#\s*(\S+)", re.I)

def _agent_log_html(rows, mode="all"):
    """Scannable decision table -- one row per decision, exceptions highlighted. Plain-
    English throughout: no raw JSON, no code-shaped field names -- the Details column uses
    _friendly_shipment_result instead of a JSON dump, and times display in Pacific.
    `mode` picks which pre-filtered `rows` this is (for the title/toggle only -- the
    filtering itself already happened in agent_log_read()): 'pickup' (default dashboard
    view, Available-for-pickup triggers + exceptions only), 'exceptions', or 'all'."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    hist_rows = history(limit=0)  # local file read only, no live calls -- cheap per page load
    def _row(r):
        flagged = bool(r.get("exception_flag"))
        m = _CONTAINER_IN_SUBJECT.search(r.get("subject") or "")
        args = r.get("tool_args") or {}
        container_raw = args.get("container") or (m.group(1) if m else None)
        resolved = (_find_later_success(container_raw, r.get("ts", ""), hist_rows, _flagged_row_masters(r))
                    if flagged else None)
        sev = "moss" if resolved else _row_severity(r)
        what = _classification_cell(r.get("classification"), esc)
        status = ('<span class="pill moss">&#10003; Resolved on retry</span>'
                   if resolved else _status_pill(r))
        container = esc(container_raw) if container_raw else esc(r.get("subject") or "")
        ship_date = esc(str(args.get("ship_date") or ""))
        result_txt = _friendly_shipment_result(r.get("tool_result"), esc)
        detail = (f"<details><summary>What happened</summary><div>{result_txt}</div></details>"
                  if result_txt else "&mdash;")
        note = esc(r.get("rationale") or "")
        if flagged:
            if resolved:
                exc_note = (f'<span style="color:var(--moss)">Shipped on a later retry '
                            f'({esc(_fmt_ts(resolved.get("ts")))}) -- no action needed now.</span>')
            else:
                exc_note = f'<span style="color:var(--rust)">{esc(r.get("exception_reason") or "needs review")}</span>'
            note = f"{exc_note}<br>{note}" if note else exc_note
        return (f'<tr class="row-{sev}"><td class=t-time>{esc(_fmt_ts(r.get("ts")))}</td>'
                f'<td class=t-container title="{esc(r.get("subject") or "")}">{container}</td>'
                f"<td class=t-time>{ship_date}</td>"
                f"<td class=t-status>{what}</td><td>{status}</td>"
                f"<td>{note}</td><td>{detail}</td></tr>")
    body_rows = "".join(_row(r) for r in rows)
    title_suffix = {"pickup": " &mdash; available for pickup", "exceptions": " &mdash; exceptions only",
                    "all": " &mdash; all classifications", "created": " &mdash; created shipments only"}.get(mode, "")
    title = "Agent decisions" + title_suffix
    toggle = ('<a class=pill href="/agent/log">available for pickup</a> '
              '<a class=pill href="/agent/log?all=1">all classifications</a> '
              '<a class=pill href="/agent/log?exceptions_only=1">exceptions only</a> '
              '<a class=pill href="/agent/log?created_only=1">created shipments only</a>')
    return ('<div class=card><h1 style="font-size:16px">%s</h1>'
            '<p class=sub>One row per decision the mailbox-agent made (not per LLM turn). '
            'Flagged rows are highlighted. Times are Pacific. %s</p>'
            '<p class=sub>%s</p>'
            '<div class=twrap><table><tr><th>Received</th><th>Container</th><th>Pickup date</th>'
            '<th>Email status</th><th>Result</th><th>Why</th><th>Details</th></tr>'
            '%s</table></div></div>') % (title, toggle, CLASSIFICATION_LEGEND, body_rows or
            '<tr><td colspan=7 class=sub>No decisions logged yet.</td></tr>')

# ---------------- unified lookup: one container or Master PO's full story ----------------
_ISO_CONTAINER_RE = re.compile(r"^[A-Z]{4}\d{6,7}$")

def _lookup_order(query):
    """Stitch together everything known about one container or Master PO, across the
    three places its story otherwise lives split up: container_ledger.json (is it still
    waiting?), agent_log.jsonl (what did the agent decide about each of its containers?),
    and ship_runs.jsonl (what actually got created?). Pure local-file reads -- no live
    Acumatica calls, so this is instant and free regardless of the API rate limit.

    A query can be a container (ISO-format) or a Master PO token -- resolves either
    direction: given a container, finds its Master PO(s) via the ledger; given a Master
    PO, finds every container recorded against it."""
    q = (query or "").strip().upper()
    is_container = bool(_ISO_CONTAINER_RE.match(q))
    ledger = load_json(LEDGER_PATH) or {}
    hist = history(limit=0)
    alog = agent_log_read(limit=0)

    master_tokens = set()
    containers_involved = set()
    if is_container:
        containers_involved.add(q)
        for tok, entry in ledger.items():
            if q in (entry.get("containers") or {}):
                master_tokens.add(tok)
    else:
        master_tokens.add(q)
        if q in ledger:
            containers_involved.update((ledger[q].get("containers") or {}).keys())

    # History rows matching either a known Master PO or a known/queried container --
    # discovering more of either along the way (a run's own record is the source of
    # truth for which containers/tokens actually belong together).
    history_rows = []
    for h in hist:
        conts = h.get("containers") or ""
        po_hit = any(o.get("po") in master_tokens for o in (h.get("orders") or []))
        cont_hit = (q in conts) or any(c in conts for c in containers_involved)
        if po_hit or cont_hit:
            history_rows.append(h)
            containers_involved.update(c.strip() for c in conts.split(",") if c.strip())
            for o in (h.get("orders") or []):
                if o.get("po"):
                    master_tokens.add(o.get("po"))

    # A second ledger pass -- history may have surfaced Master PO tokens or containers
    # the first pass didn't know about yet.
    ledger_entries = {tok: ledger[tok] for tok in master_tokens if tok in ledger}
    for entry in ledger_entries.values():
        containers_involved.update((entry.get("containers") or {}).keys())

    # Agent decisions: matched on container (from tool_args, falling back to the subject).
    agent_rows = []
    for r in alog:
        args = r.get("tool_args") or {}
        c = args.get("container")
        if not c:
            m = _CONTAINER_IN_SUBJECT.search(r.get("subject") or "")
            c = m.group(1) if m else None
        if c and (c == q or c in containers_involved):
            agent_rows.append(r)
            containers_involved.add(c)

    return {"query": q, "is_container": is_container,
            "master_tokens": sorted(master_tokens),
            "containers_involved": sorted(containers_involved),
            "ledger_entries": ledger_entries,
            "history_rows": history_rows, "agent_rows": agent_rows}

LOOKUP_STATUS_PILL = {"waiting": "pill fog", "partial": "pill fog", "shipped": "pill moss"}

def _lookup_html(query=None):
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    form = ('<div class=card><h1 style="font-size:18px">Look up a container or Master PO</h1>'
            '<p class=sub>Pulls together everything known about one order from the ledger, '
            'the agent\'s decisions, and the shipment run history -- one place instead of three. '
            'No Acumatica calls; instant either way.</p>'
            '<form method=get action=/lookup class=search-row>'
            f'<input type=text name=q placeholder="e.g. SEKU9013424 or 645410" value="{esc(query or "")}">'
            '<button class=fog>Look up</button></form></div>')
    if not query:
        return form
    info = _lookup_order(query)
    # NOTE: containers_involved (for a container query) and master_tokens (for a Master PO
    # query) both always include the query itself, seeded unconditionally in
    # _lookup_order -- neither can be used to detect "found nothing". ledger_entries/
    # history_rows/agent_rows are only ever populated by a genuine match, so those are
    # the real signal.
    if not info["ledger_entries"] and not info["history_rows"] and not info["agent_rows"]:
        return form + ('<div class=card><div class=empty-state><span class=e-icon>&#128269;</span>'
                       f'<h3>Nothing found for &#8220;{esc(query)}&#8221;</h3>'
                       '<p>Check the container number or Master PO, or it may not have come through the agent yet.</p></div></div>')

    parts = [form]
    # FIXED 2026-07-29 (found while checking a different fix): esc()-wrapping the WHOLE
    # "join(...) or fallback" expression re-escapes the literal &mdash; entity into visible
    # "&mdash;" text on screen instead of rendering an em dash -- only the real joined
    # value needs escaping, never the pre-built fallback entity.
    master_tokens_display = esc(", ".join(info["master_tokens"])) if info["master_tokens"] else "&mdash;"
    containers_display = esc(", ".join(info["containers_involved"])) if info["containers_involved"] else "&mdash;"
    parts.append('<div class=card><h2>Summary</h2>'
                 f'<p class=sub>Master PO(s): <b>{master_tokens_display}</b> '
                 f'&nbsp; Container(s): <b>{containers_display}</b></p></div>')

    master_cards = []
    for tok in info["master_tokens"]:
        entry = info["ledger_entries"].get(tok)
        if not entry:
            continue
        status_label = {"waiting": "Waiting", "partial": "Partially shipped", "shipped": "Shipped"}.get(
            entry.get("status"), entry.get("status") or "&mdash;")
        pill_class = LOOKUP_STATUS_PILL.get(entry.get("status"), "pill")
        checked = entry.get("last_checked")
        cont_rows = "".join(f'<tr><td class=mc>{esc(c)}</td><td class=md>{esc(d)}</td></tr>'
                            for c, d in sorted((entry.get("containers") or {}).items(), key=lambda kv: kv[1]))
        master_cards.append(
            f'<div class=master-card><div class=master-card-head><span class=m-id>{esc(tok)}</span>'
            f'<span class={pill_class}>{status_label}</span></div>'
            f'<table class=mini-table><tr><th>Container</th><th>Available for pickup</th></tr>{cont_rows}</table>'
            f'<div class=as-of>{"Last checked live: " + esc(_fmt_ts(checked)) if checked else "Not yet checked live"} '
            f'&mdash; <a href="/splits?live=1">refresh live</a></div></div>')
    if master_cards:
        parts.append('<div class=master-grid>%s</div>' % "".join(master_cards))

    if info["agent_rows"]:
        parts.append('<div class=section-head><h2>Agent decisions</h2></div>'
                     + _agent_log_html(sorted(info["agent_rows"], key=lambda r: r.get("ts", "")), mode="all"))

    if info["history_rows"]:
        hrows = sorted(info["history_rows"], key=lambda h: h.get("ts", ""), reverse=True)
        rows_html = "".join(
            f'<tr><td class=t-time>{esc(_fmt_ts(h.get("ts")))}</td><td>{esc(h.get("status") or "")}</td>'
            f'<td class=t-container>{esc(h.get("containers") or "")}</td>'
            f'<td>{esc(", ".join(sorted({o.get("po") for o in (h.get("orders") or []) if o.get("po")})))}</td>'
            f'<td>{esc(", ".join(sorted({o.get("shipment_nbr") for o in (h.get("orders") or []) if o.get("shipment_nbr")})))}</td></tr>'
            for h in hrows)
        parts.append('<div class=section-head><h2>Shipment run history</h2></div>'
                     '<div class=twrap><table><tr><th>When</th><th>Status</th><th>Containers</th>'
                     f'<th>Master PO(s)</th><th>Shipment(s)</th></tr>{rows_html}</table></div>')
    return "".join(parts)

def _container_status_days(days):
    try:
        return max(1, min(60, int(days)))
    except (TypeError, ValueError):
        return 2

def _container_status_rows(days):
    """Shared by the HTML page and the CSV export: one row per (Customer Order Nbr,
    Container) pair for masters touched in the last `days` day(s), each with the date NRT
    confirmed that container -- or None if it hasn't yet. Master PO is its OWN field
    (never folded into customer_order) -- real feedback, 2026-08-05: showing the bare
    master token inside the Customer Order column when no Sales Order has matched yet
    read as a garbled/wrong customer order number, not as "this master has no SO yet".

    Pure local-file read (ledger + load_all_orders' cached rows) for confirmed dates, plus
    one existing cache read (expected_containers_for_master, backed by load_recent_
    receipts()' own cache -- no new live API calls) to know the FULL container set a
    master's PO depends on. Same "expected containers" logic the completeness gate itself
    already gates shipments on elsewhere in this file -- deliberately not a second,
    different definition of "expected" from what the automation actually enforces."""
    ledger = load_json(LEDGER_PATH) or {}
    cutoff = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
    tokens = [tok for tok, e in ledger.items() if (e.get("last_updated") or "") >= cutoff]
    matched = find_any_sales_orders_batch(tokens) if tokens else {}
    rows = []
    for tok in tokens:
        entry = ledger[tok]
        orders = matched.get(tok) or []
        order_labels = sorted({o.get("cust_order") for o in orders if o.get("cust_order")}) or [None]
        confirmed = entry.get("containers") or {}
        # FIXED 2026-08-05, real case (master 141965): expected_containers_for_master()
        # unions containers from EVERY receipt whose VendorRef mentions this master token
        # anywhere -- correct for its actual purpose (the completeness gate, which only
        # ever runs this for a master that's still waiting/partial), but wrong here for a
        # master that's already Shipped: 141965 genuinely only ever needed MRKU5282940
        # (confirmed, and it shipped on exactly that), yet the union pulled in
        # MRKU2927958/MRKU4208510 from a LARGER sibling cluster's receipts and showed them
        # as "Waiting" on an order that has nothing left to wait on. A shipped master shows
        # only what it actually confirmed -- never a manufactured "still pending" list.
        all_containers = sorted(confirmed) if entry.get("status") == "shipped" else \
            sorted(set(confirmed) | expected_containers_for_master(tok))
        all_containers = all_containers or [None]
        email_received = entry.get("email_received") or {}
        for order_label in order_labels:
            for cont in all_containers:
                # Prefer the triggering email's own received timestamp (Parker's request,
                # 2026-08-05 -- proof of WHICH email confirmed this, not just a bare date
                # this automation recorded) -- fall back to pickup_date for ledger entries
                # written before this field existed, or for manual /backfill-pickup entries
                # where there's genuinely no email at all.
                received = (email_received.get(cont) or confirmed.get(cont)) if cont else None
                rows.append({"customer_order": order_label, "master_po": tok,
                             "container": cont, "email_received": received})
    rows.sort(key=lambda r: (r["customer_order"] or "", r["master_po"], r["container"] or ""))
    return rows

def _container_status_html(days=None):
    """Parker's morning-check request, 2026-08-05: a flat list, one row per (Customer
    Order Nbr, Container) pair, showing the date NRT confirmed that container -- or
    "Waiting" if it hasn't yet."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    days = _container_status_days(days)
    header = ('<div class=card><h1 style="font-size:18px">Container status check</h1>'
              '<p class=sub>One row per Customer Order + container, showing when the &#8220;Available for '
              'Pickup&#8221; email itself was received (not just the date this automation recorded) -- or '
              'Waiting if none has arrived yet. Masters touched in the last N day(s). Pure local-file read, '
              'no live Acumatica calls.</p>'
              '<form method=get action=/container-status class=search-row>'
              f'<input type=number name=days min=1 max=60 value="{days}" style="width:80px"> day(s) '
              '<button class=fog>Show</button>'
              f'<a href="/container-status/export.csv?days={days}" style="margin-left:12px;font-size:13px">'
              '&#8659; Export CSV</a></form></div>')
    rows = _container_status_rows(days)
    if not rows:
        return header + ('<div class=card><div class=empty-state><span class=e-icon>&#128230;</span>'
                         f'<h3>No masters touched in the last {days} day(s)</h3>'
                         '<p>Try a longer window.</p></div></div>')
    row_html = "".join(
        f'<tr><td>{esc(r["customer_order"]) if r["customer_order"] else "&mdash; (no Sales Order matched yet)"}</td>'
        f'<td>{esc(r["master_po"])}</td>'
        f'<td class=t-container>{esc(r["container"]) if r["container"] else "&mdash;"}</td>'
        + (f'<td>{esc(r["email_received"])}</td>' if r["email_received"] else '<td class=t-waiting>Waiting</td>')
        + '</tr>'
        for r in rows)
    return header + ('<div class=twrap><table><tr><th>Customer Order</th><th>Master PO</th>'
                     f'<th>Container</th><th>Email Received</th></tr>{row_html}</table></div>')

def backfill_pickup_dates(containers, dates):
    """Parker's request, 2026-08-05: a real window existed where he was removed from the
    NRT distribution list -- containers were genuinely picked up and NRT sent status
    emails during that window, but nobody (and so nothing) in this automation ever saw
    them. Outlook search can't recover a gap like that (the emails were never received in
    the first place), so this is a direct manual correction: given container/date pairs
    typed in by hand, resolve each container to its master(s) the SAME way container_scope()
    already does for a real NRT trigger, and call the SAME ledger_record() a real trigger
    would have called. Does NOT call create_shipment or touch Acumatica at all -- purely a
    ledger data correction. If a backfilled master is now complete, the existing
    /ledger/recheck job picks it up on its own schedule same as any other resolved gap.

    containers/dates: parallel lists (one row of the form = one position in each) --
    blank rows (either side empty) are silently skipped, not errors, since the form always
    submits a few trailing empty rows. Returns a list of per-row result dicts for rendering."""
    results = []
    for container, date in zip(containers, dates):
        container, date = (container or "").strip().upper(), (date or "").strip()
        if not container and not date:
            continue
        if not container or not date:
            results.append({"container": container, "date": date, "ok": False,
                            "error": "both container and date are required"})
            continue
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
            results.append({"container": container, "date": date, "ok": False,
                            "error": f"date '{date}' isn't YYYY-MM-DD"})
            continue
        scope, tokens = container_scope(container)
        if scope != "in_scope" or not tokens:
            results.append({"container": container, "date": date, "ok": False,
                            "error": f"container_scope() returned '{scope}' -- no master(s) to record against "
                                     "(check the container number, or whether its PO Receipt exists in Acumatica yet)"})
            continue
        for tok in tokens:
            ledger_record(tok, container, date)
        results.append({"container": container, "date": date, "ok": True, "masters": tokens})
    return results

BACKFILL_PICKUP_ROWS = 6  # blank starting rows shown; "+ Add another" grows the form with no server round-trip

def _backfill_pickup_html(results=None):
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    row_html = ('<div class=backfill-row><input type=text name=container placeholder="Container #" '
                'style="text-transform:uppercase"><input type=date name=date></div>')
    form = ('<div class=card><h1 style="font-size:18px">Manually record a pickup date</h1>'
            '<p class=sub>For containers NRT genuinely confirmed but this automation never saw -- e.g. a '
            'window where the NRT distribution list didn&#39;t include this inbox. Writes directly to the '
            'same ledger a real "Available for Pickup" email would update -- does NOT create any shipment '
            'or call Acumatica; if this completes a master, the next /ledger/recheck picks it up '
            'automatically.</p>'
            '<form method=post action=/backfill-pickup>'
            f'<div id=backfill-rows>{row_html * BACKFILL_PICKUP_ROWS}</div>'
            '<button type=button id=backfill-add style="margin:8px 0">+ Add another</button><br>'
            '<button class=fog>Record</button></form></div>'
            '<script>'
            "document.getElementById('backfill-add').addEventListener('click', function(){"
            "var d=document.createElement('div'); d.className='backfill-row';"
            "d.innerHTML='<input type=text name=container placeholder=\"Container #\" "
            "style=\"text-transform:uppercase\"><input type=date name=date>';"
            "document.getElementById('backfill-rows').appendChild(d);"
            "});"
            '</script>')
    if not results:
        return form
    rows = "".join(
        f'<tr><td class=t-container>{esc(r.get("container"))}</td><td>{esc(r.get("date"))}</td>'
        + (f'<td>{esc(", ".join(r.get("masters") or []))}</td><td>&#10003; recorded</td>'
           if r["ok"] else
           f'<td></td><td style="color:var(--rust)">&#10007; {esc(r.get("error"))}</td>')
        + '</tr>'
        for r in results)
    return form + ('<div class=card><h2>Results</h2><div class=twrap><table>'
                   '<tr><th>Container</th><th>Date</th><th>Master(s)</th><th>Outcome</th></tr>'
                   f'{rows}</table></div></div>')

# ---------------- automated trigger (no PDF): NRT email / Maersk+FCR watch-list ----------------
def process_manual(container, ship_date, pos=None, user=None, source=None, dry_run=False,
                    force_receipts=True, email_received_at=None):
    """The automated-trigger entry point (NRT email / Maersk+FCR watch-list) -- there is
    no manual-upload counterpart anymore (Parker's call, 2026-08-06: the old handover-PDF
    flow was removed once the mailbox agent fully replaced it). Two calling shapes:
      - container only (NRT path: the pickup email has no PO info) -> resolve PO#s via
        containers_to_pos() (container -> Acumatica PurchaseReceipt -> internal PO# ->
        VendorRef -> retail PO#).
      - container + pos (Maersk/FCR path: the FCR already lists the PO#s under that
        container) -> use the given PO#s directly, skipping containers_to_pos() entirely
        so this doesn't depend on a PO Receipt already existing in Acumatica by the time
        the vessel-loading event fires.
    create_shipment() (unconfirmed, human Confirms in Acumatica) + log_run() to the
    permanent audit log. `source` is a free-text tag (e.g. "nrt" / "maersk-fcr") recorded
    in the run history so History shows where each automated run came from.

    force_receipts (default True): force a fresh load_recent_receipts() pull before the
    completeness gate runs, so a stale cache can't understate a master's expected-container
    set (see the call site below). Default True is right for a single live-trigger call.
    Pass False when the CALLER already forced a refresh immediately before looping over
    many masters in one batch (see /ledger/recheck) -- forcing again per-master there would
    multiply into dozens of redundant full receipt refetches against Acumatica's 100
    req/min cap for zero added correctness, since the shared cache is already fresh.

    email_received_at (optional): the triggering NRT email's own received timestamp
    (YYYY-MM-DD HH:MM:SS or similar), distinct from ship_date (a bare date). Recorded on
    the permanent log entry and included in the shipment-created notification -- purely
    informational, never used for any gating/date-math decision.
    """
    if not dry_run and not ship_date:
        return {"error": "Shipment date is required."}
    container = (container or "").strip().upper()
    if not container:
        return {"error": "container is required."}

    # FIXED 2026-07-31: every one of these early-return outcomes used to skip log_run()
    # entirely -- fine for the mailbox-agent's own NRT-triggered calls (its OWN separate
    # agent_log.jsonl still captures the decision), but /ledger/recheck calls process_manual()
    # directly, bypassing the agent loop -- an out_of_scope/unresolved/anomaly/waiting outcome
    # from THAT path was never durably recorded anywhere, visible only in that one HTTP
    # response. Now every outcome gets a permanent row, so ship_runs.jsonl is a complete
    # record regardless of trigger source -- needed for the CSV export and the shipment-
    # created notification to have anything real to work from.
    def _log_early(status, extra=None):
        if dry_run:
            return
        entry = {"reference": None, "document": source or "unknown", "user": user,
                 "acumatica_user": connected_user(), "status": status, "orders_matched": 0,
                 "created": 0, "containers": container, "ship_date": ship_date,
                 "email_received_at": email_received_at, "orders": []}
        if extra:
            entry.update(extra)
        log_run(entry)

    still_waiting = []
    container_gaps = {}
    completeness_detail = []
    anomalies = []  # only ever populated on the container-resolution (NRT) path below
    # Every resolved master's full expected-container set -- only ever populated on the
    # container-resolution (NRT) path below (the pos-given/Maersk-FCR path isn't ledger-
    # tracked, so there's no per-container confirmation concept for it). Defaulted here so
    # the log_run() call further down can reference it unconditionally either way.
    expected_containers_by_master = {}
    if pos:
        all_pos = list(dict.fromkeys(p.strip() for p in pos if p and p.strip()))
        unresolved = False
    else:
        scope, resolved = container_scope(container)
        # Out of scope: 3PL-bound units are recognized at the 3PL, not at port pickup.
        # Skip quietly (not a review exception) so 3PL containers don't spam the digest.
        if scope == "out_of_scope":
            _log_early("out_of_scope")
            return {"container": container, "out_of_scope": True, "created": 0, "orders_matched": 0,
                    "reason": "out_of_scope_3pl",
                    "note": "container's PO Receipt is 3PL-bound (MMX/4006/AMAZON/HG); revenue is "
                            "recognized at the 3PL, not at port pickup -- skipped, no action needed"}
        if scope == "unresolved":
            # container_scope()'s own docstring already promises this needs human review --
            # this call site just never implemented that contract. Real bug found 2026-07-29:
            # with resolved=[] the per-master loop below runs zero times, so this fell through
            # to the generic waiting_on_containers=True/"po_incomplete" response -- the SAME
            # classification as a normal in-progress order, with no exception raised. Worse,
            # ledger_record() ALSO never fires for an empty `resolved`, so no ledger entry
            # exists to ever pick this up again via /ledger/recheck -- a container with no
            # matching receipt (or a receipt with no recognizable retail PO#) could sit
            # silently invisible forever, with zero human visibility, unless another NRT
            # email happens to arrive later.
            _log_early("unresolved")
            # Staff-plain wording (Parker's feedback, 2026-08-10): "VendorRef" and "receipt"
            # are internal Acumatica jargon that only mean something to Parker, not the
            # staff this note is actually meant to guide. REASON_STAFF_MESSAGES on the
            # dashboard's Needs-review table overrides this with the same plain phrasing
            # regardless of how the agent's own free-text exception_reason paraphrases it --
            # this note is what feeds that paraphrase, so it's worth keeping plain too.
            return {"container": container, "needs_review": True, "created": 0, "orders_matched": 0,
                    "reason": "unresolved_container",
                    "note": "This container isn't linked to a Purchase Order in Acumatica yet. "
                            "Check whether the packing list for this container has been entered -- "
                            "if it has, the PO number on that receipt may be missing or entered "
                            "incorrectly."}
        # NRT path completeness gate (Phase 2 / Tier 2 -- see majestic-swimming-melody.md):
        # does the underlying Purchase Order behind this container actually show everything
        # received yet? Runs on EVERY in-scope pickup event, not just ones that already look
        # like a multi-container split -- a PO whose containers arrived via separate
        # packing-list uploads leaves no trace on any single receipt (see
        # master_multi_receipt_flags' docstring), so only this PO-level check catches the
        # worst case: a sibling container whose receipt doesn't exist in Acumatica yet at
        # all. FAILS CLOSED: any resolution/lookup problem is treated as "not complete."
        # Ledger updated FIRST, unconditionally, before any shipment decision.
        pickup_date = ship_date or datetime.date.today().isoformat()
        original_resolved = resolved
        anomalous_tokens = set()
        # Lazy + memoized: resolve_pos_by_master() does a live $expand=Details fetch PER
        # RECEIPT tied to this container. FIXED 2026-08-05, real incident: calling it fresh
        # inside the loop below (once per already-shipped token) refetched the SAME
        # receipts once per token instead of once total -- for a container resolving to
        # several already-shipped siblings at once (e.g. CAAU6433199 -> 6 masters), that's
        # 6x redundant live API round-trips just for this one check, on top of everything
        # else /autoship already does. That extra latency is what was pushing total request
        # time past the mailbox-agent's 120s client timeout, producing the "autoship HTTP 0
        # / read operation timed out" errors -- Acumatica-side, the shipment usually still
        # completed fine (see the "Resolved on retry" rows), the CLIENT just gave up first.
        _po_refs_by_master = None
        def _po_ref_for(tok):
            nonlocal _po_refs_by_master
            if _po_refs_by_master is None:
                _po_refs_by_master = resolve_pos_by_master(container)
            return _po_refs_by_master.get(tok)
        for token in original_resolved:
            entry = ledger_entry(token)
            if entry and entry.get("status") == "shipped":
                # Don't blindly trust the local ledger's "shipped" flag -- verify against
                # Acumatica's LIVE state first. Real case (2026-07-23): master 362039's
                # shipments were deleted after being found erroneous (a separate incident),
                # but the ledger was never told -- so a genuine NEW pickup event for a
                # sibling container (DRYU9475020) got wrongly flagged as
                # pickup_after_already_shipped even though the Sales Orders were, correctly,
                # back to fully Open/unshipped. One bounded live check per matched order,
                # only on this already-rare path (a master marked shipped getting ANOTHER
                # pickup event) -- reuses the same proven idempotency lookup used elsewhere.
                # find_any_sales_orders_batch (not find_sales_orders_batch/open-only): a
                # genuinely still-shipped master's orders are commonly Shipping/Completed/
                # Closed by now, not Open -- the open-only search found nothing for exactly
                # that case, misread it as "ledger stale," and reset a correctly-shipped
                # master back to waiting for no reason (real case, masters 362040/041/044/
                # 045, 2026-07-31 -- see FULFILLED_SO_STATUSES's docstring).
                still_shipped = any(
                    _latest_shipment_for_order(m["order_type"], m["order_nbr"], retries=1, delay=0)
                    for m in find_any_sales_orders_batch([token]).get(token, []))
                if still_shipped:
                    # FIXED 2026-07-31 (real bug, caught live via /ledger/recheck): this used
                    # to `return` the WHOLE function here -- for a shared trigger container
                    # resolving to many unrelated masters (the common case, see the PER-MASTER
                    # comment below), that aborted checking every OTHER token in `resolved`
                    # too, not just this one. A container resolving to even ONE already-
                    # shipped-and-verified sibling silently blocked every genuinely-ready
                    # sibling from ever being (re)evaluated in the SAME event -- confirmed
                    # live: masters 362040/041/044/045/328810 never actually got re-checked
                    # by /ledger/recheck because container DRYU9475020 also resolves to
                    # already-shipped sibling 361421, which always got hit first in iteration
                    # order. Now excludes only THIS token from further processing and lets
                    # every sibling proceed independently -- same principle as the
                    # completeness gate below, which Parker already confirmed is correct.
                    # FIXED 2026-08-03, Parker's call (real noise: master 642058's siblings
                    # SEGU9247979/SZLU9148202/TTNU8872610 -- confirmed via a live Acumatica
                    # export that all 5 of that master's containers, including these 3, were
                    # already on the SAME PO receipt back on 2026-07-01, well before any of
                    # today's "anomaly" emails). A duplicate/late NRT pickup notification for
                    # a PO that's already fully received can't be reporting anything new --
                    # the goods are already logged into the warehouse. Deliberately checking
                    # PO_COMPLETENESS() (the Gate-1 receiving fact), NOT the DC sales order's
                    # own status -- an order THIS automation shipped itself sits at "Shipping"
                    # forever (it never auto-confirms; a clerk does that manually), so a
                    # Completed/Closed-only check on the sales order would almost never fire
                    # for exactly the case it needs to catch (first tried and reverted this
                    # same day). po_completeness() fails closed on any lookup problem, same
                    # guarantee this already relies on elsewhere in this function.
                    po_ref = _po_ref_for(token)
                    po_fully_received = bool(po_ref) and po_completeness(*po_ref)[0]
                    if po_fully_received:
                        anomalous_tokens.add(token)
                        continue
                    anomalies.append({"master": token,
                                       "note": f"master {token} was already marked shipped, but a "
                                               "new pickup event just arrived for it -- a clerk "
                                               "should investigate",
                                       "ledger_entry": entry})
                    anomalous_tokens.add(token)
                    continue
                # The ledger was stale -- no live shipment actually exists anymore (e.g. it
                # was deleted after being found erroneous). Reset so this master gets
                # re-evaluated normally instead of being permanently stuck flagging a
                # false anomaly on every future pickup event. reset_first_seen=True: this
                # is a genuinely NEW waiting period, not a continuation -- without it,
                # ledger_check_sla() would measure from whenever this master first
                # appeared, possibly months ago, and could immediately flag it as stuck.
                ledger_set_status(token, "waiting", reset_first_seen=True)
            else:
                # FIXED 2026-08-03, real gap: a master NOT yet marked "shipped" in our
                # ledger can still already be fulfilled in Acumatica -- shipped manually by
                # a clerk, entirely bypassing the NRT/completeness flow this function
                # gates on. Without this check, such a master runs the completeness gate
                # below on every single event and every /ledger/recheck, forever, since it
                # never actually completes ON ITS OWN (the manual shipment already
                # satisfied the real-world need, so there's nothing left for our own
                # criteria to catch up to). The OTHER "already fulfilled" check
                # (find_fulfilled_sales_orders, further below) exists for exactly this
                # semantic but only runs for masters that already PASSED this gate --
                # never reached by a master that fails it. Same allow-list-based detection
                # (Completed/Closed/Shipping -- see FULFILLED_SO_STATUSES's docstring for
                # why Cancelled/Voided deliberately don't count), just moved earlier so a
                # manually-shipped master gets caught regardless of gate outcome.
                fulfilled = find_fulfilled_sales_orders([token]).get(token, [])
                if fulfilled:
                    ledger_set_status(token, "shipped",
                                       note="Detected already fulfilled in Acumatica (status: "
                                            f"{fulfilled[0]['status']}) -- likely shipped "
                                            "manually, outside this automation.")
                    ledger_record(token, container, pickup_date, email_received_at)
                    anomalous_tokens.add(token)
                    continue
            ledger_record(token, container, pickup_date, email_received_at)
        resolved = [t for t in original_resolved if t not in anomalous_tokens]
        if not resolved:
            if anomalies:
                # Every resolved master for this container was an anomaly -- genuinely
                # nothing else to do this event.
                _log_early("anomaly", {"anomalies": anomalies})
                return {"container": container, "needs_review": True, "created": 0, "orders_matched": 0,
                        "reason": "pickup_after_already_shipped", "anomalies": anomalies}
            # Every resolved master for this container was excluded for a BENIGN reason
            # (PO fully received already, or a manually-fulfilled detection) -- not a real
            # anomaly, just nothing left to do. Distinct from the anomalies branch above so
            # this doesn't show up as "Needs review" noise.
            note = ("every PO tied to this container is already fully received in Acumatica, "
                    "or was already detected as fulfilled -- no action needed")
            synthetic_orders = [{"po": tok, "order": None, "shipment_nbr": None, "created": False,
                                  "reason": "already fulfilled -- fully received in Acumatica"}
                                 for tok in anomalous_tokens]
            _log_early("already_fulfilled", {"note": note, "orders": synthetic_orders})
            return {"container": container, "needs_review": False, "created": 0, "orders_matched": 0,
                    "reason": "already_closed", "note": note}
        po_refs = resolve_pos_by_master(container)
        for token in resolved:
            ledger_stamp_checked(token)
        # Force a fresh receipts pull before deciding completeness (unless the caller says
        # it already did -- see force_receipts param) -- containers_confirmed_available()
        # (below) derives "every container this PO depends on" from
        # expected_containers_for_master(), which reads load_recent_receipts()'s cache (up
        # to RECEIPTS_TTL/10min stale). A sibling container's packing list landing in
        # Acumatica in that window wouldn't be visible yet, understating the expected set --
        # which makes completeness look satisfied when a real sibling is still unaccounted
        # for. This is the one direction that matters: a STALE cache can only make the gate
        # too PERMISSIVE (fewer expected containers to satisfy), never too strict, so the fix
        # is a one-time forced refresh right before the gate runs, not after.
        if force_receipts:
            load_recent_receipts(force=True)
        # SECOND, INDEPENDENT gate (2026-07-24, real incident): the PO-receiving check
        # above is a warehouse-side fact (has Acumatica recorded all the qty as received);
        # it is NOT the same as "has every container this PO depends on been individually
        # confirmed Available for Pickup by NRT" (a port-pickup fact). A PO can show fully
        # received while a sibling container has never sent its own NRT email at all --
        # confirmed real, see containers_confirmed_available's docstring. Revenue
        # recognition is anchored to the port-pickup event, so BOTH gates must pass.
        #
        # Evaluated PER MASTER, not aggregated across the whole container event (fixed
        # 2026-07-27, real case: container ONEU9300392 resolves to 5 unrelated masters at
        # once -- 141970/378306/645410/645411/645399 -- via 5 separate receipts, and
        # treating them as one all-or-nothing unit wrongly held back the 4 that were
        # fully ready just because the 5th (645399) was still waiting on sibling
        # container FSCU5863132. A master that passes both gates ships now; a sibling
        # sharing the same pickup event that doesn't stays "waiting" on its own -- Parker
        # confirmed this is the intended behavior.
        completeness_detail = []
        container_gaps = {}
        ready = []
        # Every resolved master's FULL expected-container set, regardless of ready/waiting --
        # needed so a successful run can log which containers actually belong to whichever
        # master(s) it ships, not just the single container that happened to trigger this
        # call. See container_ship_history()'s docstring for why this matters.
        expected_containers_by_master = {}
        for token in resolved:
            ref = po_refs.get(token)
            if ref is None:
                po_ok, po_detail = False, {"error": "receipt for this master did not resolve "
                                                      "to exactly one Purchase Order"}
            else:
                po_ok, po_detail = po_completeness(*ref)
            completeness_detail.append(dict(po_detail, master=token, complete=po_ok))
            all_confirmed, missing, expected = containers_confirmed_available(token, current_container=container)
            expected_containers_by_master[token] = expected
            if not all_confirmed:
                container_gaps[token] = {"missing_containers": missing, "expected_containers": expected}
            if po_ok and all_confirmed:
                ready.append(token)
            else:
                ledger_set_status(token, "waiting")
        if not ready:
            if container_gaps:
                note = ("not every container for this order has been individually confirmed "
                         "Available for Pickup by NRT yet -- still waiting on: " +
                         "; ".join(f"master {tok}: {', '.join(g['missing_containers'])}"
                                   for tok, g in container_gaps.items()))
                reason = "containers_not_all_confirmed"
            else:
                note = ("underlying Purchase Order isn't fully received yet -- waiting for "
                         "the remaining container(s) before shipping this order; no action needed")
                reason = "po_incomplete"
            out = {"container": container, "waiting_on_containers": True, "created": 0,
                   "orders_matched": 0, "reason": reason, "note": note,
                   "completeness_detail": completeness_detail,
                   "container_gaps": container_gaps or None}
            if anomalies:
                # Don't silently drop the anomalies this event already found just because
                # every SURVIVING (non-anomalous) resolved master also isn't ready yet --
                # both facts are real and independent, a human reviewing this result should
                # see both.
                out["anomalies"] = anomalies
            _log_early("waiting", {"note": note, "unresolved_containers": []})
            return out
        all_pos = ready
        unresolved = not original_resolved
        still_waiting = sorted(set(resolved) - set(ready))

    matched = find_sales_orders_batch(all_pos)
    if all_pos and not any(matched.get(p) for p in all_pos):
        # Stale-cache guard: zero matches for EVERY resolved PO is suspicious enough to
        # warrant one forced refresh before accepting "no open sales order" as real.
        load_open_orders(force=True)
        matched = find_sales_orders_batch(all_pos)
    unmatched = [po for po in all_pos if not matched.get(po)]
    # Before flagging "no open sales order" as needing review: is there a genuinely-
    # fulfilled (Completed/Closed) order instead, meaning this was already fulfilled --
    # likely manually, before this automation existed -- rather than genuinely missing?
    # See find_fulfilled_sales_orders()'s docstring for the real incident this fixes
    # (and why Cancelled/Voided deliberately don't count).
    fulfilled = find_fulfilled_sales_orders(unmatched) if unmatched else {}
    # Real case, 2026-07-30 (378307 + siblings 118040/118072/141972): the per-PO already-
    # fulfilled fix above never propagated into the RUN's overall status. All 4 masters
    # got resolved together (one shared consolidated receipt group), but 3 were already
    # shipped and confirmed by a person days earlier (no open Sales Order left -- correctly
    # "already fulfilled"), while 378307 genuinely had no Sales Order yet at that moment.
    # to_create stayed 0 for BOTH reasons alike, so the run logged "no_matches" -- sounding
    # like nothing happened, when 3 of 4 were actually fine and only one was genuinely
    # pending. Tracked separately here so the run status below can tell them apart.
    already_fulfilled_pos = [po for po in unmatched if fulfilled.get(po)]
    genuinely_missing_pos = [po for po in unmatched if not fulfilled.get(po)]
    rows = []; log_orders = []; to_create = 0; created = 0
    po_all_created = {}  # po/master token -> did every matched order for it end up created?
    for po in all_pos:
        matches = matched.get(po, [])
        if not matches:
            fulfilled_orders = fulfilled.get(po) or []
            if fulfilled_orders:
                statuses = sorted({o["status"] for o in fulfilled_orders if o.get("status")})
                # Not always "before this automation ran" -- a Shipping-status order (see
                # FULFILLED_SO_STATUSES) commonly got its shipment from THIS SAME automation,
                # just not yet confirmed/invoiced. Kept status-agnostic so the note stays true
                # either way.
                note = (f"already fulfilled -- {len(fulfilled_orders)} sales order(s) found with "
                        f"status {', '.join(statuses)}; no action needed")
                rows.append({"po": po, "confidence": "ok", "note": note, "orders": [],
                             "already_fulfilled": True})
            else:
                note = "no open sales order"
                rows.append({"po": po, "confidence": "flag", "note": note, "orders": []})
            if not dry_run:
                log_orders.append({"po": po, "order": None, "shipment_nbr": None,
                                    "created": False, "reason": note})
            # An already-fulfilled master is done, not pending -- mark it "shipped" so it
            # stops re-flagging on every future recheck, same as a real successful creation.
            po_all_created[po] = bool(fulfilled_orders)
            continue
        po_ok = True
        for m in matches:
            to_create += 1
            row = {"po": po, "confidence": "ok", "orders": [m], "note": ""}
            if not dry_run:
                # Per-order idempotency pre-check: if this specific order already has a real
                # shipment, don't call create_shipment again -- makes a crash-and-retry (or a
                # duplicate/resent NRT email) naturally resume/no-op without depending on
                # whether Acumatica's CreateShipment itself would reject or duplicate a
                # re-call (confirmed unresolved either way, see the Phase-2 plan).
                # Ship at the LATEST recorded pickup date for this master (spans however many
                # separate NRT events it took), not just this one event's own date -- falls
                # back to the passed-in ship_date for the pos-given (Maersk/FCR) path, which
                # isn't ledger-tracked. Computed unconditionally (not just in the fresh-create
                # branch below) since the certificate needs a real date either way, including
                # on the idempotency-shortcut path.
                effective_date = ledger_latest_date(po) or ship_date
                existing = _latest_shipment_for_order(m["order_type"], m["order_nbr"], retries=1, delay=0)
                if existing:
                    res = {"order": f"{m['order_type']} {m['order_nbr']}", "created": True,
                           "shipment_nbr": existing.get("shipment_nbr"), "already_existed": True}
                else:
                    res = create_shipment(m["order_type"], m["order_nbr"], container, effective_date, po=po)
                row["result"] = res
                if res.get("created"):
                    created += 1
                else:
                    po_ok = False
                log_orders.append({"po": po, "order": f"{m['order_type']} {m['order_nbr']}".strip(),
                                    "customer": m.get("customer"),
                                    "shipment_nbr": res.get("shipment_nbr"), "created": res.get("created"),
                                    "ship_date": res.get("ship_date"), "reason": res.get("reason") or res.get("error")})
            rows.append(row)
        po_all_created[po] = po_ok

    if not dry_run and not pos:
        # Only the container-resolution (NRT) path is ledger-tracked -- mark each master
        # "shipped" once every one of its matched DC orders is confirmed created (existing
        # or new); if only some succeeded, leave it "partial" so the recheck job (and SLA
        # flagging) can finish/surface the rest rather than silently losing track.
        for token in all_pos:
            ledger_set_status(token, "shipped" if po_all_created.get(token) else "partial")

    unresolved_containers = [container] if (unresolved and not all_pos) else []
    summary = {"container": container, "source": source, "po_count": len(all_pos),
               "unresolved_containers": unresolved_containers,
               "orders_matched": to_create, "created": created, "dry_run": dry_run, "rows": rows}
    if still_waiting:
        # Some of this pickup event's masters shipped above; these siblings are still
        # gated (Gate 1 and/or Gate 2) and stay "waiting" -- surfaced alongside the
        # created rows rather than as a separate blocking event, see the per-master gate
        # comment above.
        summary["still_waiting_masters"] = still_waiting
        summary["container_gaps"] = container_gaps or None
        summary["completeness_detail"] = completeness_detail
    if anomalies:
        # A sibling sharing this same trigger container was already marked shipped and
        # genuinely still is -- excluded from processing (see the stale-ledger check
        # above), surfaced here rather than aborting the whole event for every OTHER
        # sibling too.
        summary["anomalies"] = anomalies
    if not dry_run:
        if to_create == 0:
            if not already_fulfilled_pos:
                status = "no_matches"           # nothing found for anyone -- genuinely needs a look
            elif not genuinely_missing_pos:
                status = "already_fulfilled"    # everyone in this event was already done -- no concern
            else:
                status = "partial"              # a real mix: some already fine, one+ still genuinely missing
        elif created == to_create and not genuinely_missing_pos:
            status = "ok"
        elif created > 0 or already_fulfilled_pos:
            status = "partial"
        else:
            status = "failed"
        # FIXED 2026-08-03, real incident: master 642058's own containers (SZLU9148202,
        # KKFU6781146, SEGU9247979, TTNU8872610, TCLU1353206) arrived as 5 SEPARATE real NRT
        # events -- only the LAST one to arrive actually completed the set and triggered
        # creation, so ONLY that one container's string ended up in a successful run's own
        # "containers" field. container_ship_history() matches on that field, so the other 4
        # -- equally real, equally shipped -- always read shipped=false when checked later,
        # since they were never personally the trigger of a successful run. That falsely
        # tripped the missed-trigger-backfill logic days later when NRT sent their NEXT
        # lifecycle-stage email ("Scheduled for Pickup"), re-firing create_shipment for
        # containers that had already done their job -- which then correctly (but uselessly)
        # tripped the SEPARATE already-shipped anomaly check. Recording the FULL confirmed-
        # container set for every master that actually ships in THIS run -- not just the
        # single container parameter that happened to trigger it -- lets
        # container_ship_history() match against any of them, not just the one.
        all_confirmed_containers = sorted({
            c for token in all_pos if po_all_created.get(token)
            for c in (expected_containers_by_master.get(token) or [])
        })
        log_run({"reference": None, "document": f"auto:{source or 'unknown'}",
                 "user": user or f"auto:{source or 'unknown'}", "acumatica_user": connected_user(),
                 "status": status, "orders_matched": to_create, "created": created, "containers": container,
                 "all_confirmed_containers": all_confirmed_containers or None,
                 "unresolved_containers": unresolved_containers, "ship_date": ship_date,
                 "email_received_at": email_received_at,
                 "still_waiting_masters": still_waiting or None, "anomalies": anomalies or None,
                 "orders": log_orders})
        if created:
            notify_shipment_created({
                "container": container, "source": source or "unknown",
                "acumatica_user": connected_user(), "email_received_at": email_received_at,
                "ship_date": ship_date, "created_count": created,
                "orders": [o for o in log_orders if o.get("created")],
                "still_waiting_masters": still_waiting or None, "anomalies": anomalies or None,
            })
    return summary

# ---------------- FCR (Forwarder's Cargo Receipt) parser -- Maersk/origin-title path ----------------
_FCR_SKIP = ("SHIPPER", "CONSIGNEE", "NOTIFY PARTY")

def parse_fcr(path):
    """Extract container#, the PO#s under it, and Port of Loading from a Forwarder's
    Cargo Receipt PDF. Port of Loading is the anchor used later to pick the correct
    "Load on [vessel]" event on the Maersk tracking timeline (containers that transship
    through a hub port show a second, later "Load on" event elsewhere that must be
    ignored -- matching the named origin location, not "take the first one", resolves
    this). Confirmed against a real FCR (receipt HPH1337209, Light Forever -> Winners):
    header table has "PORT AND COUNTRY OF ORIGIN" / port of loading in one grid, and the
    container/PO list appears on a later page as "MNBU0506461/ ... PO# <one per line>".
    """
    if pdfplumber is None:
        raise RuntimeError("pdfplumber not installed")
    receipt_no = None; port_of_loading = None; vessel = None
    container = None; pos = []
    with pdfplumber.open(path) as pdf:
        full = ""
        for pg in pdf.pages:
            full += (pg.extract_text() or "") + "\n"
    m = re.search(r"RECEIPT\s*NO\.?\s*:?\s*([A-Z0-9]+)", full, re.I)
    if m: receipt_no = m.group(1)
    # The header grid flattens to one label line ("PLACE OF RECEIPT / PORT OF LOADING /
    # PORT OF DISCHARGE / PLACE OF DELIVERY", sometimes "PLACEOF" with no space from PDF
    # kerning) followed by one value line with the same 4 slots -- Port of Loading is the
    # 2nd token. Confirmed against a real FCR (receipt HPH1337209); single-word port names
    # only so far -- revisit if a multi-word port name shows up.
    m = re.search(r"PLACE\s*OF\s+RECEIPT\s+PORT\s+OF\s+LOADING\s+PORT\s+OF\s+DISCHARGE\s+"
                  r"PLACE\s*OF\s+DELIVERY\s*\n\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", full, re.I)
    if m: port_of_loading = m.group(2).strip()
    m = re.search(r"VESSEL\s*:?\s*([A-Z0-9 ]{3,30})", full, re.I)
    if m: vessel = m.group(1).strip()
    m = re.search(r"\b([A-Z]{4}\d{7})\s*/", full)   # ISO container no. immediately before "/ PO#" or "/ <ref>"
    if m: container = m.group(1)
    po_block = re.search(r"PO#\s*\n(.*?)\n\s*(?:PCS|TOTAL|\*\*)", full, re.S)
    if po_block:
        for line in po_block.group(1).splitlines():
            # PO# can share its line with other reference text (e.g. "ML-VN1607577
            # 3500315493", "40HREF 3500322381") -- take the trailing digit run, not the
            # whole line.
            t = re.search(r"(\d{8,12})\s*$", line.strip())
            if t and t.group(1) not in pos:
                pos.append(t.group(1))
    return {"receipt_no": receipt_no, "container": container, "port_of_loading": port_of_loading,
            "vessel": vessel, "pos": pos}

# ---------------- Maersk tracking check (origin Load-on-vessel event) ----------------
# No login needed for maersk.com/tracking/{container} (confirmed live) -- but its backing
# JSON API (api.maersk.com/synergy/tracking/...) is Akamai-protected even from the page's
# own JS, so this drives a real headless page load and reads the rendered text, same as a
# person would, rather than trying to call that API directly.
_MAERSK_DATE_RE = re.compile(r'^\d{1,2} [A-Za-z]{3}\.?,? \d{4} \d{2}:\d{2}$')
_MAERSK_LOAD_ON_RE = re.compile(r'^Load on\b', re.I)

def parse_maersk_timeline(text):
    """Ordered [(location, event_desc, date_str), ...] from the tracking page's rendered
    text. Structure (confirmed against a real multi-leg container MNBU3690916): a location
    line, a facility-name line, then repeating (event, date) line pairs until the next
    location. State machine, not per-line dead-reckoning: whenever the line after the
    "current" one fails to look like a date, that current line is actually the start of a
    new location block, not an event with a missing date."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for idx, l in enumerate(lines):
        if l.lower().startswith("note: all times are given"):
            lines = lines[idx + 1:]
            break
    events = []
    i, n = 0, len(lines)
    location = None
    expect = "location"
    while i < n:
        line = lines[i]
        if expect == "location":
            location = line
            i += 1
            if i < n:
                i += 1  # facility name line, not needed
            expect = "event"
            continue
        if i + 1 < n and _MAERSK_DATE_RE.match(lines[i + 1]):
            events.append((location, line, lines[i + 1]))
            i += 2
        else:
            expect = "location"
    return events

def _maersk_iso_date(s):
    return datetime.datetime.strptime(s, "%d %b %Y %H:%M").strftime("%Y-%m-%d")

def find_origin_load_on(text, port_of_loading):
    """The correct revenue-recognition anchor for these accounts: the "Load on [vessel]"
    event at the location matching the FCR's Port of Loading -- NOT the first Load-on event
    overall, since transshipping containers show a second, later one at the hub port that
    must be ignored. Returns None if that container hasn't shown this event yet (keep
    watching) -- distinguish from a parse failure by checking the caller's own error field."""
    port = (port_of_loading or "").strip().upper()
    if not port:
        return None
    for location, desc, date_str in parse_maersk_timeline(text):
        if port in location.upper() and _MAERSK_LOAD_ON_RE.match(desc):
            return {"matched_location": location, "event": desc, "date": _maersk_iso_date(date_str)}
    return None

def check_maersk_container(container, port_of_loading, timeout_ms=20000):
    """Headless page load of maersk.com/tracking/{container}; returns find_origin_load_on's
    result (or None if not found yet) plus a bit of context for the caller to log."""
    if sync_playwright is None:
        raise RuntimeError("playwright not installed")
    container = (container or "").strip().upper()
    url = f"https://www.maersk.com/tracking/{container}"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            page.wait_for_selector("text=Note: All times are given", timeout=timeout_ms)
            text = page.inner_text("body")
        finally:
            browser.close()
    result = find_origin_load_on(text, port_of_loading)
    return {"container": container, "port_of_loading": port_of_loading, "found": result is not None,
            "match": result}

# ---------------- diagnostics ----------------
def _stage(r):
    """Derive the next-action stage from a pipeline record. so_pipeline() now matches
    orders in any status (see its docstring), so this can see an order anywhere in its
    life -- from before a shipment exists through invoice release. Shipment 'Status' is
    Open until Confirmed/Completed."""
    if not r.get("shipment"): return "Create shipment"
    sst = (r.get("shipment_status") or "").lower()
    if "confirm" not in sst and "complet" not in sst:  # still Open / not confirmed
        return "Confirm shipment"
    if not r.get("invoice"): return "Create invoice"
    return "Release invoice"

def _sh_field(sh, *names):
    """Read the first present field 'value' from a Shipments sub-record."""
    for n in names:
        v = sh.get(n)
        if isinstance(v, dict) and v.get("value") not in (None, ""):
            return v.get("value")
    return None

def _order_pipeline(m, po=None):
    """Build one pipeline record from an open-order match: read the order's
    Shipments expand (GET-by-key, no substringof) and derive the stage."""
    ot, on = m["order_type"], m["order_nbr"]
    rec = {"po": po, "order": f"{ot} {on}".strip(), "order_status": m.get("status"),
           "cust_order": m.get("cust_order"),
           "shipment": None, "shipment_status": None, "invoice": None, "invoice_status": None}
    est, ed = api("GET", f"{ENTITY}/SalesOrder/{ot}/{on}?$expand=Shipments")
    if est == 200 and isinstance(ed, dict):
        shs = ed.get("Shipments") or []
        # Real shipment records carry a ShipmentNbr; credit-memo / auto-issue
        # rows have an empty ShipmentNbr and are ignored for the shipment stage.
        ship_recs = [s for s in shs if _sh_field(s, "ShipmentNbr")]
        if ship_recs:
            sh = ship_recs[-1]
            rec["shipment"] = _sh_field(sh, "ShipmentNbr")
            rec["shipment_status"] = _sh_field(sh, "Status", "ShipmentStatus")
        # Invoice can appear on any of the rows (incl. the issue row).
        for s in shs:
            inv = _sh_field(s, "InvoiceNbr", "InvoiceRefNbr")
            if inv:
                rec["invoice"] = inv
                rec["invoice_status"] = _sh_field(s, "InvoiceStatus")
                break
    rec["stage"] = _stage(rec)
    return rec

def so_pipeline(po):
    """For a PO#, return each matched sales order's shipment/invoice pipeline stage.
    Avoids substringof (500s on this tenant): matches the PO against the cached order
    list client-side, then reads each order's shipments via GET-by-key.

    Uses find_any_sales_orders_batch (ALL statuses), not the open-only search. FIXED
    2026-07-31: the order leaves "Open" the moment ANY shipment is created against it
    (Acumatica flips it to "Shipping" -- see FULFILLED_SO_STATUSES's docstring), well
    before it's confirmed or invoiced. The old open-only match silently showed nothing for
    that order the instant a shipment existed, which read on /splits as "already fully
    processed" -- when it was really just sitting at "shipment created, needs
    confirmation," exactly the kind of thing a clerk should still see. A genuinely done
    order (invoice released) still correctly shows nothing further to do -- _stage() below
    already handles that case via Confirmed/invoice-released, this only widens which
    orders get INTO the pipeline check at all."""
    return [_order_pipeline(m, po) for m in find_any_sales_orders_batch([po]).get(po, [])]

def split_order_status(master_token, entry):
    """Live status for one in-progress split order (a container_ledger.json entry): its
    containers' recorded pickup dates, the underlying Purchase Order(s)' receiving
    completeness, and the matched Sales Orders. Re-checks PO completeness live (a couple
    of calls per container/PO, same functions the completeness gate and /diag already
    use) -- but the full shipment/invoice PIPELINE check (one live call per matched DC
    order, and a master fans out to several) is only run for 'partial' masters, where
    something might already be shipped. A 'waiting' master hasn't shipped anything at
    all by definition, so that check would just be extra live calls confirming a known
    negative -- skip it and show the cached (no-API-call) match list instead."""
    containers = entry.get("containers", {})
    po_refs = set()
    for c in containers:
        for ref in resolve_pos_from_container(c):
            if ref:
                po_refs.add(ref)
    po_status = []
    for po_type, po_nbr in sorted(po_refs, key=lambda r: r[1] or ""):
        ok, detail = po_completeness(po_type, po_nbr)
        po_status.append({"po": po_nbr, "complete": ok,
                           "status": detail.get("po_status") or detail.get("error") or "unknown"})
    if entry.get("status") == "partial":
        orders = so_pipeline(master_token)
    else:
        orders = [{"order": f"{m['order_type']} {m['order_nbr']}".strip(), "cust_order": m.get("cust_order"),
                    "stage": "Not shipped yet"} for m in find_sales_orders_batch([master_token]).get(master_token, [])]
    ledger_stamp_checked(master_token)
    return {"master": master_token, "ledger_status": entry.get("status"),
            "containers": containers, "purchase_orders": po_status, "orders": orders}

def _splits_html(limit=10, live=False):
    """Dashboard page for orders currently split across multiple containers/receipts --
    the cases the Phase-2 completeness gate is holding rather than shipping yet.

    Defaults to CACHED (zero Acumatica calls): just the ledger's own last-known state
    (containers, pickup dates, status, when it was last actually checked). Acumatica's
    license caps this tenant at 100 web-service API requests/minute -- a live re-check on
    every single page view (the original design) meant a couple of quick reloads could
    burst toward that cap for no reason, since PO receiving status doesn't change between
    reloads seconds apart. Pass live=True (the /splits?live=1 link) to force a real,
    paced re-check against Acumatica when you actually want current status."""
    ledger = load_json(LEDGER_PATH) or {}
    active = {tok: e for tok, e in ledger.items() if e.get("status") in ("waiting", "partial")}
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if not active:
        body = ('<div class=card><div class=empty-state><span class=e-icon>&#10003;</span>'
                '<h3>Nothing waiting on a split right now</h3>'
                '<p>Every order with more than one container has shipped. New splits will show up here automatically.</p>'
                '</div></div>')
    else:
        ordered = sorted(active.items(), key=lambda kv: kv[1].get("first_seen") or "")
        shown, hidden = ordered[:limit], ordered[limit:]
        cards = []
        for i, (tok, entry) in enumerate(shown):
            if live and i > 0:
                time.sleep(0.5)  # same 100-req/min license cap as /ledger/recheck; only matters when live
            try:
                cards.append(_split_order_card(tok, entry, esc, live))
            except Exception as e:
                # One master's data shouldn't be able to take the whole page down --
                # show what broke for this one and keep going.
                cards.append('<div class=group-card><h3>Master %s</h3>'
                              '<p class=sub style="color:var(--rust)">Could not load: %s</p></div>'
                              % (esc(tok), esc(str(e))))
        body = "".join(cards)
        if hidden:
            body += ('<p class=sub>%d more, oldest-waiting-first shown above -- '
                      '<a href="/splits?live=%s&limit=%d">show all %d</a>.</p>'
                      % (len(hidden), "1" if live else "0", len(ordered), len(ordered)))
    toggle = ('<a class="pill fog" href="/splits?live=1">Refresh live status</a>' if not live
              else '<a class=pill href="/splits">Back to cached view</a>')
    freshness = ("Showing live status, just checked against Acumatica." if live else
                 "Showing the last-known status from previous checks -- no Acumatica calls made "
                 "just to view this page.")
    return ('<div class=section-head><h1 style="font-size:20px">Orders split across containers</h1>%s</div>'
            '<p class=section-sub>Master POs currently waiting on more than one container before they can ship. %s</p>'
            % (toggle, freshness)
            + body)

def _split_order_card(tok, entry, esc, live=False):
    """Build one master's card for _splits_html. Split out so a failure building ONE
    card (bad/unexpected data for that master) can be caught and shown inline without
    taking down the rest of the page. live=False (the default) makes ZERO Acumatica
    calls -- everything comes straight from the ledger entry."""
    status_label = "Partially shipped" if entry.get("status") == "partial" else "Waiting"
    pill_class = "pill fog"
    if not live:
        # Real confusion, 2026-07-29: this card used to list ONLY the containers already
        # confirmed (entry["containers"]) -- with dates on every row, it reads as "all of
        # these are done, so why is this still waiting?" The actual reason is usually a
        # SIBLING container Acumatica's own receipts say belongs to this master, which
        # hasn't sent its own Available-for-pickup confirmation yet -- invisible here
        # unless it's shown explicitly. expected_containers_for_master() and
        # containers_confirmed_available() are both purely local (load_recent_receipts()
        # is already cached, confirmed_pickup_containers() is a local log read) -- adding
        # them here costs zero additional Acumatica calls, so the "zero API calls" promise
        # for the cached view still holds.
        _, missing, _ = containers_confirmed_available(tok)
        cont_rows = "".join(
            f"<tr><td class=mc>{esc(c)}</td><td class=md>{esc(d)}</td></tr>"
            for c, d in sorted(entry.get("containers", {}).items(), key=lambda kv: kv[1]))
        cont_rows += "".join(
            f'<tr><td class=mc>{esc(c)}</td><td class=md style="color:var(--rust)">not confirmed yet</td></tr>'
            for c in missing)
        checked = entry.get("last_checked")
        checked_note = (f"Purchase order status as of last check ({esc(_fmt_ts(checked))}) -- "
                        f'<a href="/splits?live=1">refresh live</a> for current status.') if checked else \
                       'Purchase order status not yet checked live -- <a href="/splits?live=1">refresh live</a> to check now.'
        return (
            f'<div class=group-card><div class=group-card-head><h3>Master PO {esc(tok)}</h3>'
            f'<span class={pill_class}>{status_label}</span></div>'
            f'<table class=mini-table><tr><th>Container</th><th>Available for pickup</th></tr>{cont_rows}</table>'
            f'<div class=as-of>{checked_note}</div></div>')
    info = split_order_status(tok, entry)
    _, live_missing, _ = containers_confirmed_available(tok)
    cont_rows = "".join(
        f"<tr><td class=mc>{esc(c)}</td><td class=md>{esc(d)}</td></tr>"
        for c, d in sorted(info["containers"].items(), key=lambda kv: kv[1]))
    cont_rows += "".join(
        f'<tr><td class=mc>{esc(c)}</td><td class=md style="color:var(--rust)">not confirmed yet</td></tr>'
        for c in live_missing)
    po_rows = "".join(
        f"<tr><td class=mc>{esc(p['po'])}</td><td class=md>{'&#10003; Received in full' if p['complete'] else '&#9678; ' + esc(p['status'])}</td></tr>"
        for p in info["purchase_orders"]) or "<tr><td colspan=2 class=sub>Could not resolve a Purchase Order</td></tr>"
    order_rows = "".join(
        f"<tr><td class=mc>{esc(o['order'])}</td><td>{esc(o.get('cust_order') or '')}</td><td class=md>{esc(o['stage'])}</td></tr>"
        for o in info["orders"]) or "<tr><td colspan=3 class=sub>No open sales order matched</td></tr>"
    return (
        f'<div class=group-card><div class=group-card-head><h3>Master PO {esc(tok)}</h3>'
        f'<span class={pill_class}>{status_label}</span></div>'
        f'<p class=sub>Containers seen so far, in order of pickup date:</p>'
        f'<table class=mini-table><tr><th>Container</th><th>Available for pickup</th></tr>{cont_rows}</table>'
        f'<p class=sub style="margin-top:14px">Underlying Purchase Order(s) &mdash; ALL must be fully received before this ships:</p>'
        f'<table class=mini-table><tr><th>Purchase Order</th><th>Status</th></tr>{po_rows}</table>'
        f'<p class=sub style="margin-top:14px">Matched Sales Order(s):</p>'
        f'<table class=mini-table><tr><th>Order</th><th>Customer order #</th><th>Stage</th></tr>{order_rows}</table>'
        f'</div>')

def _identity_probe():
    """Raw view of what the identity-detection path actually sees, for diagnosing why the
    'Connected as ...' banner can't name a user. Shows JWT payload KEYS (not full token) and
    the raw userinfo call outcome -- enough to tell whether Acumatica granted openid/profile
    or silently dropped them, without ever printing the token itself."""
    tok = load_json(TOKEN_PATH) or {}
    at = tok.get("access_token", "")
    out = {"stored_user": tok.get("_user"), "scope_in_token_response": tok.get("scope"),
           "jwt_decodable": False, "jwt_payload_keys": [], "userinfo_status": None, "userinfo_body": None}
    try:
        parts = at.split(".")
        if len(parts) >= 2:
            pad = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(pad.encode()))
            out["jwt_decodable"] = True
            out["jwt_payload_keys"] = sorted(payload.keys())
    except Exception as e:
        out["jwt_decode_error"] = str(e)
    try:
        req = urllib.request.Request(CFG["base_url"] + "/identity/connect/userinfo",
                                     headers={"Authorization": "Bearer " + at})
        with urllib.request.urlopen(req, timeout=20) as r:
            out["userinfo_status"] = r.status
            out["userinfo_body"] = json.loads(r.read())
    except urllib.error.HTTPError as e:
        out["userinfo_status"] = e.code
        out["userinfo_body"] = e.read().decode("utf-8", "ignore")[:500]
    except Exception as e:
        out["userinfo_error"] = str(e)
    return out

def diagnostics(sample_po=None, sample_container=None, sample_receipt=None):
    out = {"connected": bool(access_token()), "tenant": CFG["tenant"],
           "container_field": CFG["container_field"] or "(not set)", "warehouse": CFG["warehouse"] or "(SO default)"}
    if not out["connected"]: return out
    out["identity_probe"] = _identity_probe()
    # Rate-limit visibility (Parker asked whether we're approaching an Acumatica API
    # quota) -- dump every response header from one real call. If Acumatica surfaces
    # anything rate-limit-related (X-RateLimit-*, Retry-After, etc.) it'll show up here;
    # if not, this tenant/API doesn't expose that and usage has to be checked from
    # Acumatica's own side (License Management / your reseller), not from here.
    _, _, hdrs = api_with_headers("GET", f"{ENTITY}/SalesOrder?$top=1")
    out["response_headers_sample"] = hdrs
    out["rate_limit_headers_found"] = {k: v for k, v in hdrs.items()
                                        if "rate" in k or "limit" in k or "retry" in k or "throttl" in k}
    # Structural samples (no substringof — that operator 500s on this tenant).
    # A single order with its Shipments expand reveals the real field names.
    sst, sso = api("GET", f"{ENTITY}/SalesOrder?$top=1&$expand=Shipments")
    if sst == 200 and isinstance(sso, list) and sso:
        so0 = sso[0]
        out["so_keys"] = sorted(so0.keys())
        shs = so0.get("Shipments")
        out["so_shipments_sample"] = (shs[0] if isinstance(shs, list) and shs else shs)
    else:
        out["so_sample_status"] = sst
    shst, shd = api("GET", f"{ENTITY}/Shipment?$top=1")
    if shst == 200 and isinstance(shd, list) and shd:
        out["shipment_keys"] = sorted(shd[0].keys())
    else:
        out["shipment_sample_status"] = shst
    # Live pipeline sample: run the real stage logic against a few OPEN orders.
    open_orders = load_open_orders()
    out["open_orders_count"] = len(open_orders)
    out["pipeline_sample"] = [_order_pipeline(o) for o in open_orders[:6]]
    if sample_po:
        matches = find_sales_orders_batch([sample_po]).get(sample_po, [])
        out["sample_po"] = sample_po
        out["open_matches"] = matches[:5]
        out["sample_pipeline"] = so_pipeline(sample_po)
        # READ-ONLY qty probe for the Phase-2 (multi-container aggregation) design question:
        # does Acumatica already show enough received/available qty to ship on a SO whose
        # linked PO spans multiple containers, only SOME of which have arrived? If so,
        # CreateShipment could create a premature PARTIAL shipment the moment any one
        # container's PO Receipt posts qty -- before master_multi_receipt_flags' refusal even
        # matters for a would-be Phase 2 that tries to call it early. Never calls
        # CreateShipment itself -- just reads each matched SO's Detail lines.
        qty_probe = []
        for m in matches[:5]:
            qst, qd = api("GET", f"{ENTITY}/SalesOrder/{m['order_type']}/{m['order_nbr']}?$expand=Details")
            if qst == 200 and isinstance(qd, dict):
                lines = []
                for dline in (qd.get("Details") or []):
                    lines.append({k: (v.get("value") if isinstance(v, dict) else v)
                                  for k, v in dline.items()
                                  if re.search(r"qty|quantity|open|ship|complet", k, re.I)})
                qty_probe.append({"order": f"{m['order_type']} {m['order_nbr']}", "lines": lines})
            else:
                qty_probe.append({"order": f"{m['order_type']} {m['order_nbr']}", "status": qst})
        out["sample_po_qty_probe"] = qty_probe
        # READ-ONLY PurchaseOrder-completeness probe (Tier 2 of the Phase-2 plan, see
        # majestic-swimming-melody.md). Answers, before any code is written against it:
        # (a) does a receipt's Details agree on ONE POOrderNbr, (b) what field name/value
        # does PurchaseOrder actually use for its Type ("Type" vs "OrderType" -- even the
        # sibling packing-list-acumatica app hedges between the two), (c) which qty field
        # (OpenQty vs OrderQty-QtyOnReceipts) is trustworthy, (d) whether that qty reflects
        # the SUM across every receipt tied to this PO when more than one receipt is found
        # below (the entire premise of the completeness-check design). Uses an EXACT $filter
        # (OrderNbr eq '...'), never substringof -- substringof is confirmed to 500 on this
        # tenant (see _latest_shipment_for_order's docstring); an exact eq filter is the same
        # safe pattern diagnostics() already uses elsewhere (e.g. probe_007068 below).
        po_probe = {"receipts_checked": []}
        matching_receipts = [r for r in load_recent_receipts()
                              if sample_po in _extract_order_tokens(r.get("vendor_ref"))]
        for r in matching_receipts[:5]:
            rflt = urllib.parse.quote(f"ReceiptNbr eq '{r['receipt_nbr']}'")
            rst, rd = api("GET", f"{ENTITY}/PurchaseReceipt?$filter={rflt}&$expand=Details")
            entry = {"receipt_nbr": r["receipt_nbr"]}
            if rst == 200 and isinstance(rd, list) and rd:
                details = rd[0].get("Details") or []
                po_nbrs = sorted({(d.get("POOrderNbr") or {}).get("value")
                                   for d in details if d.get("POOrderNbr")})
                po_types = sorted({(d.get("POOrderType") or {}).get("value")
                                    for d in details if d.get("POOrderType")})
                entry["po_order_nbrs_on_this_receipt"] = po_nbrs
                entry["po_order_types_on_this_receipt"] = po_types
                entry["details_agree_on_one_po"] = len(po_nbrs) <= 1
            else:
                entry["status"] = rst
            po_probe["receipts_checked"].append(entry)
        distinct_po_nbrs = sorted({n for e in po_probe["receipts_checked"]
                                    for n in e.get("po_order_nbrs_on_this_receipt", [])})
        po_probe["distinct_po_order_nbrs_across_receipts"] = distinct_po_nbrs
        po_probe["receipt_count_for_this_master"] = len(matching_receipts)
        if distinct_po_nbrs:
            target_nbr = distinct_po_nbrs[0]
            pflt = urllib.parse.quote(f"OrderNbr eq '{target_nbr}'")
            pst, pd = api("GET", f"{ENTITY}/PurchaseOrder?$filter={pflt}&$expand=Details")
            po_probe["po_lookup_status"] = pst
            if pst == 200 and isinstance(pd, list) and pd:
                po_body = pd[0]
                po_probe["po_keys"] = sorted(po_body.keys())
                type_field = "Type" if "Type" in po_body else ("OrderType" if "OrderType" in po_body else None)
                po_probe["po_type_field_name"] = type_field
                po_probe["po_type_field_value"] = (po_body.get(type_field) or {}).get("value") if type_field else None
                po_probe["po_status"] = (po_body.get("Status") or {}).get("value")
                details = po_body.get("Details") or []
                po_probe["po_detail_qty_fields"] = [
                    {k: (v.get("value") if isinstance(v, dict) else v) for k, v in d.items()
                     if re.search(r"qty|quantity|open|receiv|complet", k, re.I)}
                    for d in details]
            else:
                po_probe["po_lookup_error"] = pd
        out["po_completeness_probe"] = po_probe
    st, schema = api("GET", f"{ENTITY}/Shipment/$adHocSchema")
    if st == 200 and isinstance(schema, dict):
        cands = []
        for view, fields in (schema.get("custom", {}) or {}).items():
            for fn in fields:
                if re.search(r"contain|ctnr|cont", fn, re.I) and not re.search(r"eta|arriv|estimat", fn, re.I):
                    cands.append(f"{view}.{fn}")
        out["container_field_candidates"] = cands
    else:
        out["schema_status"] = st
    # PO Receipt -> internal PO -> VendorRef chain (see containers_to_pos()).
    rc_field, rc_view = discover_receipt_container_field()
    out["receipt_container_field"] = f"{rc_view}.{rc_field}" if rc_field else "(not found)"
    # DECISIVE PROBE: does the container ($custom field) come back on a LIST GET the way it
    # does on a single-entity GET? Compare how many recent receipts load_recent_receipts
    # actually loaded vs how many carry a container, and dump the raw custom block from a
    # small list query. If list rows have empty custom{} but the single-receipt fetch had
    # the value, that's the Acumatica quirk (custom returned per-entity, not per-list).
    if rc_field:
        recs = load_recent_receipts(force=True)
        out["receipts_loaded"] = len(recs)
        out["receipts_with_container"] = sum(1 for r in recs if r.get("containers"))
        out["receipts_sample"] = recs[:3]
        # Status probe of the EXACT load-shape query (top 5) -- if receipts_loaded is 0 this
        # shows whether the query errored (status != 200) or genuinely returned nothing.
        cutoff = (datetime.date.today() - datetime.timedelta(days=RECEIPT_LOOKBACK_DAYS)).isoformat()
        pst, pdata = api("GET", f"{ENTITY}/PurchaseReceipt?$filter=Date ge datetimeoffset'{cutoff}T00:00:00Z'"
                                f"&$expand=Details&$custom={rc_view}.{rc_field}&$top=5")
        out["load_shape_probe"] = {"status": pst,
                                   "count": (len(pdata) if isinstance(pdata, list) else None),
                                   "error": (None if isinstance(pdata, list) else pdata)}
        # COVERAGE PROBES: why isn't a known recent receipt (007068) in the loaded set?
        out["receipts_raw_total"] = _RECEIPTS_CACHE.get("raw_total")  # pre-filter count; ~3000 => page cap hit
        def _rc(lst):
            return ([{"ReceiptNbr": (r.get("ReceiptNbr") or {}).get("value"),
                      "container": ((r.get("custom") or {}).get(rc_view, {}).get(rc_field) or {}).get("value")}
                     for r in lst] if isinstance(lst, list) else lst)
        # (a) does descending order work, and do the newest receipts carry containers?
        _, dd = api("GET", f"{ENTITY}/PurchaseReceipt?$orderby=ReceiptNbr desc&$top=5&$custom={rc_view}.{rc_field}")
        out["probe_orderby_desc"] = _rc(dd)
        # (b) can we get the exact target receipt via a ReceiptNbr filter, with its container?
        _, td = api("GET", f"{ENTITY}/PurchaseReceipt?$filter=ReceiptNbr eq '007068'&$custom={rc_view}.{rc_field}")
        out["probe_007068"] = _rc(td)
    # FULL custom-field inventory on PurchaseReceipt (all views, every field name) --
    # so if auto-discovery picked the wrong container field we can see the real one
    # (e.g. the "Container Tracking" field) and its exact contract-API name/view to set
    # RECEIPT_CONTAINER_FIELD / RECEIPT_CONTAINER_VIEW. Also the standard field keys.
    rst, rsch = api("GET", f"{ENTITY}/PurchaseReceipt/$adHocSchema")
    if rst == 200 and isinstance(rsch, dict):
        out["receipt_all_custom_fields"] = {v: sorted(fs.keys()) for v, fs in (rsch.get("custom", {}) or {}).items()}
    else:
        out["receipt_schema_status"] = rst
    rkst, rk = api("GET", f"{ENTITY}/PurchaseReceipt?$top=1")
    if rkst == 200 and isinstance(rk, list) and rk:
        out["receipt_standard_keys"] = sorted(rk[0].keys())
    if sample_container:
        sc = sample_container.strip().upper()
        receipts = [r for r in load_recent_receipts() if sc in r.get("containers", [])]
        out["sample_container"] = sc
        out["sample_container_receipts"] = receipts
        out["sample_container_vendor_refs"] = sorted({r.get("vendor_ref") for r in receipts if r.get("vendor_ref")})
        out["sample_container_resolved_pos"] = containers_to_pos([sc]).get(sc, [])
    if sample_receipt:
        # Raw contract-API view of one receipt as THIS connection sees it, requesting the
        # discovered container field via $custom (the correct way to get custom fields).
        cust = ("%s.%s" % (rc_view, rc_field)) if rc_field else ""
        q = (f"{ENTITY}/PurchaseReceipt?$filter=ReceiptNbr eq '{sample_receipt}'&$expand=Details"
             + (f"&$custom={cust}" if cust else ""))
        rrst, rr = api("GET", q)
        out["sample_receipt"] = sample_receipt
        out["sample_receipt_raw"] = (rr[0] if (rrst == 200 and isinstance(rr, list) and rr)
                                     else {"status": rrst, "data": rr})
    return out

# ================= Web UI =================
def make_session(who="staff"):
    tok = secrets.token_hex(16)
    sig = hmac.new(COOKIE_SECRET, tok.encode(), hashlib.sha256).hexdigest()[:16]
    SESSIONS[tok] = who
    return f"{tok}.{sig}"

def session_user(val):
    if not val or "." not in val: return None
    u = SESSIONS.get(val.rsplit(".", 1)[0])
    return u if isinstance(u, str) else None

def valid_session(val):
    if not val or "." not in val: return False
    tok, sig = val.rsplit(".", 1)
    good = hmac.new(COOKIE_SECRET, tok.encode(), hashlib.sha256).hexdigest()[:16]
    return hmac.compare_digest(sig, good) and tok in SESSIONS

CSS = """
:root{
  --sand:#efece3; --paper:#fbf9f5; --stone:#38352f; --taupe:#7d7363;
  --line:#ddd5c4; --line-strong:#c9c0ad;
  --fog:#5d7682; --fog-bg:#e9f0f1; --fog-bg-strong:#dbe8ea;
  --moss:#5a7d5a; --moss-bg:#eaf1e7; --moss-bg-strong:#d9e8d3;
  --rust:#b0653a; --rust-bg:#f9ece3; --rust-bg-strong:#f3dbc9;
  --neutral-bg:#f1efe9;
  --font-display:"Segoe UI Variable Display","Segoe UI",-apple-system,BlinkMacSystemFont,"Helvetica Neue",Arial,sans-serif;
  --font-body:"Segoe UI Variable Text","Segoe UI",-apple-system,BlinkMacSystemFont,Arial,sans-serif;
  --font-mono:"Cascadia Code","SF Mono",ui-monospace,Consolas,"Courier New",monospace;
  --shadow-card: 0 1px 2px rgba(56,53,47,.04), 0 1px 8px rgba(56,53,47,.03);
}
*{box-sizing:border-box}
body{margin:0;background:var(--sand);color:var(--stone);font-family:var(--font-body);-webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:28px}
.card{background:var(--paper);border:1px solid var(--line);border-radius:14px;padding:22px 24px;margin-bottom:18px;box-shadow:var(--shadow-card)}
h1{font:600 22px var(--font-display);letter-spacing:-.01em;margin:0 0 4px}
.sub{color:var(--taupe);font-size:13px;margin:0 0 16px;line-height:1.5}
.brand{letter-spacing:.18em;color:var(--taupe);font-weight:700;font-size:12px}
button{background:var(--stone);color:var(--paper);border:0;border-radius:8px;padding:10px 16px;cursor:pointer;font:600 14px var(--font-body)}
button.fog{background:var(--fog)}button:hover{opacity:.9}button:disabled{opacity:.5}
input[type=file],input[type=date],input[type=password],input[type=text]{padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--sand);color:var(--stone);width:100%;font:13px var(--font-body)}
input:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--fog);outline-offset:1px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line)}
th{font:600 11px var(--font-body);letter-spacing:.05em;text-transform:uppercase;color:var(--taupe)}
tbody tr:hover{background:var(--neutral-bg)}
.twrap{overflow-x:auto;background:var(--paper);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow-card)}
.twrap table{margin:0}.twrap table tr:last-child td{border-bottom:none}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%}.ok{background:var(--moss)}.flag{background:var(--rust)}
a{color:var(--fog);text-decoration:none}a:hover{text-decoration:underline}
.pill{background:var(--neutral-bg);color:var(--taupe);border-radius:20px;padding:5px 12px;font:600 12px var(--font-body);
  margin:0 6px 6px 0;display:inline-flex;align-items:center;gap:5px;white-space:nowrap;text-decoration:none}
a.pill:hover{background:var(--line);text-decoration:none}
.pill.moss{background:var(--moss-bg);color:var(--moss)}
.pill.rust{background:var(--rust-bg);color:var(--rust)}
.pill.fog{background:var(--fog-bg);color:var(--fog)}
pre{background:#2b2b2b;color:#d7d2c6;padding:14px;border-radius:8px;overflow:auto;font:12px/1.6 var(--font-mono)}
code{font-family:var(--font-mono)}

/* ---- shared site header ---- */
header.site-head{background:var(--paper);border-bottom:1px solid var(--line);margin-bottom:24px}
.head-inner{max-width:1180px;margin:0 auto;padding:18px 28px}
.head-top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:14px}
.brand-block{display:flex;flex-direction:column;gap:2px}
.eyebrow{font:600 11px/1 var(--font-body);letter-spacing:.16em;text-transform:uppercase;color:var(--taupe)}
h1.title{font:600 24px/1.15 var(--font-display);letter-spacing:-.01em;margin:2px 0 0}
.account-chip{display:flex;align-items:center;gap:10px;font:13px var(--font-body);color:var(--taupe);flex-wrap:wrap}
.account-chip .dot{width:7px;height:7px;flex-shrink:0}
.account-chip b{color:var(--stone);font-weight:600}
nav.pillnav{display:flex;flex-wrap:wrap;gap:8px}
nav.pillnav a{font:500 13px var(--font-body);color:var(--stone);text-decoration:none;
  padding:7px 13px;border:1px solid var(--line);border-radius:20px;background:var(--sand);
  transition:border-color .12s,background .12s}
nav.pillnav a:hover{border-color:var(--line-strong);background:var(--neutral-bg);text-decoration:none}
nav.pillnav a.current{background:var(--stone);color:var(--paper);border-color:var(--stone)}

/* ---- KPI band ---- */
.kpi-band{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}
.kpi{position:relative;background:var(--paper);border:1px solid var(--line);border-radius:14px;
  padding:20px 20px 18px;box-shadow:var(--shadow-card);overflow:hidden}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px}
.kpi.moss::before{background:var(--moss)} .kpi.rust::before{background:var(--rust)}
.kpi.fog::before{background:var(--fog)} .kpi.neutral::before{background:var(--line-strong)}
.kpi-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.kpi-label{font:600 12.5px var(--font-body);letter-spacing:.02em;color:var(--taupe)}
.kpi-icon{width:26px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.kpi.moss .kpi-icon{background:var(--moss-bg);color:var(--moss)}
.kpi.rust .kpi-icon{background:var(--rust-bg);color:var(--rust)}
.kpi.fog .kpi-icon{background:var(--fog-bg);color:var(--fog)}
.kpi.neutral .kpi-icon{background:var(--neutral-bg);color:var(--taupe)}
.kpi-num{font:600 38px/1 var(--font-mono);letter-spacing:-.02em;font-variant-numeric:tabular-nums;color:var(--stone)}
.kpi-sub{font:400 12.5px var(--font-body);color:var(--taupe);margin-top:6px;line-height:1.4}
.kpi-sub b{color:var(--stone);font-weight:600}
@media (max-width:900px){.kpi-band{grid-template-columns:repeat(2,1fr)}}
@media (max-width:600px){.kpi-band{grid-template-columns:1fr}}

/* ---- at-a-glance strip ---- */
.glance{display:flex;align-items:center;flex-wrap:wrap;gap:10px 22px;background:var(--paper);
  border:1px solid var(--line);border-radius:12px;padding:13px 20px;margin-bottom:26px;font-size:13px;box-shadow:var(--shadow-card)}
.glance .g-item{display:flex;align-items:center;gap:7px;color:var(--taupe)}
.glance .g-item b{color:var(--stone);font:600 13px var(--font-mono);font-variant-numeric:tabular-nums}
.mode-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.glance .divider{width:1px;height:16px;background:var(--line)}
.glance .split-chip{margin-left:auto}

.class-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:28px}
.class-chip{display:flex;align-items:center;gap:8px;font:500 12.5px var(--font-body);
  background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:8px 13px}
.class-chip .n{font:600 13px var(--font-mono);font-variant-numeric:tabular-nums;color:var(--stone)}
.class-chip .swatch{width:8px;height:8px;border-radius:2px;display:inline-block}

.section-head{display:flex;align-items:baseline;justify-content:space-between;margin:0 0 4px;gap:12px;flex-wrap:wrap}
.section-head h1,.section-head h2{margin:0}
.section-sub{font:400 12.5px var(--font-body);color:var(--taupe);margin:0 0 16px;max-width:70ch;line-height:1.5}
.section-sub b{color:var(--stone);font-weight:600}

/* ---- decision-log severity rows ---- */
tbody tr.row-moss,tbody tr.row-rust,tbody tr.row-neutral,tbody tr.row-fog{position:relative}
tbody tr.row-moss::before,tbody tr.row-rust::before,tbody tr.row-neutral::before,tbody tr.row-fog::before{
  content:"";position:absolute;left:0;top:0;bottom:0;width:3px}
tbody tr.row-moss::before{background:var(--moss)} tbody tr.row-rust::before{background:var(--rust)}
tbody tr.row-neutral::before{background:var(--line-strong)} tbody tr.row-fog::before{background:var(--fog)}
.t-time{font:400 12.5px var(--font-mono);color:var(--taupe);white-space:nowrap;font-variant-numeric:tabular-nums}
.t-container{font:600 13px var(--font-mono);color:var(--stone);letter-spacing:.01em}
.t-waiting{color:var(--fog);font-weight:600}
.backfill-row{display:flex;gap:10px;margin-bottom:8px;max-width:480px}
.backfill-row input[type=text]{flex:1 1 auto;min-width:0;width:auto}
.backfill-row input[type=date]{flex:0 0 170px;width:auto}
.t-status{color:var(--stone)}
.status-sub{display:block;color:var(--taupe);font-weight:400;font-size:12px;margin-top:2px}

/* ---- lookup ---- */
.search-row{display:flex;gap:10px}
.search-row input{flex:1}

/* ---- master/group cards (lookup, splits) ---- */
.master-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;margin-bottom:22px}
.master-card,.group-card{background:var(--paper);border:1px solid var(--line);border-radius:12px;
  padding:16px 18px;box-shadow:var(--shadow-card);margin-bottom:16px}
.master-card-head,.group-card-head{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:12px;flex-wrap:wrap;gap:8px}
.master-card-head .m-id,.group-card-head h3{font:600 15px var(--font-mono);color:var(--stone);margin:0}
.mini-table{width:100%;border-collapse:collapse;font-size:12.5px}
.mini-table th{padding:6px 0;border-bottom:1px solid var(--line);font-size:10.5px}
.mini-table th:last-child{text-align:right}
.mini-table td{padding:6px 0;border-bottom:1px solid var(--line)}
.mini-table tr:last-child td{border-bottom:none}
.mini-table .mc{font-family:var(--font-mono);color:var(--stone)}
.mini-table .md{font-family:var(--font-mono);color:var(--taupe);text-align:right;font-variant-numeric:tabular-nums}
.member-row{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--line);gap:12px;flex-wrap:wrap}
.member-row:last-child{border-bottom:none}
.member-row .m-po{font:600 13px var(--font-mono);color:var(--stone);min-width:70px}
.member-row .m-containers{font-size:12px;color:var(--taupe);flex:1;font-family:var(--font-mono)}
.as-of{font-size:12px;color:var(--taupe);margin-top:12px}

/* ---- empty state ---- */
.empty-state{display:flex;flex-direction:column;align-items:center;text-align:center;padding:40px 24px;color:var(--taupe)}
.empty-state .e-icon{width:40px;height:40px;border-radius:12px;background:var(--neutral-bg);color:var(--taupe);
  display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:12px}
.empty-state h3{font:600 14px var(--font-body);color:var(--stone);margin:0 0 4px}
.empty-state p{font-size:12.5px;margin:0;max-width:40ch;line-height:1.5}

/* ---- diagnostics ---- */
.status-strip{display:flex;align-items:center;gap:18px;flex-wrap:wrap;background:var(--paper);
  border:1px solid var(--line);border-radius:12px;padding:12px 18px;margin-bottom:22px;font-size:13px;box-shadow:var(--shadow-card)}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--moss);flex-shrink:0}
.status-strip .s-item{display:flex;align-items:center;gap:7px;color:var(--taupe)}
.status-strip .s-item b{color:var(--stone);font-weight:600}
.status-strip .divider{width:1px;height:14px;background:var(--line)}
.probe-fields{display:grid;grid-template-columns:repeat(3,1fr) auto;gap:10px;align-items:end}
.field label{display:block;font:600 11px var(--font-body);letter-spacing:.03em;text-transform:uppercase;color:var(--taupe);margin-bottom:6px}
.field input{font-family:var(--font-mono)}
.result-card{border-left:4px solid var(--fog)}
.result-head{display:flex;align-items:center;gap:10px;margin-bottom:16px}
.result-head .r-icon{width:28px;height:28px;border-radius:8px;background:var(--fog-bg);color:var(--fog);
  display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0}
.kv-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:18px}
.kv-grid .kv label{display:block;font:600 10.5px var(--font-body);letter-spacing:.04em;text-transform:uppercase;color:var(--taupe);margin-bottom:4px}
.kv-grid .kv .v{font:600 15px var(--font-mono);color:var(--stone);font-variant-numeric:tabular-nums}
.field-label{display:block;font:600 10.5px var(--font-body);letter-spacing:.04em;text-transform:uppercase;color:var(--taupe);margin-bottom:8px}
.chip-wrap{display:flex;flex-wrap:wrap;gap:6px}
.chip{font:600 12px var(--font-mono);background:var(--fog-bg);color:var(--fog);padding:4px 10px;border-radius:6px}
details.section-acc{background:var(--paper);border:1px solid var(--line);border-radius:12px;margin-bottom:12px;box-shadow:var(--shadow-card);overflow:hidden}
details.section-acc summary{list-style:none;cursor:pointer;padding:15px 20px;display:flex;align-items:center;
  justify-content:space-between;font:600 13px var(--font-body);color:var(--stone)}
details.section-acc summary::-webkit-details-marker{display:none}
details.section-acc summary .acc-meta{font:400 12px var(--font-body);color:var(--taupe);font-weight:400}
details.section-acc summary::after{content:"\\2304";color:var(--taupe);font-size:14px;transition:transform .15s}
details.section-acc[open] summary::after{transform:rotate(180deg)}
details.section-acc summary:focus-visible{outline:2px solid var(--fog);outline-offset:-2px}
.acc-body{padding:0 20px 18px;font-size:12.5px;color:var(--taupe);line-height:1.6}
.acc-body ul{margin:6px 0 14px;padding-left:18px}
.section-label{font:600 11px var(--font-body);letter-spacing:.1em;text-transform:uppercase;color:var(--taupe);margin:26px 0 10px}
"""

# ---- Personalized browser-tab icons (Sand + Fog stone/fog palette). Base64 data-URI
# SVGs so no external file / URL-encoding fuss. Ship-container for the shipments tool;
# a distinct robot for the agent decision log so the two tabs are tellable apart.
def _favicon(svg):
    return '<link rel="icon" href="data:image/svg+xml;base64,%s">' % base64.b64encode(svg.encode()).decode()
SHIP_FAVICON = _favicon('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect x="3" y="11" width="26" height="13" rx="2" fill="#5d7682"/>'
    '<path d="M8 11v13M14 11v13M20 11v13M26 11v13" stroke="#efece3" stroke-width="1.6"/></svg>')
AGENT_FAVICON = _favicon('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect x="6" y="10" width="20" height="15" rx="4" fill="#5d7682"/>'
    '<rect x="15" y="3" width="2" height="5" rx="1" fill="#7d7363"/><circle cx="16" cy="6" r="2" fill="#7d7363"/>'
    '<circle cx="12" cy="17" r="2.3" fill="#efece3"/><circle cx="20" cy="17" r="2.3" fill="#efece3"/></svg>')

LOGIN = """<!doctype html><meta charset=utf-8><title>Sign in</title>%s<style>%s
.box{max-width:340px;margin:12vh auto}</style><div class=wrap><div class="card box">
<div class=brand>SAND + FOG</div><h1>POE Shipment Agent</h1>
<form method=post action=/login><p><input type=text name=user placeholder="Username" autofocus></p>
<p><input type=password name=pw placeholder="Password"></p>
<button>Sign in</button></form></div></div>""" % (SHIP_FAVICON, CSS)

NAV_ITEMS = [
    ("dashboard", "/", "Dashboard"),
    ("lookup", "/lookup", "Look up"),
    ("container-status", "/container-status", "Container check"),
    ("backfill-pickup", "/backfill-pickup", "Backfill pickup"),
    ("guide", "/guide", "Guide"),
    ("history", "/history", "Shipment history"),
]
# Trimmed from the nav for staff clarity, 2026-08-10 (Parker's call) -- not removed, still
# reachable directly by URL when needed:
#   /splits -- operational backlog view, not referenced by the staff verification checklist
#   /diag -- pure engineering/debugging (Acumatica API field probes), never a staff need

def page(body, favicon=None, current=None):
    favicon = favicon or SHIP_FAVICON
    connected = bool(access_token())
    if connected:
        u = (connected_user() or "").replace("<", "").replace(">", "")
        exp = os.environ.get("EXPECTED_ACU_USER", "").strip()
        if exp and u and exp.lower() not in u.lower():
            account = ('<span class=dot style="background:var(--rust)"></span> '
                       '<span style="color:var(--rust)">&#9888; Connected as <b>%s</b> &mdash; expected %s</span>'
                       ' &middot; <a href=/connect>Switch account</a>' % (u, exp))
        elif not u:
            # Detection failed (or the token predates requesting the openid/profile scope) --
            # warn loudly rather than showing a calm green "Connected" that implies verified.
            # Every write on this service runs as whoever is ACTUALLY logged in regardless of
            # what this banner says, so an unverifiable identity must not look fine.
            account = ('<span class=dot style="background:var(--rust)"></span> '
                       '<span style="color:var(--rust)">&#9888; Connected &mdash; user identity unknown, '
                       'verify manually before any write</span> &middot; <a href=/connect>Switch account</a>')
        else:
            account = ('<span class=dot style="background:var(--moss)"></span> Connected as <b>%s</b>'
                       ' &middot; <a href=/connect>Switch account</a>' % u)
    else:
        account = '<a href=/connect>Connect to Acumatica</a>'
    nav = "".join('<a href="%s"%s>%s</a>' % (href, ' class=current' if key == current else '', label)
                  for key, href, label in NAV_ITEMS)
    return """<!doctype html><meta charset=utf-8><title>POE Shipment Agent</title>%s<style>%s</style>
<header class=site-head><div class=head-inner>
<div class=head-top><div class=brand-block><span class=eyebrow>Sand + Fog</span><h1 class=title>POE Shipment Agent</h1></div>
<div class=account-chip>%s</div></div>
<nav class=pillnav>%s</nav>
</div></header>
<main class=wrap>%s</main>""" % (favicon, CSS, account, nav, body)

def _diag_html(d, sample_po, sample_container, sample_receipt):
    """Diagnostics page -- diagnostics() always runs a large batch of schema/health probes
    (identity, rate-limit headers, field-name discovery, receipt-loading coverage checks)
    on every call, regardless of what was searched for. Previously this whole dict, dozens
    of fields deep, was dumped as one raw <pre>json.dumps(...)</pre> block -- Parker's
    words: 'the diagnostics tab has too much data in it.' This surfaces a readable summary
    for whatever was actually searched, and tucks the schema/raw-JSON bulk into collapsed
    <details> sections instead of showing it all up front."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    status_strip = ('<div class=status-strip>'
        '<div class=s-item><span class=status-dot style="background:%s"></span> %s</div>'
        '<div class=divider></div><div class=s-item>Tenant <b>%s</b></div>'
        '<div class=divider></div><div class=s-item>Warehouse <b>%s</b></div>'
        '<div class=divider></div><div class=s-item>API rate limit <b>%s</b></div></div>'
        % ("var(--moss)" if d.get("connected") else "var(--rust)",
           "Connected to Acumatica" if d.get("connected") else "Not connected",
           esc(d.get("tenant")), esc(d.get("warehouse")),
           "no warnings" if not d.get("rate_limit_headers_found") else
           f"{len(d['rate_limit_headers_found'])} header(s) found -- see raw data below"))

    form = ('<div class=card><h2>Test a specific container or PO</h2>'
            '<p class=sub>Look up exactly what Acumatica returns for one thing, without digging through raw exports.</p>'
            '<form method=get action=/diag><div class=probe-fields>'
            f'<div class=field><label>PO&nbsp;#</label><input type=text name=po placeholder="e.g. 117256" value="{esc(sample_po or "")}"></div>'
            f'<div class=field><label>Container</label><input type=text name=container placeholder="e.g. FBIU5261330" value="{esc(sample_container or "")}"></div>'
            f'<div class=field><label>Receipt</label><input type=text name=receipt placeholder="e.g. 007068" value="{esc(sample_receipt or "")}"></div>'
            '<button class=fog>Run</button></div></form></div>')

    result = ""
    if sample_container and d.get("sample_container_receipts") is not None:
        receipts = d.get("sample_container_receipts") or []
        masters = d.get("sample_container_resolved_pos") or []
        chips = "".join(f'<span class=chip>{esc(m)}</span>' for m in masters) or '<span class=sub>none found</span>'
        rows = "".join(
            '<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                esc(r.get("receipt_nbr")), esc(r.get("vendor_ref")),
                esc(", ".join(c for c in (r.get("containers") or []) if c != sample_container.strip().upper())))
            for r in receipts)
        result = ('<div class="card result-card"><div class=result-head><span class=r-icon>&#128230;</span>'
            f'<div><h2>Container {esc(sample_container)}</h2>'
            f'<div class=sub style="margin:2px 0 0">Found on {len(receipts)} purchase receipt(s)</div></div></div>'
            f'<div class=kv-grid><div class=kv><label>Master POs found</label><div class=v>{len(masters)}</div></div>'
            f'<div class=kv><label>Receipts checked</label><div class=v>{len(receipts)}</div></div>'
            f'<div class=kv><label>Field used</label><div class=v style="font-size:13px">{esc(d.get("receipt_container_field"))}</div></div></div>'
            f'<span class=field-label>Resolves to</span><div class=chip-wrap style="margin-bottom:20px">{chips}</div>'
            '<span class=field-label>Receipts</span><div class=twrap><table class=diag-table>'
            '<thead><tr><th>Receipt</th><th>Vendor ref</th><th>Other containers on this receipt</th></tr></thead>'
            f'<tbody>{rows or "<tr><td colspan=3 class=sub>No matching receipts.</td></tr>"}</tbody></table></div></div>')
    elif sample_po and d.get("po_completeness_probe") is not None:
        probe = d.get("po_completeness_probe") or {}
        matches = d.get("open_matches") or []
        result = ('<div class="card result-card"><div class=result-head><span class=r-icon>&#128196;</span>'
            f'<div><h2>Master PO {esc(sample_po)}</h2>'
            f'<div class=sub style="margin:2px 0 0">Resolved to internal PO(s) {esc(", ".join(probe.get("distinct_po_order_nbrs_across_receipts") or []) or "none")}</div></div></div>'
            f'<div class=kv-grid><div class=kv><label>Open sales orders</label><div class=v>{len(matches)}</div></div>'
            f'<div class=kv><label>Receipts checked</label><div class=v>{len(probe.get("receipts_checked") or [])}</div></div>'
            f'<div class=kv><label>PO status</label><div class=v style="font-size:13px">'
            f'{esc(probe.get("po_status")) if probe.get("po_status") else "&mdash;"}</div></div></div></div>')
    elif sample_receipt and d.get("sample_receipt_raw") is not None:
        raw = d.get("sample_receipt_raw") or {}
        result = ('<div class="card result-card"><div class=result-head><span class=r-icon>&#128203;</span>'
            f'<div><h2>Receipt {esc(sample_receipt)}</h2></div></div>'
            f'<pre class=raw-json>{esc(json.dumps(raw, indent=2))}</pre></div>')

    reference = ('<details class=section-acc><summary>Field reference'
        '<span class=acc-meta>Sales Order, Shipment, Purchase Receipt columns</span></summary>'
        '<div class=acc-body>Rarely needed &mdash; useful if a lookup starts behaving oddly and you want to '
        f'check what a field is actually called in Acumatica.<ul>'
        f'<li><code>Sales Order</code>: {esc(", ".join(d.get("so_keys") or []) or "unavailable")}</li>'
        f'<li><code>Shipment</code>: {esc(", ".join(d.get("shipment_keys") or []) or "unavailable")}</li>'
        f'<li><code>Purchase Receipt</code>: {esc(", ".join(d.get("receipt_standard_keys") or []) or "unavailable")}</li>'
        '</ul></div></details>')

    raw_json = ('<details class=section-acc><summary>Full raw response'
        '<span class=acc-meta>everything above, unformatted</span></summary>'
        f'<div class=acc-body><pre class=raw-json>{esc(json.dumps(d, indent=2))}</pre></div></details>')

    return (status_strip + form + result
            + '<div class=section-label>Reference &amp; raw data</div>' + reference + raw_json)

def _dashboard_html():
    """Agent dashboard -- the default landing page. Rebuilt 2026-08-09 for staff clarity
    (Parker's ask, ahead of sharing this with his team): the classification chips, the
    4-tile KPI band, and the mixed-classification "recent decisions" table all required
    knowing this tool's internal vocabulary (waiting_on_containers vs no_action vs
    exception_flag) to actually read. Staff need exactly two answers -- what shipped, and
    what needs a person -- so the page is now just those two tables, plus the smallest
    possible trust signal (is the agent actually running) above them. The fuller views
    (classification breakdown, full history, split-order backlog) all still exist, just
    one click away via the top nav or each table's own "see all" link, not on the front
    page every day."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = agent_summary(hours=24)
    created_rows = agent_log_read(limit=15, created_only=True)
    review_rows = agent_log_read(limit=15, exceptions_only=True)

    # Same dead-man's-switch signal the daily digest email relies on, surfaced here too so
    # a glance at the dashboard catches a stuck/stopped agent without waiting for 7am.
    warn = ""
    if s["last_decision_at"]:
        try:
            age_h = (time.time() - time.mktime(time.strptime(s["last_decision_at"], "%Y-%m-%d %H:%M:%S"))) / 3600
            if age_h > 6:
                warn = ('<p class=sub style="color:var(--rust)">&#9888; Last decision was %.0fh ago &mdash; '
                        'check the agent is still running (Render cron logs).</p>' % age_h)
        except Exception:
            pass
    elif s["decisions"] == 0:
        warn = '<p class=sub style="color:var(--rust)">&#9888; No decisions logged in the last 24h.</p>'

    glance = ('<div class=glance>'
        '<div class=g-item>Mode <span class="pill %s">%s</span></div>'
        '<div class=divider></div><div class=g-item>Last decision <b>%s</b></div></div>'
        % ({"live": "moss", "shadow": "", "mixed": "rust", "n/a": ""}.get(s["mode"], ""), esc(s["mode"]),
           esc(_fmt_ts(s["last_decision_at"])) if s["last_decision_at"] else "&mdash;"))

    # ledger_check_sla()'s result (a master stuck "waiting"/"partial" past LEDGER_SLA_DAYS)
    # is also fundamentally a "needs a person" signal, same spirit as the exceptions table
    # below -- shown as its own alert since it's ledger-sourced, not an agent_log row.
    stale = s.get("ledger_stale") or []
    stale_html = ""
    if stale:
        stale_rows = "".join(
            f'<div class=member-row><span class=m-po>'
            f'<a href="/lookup?q={urllib.parse.quote(e["master"])}">{esc(e["master"])}</a></span>'
            f'<span class=m-containers>{esc(", ".join(e.get("containers") or []))}</span>'
            f'<span class="pill rust">{e["days_waiting"]}d stuck</span></div>'
            for e in stale)
        stale_html = ('<div class=group-card style="border-left:4px solid var(--rust)">'
            f'<div class=group-card-head><h3>&#9888; {len(stale)} master PO(s) stuck past '
            f'{LEDGER_SLA_DAYS} days</h3></div>{stale_rows}</div>')

    header = ('<div class=section-head><h1 style="font-size:20px">Agent dashboard</h1></div>'
              '<p class=section-sub>Last 24 hours.</p>%s' % warn)

    # Parker's ask, 2026-08-09, while still testing before staff rollout: the verification
    # steps he wanted staff following live in chat, embedded on the page itself rather than
    # a separate guide they'd have to remember exists. Collapsed by default (<details>, same
    # pattern already used for "What happened" elsewhere in this app) so it doesn't clutter
    # the two-table simplicity for anyone who already knows the drill.
    howto = ('<div class=card><details><summary style="cursor:pointer;font-weight:600">'
        'How to check a shipment before confirming it in Acumatica</summary>'
        '<ol style="line-height:1.8;font-size:13.5px;padding-left:20px;margin-top:10px">'
        '<li>Every shipment in the table below already has a real order/shipment number -- '
        'that\'s your list for the day.</li>'
        '<li>For each one, check <a href=/container-status>Container check</a> (default '
        '2-day window covers overnight). It lists every container that Customer Order '
        'depends on, and the date NRT confirmed each one. <b>If every container shows a '
        'real date, that shipment is genuinely backed by NRT confirmations -- nothing more '
        'to check.</b> A container still showing "Waiting" for an already-created shipment '
        'is the one thing worth flagging.</li>'
        '<li>That date column already IS the inbox check -- it\'s the actual email\'s '
        'received timestamp, not just a date this tool recorded, so there\'s no need to '
        'separately open Outlook for each one.</li>'
        '<li>Spot-check one or two a day against the NRT Updates folder directly while '
        'we\'re still testing this, even though step 3 makes it unnecessary long-term.</li>'
        '<li>If anything looks off, <a href=/lookup>Look up</a> the Master PO for the '
        'single deepest view, including a "refresh live" link to re-verify directly '
        'against Acumatica.</li>'
        '</ol></details></div>')

    return (header + glance + stale_html + howto
            + _dashboard_created_html(created_rows, s["shipped"])
            + _dashboard_review_html(review_rows, s["flagged"]))

def _dashboard_created_html(rows, total):
    """Shipments the agent actually created, plain and simple -- for staff, not just
    Parker: no classification jargon, no severity coloring, nothing here needs a person to
    do anything. Reuses _friendly_shipment_result() for the detail column so a real
    shipment number/date shows, not a raw JSON blob."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    def _row(r):
        m = _CONTAINER_IN_SUBJECT.search(r.get("subject") or "")
        args = r.get("tool_args") or {}
        container = esc(args.get("container") or (m.group(1) if m else None) or r.get("subject") or "")
        detail = _friendly_shipment_result(r.get("tool_result"), esc) or "&mdash;"
        return (f'<tr class=row-moss><td class=t-time>{esc(_fmt_ts(r.get("ts")))}</td>'
                f'<td class=t-container>{container}</td><td>{detail}</td></tr>')
    body = "".join(_row(r) for r in rows)
    return ('<div class=section-head><h2>&#10003; Shipments created (last %d)</h2></div>'
            '<p class=section-sub>Times are Pacific. Ready and waiting in Acumatica for a clerk to confirm. '
            '<a href="/agent/log?created_only=1&view=html">see all</a>.</p>'
            '<div class=twrap><table><tr><th>Received</th><th>Container</th><th>Shipment</th></tr>%s</table></div>'
            % (total, body or '<tr><td colspan=3 class=sub>No shipments created in the last 24h.</td></tr>'))

def _dashboard_review_html(rows, total):
    """Everything currently needing a person to look at it -- for staff, the other half of
    the two things that matter. Shows the reason plainly instead of a redundant "Needs
    review" pill on every row (that's already the whole point of this table)."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    hist_rows = history(limit=0)  # local file read only, no live calls -- cheap per page load
    def _row(r):
        m = _CONTAINER_IN_SUBJECT.search(r.get("subject") or "")
        container_raw = m.group(1) if m else None
        container = esc(container_raw) if container_raw else esc(r.get("subject") or "")
        resolved = _find_later_success(container_raw, r.get("ts", ""), hist_rows, _flagged_row_masters(r))
        if resolved:
            why = ('<span style="color:var(--moss)">&#10003; Shipped on a later retry &mdash; '
                   'no action needed now.</span>')
        else:
            reason_code = ((r.get("tool_result") or {}).get("data") or {}).get("reason")
            text = REASON_STAFF_MESSAGES.get(reason_code) or r.get("exception_reason") or "Needs review"
            why = f'<span style="color:var(--rust)">{esc(text)}</span>'
        link = f' &middot; <a href="/lookup?q={urllib.parse.quote(container_raw)}">details</a>' if container_raw else ""
        return (f'<tr class="row-{"moss" if resolved else "rust"}"><td class=t-time>{esc(_fmt_ts(r.get("ts")))}</td>'
                f'<td class=t-container>{container}</td><td>{why}{link}</td></tr>')
    body = "".join(_row(r) for r in rows)
    return ('<div class=section-head><h2>&#9888; Needs review (last %d)</h2></div>'
            '<p class=section-sub>Times are Pacific. '
            '<a href="/agent/log?exceptions_only=1&view=html">see all</a>.</p>'
            '<div class=twrap><table><tr><th>Received</th><th>Container</th><th>Why</th></tr>%s</table></div>'
            % (total, body or '<tr><td colspan=3 class=sub>Nothing needs review right now.</td></tr>'))

GUIDE = """<div class=card>
<h1 style="font-size:18px">User guide &mdash; how this tool works</h1>
<p class=sub>A mailbox agent reads NRT pickup emails and creates shipment records in Acumatica automatically &mdash; with a person always in control of the revenue step.</p>
<ol style="line-height:1.75;font-size:14px;padding-left:20px">
<li><b>Connect as the shipments account.</b> Click <b>Switch account</b> (top) and sign in with the dedicated Acumatica login &mdash; not a personal one. The banner shows who&#39;s connected.</li>
<li><b>Monitor from the Dashboard.</b> That&#39;s the home page: last-24h stats, mode (shadow/live), queue depth, and the most recent decisions. A stale "last decision" time or a red exception row is what to watch for.</li>
<li><b>Review flagged items.</b> <a href="/agent/log?exceptions_only=1&view=html">Exceptions only</a> lists anything the agent couldn&#39;t safely resolve on its own (e.g. no open sales order, a multi-container receipt, an unresolved container) &mdash; check those by hand.</li>
<li><b>Manual fallback, if ever needed.</b> <a href=/manual>Manual upload</a> is the same PDF&rarr;shipment flow this tool started as, kept as a fallback for a flagged item or if the agent/email pipeline is down. Container&rarr;PO resolution there also goes through Acumatica PO Receipts (container &rarr; receipt &rarr; internal PO &rarr; VendorRef &rarr; retail PO#), independent of the advice text.</li>
<li><b>Confirm &amp; invoice in Acumatica.</b> A person confirms each shipment (this recognizes revenue), then creates and releases the invoice. <b>Neither the agent nor this tool ever confirms</b> &mdash; that stays a human decision.</li>
</ol>
<p class=sub>If a line can&#39;t be created, the Result column (or the log&#39;s exception reason) explains why (e.g. nothing available to ship, order on hold). <a href=/history>Shipment history</a> lists past runs and who ran them.</p>
</div>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _cookie(self):
        c = self.headers.get("Cookie", "")
        for part in c.split(";"):
            if part.strip().startswith("s="):
                return part.strip()[2:]
        return None

    def _authed(self):
        return valid_session(self._cookie())

    def _send(self, code, body, ctype="text/html", cookie=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        if cookie:
            self.send_header("Set-Cookie", f"s={cookie}; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/callback":
            qs = urllib.parse.parse_qs(u.query)
            if "code" in qs:
                try:
                    exchange_code(qs["code"][0])
                    return self._send(200, page("<div class=card>Connected to Acumatica. <a href=/>Continue</a></div>"))
                except Exception as e:
                    return self._send(200, page(f"<div class=card>Token exchange failed: {e}</div>"))
            return self._send(400, page("<div class=card>Missing code</div>"))
        if u.path == "/status":
            qs = urllib.parse.parse_qs(u.query)
            want = os.environ.get("STATUS_TOKEN", "")
            token_ok = bool(want) and hmac.compare_digest(qs.get("token", [""])[0].encode(), want.encode())
            # Accept either a valid token (automated sync) or a logged-in session (browser).
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            pos = [p.strip() for p in qs.get("pos", [""])[0].split(",") if p.strip()][:250]
            out = {p: so_pipeline(p) for p in pos}
            return self._send(200, json.dumps(out), "application/json")
        if u.path == "/checkmaersk":
            # Read-only: no Acumatica calls, just fetches Maersk's public tracking page.
            # Called by the Maersk Watch List Power Automate flow on a schedule -- it owns
            # deciding what to do with the result (call /autoship, update the SharePoint
            # row, or leave it watching another cycle).
            qs = urllib.parse.parse_qs(u.query)
            want = MAERSK_TOKEN
            token_ok = bool(want) and qs.get("token", [""])[0] == want
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            container = qs.get("container", [""])[0].strip()
            port = qs.get("port", [""])[0].strip()
            if not container or not port:
                return self._send(400, json.dumps({"error": "container and port are required"}), "application/json")
            try:
                out = check_maersk_container(container, port)
                return self._send(200, json.dumps(out), "application/json")
            except Exception as e:
                return self._send(200, json.dumps({"error": str(e)}), "application/json")
        if u.path == "/watchlist/list":
            # Read for the local Maersk-checker script. Runs the SLA sweep on every call so
            # a container that's been watching too long shows up as "alert" without a
            # separate scheduled job.
            qs = urllib.parse.parse_qs(u.query)
            want = MAERSK_TOKEN
            token_ok = bool(want) and qs.get("token", [""])[0] == want
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            wl = watchlist_check_sla()
            status_filter = qs.get("status", [""])[0].strip()
            if status_filter:
                wl = {c: e for c, e in wl.items() if e.get("status") == status_filter}
            return self._send(200, json.dumps(wl), "application/json")
        if u.path == "/autoship":
            # Browser-friendly PREVIEW of the same resolution logic /autoship (POST) runs --
            # for eyeballing container -> PO -> sales-order matches in a URL bar. Always
            # forces dry_run=True regardless of query string: this route can never create
            # a shipment (writes stay POST-only, above).
            qs = urllib.parse.parse_qs(u.query)
            want = AUTOSHIP_TOKEN
            token_ok = bool(want) and hmac.compare_digest(qs.get("token", [""])[0].encode(), want.encode())
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            container = qs.get("container", [""])[0].strip()
            pos = [p.strip() for p in qs.get("pos", [""])[0].split(",") if p.strip()] or None
            source = (qs.get("source", ["preview"])[0] or "preview").strip()
            if not container:
                return self._send(400, json.dumps({"error": "container is required"}), "application/json")
            try:
                out = process_manual(container, None, pos=pos, source=source, dry_run=True)
                return self._send(200, json.dumps(out), "application/json")
            except Exception as e:
                return self._send(200, json.dumps({"error": str(e)}), "application/json")
        if u.path == "/agent/log":
            # The mailbox-agent's decision audit trail. JSON for the agent's own
            # idempotency check (?message_id=...) and programmatic reads; a rendered HTML
            # table (?view=html) for a person to scan a day's decisions in under a minute.
            # Default view is pickup_only (2026-07-27, Parker's request) -- routine NRT
            # status noise hidden, exceptions always still shown; ?all=1 for everything.
            qs = urllib.parse.parse_qs(u.query)
            want = AGENT_TOKEN
            token_ok = bool(want) and hmac.compare_digest(qs.get("token", [""])[0].encode(), want.encode())
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            msg_id = qs.get("message_id", [""])[0].strip() or None
            exc_only = qs.get("exceptions_only", ["0"])[0] == "1"
            show_all = qs.get("all", ["0"])[0] == "1"
            created_only = qs.get("created_only", ["0"])[0] == "1"
            mode = "created" if created_only else ("exceptions" if exc_only else ("all" if show_all else "pickup"))
            try:
                limit = int(qs.get("limit", ["200"])[0])
            except Exception:
                limit = 200
            rows = agent_log_read(limit=limit, exceptions_only=exc_only, created_only=created_only,
                                   pickup_only=(mode == "pickup"), message_id=msg_id)
            if qs.get("view", [""])[0] == "html" or self._authed():
                return self._send(200, page(_agent_log_html(rows, mode), favicon=AGENT_FAVICON))
            return self._send(200, json.dumps(rows), "application/json")
        if u.path == "/containerstatus":
            # For the mailbox-agent to call on EVERY NRT status email, not just triggers --
            # catches NRT sending a status update that walks BACKWARD after a shipment
            # already exists for this container (see container_ship_history's docstring
            # for the real 2026-07-23 incident this closes). Read-only, no Acumatica calls.
            qs = urllib.parse.parse_qs(u.query)
            want = AGENT_TOKEN
            token_ok = bool(want) and hmac.compare_digest(qs.get("token", [""])[0].encode(), want.encode())
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            container = (qs.get("container", [""])[0] or "").strip().upper()
            return self._send(200, json.dumps(container_ship_history(container)), "application/json")
        if u.path == "/agent/summary":
            # Rollup for the notification digest (a scheduled Power Automate flow reads
            # this and emails/Teams-messages Parker). AGENT_TOKEN-authed. ?hours=N window.
            qs = urllib.parse.parse_qs(u.query)
            want = AGENT_TOKEN
            token_ok = bool(want) and hmac.compare_digest(qs.get("token", [""])[0].encode(), want.encode())
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            try:
                hours = int(qs.get("hours", ["24"])[0])
            except Exception:
                hours = 24
            return self._send(200, json.dumps(agent_summary(hours)), "application/json")
        if u.path == "/ingest/list":
            # The mailbox-agent cron job pulls the queue of pushed emails here.
            qs = urllib.parse.parse_qs(u.query)
            want = AGENT_TOKEN
            token_ok = bool(want) and hmac.compare_digest(qs.get("token", [""])[0].encode(), want.encode())
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            return self._send(200, json.dumps(ingest_list()), "application/json")
        if u.path == "/setshipdates":
            # Daily sync pushes each PO's NRT pickup date here (chunked GET). Merges into
            # po_shipdates.json; pass reset=1 on the first chunk to clear stale entries.
            qs = urllib.parse.parse_qs(u.query)
            want = os.environ.get("STATUS_TOKEN", "")
            token_ok = bool(want) and hmac.compare_digest(qs.get("token", [""])[0].encode(), want.encode())
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            with _JSON_LOCK:
                cur = {} if qs.get("reset", ["0"])[0] == "1" else (load_json(SHIPDATES_PATH) or {})
                n = 0
                for pr in qs.get("pairs", [""])[0].split(","):
                    if ":" in pr:
                        k, v = pr.split(":", 1); k = k.strip(); v = v.strip()
                        if k and v: cur[k] = v; n += 1
                save_json(SHIPDATES_PATH, cur)
            return self._send(200, json.dumps({"stored": n, "total": len(cur)}), "application/json")
        if u.path == "/setcontainerdates":
            qs = urllib.parse.parse_qs(u.query)
            want = os.environ.get("STATUS_TOKEN", "")
            token_ok = bool(want) and hmac.compare_digest(qs.get("token", [""])[0].encode(), want.encode())
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            with _JSON_LOCK:
                cur = {} if qs.get("reset", ["0"])[0] == "1" else (load_json(CONTAINERDATES_PATH) or {})
                n = 0
                for pr in qs.get("pairs", [""])[0].split(","):
                    if ":" in pr:
                        k, v = pr.split(":", 1); k = k.strip(); v = v.strip()
                        if k and v: cur[k] = v; n += 1
                save_json(CONTAINERDATES_PATH, cur)
            return self._send(200, json.dumps({"stored": n, "total": len(cur)}), "application/json")
        if not self._authed():
            return self._send(200, LOGIN)
        if u.path == "/":
            return self._send(200, page(_dashboard_html(), current="dashboard"))
        if u.path == "/backfill-pickup":
            return self._send(200, page(_backfill_pickup_html(), current="backfill-pickup"))
        if u.path == "/connect":
            self.send_response(302); self.send_header("Location", build_authorize_url()); self.end_headers(); return
        if u.path == "/diag":
            qs = urllib.parse.parse_qs(u.query)
            sample_po = qs.get("po", [None])[0]
            sample_container = qs.get("container", [None])[0]
            sample_receipt = qs.get("receipt", [None])[0]
            d = diagnostics(sample_po, sample_container, sample_receipt)
            body = _diag_html(d, sample_po, sample_container, sample_receipt)
            return self._send(200, page(body, current="diag"))
        if u.path == "/guide":
            return self._send(200, page(GUIDE, current="guide"))
        if u.path == "/splits":
            qs = urllib.parse.parse_qs(u.query)
            try:
                limit = max(1, int(qs.get("limit", ["10"])[0]))
            except ValueError:
                limit = 10
            live = qs.get("live", ["0"])[0] == "1"
            # http.server has no built-in exception->500 handling -- an uncaught error in
            # here would otherwise just hang or drop the connection with no response at
            # all, which looks identical to a slow page from the browser's side. Catch and
            # show it plainly instead of guessing next time this happens.
            try:
                out = _splits_html(limit=limit, live=live)
            except Exception as e:
                out = ('<div class=card><h1 style="font-size:16px">Split orders &mdash; error</h1>'
                       '<p class=sub style="color:var(--rust)">%s</p></div>' % str(e).replace("<", "&lt;"))
            return self._send(200, page(out, current="splits"))
        if u.path == "/lookup":
            qs = urllib.parse.parse_qs(u.query)
            q = (qs.get("q", [None])[0] or "").strip()
            try:
                out = _lookup_html(q or None)
            except Exception as e:
                out = ('<div class=card><h1 style="font-size:16px">Lookup &mdash; error</h1>'
                       '<p class=sub style="color:var(--rust)">%s</p></div>' % str(e).replace("<", "&lt;"))
            return self._send(200, page(out, current="lookup"))
        if u.path == "/container-status":
            qs = urllib.parse.parse_qs(u.query)
            days = qs.get("days", ["2"])[0]
            try:
                out = _container_status_html(days)
            except Exception as e:
                out = ('<div class=card><h1 style="font-size:16px">Container status &mdash; error</h1>'
                       '<p class=sub style="color:var(--rust)">%s</p></div>' % str(e).replace("<", "&lt;"))
            return self._send(200, page(out, current="container-status"))
        if u.path == "/container-status/export.csv":
            qs = urllib.parse.parse_qs(u.query)
            days = _container_status_days(qs.get("days", ["2"])[0])
            rows = _container_status_rows(days)
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=["customer_order", "master_po", "container", "email_received"])
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
            data = buf.getvalue().encode("utf-8-sig")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition",
                              'attachment; filename="container_status_%s.csv"' % time.strftime("%Y%m%d"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path == "/history/export.csv":
            # Session-authed (browser download button), same as every other dashboard
            # page -- not token-gated like the automated endpoints, since this is a human
            # clicking a link, not a scheduled flow. Full history (limit=0), no cap --
            # this is a report, not a preview.
            rows = export_history_rows(limit=0)
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=EXPORT_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
            # utf-8-sig (BOM) so Excel opens the file as UTF-8 directly instead of
            # guessing the system codepage and mangling any non-ASCII customer/vendor text.
            data = buf.getvalue().encode("utf-8-sig")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition",
                              'attachment; filename="shipments_export_%s.csv"' % time.strftime("%Y%m%d"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path == "/history":
            _badge = {"ok": "pill moss", "partial": "pill fog", "failed": "pill rust",
                      "no_matches": "pill", "already_fulfilled": "pill moss",
                      "out_of_scope": "pill", "unresolved": "pill rust",
                      "anomaly": "pill rust", "waiting": "pill fog"}
            _status_label = {"ok": "Created", "partial": "Partially created", "failed": "Failed",
                              "no_matches": "No matching order", "already_fulfilled": "Already fulfilled",
                              "out_of_scope": "Out of scope (3PL)", "unresolved": "Unresolved container",
                              "anomaly": "Anomaly (already shipped)", "waiting": "Waiting on containers"}
            def _hrow(h):
                status = h.get("status") or ""
                label = _status_label.get(status, status or "&mdash;")
                pill = f'<span class="{_badge.get(status, "pill")}">{label}</span>'
                orders = h.get("orders") or []
                # The Master PO number(s) behind this run, visible directly -- previously only
                # findable by expanding "N order(s)" below. NOTE: this is the retail Master PO
                # token (e.g. 645410), not the internal Acumatica Purchase Order record (e.g.
                # 007534, shown on /splits) -- two genuinely different numbers, not just a
                # naming choice. One master PO fans out to several DC Sales Orders (same po,
                # different order/shipment per DC) -- dedupe to the unique list so a normal
                # DC-split run shows one Master PO, not a repeated copy per DC.
                po_list = sorted({o.get("po") for o in orders if o.get("po")})
                po_cell = ", ".join(po_list) if po_list else "&mdash;"
                if orders:
                    detail = "".join(
                        "<div>%s &rarr; %s &mdash; %s</div>" % (
                            o.get("po", ""), o.get("order") or "&mdash;",
                            ("&#10003; " + (o.get("shipment_nbr") or "created")) if o.get("created")
                            else ("&#9888; " + (o.get("reason") or "not created")))
                        for o in orders)
                    detail_cell = f"<details><summary>{len(orders)} order(s)</summary>{detail}</details>"
                else:
                    detail_cell = "&mdash;"
                unresolved = h.get("unresolved_containers") or []
                out_of_scope = h.get("out_of_scope_containers") or []
                cont_cell = h.get("containers", "")
                if unresolved:
                    cont_cell += f' <span class="pill rust">&#9888; unresolved: {", ".join(unresolved)}</span>'
                if out_of_scope:
                    cont_cell += f' <span class="pill">3PL, no shipment expected: {", ".join(out_of_scope)}</span>'
                # Which Acumatica identity actually performed this write (not the app-level
                # "By" caller/source tag) -- flag red if it doesn't match EXPECTED_ACU_USER, so
                # segregation-of-duties drift shows up per-run in the permanent log, not only
                # in the live banner (which only reflects whoever is connected RIGHT NOW).
                acu_user = h.get("acumatica_user") or ""
                exp = os.environ.get("EXPECTED_ACU_USER", "").strip()
                if not acu_user:
                    acu_cell = '<span class=pill>unknown</span>'
                elif exp and exp.lower() not in acu_user.lower():
                    acu_cell = f'<span class="pill rust">&#9888; {acu_user}</span>'
                else:
                    acu_cell = acu_user
                # Document/Reference only mean anything for a manual PDF upload; an
                # automated run's "document" is just its own auto:<source> tag (redundant
                # with "Triggered by") and its reference is always empty -- merge into one
                # column that shows nothing rather than a confusing "auto:test" / "None".
                doc = h.get("document") or ""
                ref = h.get("reference") or ""
                if doc.startswith("auto:"):
                    source_cell = "&mdash;"
                else:
                    source_cell = doc or "&mdash;"
                    if ref:
                        source_cell += f" &middot; ref {ref}"
                return (f"<tr><td>{_fmt_ts(h.get('ts'))}</td><td>{_friendly_run_source(h.get('user'))}</td>"
                        f"<td>{acu_cell}</td>"
                        f"<td>{source_cell}</td>"
                        f"<td>{pill}</td><td>{h.get('created','')}/{h.get('orders_matched','')}</td>"
                        f"<td>{cont_cell}</td><td>{po_cell}</td><td>{detail_cell}</td></tr>")
            rows = "".join(_hrow(h) for h in history())
            body = ('<div class=section-head><h1 style="font-size:20px">Shipment run history</h1>'
                    '<a href="/history/export.csv" style="font-size:13px">&#8659; Export CSV</a></div>'
                    '<p class=section-sub>Every shipment-creation run, kept permanently on the tool&#39;s disk (not just this session). '
                    'Times are Pacific. Expand the last column for per-order/shipment detail. &#8220;Acumatica user&#8221; is who was '
                    'actually connected when the write ran (set <code>EXPECTED_ACU_USER</code> to flag any run under a different account).</p>'
                    '<div class=twrap><table><tr><th>Received</th><th>Triggered by</th><th>Acumatica user</th><th>Source</th><th>Status</th>'
                    '<th>Created/Matched</th><th>Containers</th><th>Master PO(s)</th><th>Orders</th></tr>' + rows + '</table></div>')
            return self._send(200, page(body, current="history"))
        return self._send(404, page("<div class=card>Not found</div>"))

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/backfill-pickup":
            # Session-authed (browser form submit) -- a human correcting data by hand,
            # not an automated flow.
            if not self._authed():
                return self._send(200, LOGIN)
            ln = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(ln).decode())
            containers, dates = data.get("container", []), data.get("date", [])
            try:
                results = backfill_pickup_dates(containers, dates)
            except Exception as e:
                results = [{"container": "", "date": "", "ok": False, "error": str(e)}]
            return self._send(200, page(_backfill_pickup_html(results), current="backfill-pickup"))
        if u.path == "/autoship":
            # Token-authenticated (not a browser session) -- called by the NRT Power
            # Automate flow and the Maersk/FCR watch-list checker. Separate token from
            # the read-only STATUS_TOKEN since this one creates real Acumatica shipments.
            want = AUTOSHIP_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln).decode() or "{}")
            except Exception:
                return self._send(400, json.dumps({"error": "invalid JSON body"}), "application/json")
            container = body.get("container")
            ship_date = (body.get("ship_date") or "").strip() or None
            pos = body.get("pos")
            source = (body.get("source") or "unknown").strip()
            dry = bool(body.get("dry_run"))
            email_received_at = (body.get("email_received_at") or "").strip() or None
            if not container:
                return self._send(400, json.dumps({"error": "container is required"}), "application/json")
            try:
                out = process_manual(container, ship_date, pos=pos, source=source, dry_run=dry,
                                      email_received_at=email_received_at)
                return self._send(200, json.dumps(out), "application/json")
            except Exception as e:
                return self._send(200, json.dumps({"error": str(e)}), "application/json")
        if u.path == "/ledger/recheck":
            # Cron-triggered (e.g. daily, alongside the digest). Without this, a master
            # whose LAST container's pickup email fires before its receipt posts in
            # Acumatica has no future NRT event to re-trigger it -- it would sit "waiting"
            # forever even after the PO genuinely becomes complete. Re-runs the exact same
            # per-master completeness gate process_manual already uses (picking any one of
            # the master's recorded containers is enough -- resolve_pos_by_master() checks
            # that master's own underlying PO, not just that one container). Same write
            # stakes as /autoship, same token.
            want = AUTOSHIP_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ledger = load_json(LEDGER_PATH) or {}
            results = []
            # One forced receipts refresh for the WHOLE batch, not per master -- the cache is
            # shared, so this single refresh is what process_manual's own completeness gate
            # relies on for every master below (force_receipts=False on each call skips a
            # redundant re-force). See process_manual's docstring for why this matters here
            # specifically: looping 20-30+ masters, each doing its own full paginated receipts
            # refetch, would multiply straight into Acumatica's 100 req/min cap for zero added
            # correctness once the shared cache is already fresh.
            load_recent_receipts(force=True)
            # Acumatica's license caps this at 100 web-service API requests/minute
            # (confirmed via the License Monitoring Console). process_manual costs a
            # few calls per master (receipt/PO resolution, completeness, possibly a
            # shipment create) -- looping tight over 20-30+ active masters with no
            # pacing could burst past that cap in well under a minute. Paced well
            # below the limit, not right up against it.
            # Dedupe by CONTAINER, not master (FIXED 2026-08-03, real incident: GCXU5545290).
            # process_manual(container) resolves and re-checks EVERY master tied to that
            # container in one call -- so looping per-master (the old approach below) called
            # process_manual on the SAME shared container once per master sharing it. The
            # first call correctly shipped everyone; every call after it saw those same
            # masters as "already shipped" (because they were, seconds earlier, in this same
            # run) and raised a false "pickup_after_already_shipped" anomaly needing clerk
            # review. Real case: one shared container generated 6 false anomaly flags this
            # way even though every underlying shipment was correct. Collect the unique set
            # of containers first; process each exactly once.
            container_to_sample_master = {}
            for token, entry in ledger.items():
                if entry.get("status") not in ("waiting", "partial"):
                    continue
                containers = list(entry.get("containers", {}).keys())
                if not containers:
                    continue
                container_to_sample_master.setdefault(containers[-1], token)
            first = True
            for container, sample_master in container_to_sample_master.items():
                if not first:
                    time.sleep(2.5)
                first = False
                # A reasonable fallback ship_date only -- process_manual recomputes the
                # correct per-master date internally via ledger_latest_date(po) regardless
                # (see line ~2599), so this doesn't need to be exact per master.
                latest = ledger_latest_date(sample_master)
                try:
                    out = process_manual(container, latest, source="ledger-recheck",
                                          dry_run=False, force_receipts=False)
                except Exception as e:
                    out = {"error": str(e)}
                results.append({"container": container, "result": out})
            return self._send(200, json.dumps({"checked": len(results), "results": results}), "application/json")
        if u.path == "/fixshipdate":
            # Correct ShipmentDate on an ALREADY-CREATED shipment without re-running
            # CreateShipment (which would create a duplicate). Takes the SALES ORDER (not
            # the bare shipment number) because resolving a shipment's internal id directly
            # by ShipmentNbr proved unreliable three different ways -- _latest_shipment_
            # for_order()'s $expand=Shipments read via the parent order is the one path
            # that's actually proven to return a usable id.
            want = AUTOSHIP_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln).decode() or "{}")
            except Exception:
                return self._send(400, json.dumps({"error": "invalid JSON body"}), "application/json")
            order_type = (body.get("order_type") or "").strip()
            order_nbr = (body.get("order_nbr") or "").strip()
            date = (body.get("ship_date") or "").strip()
            if not order_type or not order_nbr or not date:
                return self._send(400, json.dumps({"error": "order_type, order_nbr, and ship_date are required"}), "application/json")
            try:
                ship = _latest_shipment_for_order(order_type, order_nbr)
                if not ship or not ship.get("id"):
                    return self._send(200, json.dumps({"order": f"{order_type} {order_nbr}",
                        "error": "could not find a shipment (with a resolvable id) for this order",
                        "debug_ship": ship}), "application/json")
                out = set_shipment_date_and_container(ship["id"], ship["shipment_nbr"], date=date)
                out["order"] = f"{order_type} {order_nbr}"
                out["shipment"] = ship["shipment_nbr"]
                return self._send(200, json.dumps(out), "application/json")
            except Exception as e:
                return self._send(200, json.dumps({"error": str(e)}), "application/json")
        if u.path == "/agent/log":
            # The mailbox-agent posts one decision row here. No Acumatica calls -- pure
            # audit logging. Kept deliberately permissive on field shape (whatever the
            # agent sends in the known fields is recorded) so the log format can evolve
            # with the agent's prompt without a coordinated deploy.
            want = AGENT_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln).decode() or "{}")
            except Exception:
                return self._send(400, json.dumps({"error": "invalid JSON body"}), "application/json")
            row = agent_log(body)
            return self._send(200, json.dumps({"logged": row}), "application/json")
        if u.path == "/ingest":
            # Power Automate pushes a raw email here (metadata + body + attachments).
            # Just enqueues -- no parsing/judgment (that's the agent's job when it drains).
            want = INGEST_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln).decode() or "{}")
            except Exception:
                return self._send(400, json.dumps({"error": "invalid JSON body"}), "application/json")
            if not body.get("message_id") and not body.get("subject"):
                return self._send(400, json.dumps({"error": "message_id or subject required"}), "application/json")
            item_id, existed = ingest_enqueue(body)
            return self._send(200, json.dumps({"id": item_id, "already_queued": existed}), "application/json")
        if u.path == "/ingest/delete":
            # The agent calls this once it has fully processed a queue item.
            want = AGENT_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln).decode() or "{}")
            except Exception:
                return self._send(400, json.dumps({"error": "invalid JSON body"}), "application/json")
            item_id = body.get("id")
            if not item_id:
                return self._send(400, json.dumps({"error": "id is required"}), "application/json")
            return self._send(200, json.dumps({"deleted": ingest_delete(item_id)}), "application/json")
        if u.path == "/watchlist/add":
            # Called by the FCR-intake Power Automate flow after /parsefcr. No Acumatica
            # calls here -- just records what to watch for.
            want = MAERSK_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln).decode() or "{}")
            except Exception:
                return self._send(400, json.dumps({"error": "invalid JSON body"}), "application/json")
            container = body.get("container")
            if not container:
                return self._send(400, json.dumps({"error": "container is required"}), "application/json")
            entry = watchlist_add(container, pos=body.get("pos"), port_of_loading=body.get("port_of_loading"),
                                   receipt_no=body.get("receipt_no"), vessel=body.get("vessel"),
                                   source=body.get("source"))
            return self._send(200, json.dumps({"container": container.strip().upper(), "entry": entry}), "application/json")
        if u.path == "/watchlist/resolve":
            # Called by the local Maersk-checker script once it finds the anchored Load-on
            # event (status="resolved") or a container sits unresolved past a manual review
            # decision (status="alert" is normally set automatically by the SLA sweep, but
            # this lets a person clear/override it too).
            want = MAERSK_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln).decode() or "{}")
            except Exception:
                return self._send(400, json.dumps({"error": "invalid JSON body"}), "application/json")
            container = body.get("container")
            status = body.get("status")
            if not container or not status:
                return self._send(400, json.dumps({"error": "container and status are required"}), "application/json")
            entry = watchlist_resolve(container, status, note=body.get("note"), ship_date=body.get("ship_date"))
            if entry is None:
                return self._send(404, json.dumps({"error": "container not on watch-list"}), "application/json")
            return self._send(200, json.dumps({"container": container.strip().upper(), "entry": entry}), "application/json")
        if u.path == "/parsefcr":
            # Token-authenticated, read-only: parses an FCR PDF and returns container#/PO#s/
            # Port of Loading. No Acumatica calls here -- the caller (Power Automate) feeds
            # the result into /autoship separately once it has a ship date to attach.
            want = FCR_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ctype = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in ctype or "boundary=" not in ctype:
                return self._send(400, json.dumps({"error": "expected upload"}), "application/json")
            boundary = ctype.split("boundary=", 1)[1].strip().strip('"').encode()
            ln = int(self.headers.get("Content-Length", 0))
            fields = parse_multipart(self.rfile.read(ln), boundary)
            filedata = fields.get("pdf")
            if not filedata:
                return self._send(400, json.dumps({"error": "no file"}), "application/json")
            tmp = os.path.join(TOKEN_DIR, "_fcr_upload_%s.pdf" % secrets.token_hex(8))
            with open(tmp, "wb") as f:
                f.write(filedata if isinstance(filedata, bytes) else filedata.encode())
            try:
                out = parse_fcr(tmp)
                return self._send(200, json.dumps(out), "application/json")
            except Exception as e:
                return self._send(200, json.dumps({"error": str(e)}), "application/json")
            finally:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
        if u.path == "/login":
            ip = self.client_address[0]
            if _login_blocked(ip):
                return self._send(429, "<!doctype html><meta charset=utf-8><p>Too many failed sign-in attempts. Please wait a few minutes and try again.</p>")
            ln = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(ln).decode())
            pw = data.get("pw", [""])[0]
            uname = (data.get("user", [""])[0] or "").strip()
            ok = False; who = uname or "staff"
            if CFG["users"]:  # per-user logins (APP_USERS): name + password must match
                if uname in CFG["users"] and hmac.compare_digest(CFG["users"][uname].encode(), pw.encode()):
                    ok = True; who = uname
            elif CFG["app_password"] and hmac.compare_digest(pw.encode(), CFG["app_password"].encode()):
                ok = True; who = uname or "staff"  # single shared password; name is a label
            if ok:
                return self._redirect_with_cookie(make_session(who))
            _record_login_failure(ip)
            return self._send(200, LOGIN)
        if not self._authed():
            return self._send(403, "forbidden", "text/plain")
        return self._send(404, json.dumps({"error": "not found"}), "application/json")

    def _redirect_with_cookie(self, cookie):
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"s={cookie}; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()

if __name__ == "__main__":
    bind = "0.0.0.0" if CFG["public_url"] and "localhost" not in CFG["public_url"] else "127.0.0.1"
    print(f"Shipments tool on {bind}:{PORT}")
    ThreadingHTTPServer((bind, PORT), H).serve_forever()
