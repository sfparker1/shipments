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
import os, re, json, time, base64, hashlib, hmac, secrets, datetime
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
def ledger_record(master_token, container, pickup_date):
    """Idempotent upsert -- a duplicate/resent NRT email for a container already in the
    ledger just re-writes the same date, harmless. Always called BEFORE any shipment
    decision, so the ledger reflects reality even if the completeness check or the
    shipment-creation loop below it fails partway through."""
    if not master_token or not container:
        return None
    data = load_json(LEDGER_PATH) or {}
    entry = data.setdefault(master_token, {"containers": {}, "status": "waiting",
                                            "first_seen": pickup_date, "last_updated": pickup_date})
    entry["containers"][container] = pickup_date
    entry["last_updated"] = pickup_date
    save_json(LEDGER_PATH, data)
    return entry

def ledger_set_status(master_token, status, note=None):
    data = load_json(LEDGER_PATH) or {}
    if master_token not in data:
        return None
    data[master_token]["status"] = status
    if note:
        data[master_token]["note"] = note
    save_json(LEDGER_PATH, data)
    return data[master_token]

def ledger_latest_date(master_token):
    data = load_json(LEDGER_PATH) or {}
    dates = list((data.get(master_token) or {}).get("containers", {}).values())
    return max(dates) if dates else None

def ledger_stamp_checked(master_token):
    """Records WHEN a live PO-completeness check last actually ran for this master --
    distinct from last_updated (which tracks container pickup dates, not live-check time).
    Lets /splits show a cached, zero-API-call view by default with an honest 'as of' time,
    rather than needing a live call just to know how stale the cache is."""
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

# ---------------- PDF parser (Dachser formats A & B) ----------------
_SKIP_MARK = ("CUBE", "STANDARD", "REEFER", "HIGH", "N/M", "CONTAINER", "40'", "20'", "45'")

def parse_handover(path):
    if pdfplumber is None: raise RuntimeError("pdfplumber not installed")
    # NOTE: most containers on a real advice do NOT list PO#s in Description of
    # Goods -- often only one container out of many does (confirmed against a
    # real 10-container advice). `po_numbers` below is best-effort text parsing
    # and is known-incomplete; process_file() fills the gap by resolving each
    # container's POs via Acumatica PO Receipts (see containers_to_pos()).
    ref = None; ports = []; dates = []; containers = {}; pos = []; text_pos_by_container = {}
    with pdfplumber.open(path) as pdf:
        full = ""
        for pg in pdf.pages:
            full += (pg.extract_text() or "") + "\n"
            # Column mapping for the current "Container No / Marks / Description of
            # Goods" block on this page. Scanned per ROW (not per-table t[0] only):
            # pdfplumber sometimes merges a container's header+data into the same
            # table object as a leftover "Pieces/SLAC" row from the *previous*
            # container (different column count), which shifts the real header
            # off row 0 and silently drops that container if we only look at t[0].
            ci = mi = di = None
            for t in pg.extract_tables():
                if not t: continue
                for row in t:
                    if any((c or "") == "Container No" for c in row) and any((c or "") == "Marks" for c in row):
                        ci = [i for i, c in enumerate(row) if (c or "") == "Container No"][0]
                        mi = [i for i, c in enumerate(row) if (c or "") == "Marks"][0]
                        dd = [i for i, c in enumerate(row) if (c or "") == "Description of Goods"]
                        di = dd[0] if dd else None
                        continue  # header row itself, not a data row
                    if ci is None: continue
                    cont = (row[ci].strip() if ci < len(row) and row[ci] else "")
                    if not re.match(r"^[A-Z]{4}\d{7}$", cont): continue
                    containers.setdefault(cont, None)
                    if mi is not None and mi < len(row) and row[mi]:
                        for ln in row[mi].split("\n"):
                            s = ln.strip().rstrip(",").strip()
                            if not s or any(k in s.upper() for k in _SKIP_MARK): continue
                            if re.match(r"^[A-Za-z]{0,3}\d{5,9}$", s) and s not in pos: pos.append(s)
                    if di is not None and di < len(row) and row[di] and "PO#" in row[di]:
                        for blk in re.findall(r"PO#\s*(.*?)(?:Q'ty|HS code|In Gate|Total NW|$)", row[di], re.DOTALL):
                            for n in re.findall(r"\b(\d{6})\b", blk):
                                if n not in pos: pos.append(n)
                                cset = text_pos_by_container.setdefault(cont, [])
                                if n not in cset: cset.append(n)
        for c, p, w in re.findall(r"\b([A-Z]{4}\d{7})\b\s+\d+\s+([\d,]+)\s+([\d,\.]+)", full):
            containers.setdefault(c, None); containers[c] = int(p.replace(",", ""))
        m = re.search(r"\b(\d{11})\b", full); ref = m.group(1) if m else None
        for p in re.findall(r"\b([A-Z]{2}\s[A-Z]{3})\b", full):
            if p not in ports: ports.append(p)
        for d in re.findall(r"\b(20\d\d-\d\d-\d\d)\b", full):
            if d not in dates: dates.append(d)
    return {"dachser_reference": ref, "pol": ports[0] if ports else None,
            "pod": ports[1] if len(ports) > 1 else None, "eta": dates[-1] if dates else None,
            "containers": [{"container": c, "pieces": containers[c],
                             "po_numbers_text": text_pos_by_container.get(c, [])} for c in containers],
            "po_numbers": pos}

# ---------------- container -> PO resolution (Acumatica PO Receipts) ----------------
# The advice text only lists PO#s for a container "sometimes" (see the note in
# parse_handover). The reliable source is Acumatica: the PO-receipts tool tags
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
    """GET with $top/$skip paging, capped at max_pages as a safety limit."""
    rows = []
    sep = "&" if "?" in path else "?"
    for page in range(max_pages):
        q = f"{path}{sep}$top={page_size}&$skip={page * page_size}"
        st, data = api("GET", q)
        if st != 200 or not isinstance(data, list):
            break
        rows.extend(data)
        if len(data) < page_size:
            break
    return rows

def discover_receipt_container_field():
    """Find the container-number custom/UDF field on PurchaseReceipt -- the
    PO-receipts tool writes this same field (mirrors its own discovery logic)."""
    if _RCPT_CONTAINER_FIELD["checked"]:
        return _RCPT_CONTAINER_FIELD["field"], _RCPT_CONTAINER_FIELD["view"]
    _RCPT_CONTAINER_FIELD["checked"] = True  # only ever hit the schema endpoint once per process
    env_f = cfg("RECEIPT_CONTAINER_FIELD")
    if env_f:
        _RCPT_CONTAINER_FIELD.update(field=env_f, view=cfg("RECEIPT_CONTAINER_VIEW", "Document"))
        return _RCPT_CONTAINER_FIELD["field"], _RCPT_CONTAINER_FIELD["view"]
    st, data = api("GET", f"{ENTITY}/PurchaseReceipt/$adHocSchema")
    if st == 200 and isinstance(data, dict):
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
    data = _fetch_all_pages(path, page_size=500, max_pages=40)
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

def containers_completeness(container):
    """Combines resolve_pos_from_container + po_completeness across ALL of a container's
    resolved POs -- every one of them must be Completed for the container's order to be
    considered ready to ship. Returns (complete: bool, detail: list) -- fails closed if
    resolution itself came back empty or ambiguous (a genuinely single-container, fully
    resolved order still passes this the same as it does today; nothing changes for the
    normal case)."""
    refs = resolve_pos_from_container(container)
    if not refs or any(r is None for r in refs):
        return False, [{"error": "one or more receipts for this container did not resolve "
                                  "to exactly one Purchase Order"}]
    detail = []
    complete = True
    for po_type, po_nbr in refs:
        ok, d = po_completeness(po_type, po_nbr)
        detail.append(d)
        complete = complete and ok
    return complete, detail

def expected_containers_for_master(master_token):
    """Every container Acumatica's OWN receipts say belongs to this master -- the union
    across every receipt whose VendorRef resolves to this master, regardless of how many
    separate uploads it took (mirrors the /diag po_completeness_probe pattern)."""
    containers = set()
    for r in load_recent_receipts():
        if master_token in _extract_order_tokens(r.get("vendor_ref")):
            containers.update(r.get("containers") or [])
    return containers

def containers_confirmed_available(master_token):
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

    "Confirmed" = present in container_ledger.json for this master -- ledger_record()
    only ever fires from a real NRT trigger event (see process_manual), so a container
    that never sent its own email is correctly never in there. Returns (all_confirmed,
    missing_containers, expected_containers)."""
    expected = expected_containers_for_master(master_token)
    entry = ledger_entry(master_token) or {}
    confirmed = set((entry.get("containers") or {}).keys())
    missing = expected - confirmed
    return (not missing), sorted(missing), sorted(expected)

# ---------------- matching ----------------
_OPEN_ORDERS = {"rows": None, "ts": 0}
OPEN_TTL = 600   # cache open sales orders for 10 min

def load_open_orders(force=False):
    """Fetch all OPEN sales orders once (no slow 'contains' scan — just a Status
    filter), cache them, and reuse. Turns N table scans into one bounded fetch."""
    now = time.time()
    if not force and _OPEN_ORDERS["rows"] is not None and now - _OPEN_ORDERS["ts"] < OPEN_TTL:
        return _OPEN_ORDERS["rows"]
    rows = []
    q = (f"{ENTITY}/SalesOrder?$filter=Status eq 'Open'"
         f"&$select=OrderType,OrderNbr,CustomerOrder,CustomerID,Status")
    st, data = api("GET", q)
    if st == 200 and isinstance(data, list):
        for so in data:
            g = lambda k: (so.get(k) or {}).get("value")
            rows.append({"order_type": g("OrderType"), "order_nbr": g("OrderNbr"),
                         "cust_order": g("CustomerOrder") or "", "customer": g("CustomerID"),
                         "status": g("Status")})
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

def _failure_reason(order_type, order_nbr):
    """When CreateShipment fails, look at the order to give a human reason
    instead of Acumatica's generic 'Operation failed' stack trace."""
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

def create_shipment(order_type, order_nbr, container_ref=None, ship_date=None, po=None):
    # ship_date is required by the caller (process_file hard-stops before this
    # point if it's missing) -- no more silent fallback to a synced date or to
    # "today". po is accepted for logging only.
    # NOTE: the ShipmentDate action PARAMETER below is NOT reliably honored by Acumatica --
    # confirmed via a real run where the resulting shipment came back dated "today" despite
    # this parameter. Kept here in case it helps in some configs, but the real mechanism is
    # the corrective PUT + verification read further down, right after the shipment exists.
    date = ship_date
    params = {}
    if date: params["ShipmentDate"] = {"value": date}
    if CFG["warehouse"]: params["WarehouseID"] = {"value": CFG["warehouse"]}
    body = {"entity": {"OrderType": {"value": order_type}, "OrderNbr": {"value": order_nbr}}, "parameters": params}
    st, resp, headers = api_with_headers("POST", f"{ENTITY}/SalesOrder/CreateShipment", body)
    res = {"order": f"{order_type} {order_nbr}", "invoke_status": st, "ship_date": date}

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
            res.update(created=False, verified=False,
                       error="Acumatica did not finish processing within 15s (still 202) -- check manually")
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
        res["reason"] = _failure_reason(order_type, order_nbr)
    return res

# ---------------- run log ----------------
def log_run(entry):
    try:
        os.makedirs(TOKEN_DIR, exist_ok=True)
        entry["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(RUNS_PATH, "a") as f: f.write(json.dumps(entry) + "\n")
    except Exception: pass

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

def _find_later_success(container, after_ts, hist_rows):
    """Did a LATER run (e.g. a manual retry after a timeout exception) succeed for this
    same container? agent_log.jsonl is append-only by design (a permanent record of what
    the agent decided at the time) -- a retry never edits an old flagged row, it just adds
    a new one to ship_runs.jsonl. Without this check, a resolved exception sits flagged
    forever, which reads as an open problem long after it's actually been fixed. Pure
    local-file lookup (history() reads ship_runs.jsonl) -- no live Acumatica calls, cheap
    to run per row on every page render."""
    if not container or not after_ts:
        return None
    for h in hist_rows:
        if h.get("ts", "") <= after_ts:
            continue
        if container not in (h.get("containers") or ""):
            continue
        if h.get("status") == "ok" and h.get("created"):
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
    only, no live Acumatica calls."""
    if not container:
        return {"shipped": False}
    for h in history(limit=0):
        if container in (h.get("containers") or "") and h.get("status") == "ok" and h.get("created"):
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

def agent_log_read(limit=200, exceptions_only=False, message_id=None):
    """Newest-first. exceptions_only filters to flagged rows for quick review;
    message_id returns every row for one source email (the idempotency lookup)."""
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
    prepared = flagged = no_action = 0
    exceptions = []
    for r in rows:
        c = r.get("classification") or "unknown"
        by_class[c] = by_class.get(c, 0) + 1
        if r.get("action_taken") == "create_shipment":
            prepared += 1
        else:
            no_action += 1
        if r.get("exception_flag"):
            flagged += 1
            exceptions.append({
                "when": r.get("ts"), "subject": (r.get("subject") or "")[:80],
                "classification": c, "reason": r.get("exception_reason") or "(none)",
                "message_id": r.get("message_id") or "",
            })
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
        "shipments_prepared": prepared,   # in shadow these are "would-be"; see mode
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
    "nrt_waiting_on_containers": "Waiting on containers",
    "nrt_other_status": "NRT update, not a pickup",
    "not_nrt": "Not an NRT email",
    "ambiguous": "Ambiguous",
    "skip": "Skipped",
}
CLASSIFICATION_LEGEND = ("<b>Email status:</b> what the agent decided this email was about &mdash; "
    "<b>Available for pickup</b> is the shipment trigger; the others result in no shipment.")

def _friendly_classification(c):
    return CLASSIFICATION_LABELS.get(c, c or "&mdash;")

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

def _status_pill(r):
    """One colored badge that says, at a glance, what happened -- replaces the separate
    raw Action/Mode text columns. Derived from fields already on every decision row:
    exception_flag (needs a human), action_taken (create_shipment vs none), mode (shadow
    vs live), and -- for live create_shipment calls -- the actual tool_result.data, so a
    waiting_on_containers=true outcome (Phase 2 completeness gate) isn't mislabeled as a
    success just because the tool was CALLED; nothing was actually created."""
    if r.get("exception_flag"):
        return '<span class=pill style="border-color:#b06a5a;color:#b06a5a">&#9888; Needs review</span>'
    if r.get("action_taken") == "create_shipment":
        if r.get("mode") != "live":
            return '<span class=pill style="border-color:#5d7682;color:#5d7682">&#9678; Would create &middot; shadow</span>'
        data = (r.get("tool_result") or {}).get("data") or {}
        if data.get("waiting_on_containers"):
            return '<span class=pill style="border-color:#5d7682;color:#5d7682">&#8987; Waiting on containers</span>'
        if data.get("created"):
            return '<span class=pill style="border-color:#5a7d5a;color:#5a7d5a">&#10003; Shipment created</span>'
        return '<span class=pill style="border-color:#c9c0ad">No action needed</span>'
    return '<span class=pill style="border-color:#c9c0ad">No action needed</span>'

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
        received = sum(1 for d in detail if d.get("po_status") == "Completed")
        counts = (f"<div class=sub>{received} of {total} purchase orders received in full &mdash; "
                  f'<a href=/splits>see Split orders</a> for the breakdown.</div>') if total else ""
        return ("Waiting on the rest of this order to arrive &mdash; no shipment created yet; "
                "it'll ship automatically once every container is in." + counts)
    if data.get("out_of_scope"):
        return "Skipped &mdash; this container is 3PL-bound, not tracked here."
    if data.get("needs_review"):
        return f"Needs a person to look at this &mdash; {esc(str(data.get('note') or data.get('reason') or ''))}"
    rows = data.get("rows") or []
    created_lines, other_lines = [], []
    for row in rows:
        res = row.get("result") or {}
        po = esc(str(row.get("po") or ""))
        order = esc(str(res.get("order") or ""))
        if res.get("created"):
            already = " (already existed)" if res.get("already_existed") else ""
            created_lines.append(
                f"Order {order} (Master PO {po}) &rarr; Shipment {esc(str(res.get('shipment_nbr') or '?'))}, "
                f"dated {esc(str(res.get('ship_date') or ''))}{already}")
        elif order or po:
            reason = res.get("reason") or res.get("error") or row.get("note") or "not created"
            other_lines.append(f"Order {order} (Master PO {po}) &mdash; {esc(str(reason))}")
    if not rows:
        note = data.get("note") or data.get("reason")
        return esc(str(note)) if note else None
    parts = []
    if created_lines:
        parts.append("<br>".join(created_lines))
    if other_lines:
        parts.append(("<br>" if created_lines else "") + "<br>".join(other_lines))
    return "".join(parts) if parts else None

_CONTAINER_IN_SUBJECT = re.compile(r"Container\s*#\s*(\S+)", re.I)

def _agent_log_html(rows, exc_only):
    """Scannable decision table -- one row per decision, exceptions highlighted. Plain-
    English throughout: no raw JSON, no code-shaped field names -- the Details column uses
    _friendly_shipment_result instead of a JSON dump, and times display in Pacific."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    hist_rows = history(limit=0)  # local file read only, no live calls -- cheap per page load
    def _row(r):
        flagged = bool(r.get("exception_flag"))
        m = _CONTAINER_IN_SUBJECT.search(r.get("subject") or "")
        args = r.get("tool_args") or {}
        container_raw = args.get("container") or (m.group(1) if m else None)
        resolved = _find_later_success(container_raw, r.get("ts", ""), hist_rows) if flagged else None
        rowstyle = ' style="background:#eaf1e8"' if resolved else (' style="background:#f6ece8"' if flagged else "")
        what = esc(_friendly_classification(r.get("classification")))
        status = ('<span class=pill style="border-color:#5a7d5a;color:#5a7d5a">&#10003; Resolved on retry</span>'
                   if resolved else _status_pill(r))
        container = esc(container_raw) if container_raw else esc(r.get("subject") or "")
        ship_date = esc(str(args.get("ship_date") or ""))
        result_txt = _friendly_shipment_result(r.get("tool_result"), esc)
        detail = (f"<details><summary>What happened</summary><div>{result_txt}</div></details>"
                  if result_txt else "&mdash;")
        note = esc(r.get("rationale") or "")
        if flagged:
            if resolved:
                exc_note = (f'<span style="color:#5a7d5a">Shipped on a later retry '
                            f'({esc(_fmt_ts(resolved.get("ts")))}) -- no action needed now.</span>')
            else:
                exc_note = f'<span style="color:#b06a5a">{esc(r.get("exception_reason") or "needs review")}</span>'
            note = f"{exc_note}<br>{note}" if note else exc_note
        return (f"<tr{rowstyle}><td>{esc(_fmt_ts(r.get('ts')))}</td>"
                f"<td title=\"{esc(r.get('subject') or '')}\">{container}</td>"
                f"<td>{ship_date}</td>"
                f"<td>{what}</td><td>{status}</td>"
                f"<td>{note}</td><td>{detail}</td></tr>")
    body_rows = "".join(_row(r) for r in rows)
    title = "Agent decisions" + (" &mdash; exceptions only" if exc_only else "")
    toggle = ('<a class=pill href="/agent/log">all</a> '
              '<a class=pill href="/agent/log?exceptions_only=1">exceptions only</a>')
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

def _lookup_html(query=None):
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    form = ('<div class=card><h1 style="font-size:18px">Look up a container or Master PO</h1>'
            '<p class=sub>Pulls together everything known about one order from the ledger, '
            'the agent\'s decisions, and the shipment run history -- one place instead of three. '
            'No Acumatica calls; instant either way.</p>'
            '<form method=get action=/lookup><input type=text name=q placeholder="e.g. SEKU9013424 or 645410" '
            f'value="{esc(query or "")}" style="min-width:260px"> <button class=fog>Look up</button></form></div>')
    if not query:
        return form
    info = _lookup_order(query)
    # NOTE: containers_involved (for a container query) and master_tokens (for a Master PO
    # query) both always include the query itself, seeded unconditionally in
    # _lookup_order -- neither can be used to detect "found nothing". ledger_entries/
    # history_rows/agent_rows are only ever populated by a genuine match, so those are
    # the real signal.
    if not info["ledger_entries"] and not info["history_rows"] and not info["agent_rows"]:
        return form + f'<div class=card><p class=sub>Nothing found for &#8220;{esc(query)}&#8221;.</p></div>'

    parts = [form]
    parts.append('<div class=card><h1 style="font-size:16px">Summary</h1>'
                 f'<p class=sub>Master PO(s): <b>{esc(", ".join(info["master_tokens"]) or "&mdash;")}</b> '
                 f'&nbsp; Container(s): <b>{esc(", ".join(info["containers_involved"]) or "&mdash;")}</b></p></div>')

    for tok in info["master_tokens"]:
        entry = info["ledger_entries"].get(tok)
        if not entry:
            continue
        status_label = {"waiting": "Waiting", "partial": "Partially shipped", "shipped": "Shipped"}.get(
            entry.get("status"), entry.get("status") or "&mdash;")
        checked = entry.get("last_checked")
        cont_rows = "".join(f"<tr><td>{esc(c)}</td><td>{esc(d)}</td></tr>"
                            for c, d in sorted((entry.get("containers") or {}).items(), key=lambda kv: kv[1]))
        parts.append(f'<div class=card><h1 style="font-size:16px">Master PO {esc(tok)} '
                     f'<span class=pill style="border-color:#5d7682;color:#5d7682">{status_label}</span></h1>'
                     f'<p class=sub>{"Last checked live: " + esc(_fmt_ts(checked)) if checked else "Not yet checked live"} '
                     f'&mdash; <a href="/splits?live=1">refresh live</a></p>'
                     f'<div class=twrap><table><tr><th>Container</th><th>Available for pickup</th></tr>{cont_rows}</table></div></div>')

    if info["agent_rows"]:
        parts.append('<div class=card><h1 style="font-size:16px">Agent decisions</h1>'
                     + _agent_log_html(sorted(info["agent_rows"], key=lambda r: r.get("ts", "")), exc_only=False))

    if info["history_rows"]:
        hrows = sorted(info["history_rows"], key=lambda h: h.get("ts", ""), reverse=True)
        rows_html = "".join(
            f'<tr><td>{esc(_fmt_ts(h.get("ts")))}</td><td>{esc(h.get("status") or "")}</td>'
            f'<td>{esc(h.get("containers") or "")}</td>'
            f'<td>{esc(", ".join(sorted({o.get("po") for o in (h.get("orders") or []) if o.get("po")})))}</td>'
            f'<td>{esc(", ".join(sorted({o.get("shipment_nbr") for o in (h.get("orders") or []) if o.get("shipment_nbr")})))}</td></tr>'
            for h in hrows)
        parts.append('<div class=card><h1 style="font-size:16px">Shipment run history</h1>'
                     '<div class=twrap><table><tr><th>When</th><th>Status</th><th>Containers</th>'
                     f'<th>Master PO(s)</th><th>Shipment(s)</th></tr>{rows_html}</table></div></div>')
    return "".join(parts)

# ---------------- process a handover PDF ----------------
def process_file(path, dry_run=True, ship_date=None, user=None, source_name=None):
    # Hard stop: creation requires a typed Shipment date. No more silent fallback
    # to a per-PO/advice date or to "today" -- if it's blank, nothing is created.
    # (Preview / dry_run is unaffected -- you can preview matches before typing a date.)
    if not dry_run and not ship_date:
        return {"error": "Shipment date is required. Enter the NRT pickup date before creating shipments."}

    parsed = parse_handover(path)
    containers = [c["container"] for c in parsed["containers"]]
    container_ref = ", ".join(containers)

    # Most containers don't list PO#s in the advice text (see parse_handover) --
    # resolve the gap via Acumatica PO Receipts, and merge with whatever the
    # advice text did give us (belt-and-suspenders; text PO#s still count).
    text_pos_by_container = {c["container"]: (c.get("po_numbers_text") or []) for c in parsed["containers"]}
    receipt_pos_by_container = containers_to_pos(containers)
    all_pos = list(parsed["po_numbers"])
    for c in containers:
        for p in receipt_pos_by_container.get(c, []):
            if p not in all_pos: all_pos.append(p)
    unresolved_containers = [c for c in containers
                              if not receipt_pos_by_container.get(c) and not text_pos_by_container.get(c)]

    matched = find_sales_orders_batch(all_pos)
    if all_pos and not any(matched.get(p) for p in all_pos):
        # Every PO missed -- before flagging "no open sales order" across the board, force
        # one fresh fetch. The 10-min open-orders cache (load_open_orders) can lag behind a
        # very recent status change in Acumatica: confirmed via a real case where an order
        # was genuinely Open in Acumatica but the cached snapshot pre-dated that.
        load_open_orders(force=True)
        matched = find_sales_orders_batch(all_pos)
    rows = []; log_orders = []; to_create = 0; created = 0
    for po in all_pos:
        matches = matched.get(po, [])
        if not matches:
            rows.append({"po": po, "confidence": "flag", "note": "no open sales order", "orders": []})
            if not dry_run:
                log_orders.append({"po": po, "order": None, "shipment_nbr": None,
                                    "created": False, "reason": "no open sales order"})
            continue
        for m in matches:
            to_create += 1
            row = {"po": po, "confidence": "ok", "orders": [m], "note": ""}
            if not dry_run:
                res = create_shipment(m["order_type"], m["order_nbr"], container_ref, ship_date, po=po)
                row["result"] = res
                if res.get("created"): created += 1
                log_orders.append({"po": po, "order": f"{m['order_type']} {m['order_nbr']}".strip(),
                                    "shipment_nbr": res.get("shipment_nbr"), "created": res.get("created"),
                                    "ship_date": res.get("ship_date"), "reason": res.get("reason") or res.get("error")})
            rows.append(row)
    summary = {"dachser_reference": parsed["dachser_reference"],
               "route": f'{parsed["pol"]} -> {parsed["pod"]}', "eta": parsed["eta"],
               "containers": containers, "po_count": len(all_pos),
               "unresolved_containers": unresolved_containers,
               "orders_matched": to_create, "created": created, "dry_run": dry_run, "rows": rows}
    if not dry_run:
        if to_create == 0:
            status = "no_matches"
        elif created == to_create:
            status = "ok"
        elif created > 0:
            status = "partial"
        else:
            status = "failed"
        log_run({"reference": parsed["dachser_reference"], "document": source_name or os.path.basename(path),
                 "user": user, "acumatica_user": connected_user(), "status": status,
                 "orders_matched": to_create, "created": created,
                 "containers": container_ref, "unresolved_containers": unresolved_containers,
                 "ship_date": ship_date, "orders": log_orders})
    return summary

# ---------------- automated trigger (no PDF): NRT email / Maersk+FCR watch-list ----------------
def process_manual(container, ship_date, pos=None, user=None, source=None, dry_run=False):
    """Programmatic twin of process_file() for automated triggers that never see a
    handover PDF. Two calling shapes:
      - container only (NRT path: the pickup email has no PO info) -> resolve PO#s the
        same way process_file() does, via containers_to_pos() (container -> Acumatica
        PurchaseReceipt -> internal PO# -> VendorRef -> retail PO#).
      - container + pos (Maersk/FCR path: the FCR already lists the PO#s under that
        container) -> use the given PO#s directly, skipping containers_to_pos() entirely
        so this doesn't depend on a PO Receipt already existing in Acumatica by the time
        the vessel-loading event fires.
    Same creation path as process_file(): create_shipment() (unconfirmed, human Confirms
    in Acumatica) + log_run() to the same permanent audit log. `source` is a free-text tag
    (e.g. "nrt" / "maersk-fcr") recorded in the run history so History shows where each
    automated run came from.
    """
    if not dry_run and not ship_date:
        return {"error": "Shipment date is required."}
    container = (container or "").strip().upper()
    if not container:
        return {"error": "container is required."}

    if pos:
        all_pos = list(dict.fromkeys(p.strip() for p in pos if p and p.strip()))
        unresolved = False
    else:
        scope, resolved = container_scope(container)
        # Out of scope: 3PL-bound units are recognized at the 3PL, not at port pickup.
        # Skip quietly (not a review exception) so 3PL containers don't spam the digest.
        if scope == "out_of_scope":
            return {"container": container, "out_of_scope": True, "created": 0, "orders_matched": 0,
                    "reason": "out_of_scope_3pl",
                    "note": "container's PO Receipt is 3PL-bound (MMX/4006/AMAZON/HG); revenue is "
                            "recognized at the 3PL, not at port pickup -- skipped, no action needed"}
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
        for token in resolved:
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
                still_shipped = any(
                    _latest_shipment_for_order(m["order_type"], m["order_nbr"], retries=1, delay=0)
                    for m in find_sales_orders_batch([token]).get(token, []))
                if still_shipped:
                    return {"container": container, "needs_review": True, "created": 0, "orders_matched": 0,
                            "reason": "pickup_after_already_shipped",
                            "note": f"master {token} was already marked shipped, but a new pickup "
                                    "event just arrived for it -- a clerk should investigate",
                            "ledger_entry": entry}
                # The ledger was stale -- no live shipment actually exists anymore (e.g. it
                # was deleted after being found erroneous). Reset so this master gets
                # re-evaluated normally instead of being permanently stuck flagging a
                # false anomaly on every future pickup event.
                ledger_set_status(token, "waiting")
            ledger_record(token, container, pickup_date)
        complete, completeness_detail = containers_completeness(container)
        for token in resolved:
            ledger_stamp_checked(token)
        # SECOND, INDEPENDENT gate (2026-07-24, real incident): the PO-receiving check
        # above is a warehouse-side fact (has Acumatica recorded all the qty as received);
        # it is NOT the same as "has every container this PO depends on been individually
        # confirmed Available for Pickup by NRT" (a port-pickup fact). A PO can show fully
        # received while a sibling container has never sent its own NRT email at all --
        # confirmed real, see containers_confirmed_available's docstring. Revenue
        # recognition is anchored to the port-pickup event, so BOTH gates must pass.
        container_gaps = {}
        for token in resolved:
            all_confirmed, missing, expected = containers_confirmed_available(token)
            if not all_confirmed:
                container_gaps[token] = {"missing_containers": missing, "expected_containers": expected}
        if not complete or container_gaps:
            for token in resolved:
                ledger_set_status(token, "waiting")
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
            return {"container": container, "waiting_on_containers": True, "created": 0,
                    "orders_matched": 0, "reason": reason, "note": note,
                    "completeness_detail": completeness_detail,
                    "container_gaps": container_gaps or None}
        all_pos = resolved
        unresolved = not resolved

    matched = find_sales_orders_batch(all_pos)
    if all_pos and not any(matched.get(p) for p in all_pos):
        # Same stale-cache guard as process_file() -- see its comment above.
        load_open_orders(force=True)
        matched = find_sales_orders_batch(all_pos)
    rows = []; log_orders = []; to_create = 0; created = 0
    po_all_created = {}  # po/master token -> did every matched order for it end up created?
    for po in all_pos:
        matches = matched.get(po, [])
        if not matches:
            rows.append({"po": po, "confidence": "flag", "note": "no open sales order", "orders": []})
            if not dry_run:
                log_orders.append({"po": po, "order": None, "shipment_nbr": None,
                                    "created": False, "reason": "no open sales order"})
            po_all_created[po] = False
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
                existing = _latest_shipment_for_order(m["order_type"], m["order_nbr"], retries=1, delay=0)
                if existing:
                    res = {"order": f"{m['order_type']} {m['order_nbr']}", "created": True,
                           "shipment_nbr": existing.get("shipment_nbr"), "already_existed": True}
                else:
                    # Ship at the LATEST recorded pickup date for this master (spans however
                    # many separate NRT events it took), not just this one event's own date --
                    # falls back to the passed-in ship_date for the pos-given (Maersk/FCR) path,
                    # which isn't ledger-tracked.
                    effective_date = ledger_latest_date(po) or ship_date
                    res = create_shipment(m["order_type"], m["order_nbr"], container, effective_date, po=po)
                row["result"] = res
                if res.get("created"):
                    created += 1
                else:
                    po_ok = False
                log_orders.append({"po": po, "order": f"{m['order_type']} {m['order_nbr']}".strip(),
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
    if not dry_run:
        if to_create == 0:
            status = "no_matches"
        elif created == to_create:
            status = "ok"
        elif created > 0:
            status = "partial"
        else:
            status = "failed"
        log_run({"reference": None, "document": f"auto:{source or 'unknown'}",
                 "user": user or f"auto:{source or 'unknown'}", "acumatica_user": connected_user(),
                 "status": status, "orders_matched": to_create, "created": created, "containers": container,
                 "unresolved_containers": unresolved_containers, "ship_date": ship_date,
                 "orders": log_orders})
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
    """Derive the next-action stage from a pipeline record.
    The order is still Open (so_pipeline only sees open orders); it leaves the
    Open list once its invoice is released, so 'Done' is handled upstream as an
    empty pipeline. Shipment 'Status' is Open until Confirmed/Completed."""
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
    Avoids substringof (500s on this tenant): matches the PO against the cached
    OPEN-order list client-side, then reads each order's shipments via GET-by-key.
    An order stays Open until fully invoiced, so a picked-up PO with no open match
    is already fully processed ('Done')."""
    return [_order_pipeline(m, po) for m in find_sales_orders_batch([po]).get(po, [])]

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
        body = '<p class=sub>No orders currently split across multiple containers.</p>'
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
                cards.append('<div class=card><h1 style="font-size:16px">Master %s</h1>'
                              '<p class=sub style="color:#b06a5a">Could not load: %s</p></div>'
                              % (esc(tok), esc(str(e))))
        body = "".join(cards)
        if hidden:
            body += ('<p class=sub>%d more, oldest-waiting-first shown above -- '
                      '<a href="/splits?live=%s&limit=%d">show all %d</a>.</p>'
                      % (len(hidden), "1" if live else "0", len(ordered), len(ordered)))
    toggle = ('<a class=pill href="/splits?live=1">Refresh live status</a>' if not live
              else '<a class=pill href="/splits">Back to cached view</a>')
    freshness = ("Showing live status, just checked against Acumatica." if live else
                 "Showing the last-known status from previous checks -- no Acumatica calls made "
                 "just to view this page.")
    return ('<div class=card><h1 style="font-size:18px">Orders split across containers</h1>'
            '<p class=sub>Orders currently waiting on more than one container before they can ship. '
            '%s</p><p>%s</p></div>'
            % (freshness, toggle)
            + body)

def _split_order_card(tok, entry, esc, live=False):
    """Build one master's card for _splits_html. Split out so a failure building ONE
    card (bad/unexpected data for that master) can be caught and shown inline without
    taking down the rest of the page. live=False (the default) makes ZERO Acumatica
    calls -- everything comes straight from the ledger entry."""
    if not live:
        cont_rows = "".join(
            f"<tr><td>{esc(c)}</td><td>{esc(d)}</td></tr>"
            for c, d in sorted(entry.get("containers", {}).items(), key=lambda kv: kv[1]))
        status_label = "Partially shipped" if entry.get("status") == "partial" else "Waiting"
        checked = entry.get("last_checked")
        checked_note = (f"Purchase order status as of last check ({esc(_fmt_ts(checked))}) -- "
                        f'<a href="/splits?live=1">refresh live</a> for current status.') if checked else \
                       'Purchase order status not yet checked live -- <a href="/splits?live=1">refresh live</a> to check now.'
        return (
            f'<div class=card><h1 style="font-size:16px">Master PO {esc(tok)} '
            f'<span class=pill style="border-color:#5d7682;color:#5d7682">{status_label}</span></h1>'
            f'<p class=sub>Containers seen so far, in order of pickup date:</p>'
            f'<div class=twrap><table><tr><th>Container</th><th>Available for pickup</th></tr>{cont_rows}</table></div>'
            f'<p class=sub>{checked_note}</p></div>')
    info = split_order_status(tok, entry)
    cont_rows = "".join(
        f"<tr><td>{esc(c)}</td><td>{esc(d)}</td></tr>"
        for c, d in sorted(info["containers"].items(), key=lambda kv: kv[1]))
    po_rows = "".join(
        f"<tr><td>{esc(p['po'])}</td><td>{'&#10003; Received in full' if p['complete'] else '&#9678; ' + esc(p['status'])}</td></tr>"
        for p in info["purchase_orders"]) or "<tr><td colspan=2 class=sub>Could not resolve a Purchase Order</td></tr>"
    order_rows = "".join(
        f"<tr><td>{esc(o['order'])}</td><td>{esc(o.get('cust_order') or '')}</td><td>{esc(o['stage'])}</td></tr>"
        for o in info["orders"]) or "<tr><td colspan=3 class=sub>No open sales order matched</td></tr>"
    status_label = "Partially shipped" if entry.get("status") == "partial" else "Waiting"
    return (
        f'<div class=card><h1 style="font-size:16px">Master PO {esc(tok)} '
        f'<span class=pill style="border-color:#5d7682;color:#5d7682">{status_label}</span></h1>'
        f'<p class=sub>Containers seen so far, in order of pickup date:</p>'
        f'<div class=twrap><table><tr><th>Container</th><th>Available for pickup</th></tr>{cont_rows}</table></div>'
        f'<p class=sub>Underlying Purchase Order(s) -- ALL must be fully received before this ships:</p>'
        f'<div class=twrap><table><tr><th>Purchase Order</th><th>Status</th></tr>{po_rows}</table></div>'
        f'<p class=sub>Matched Sales Order(s):</p>'
        f'<div class=twrap><table><tr><th>Order</th><th>Customer order #</th><th>Stage</th></tr>{order_rows}</table></div>'
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
:root{--sand:#efece3;--taupe:#7d7363;--stone:#4a4640;--fog:#5d7682;--line:#c9c0ad}
*{box-sizing:border-box;font-family:Arial,Helvetica,sans-serif}
body{margin:0;background:var(--sand);color:var(--stone)}
.wrap{max-width:960px;margin:0 auto;padding:28px}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:22px;margin-bottom:18px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--taupe);font-size:13px;margin:0 0 16px}
.brand{letter-spacing:.18em;color:var(--taupe);font-weight:700;font-size:12px}
button{background:var(--stone);color:#fff;border:0;border-radius:8px;padding:10px 16px;cursor:pointer;font-size:14px}
button.fog{background:var(--fog)}button:disabled{opacity:.5}
input[type=file],input[type=date],input[type=password],input[type=text]{padding:9px;border:1px solid var(--line);border-radius:8px;background:#faf8f4;width:100%}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line)}
.twrap{overflow-x:auto}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%}.ok{background:#5a7d5a}.flag{background:#b06a5a}
a{color:var(--fog)}.pill{background:var(--sand);border:1px solid var(--line);border-radius:14px;padding:2px 10px;font-size:12px;margin:0 6px 6px 0;display:inline-block}
pre{background:#2b2b2b;color:#d7d2c6;padding:14px;border-radius:8px;overflow:auto;font-size:12px}
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

def page(body, favicon=None):
    favicon = favicon or SHIP_FAVICON
    connected = bool(access_token())
    if connected:
        u = (connected_user() or "").replace("<", "").replace(">", "")
        exp = os.environ.get("EXPECTED_ACU_USER", "").strip()
        if exp and u and exp.lower() not in u.lower():
            badge = ('<span class=pill style="border-color:#b0653a;color:#b0653a">&#9888; Connected as %s &mdash; expected %s</span>'
                     ' <a class=pill href=/connect>Switch account</a>' % (u, exp))
        elif not u:
            # Detection failed (or the token predates requesting the openid/profile scope) --
            # warn loudly rather than showing a calm green "Connected" that implies verified.
            # Every write on this service runs as whoever is ACTUALLY logged in regardless of
            # what this banner says, so an unverifiable identity must not look fine.
            badge = ('<span class=pill style="border-color:#b0653a;color:#b0653a">'
                     '&#9888; Connected &mdash; user identity unknown, verify manually before any write</span>'
                     ' <a class=pill href=/connect>Switch account</a>')
        else:
            badge = ('<span class=pill style="border-color:#5a7d5a">Connected as %s</span>'
                     ' <a class=pill href=/connect>Switch account</a>' % u)
    else:
        badge = '<a class=pill href=/connect>Connect to Acumatica</a>'
    return """<!doctype html><meta charset=utf-8><title>POE Shipment Agent</title>%s<style>%s</style>
<div class=wrap><div class=brand>SAND + FOG</div><h1>POE Shipment Agent</h1>
<p class=sub>%s &nbsp; <a class=pill href=/>Dashboard</a> <a class=pill href=/lookup>Look up</a> <a class=pill href=/splits>Split orders</a> <a class=pill href=/manual>Manual upload</a> <a class=pill href=/guide>Guide</a> <a class=pill href=/history>Shipment history</a> <a class=pill href=/diag>Diagnostics</a></p>
%s</div>""" % (favicon, CSS, badge, body)

def _dashboard_html():
    """Agent dashboard -- the default landing page. Health/rollup stats up top (the same
    agent_summary() the daily email digest already computes), then the most recent
    decisions inline, so a glance here is enough for day-to-day monitoring. The manual
    PDF-upload tool (the old default landing page) moved to /manual -- still there as a
    fallback, just no longer the front door now that the agent handles the common case."""
    s = agent_summary(hours=24)
    recent = agent_log_read(limit=15)

    mode_color = {"live": "#5a7d5a", "shadow": "#7d7363", "mixed": "#b0653a", "n/a": "#c9c0ad"}
    mode_pill = ('<span class=pill style="border-color:%s">%s</span>'
                 % (mode_color.get(s["mode"], "#c9c0ad"), s["mode"]))

    # Same dead-man's-switch signal the daily digest email relies on, surfaced here too so
    # a glance at the dashboard catches a stuck/stopped agent without waiting for 7am.
    warn = ""
    if s["last_decision_at"]:
        try:
            age_h = (time.time() - time.mktime(time.strptime(s["last_decision_at"], "%Y-%m-%d %H:%M:%S"))) / 3600
            if age_h > 6:
                warn = ('<p class=sub style="color:#b06a5a">&#9888; Last decision was %.0fh ago &mdash; '
                        'check the agent is still running (Render cron logs).</p>' % age_h)
        except Exception:
            pass
    elif s["decisions"] == 0:
        warn = '<p class=sub style="color:#b06a5a">&#9888; No decisions logged in the last 24h.</p>'

    # Display-only: agent_summary()'s by_classification keeps the raw enum keys (the
    # digest email/Power-Automate side may match on them) -- map through
    # _friendly_classification for anything shown on screen, same as everywhere else.
    by_class = "".join('<span class=pill>%s: %d</span>' % (_friendly_classification(k), v)
                        for k, v in sorted(s["by_classification"].items()))

    # Cheap count (ledger's own stored status, not a live re-check -- that's what the
    # dedicated /splits page is for) so a glance here shows whether anything's mid-split.
    active_splits = sum(1 for e in (load_json(LEDGER_PATH) or {}).values()
                         if e.get("status") in ("waiting", "partial"))
    splits_pill = (' &nbsp; <a class=pill style="border-color:#5d7682;color:#5d7682" href=/splits>'
                    '%d order(s) split across containers</a>' % active_splits) if active_splits else ""

    stats = ('<div class=card><h1 style="font-size:16px">Agent dashboard &mdash; last 24h</h1>'
             '<p class=sub>Mode: %s &nbsp; Queue depth: <b>%s</b> &nbsp; Last decision: <b>%s</b>%s</p>'
             '%s'
             '<p><b>%s</b> decisions &middot; <b>%s</b> shipments prepared &middot; '
             '<b>%s</b> flagged for review &middot; <b>%s</b> no action needed</p>'
             '<p>%s</p>'
             '<p><a class=pill href=/lookup>Look up a container/PO</a> '
             '<a class=pill href=/agent/log?view=html>Full decision log</a> '
             '<a class=pill href="/agent/log?exceptions_only=1&view=html">Exceptions only</a> '
             '<a class=pill href=/splits>Split orders</a> '
             '<a class=pill href=/history>Shipment run history</a> '
             '<a class=pill href=/diag>Diagnostics</a> '
             '<a class=pill href=/manual>Manual PDF upload (fallback)</a></p></div>'
             % (mode_pill, s["queue_depth"], _fmt_ts(s["last_decision_at"]) or "&mdash;", splits_pill, warn,
                s["decisions"], s["shipments_prepared"], s["flagged"], s["no_action"],
                by_class or "&mdash;"))
    return stats + _dashboard_recent_html(recent)

def _dashboard_recent_html(rows):
    """Compact recent-activity table for the dashboard -- deliberately lighter than
    /agent/log's full view (no args/result expand) so it stays scannable at a glance."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    hist_rows = history(limit=0)  # local file read only, no live calls -- cheap per page load
    def _row(r):
        flagged = bool(r.get("exception_flag"))
        m = _CONTAINER_IN_SUBJECT.search(r.get("subject") or "")
        container_raw = m.group(1) if m else None
        resolved = _find_later_success(container_raw, r.get("ts", ""), hist_rows) if flagged else None
        rowstyle = ' style="background:#eaf1e8"' if resolved else (' style="background:#f6ece8"' if flagged else "")
        container = esc(container_raw) if container_raw else esc(r.get("subject") or "")
        status = ('<span class=pill style="border-color:#5a7d5a;color:#5a7d5a">&#10003; Resolved on retry</span>'
                   if resolved else _status_pill(r))
        if not flagged:
            exc_cell = "<td></td>"
        elif resolved:
            exc_cell = '<td style="color:#5a7d5a">Shipped on a later retry -- no action needed now.</td>'
        else:
            exc_cell = f'<td style="color:#b06a5a">{esc(r.get("exception_reason") or "")}</td>'
        return (f"<tr{rowstyle}><td>{esc(_fmt_ts(r.get('ts')))}</td>"
                f"<td title=\"{esc(r.get('subject') or '')}\">{container}</td>"
                f"<td>{esc(_friendly_classification(r.get('classification')))}</td>"
                f"<td>{status}</td>"
                f"{exc_cell}</tr>")
    body = "".join(_row(r) for r in rows)
    return ('<div class=card><h1 style="font-size:16px">Recent activity (last %d)</h1>'
            '<p class=sub>Times are Pacific. %s</p>'
            '<div class=twrap><table><tr><th>Received</th><th>Container</th><th>Email status</th><th>Result</th>'
            '<th>Exception</th></tr>%s</table></div></div>'
            % (len(rows), CLASSIFICATION_LEGEND, body or
               '<tr><td colspan=5 class=sub>No decisions logged yet.</td></tr>'))

MANUAL_UPLOAD = """<div class=card>
<h1 style="font-size:18px">Create shipments from a handover advice (manual fallback)</h1>
<p class=sub>The mailbox agent normally creates these automatically from NRT pickup emails &mdash; use this only as a fallback (e.g. an item the agent flagged, or a container to check manually). Drop a Dachser handover-advice PDF. Preview the matched sales orders, then create shipments (left unconfirmed for a person to confirm in Acumatica).</p>
<form id=f onsubmit="return false">
<p><input type=file id=pdf accept="application/pdf"></p>
<p style="max-width:340px"><label class=sub>Shipment date (required &mdash; type the NRT pickup date)</label><input type=date id=sd required></p>
<button class=fog onclick="go(true)">Preview</button>
<button onclick="go(false)" id=create disabled>Create shipments</button>
</form></div>
<div id=out></div>
<script>
let last=null;
async function go(dry){
 const f=document.getElementById('pdf').files[0]; if(!f){alert('Choose a PDF');return;}
 const sdVal=document.getElementById('sd').value;
 if(!dry && !sdVal){alert('Enter the Shipment date before creating shipments.');return;}
 const fd=new FormData(); fd.append('pdf',f); fd.append('dry',dry?'1':'0'); fd.append('sd',sdVal);
 document.getElementById('out').innerHTML='<div class=card>Working...</div>';
 const r=await fetch('/process',{method:'POST',body:fd}); const d=await r.json(); render(d,dry);
}
function render(d,dry){
 if(d.error){document.getElementById('out').innerHTML='<div class=card>Error: '+d.error+'</div>';return;}
 let h='<div class=card><h1 style="font-size:16px">'+(dry?'Preview':'Result')+' &mdash; ref '+(d.dachser_reference||'?')+'</h1>';
 h+='<p class=sub>'+d.route+' &nbsp; ETA '+(d.eta||'?')+'</p>';
 h+='<p>'+d.containers.map(c=>'<span class=pill'+((d.unresolved_containers||[]).includes(c)?' style="border-color:#b06a5a;color:#b06a5a"':'')+'>'+c+'</span>').join('')+'</p>';
 if((d.unresolved_containers||[]).length){
   h+='<p class=sub style="color:#b06a5a">&#9888; No PO could be found for '+d.unresolved_containers.length+' container(s) ('+d.unresolved_containers.join(', ')+') -- checked both the advice text and PO Receipts. Verify manually (e.g. against the packing list) before assuming this handover is fully covered.</p>';
 }
 h+='<p class=sub>'+d.po_count+' PO#s found (advice text + PO Receipts) &middot; '+d.orders_matched+' open sales orders matched'+(dry?'':' &middot; '+d.created+' shipments created')+'</p>';
 h+='<table><tr><th></th><th>PO#</th><th>Sales order</th><th>Customer</th><th>Result</th></tr>';
 for(const row of d.rows){
   const dot='<span class="dot '+(row.confidence=='ok'?'ok':'flag')+'"></span>';
   if(!row.orders.length){h+='<tr>'+td(dot)+td(row.po)+td('&mdash;')+td('&mdash;')+td(row.note)+'</tr>';continue;}
   for(const o of row.orders){
     let res=row.note||'';
     if(row.result){res=row.result.created?('&#10003; '+(row.result.shipment_nbr||'created')+(row.result.ship_date?' &middot; '+row.result.ship_date:'')):('&#9888; '+(row.result.reason||row.result.error||'failed'));}
     h+='<tr>'+td(dot)+td(row.po)+td((o.order_type||'')+' '+(o.order_nbr||''))+td(o.customer||'')+td(res)+'</tr>';
   }
 }
 h+='</table></div>';
 document.getElementById('out').innerHTML=h;
 document.getElementById('create').disabled = !(dry && d.orders_matched>0);
}
function td(x){return '<td>'+x+'</td>';}
</script>"""

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
            token_ok = bool(want) and qs.get("token", [""])[0] == want
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
            token_ok = bool(want) and qs.get("token", [""])[0] == want
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
            qs = urllib.parse.parse_qs(u.query)
            want = AGENT_TOKEN
            token_ok = bool(want) and qs.get("token", [""])[0] == want
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            msg_id = qs.get("message_id", [""])[0].strip() or None
            exc_only = qs.get("exceptions_only", ["0"])[0] == "1"
            try:
                limit = int(qs.get("limit", ["200"])[0])
            except Exception:
                limit = 200
            rows = agent_log_read(limit=limit, exceptions_only=exc_only, message_id=msg_id)
            if qs.get("view", [""])[0] == "html" or self._authed():
                return self._send(200, page(_agent_log_html(rows, exc_only), favicon=AGENT_FAVICON))
            return self._send(200, json.dumps(rows), "application/json")
        if u.path == "/containerstatus":
            # For the mailbox-agent to call on EVERY NRT status email, not just triggers --
            # catches NRT sending a status update that walks BACKWARD after a shipment
            # already exists for this container (see container_ship_history's docstring
            # for the real 2026-07-23 incident this closes). Read-only, no Acumatica calls.
            qs = urllib.parse.parse_qs(u.query)
            want = AGENT_TOKEN
            token_ok = bool(want) and qs.get("token", [""])[0] == want
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            container = (qs.get("container", [""])[0] or "").strip().upper()
            return self._send(200, json.dumps(container_ship_history(container)), "application/json")
        if u.path == "/agent/summary":
            # Rollup for the notification digest (a scheduled Power Automate flow reads
            # this and emails/Teams-messages Parker). AGENT_TOKEN-authed. ?hours=N window.
            qs = urllib.parse.parse_qs(u.query)
            want = AGENT_TOKEN
            token_ok = bool(want) and qs.get("token", [""])[0] == want
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
            token_ok = bool(want) and qs.get("token", [""])[0] == want
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            return self._send(200, json.dumps(ingest_list()), "application/json")
        if u.path == "/setshipdates":
            # Daily sync pushes each PO's NRT pickup date here (chunked GET). Merges into
            # po_shipdates.json; pass reset=1 on the first chunk to clear stale entries.
            qs = urllib.parse.parse_qs(u.query)
            want = os.environ.get("STATUS_TOKEN", "")
            token_ok = bool(want) and qs.get("token", [""])[0] == want
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
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
            token_ok = bool(want) and qs.get("token", [""])[0] == want
            if not (token_ok or self._authed()):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
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
            return self._send(200, page(_dashboard_html()))
        if u.path == "/manual":
            return self._send(200, page(MANUAL_UPLOAD))
        if u.path == "/connect":
            self.send_response(302); self.send_header("Location", build_authorize_url()); self.end_headers(); return
        if u.path == "/diag":
            qs = urllib.parse.parse_qs(u.query)
            d = diagnostics(qs.get("po", [None])[0], qs.get("container", [None])[0], qs.get("receipt", [None])[0])
            body = ('<div class=card><h1 style="font-size:16px">Diagnostics</h1>'
                    '<form method=get action=/diag>'
                    '<p style="max-width:260px"><input type=text name=po placeholder="test a PO# e.g. 117256"></p>'
                    '<p style="max-width:260px"><input type=text name=container placeholder="test a container e.g. FBIU5261330"></p>'
                    '<p style="max-width:260px"><input type=text name=receipt placeholder="dump a receipt e.g. 007068"></p>'
                    '<button class=fog>Run</button></form><pre>' + json.dumps(d, indent=2) + "</pre></div>")
            return self._send(200, page(body))
        if u.path == "/guide":
            return self._send(200, page(GUIDE))
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
                       '<p class=sub style="color:#b06a5a">%s</p></div>' % str(e).replace("<", "&lt;"))
            return self._send(200, page(out))
        if u.path == "/lookup":
            qs = urllib.parse.parse_qs(u.query)
            q = (qs.get("q", [None])[0] or "").strip()
            try:
                out = _lookup_html(q or None)
            except Exception as e:
                out = ('<div class=card><h1 style="font-size:16px">Lookup &mdash; error</h1>'
                       '<p class=sub style="color:#b06a5a">%s</p></div>' % str(e).replace("<", "&lt;"))
            return self._send(200, page(out))
        if u.path == "/history":
            _badge = {"ok": "#5a7d5a", "partial": "#b0653a", "failed": "#b06a5a", "no_matches": "#7d7363"}
            _status_label = {"ok": "Created", "partial": "Partially created", "failed": "Failed",
                              "no_matches": "No matching order"}
            def _hrow(h):
                status = h.get("status") or ""
                label = _status_label.get(status, status or "&mdash;")
                pill = f'<span class=pill style="border-color:{_badge.get(status, "#c9c0ad")}">{label}</span>'
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
                cont_cell = h.get("containers", "")
                if unresolved:
                    cont_cell += f' <span class=pill style="border-color:#b06a5a;color:#b06a5a">&#9888; unresolved: {", ".join(unresolved)}</span>'
                # Which Acumatica identity actually performed this write (not the app-level
                # "By" caller/source tag) -- flag red if it doesn't match EXPECTED_ACU_USER, so
                # segregation-of-duties drift shows up per-run in the permanent log, not only
                # in the live banner (which only reflects whoever is connected RIGHT NOW).
                acu_user = h.get("acumatica_user") or ""
                exp = os.environ.get("EXPECTED_ACU_USER", "").strip()
                if not acu_user:
                    acu_cell = '<span class=pill style="border-color:#c9c0ad">unknown</span>'
                elif exp and exp.lower() not in acu_user.lower():
                    acu_cell = f'<span class=pill style="border-color:#b06a5a;color:#b06a5a">&#9888; {acu_user}</span>'
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
            body = ('<div class=card><h1 style="font-size:16px">Run history</h1>'
                    '<p class=sub>Every shipment-creation run, kept permanently on the tool&#39;s disk (not just this session). '
                    'Times are Pacific. Expand the last column for per-order/shipment detail. &#8220;Acumatica user&#8221; is who was '
                    'actually connected when the write ran (set <code>EXPECTED_ACU_USER</code> to flag any run under a different account).</p>'
                    '<div class=twrap><table><tr><th>Received</th><th>Triggered by</th><th>Acumatica user</th><th>Source</th><th>Status</th>'
                    '<th>Created/Matched</th><th>Containers</th><th>Master PO(s)</th><th>Orders</th></tr>' + rows + '</table></div></div>')
            return self._send(200, page(body))
        return self._send(404, page("<div class=card>Not found</div>"))

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
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
            if not container:
                return self._send(400, json.dumps({"error": "container is required"}), "application/json")
            try:
                out = process_manual(container, ship_date, pos=pos, source=source, dry_run=dry)
                return self._send(200, json.dumps(out), "application/json")
            except Exception as e:
                return self._send(200, json.dumps({"error": str(e)}), "application/json")
        if u.path == "/ledger/recheck":
            # Cron-triggered (e.g. daily, alongside the digest). Without this, a master
            # whose LAST container's pickup email fires before its receipt posts in
            # Acumatica has no future NRT event to re-trigger it -- it would sit "waiting"
            # forever even after the PO genuinely becomes complete. Re-runs the exact same
            # completeness gate process_manual already uses (picking any one of the
            # master's recorded containers is enough -- containers_completeness() checks
            # the underlying PO, not just that one container). Same write stakes as
            # /autoship, same token.
            want = AUTOSHIP_TOKEN
            got = (self.headers.get("Authorization", "") or "").removeprefix("Bearer ").strip()
            if not (want and hmac.compare_digest(got.encode(), want.encode())):
                return self._send(403, json.dumps({"error": "auth required"}), "application/json")
            ledger = load_json(LEDGER_PATH) or {}
            results = []
            # Acumatica's license caps this at 100 web-service API requests/minute
            # (confirmed via the License Monitoring Console). process_manual costs a
            # few calls per master (receipt/PO resolution, completeness, possibly a
            # shipment create) -- looping tight over 20-30+ active masters with no
            # pacing could burst past that cap in well under a minute. Paced well
            # below the limit, not right up against it.
            first = True
            for token, entry in ledger.items():
                if entry.get("status") not in ("waiting", "partial"):
                    continue
                containers = list(entry.get("containers", {}).keys())
                if not containers:
                    continue
                if not first:
                    time.sleep(2.5)
                first = False
                latest = ledger_latest_date(token)
                try:
                    out = process_manual(containers[-1], latest, source="ledger-recheck", dry_run=False)
                except Exception as e:
                    out = {"error": str(e)}
                results.append({"master": token, "container_used": containers[-1], "result": out})
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
        if u.path == "/process":
            ctype = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in ctype or "boundary=" not in ctype:
                return self._send(400, json.dumps({"error": "expected upload"}), "application/json")
            boundary = ctype.split("boundary=", 1)[1].strip().strip('"').encode()
            ln = int(self.headers.get("Content-Length", 0))
            fields = parse_multipart(self.rfile.read(ln), boundary)
            filedata = fields.get("pdf")
            orig_name = fields.get("_fn_pdf") or None
            dry = (fields.get("dry") or "1") == "1"
            sd = (fields.get("sd") or "") or None
            if not filedata:
                return self._send(400, json.dumps({"error": "no file"}), "application/json")
            # Hard stop before we even write the temp file: no typed ship date, no creation.
            if not dry and not sd:
                return self._send(200, json.dumps({"error": "Shipment date is required. Enter the NRT pickup date before creating shipments."}), "application/json")
            tmp = os.path.join(TOKEN_DIR, "_ship_upload_%s.pdf" % secrets.token_hex(8))
            with open(tmp, "wb") as f:
                f.write(filedata if isinstance(filedata, bytes) else filedata.encode())
            try:
                out = process_file(tmp, dry_run=dry, ship_date=sd, user=session_user(self._cookie()), source_name=orig_name)
                return self._send(200, json.dumps(out), "application/json")
            except Exception as e:
                return self._send(200, json.dumps({"error": str(e)}), "application/json")
            finally:
                try:
                    os.remove(tmp)
                except Exception:
                    pass
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
