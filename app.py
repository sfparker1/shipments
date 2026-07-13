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
         "scope": "api offline_access", "code_challenge": challenge,
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
            for n in re.findall(r"\b(\d{6})\b", r.get("vendor_ref") or ""):
                pos.add(n)
    return {c: sorted(by_container.get(c, [])) for c in containers}

def container_multi_flags(containers):
    """For each queried container, True if it appears on a PO Receipt that also lists
    OTHER containers. A multi-container receipt means picking up one container doesn't
    imply the whole PO/SO is available to ship -- the NRT auto-ship path refuses these
    and flags for a human (the ~3% split case) rather than shipping items still afloat."""
    receipts = load_recent_receipts()
    flags = {}
    for c in [x.strip().upper() for x in containers if x]:
        flags[c] = any(c in r["containers"] and len(r["containers"]) > 1 for r in receipts)
    return flags

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

def _co_matches_master(cust_order, master):
    if cust_order == master:
        return True  # e.g. an order with no DC prefix (Costco)
    if cust_order.endswith(master):
        prefix = cust_order[:-len(master)]
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
def _latest_shipment_for_order(order_nbr):
    st, data = api("GET", f"{ENTITY}/Shipment?$filter=substringof('{order_nbr}',OrderNbr) eq true&$select=ShipmentNbr&$top=1&$orderby=ShipmentNbr desc")
    if st == 200 and isinstance(data, list) and data:
        return (data[0].get("ShipmentNbr") or {}).get("value")
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

def create_shipment(order_type, order_nbr, container_ref=None, ship_date=None, po=None):
    # ship_date is required by the caller (process_file hard-stops before this
    # point if it's missing) -- no more silent fallback to a synced date or to
    # "today". po is accepted for logging only.
    date = ship_date
    params = {}
    if date: params["ShipmentDate"] = {"value": date}
    if CFG["warehouse"]: params["WarehouseID"] = {"value": CFG["warehouse"]}
    body = {"entity": {"OrderType": {"value": order_type}, "OrderNbr": {"value": order_nbr}}, "parameters": params}
    st, resp = api("POST", f"{ENTITY}/SalesOrder/CreateShipment", body)
    res = {"order": f"{order_type} {order_nbr}", "invoke_status": st, "created": st in (200, 202, 204), "ship_date": date}
    if res["created"]:
        ship = _latest_shipment_for_order(order_nbr)
        res["shipment_nbr"] = ship
        if ship and container_ref and CFG["container_field"]:
            api("PUT", f"{ENTITY}/Shipment/{ship}",
                {"custom": {"Document": {CFG["container_field"]: {"type": "CustomStringField", "value": container_ref}}}})
        res["verified"] = bool(ship)
    else:
        res["error"] = resp if isinstance(resp, str) else json.dumps(resp)[:300]
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
        "last_decision_at": all_rows[0].get("ts") if all_rows else None,
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

def _agent_log_html(rows, exc_only):
    """Scannable decision table -- one row per decision, exceptions highlighted. Matches
    the low-tooling HTML style used by /history."""
    def esc(v):
        s = "" if v is None else str(v)
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    _mode = {"shadow": "#7d7363", "live": "#5a7d5a"}
    def _row(r):
        flagged = bool(r.get("exception_flag"))
        rowstyle = ' style="background:#f6ece8"' if flagged else ""
        mode = r.get("mode") or ""
        mode_pill = f'<span class=pill style="border-color:{_mode.get(mode, "#c9c0ad")}">{esc(mode) or "&mdash;"}</span>'
        cls = esc(r.get("classification") or "")
        action = esc(r.get("action_taken") or "&mdash;")
        args = r.get("tool_args")
        result = r.get("tool_result")
        detail = ""
        if args is not None or result is not None:
            detail = (f"<details><summary>args/result</summary>"
                      f"<div><b>args:</b> {esc(json.dumps(args))}</div>"
                      f"<div><b>result:</b> {esc(json.dumps(result))}</div></details>")
        note = esc(r.get("rationale") or "")
        if flagged:
            note = (f'<span style="color:#b06a5a">&#9888; {esc(r.get("exception_reason") or "exception")}</span>'
                    f'<br>{note}' if note else
                    f'<span style="color:#b06a5a">&#9888; {esc(r.get("exception_reason") or "exception")}</span>')
        subj = esc(r.get("subject") or "")
        if len(subj) > 60:
            subj = subj[:60] + "&hellip;"
        return (f"<tr{rowstyle}><td>{esc(r.get('ts',''))}</td>"
                f"<td>{esc(r.get('source_mailbox') or '')}</td>"
                f"<td title=\"{esc(r.get('message_id') or '')}\">{subj}</td>"
                f"<td>{cls}</td><td>{action}</td><td>{mode_pill}</td>"
                f"<td>{note}</td><td>{detail}</td></tr>")
    body_rows = "".join(_row(r) for r in rows)
    title = "Agent decisions" + (" &mdash; exceptions only" if exc_only else "")
    toggle = ('<a class=pill href="/agent/log">all</a> '
              '<a class=pill href="/agent/log?exceptions_only=1">exceptions only</a>')
    return ('<div class=card><h1 style="font-size:16px">%s</h1>'
            '<p class=sub>One row per decision the mailbox-agent made (not per LLM turn). '
            'Flagged rows are highlighted. %s</p>'
            '<table><tr><th>When</th><th>Mailbox</th><th>Subject</th><th>Class</th>'
            '<th>Action</th><th>Mode</th><th>Rationale / exception</th><th>Detail</th></tr>'
            '%s</table></div>') % (title, toggle, body_rows or
            '<tr><td colspan=8 class=sub>No decisions logged yet.</td></tr>')

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
                 "user": user, "status": status, "orders_matched": to_create, "created": created,
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
        # NRT path: refuse to auto-create when the container's PO Receipt also covers
        # OTHER containers. Picking up one container of a multi-container receipt doesn't
        # mean the whole PO/SO is available to ship -- surface it for a clerk instead of
        # shipping goods that may still be afloat. Authoritative here (not just in the
        # agent) so the guard can't be bypassed.
        if not dry_run and container_multi_flags([container]).get(container):
            return {"container": container, "needs_review": True, "created": 0, "orders_matched": 0,
                    "reason": "multi_container_receipt",
                    "note": "container shares a PO Receipt with other containers; a clerk should "
                            "confirm which orders are actually available before shipping"}
        resolved = containers_to_pos([container]).get(container, [])
        all_pos = resolved
        unresolved = not resolved

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
                res = create_shipment(m["order_type"], m["order_nbr"], container, ship_date, po=po)
                row["result"] = res
                if res.get("created"): created += 1
                log_orders.append({"po": po, "order": f"{m['order_type']} {m['order_nbr']}".strip(),
                                    "shipment_nbr": res.get("shipment_nbr"), "created": res.get("created"),
                                    "ship_date": res.get("ship_date"), "reason": res.get("reason") or res.get("error")})
            rows.append(row)

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
                 "user": user or f"auto:{source or 'unknown'}", "status": status,
                 "orders_matched": to_create, "created": created, "containers": container,
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

def diagnostics(sample_po=None, sample_container=None, sample_receipt=None):
    out = {"connected": bool(access_token()), "tenant": CFG["tenant"],
           "container_field": CFG["container_field"] or "(not set)", "warehouse": CFG["warehouse"] or "(SO default)"}
    if not out["connected"]: return out
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
<div class=brand>SAND + FOG</div><h1>Handover &#8594; Shipments</h1>
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
        else:
            label = ("Connected as %s" % u) if u else "Connected to Acumatica"
            badge = ('<span class=pill style="border-color:#5a7d5a">%s</span>'
                     ' <a class=pill href=/connect>Switch account</a>' % label)
    else:
        badge = '<a class=pill href=/connect>Connect to Acumatica</a>'
    return """<!doctype html><meta charset=utf-8><title>Handover &#8594; Shipments</title>%s<style>%s</style>
<div class=wrap><div class=brand>SAND + FOG</div><h1>Handover Advice &#8594; Acumatica Shipments</h1>
<p class=sub>%s &nbsp; <a class=pill href=/>Home</a> <a class=pill href=/guide>Guide</a> <a class=pill href=/history>History</a> <a class=pill href=/diag>Diagnostics</a></p>
%s</div>""" % (favicon, CSS, badge, body)

HOME = """<div class=card>
<h1 style="font-size:18px">Create shipments from a handover advice</h1>
<p class=sub>Drop a Dachser handover-advice PDF. Preview the matched sales orders, then create shipments (left unconfirmed for a person to confirm in Acumatica).</p>
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
<p class=sub>It turns a Dachser handover advice into shipment records in Acumatica &mdash; with a person always in control of the revenue step.</p>
<ol style="line-height:1.75;font-size:14px;padding-left:20px">
<li><b>Connect as the shipments account.</b> Click <b>Switch account</b> (top) and sign in with the dedicated Acumatica login &mdash; not a personal one. The banner shows who&#39;s connected.</li>
<li><b>Drop the handover advice.</b> On <b>Home</b>, choose the Dachser handover-advice PDF and click <b>Preview</b>.</li>
<li><b>Review the matches.</b> Most containers don&#39;t list PO#s in the advice text itself, so the tool also resolves each container&#39;s POs via Acumatica PO Receipts (container &rarr; receipt &rarr; internal PO &rarr; VendorRef &rarr; retail PO#). If a container can&#39;t be resolved either way, it&#39;s flagged in red &mdash; check it manually (e.g. against the packing list) before creating.</li>
<li><b>Type the Shipment date, then create.</b> Enter the NRT pickup date in <b>Shipment date</b> (required) and click <b>Create shipments</b>. Each is created <b>unconfirmed</b>, dated as typed.</li>
<li><b>Confirm &amp; invoice in Acumatica.</b> A person confirms each shipment (this recognizes revenue), then creates and releases the invoice. <b>This tool never confirms</b> &mdash; that stays a human decision.</li>
</ol>
<p class=sub>If a line can&#39;t be created, the Result column explains why (e.g. nothing available to ship, order on hold). <a href=/history>History</a> lists past runs and who ran them.</p>
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
            return self._send(200, page(HOME))
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
        if u.path == "/history":
            _badge = {"ok": "#5a7d5a", "partial": "#b0653a", "failed": "#b06a5a", "no_matches": "#7d7363"}
            def _hrow(h):
                status = h.get("status") or ""
                pill = f'<span class=pill style="border-color:{_badge.get(status, "#c9c0ad")}">{status or "&mdash;"}</span>'
                orders = h.get("orders") or []
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
                return (f"<tr><td>{h.get('ts','')}</td><td>{h.get('user','') or ''}</td>"
                        f"<td>{h.get('document','') or ''}</td><td>{h.get('reference','')}</td>"
                        f"<td>{pill}</td><td>{h.get('created','')}/{h.get('orders_matched','')}</td>"
                        f"<td>{cont_cell}</td><td>{detail_cell}</td></tr>")
            rows = "".join(_hrow(h) for h in history())
            body = ('<div class=card><h1 style="font-size:16px">Run history</h1>'
                    '<p class=sub>Every shipment-creation run, kept permanently on the tool&#39;s disk (not just this session). '
                    'Expand the last column for per-order/shipment detail.</p>'
                    '<table><tr><th>When</th><th>By</th><th>Document</th><th>Reference</th><th>Status</th>'
                    '<th>Created/Matched</th><th>Containers</th><th>Orders</th></tr>' + rows + '</table></div>')
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
