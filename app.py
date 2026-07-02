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
"""
import os, re, json, time, base64, hashlib, hmac, secrets
import urllib.parse, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import pdfplumber
except ImportError:
    pdfplumber = None

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
PORT = int(cfg("PORT", cfg("WEBSITES_PORT", "8400")))
TOKEN_DIR = cfg("TOKEN_DIR", HERE)
TOKEN_PATH = os.path.join(TOKEN_DIR, "ship_token.json")
PKCE_PATH = os.path.join(TOKEN_DIR, "ship_pkce.json")
RUNS_PATH = os.path.join(TOKEN_DIR, "ship_runs.jsonl")
REDIRECT_URI = CFG["public_url"] + "/callback"
COOKIE_SECRET = (CFG["app_password"] or "dev").encode() + b"::ship"
SESSIONS = {}
_PKCE = {}   # in-memory PKCE state (primary); disk is a backup
ENTITY = f"/entity/Default/{CFG['api_version']}"

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

def parse_multipart(body, boundary):
    """Minimal multipart/form-data parser (replaces the removed stdlib `cgi`).
    Returns {name: bytes} for file parts and {name: str} for text parts."""
    fields = {}
    for part in body.split(b"--" + boundary):
        if not part or part.strip() in (b"", b"--"): continue
        if b"\r\n\r\n" not in part: continue
        head, data = part.split(b"\r\n\r\n", 1)
        head_s = head.decode("utf-8", "ignore")
        m = re.search(r'name="([^"]+)"', head_s)
        if not m: continue
        if data.endswith(b"\r\n"): data = data[:-2]
        fields[m.group(1)] = data if 'filename="' in head_s else data.decode("utf-8", "ignore")
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
         "code_challenge_method": "S256", "state": state}
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

def exchange_code(code):
    pk = _PKCE if _PKCE.get("verifier") else (load_json(PKCE_PATH) or {})
    tok = _token_request({"grant_type": "authorization_code", "code": code,
                          "redirect_uri": REDIRECT_URI, "client_id": CFG["client_id"],
                          "client_secret": CFG["client_secret"], "code_verifier": pk.get("verifier", "")})
    tok["obtained"] = time.time(); save_json(TOKEN_PATH, tok); return tok

def refresh_token(tok):
    new = _token_request({"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                          "client_id": CFG["client_id"], "client_secret": CFG["client_secret"]})
    new["obtained"] = time.time()
    new.setdefault("refresh_token", tok["refresh_token"]); save_json(TOKEN_PATH, new); return new

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
    ref = None; ports = []; dates = []; containers = {}; pos = []
    with pdfplumber.open(path) as pdf:
        full = ""
        for pg in pdf.pages:
            full += (pg.extract_text() or "") + "\n"
            for t in pg.extract_tables():
                if not t or not t[0]: continue
                hdr = t[0]
                if any((c or "") == "Container No" for c in hdr) and any((c or "") == "Marks" for c in hdr):
                    ci = [i for i, c in enumerate(hdr) if (c or "") == "Container No"][0]
                    mi = [i for i, c in enumerate(hdr) if (c or "") == "Marks"][0]
                    dd = [i for i, c in enumerate(hdr) if (c or "") == "Description of Goods"]
                    di = dd[0] if dd else None
                    for row in t[1:]:
                        cont = (row[ci].strip() if ci < len(row) and row[ci] else "")
                        if not re.match(r"^[A-Z]{4}\d{7}$", cont): continue
                        containers.setdefault(cont, None)
                        if mi < len(row) and row[mi]:
                            for ln in row[mi].split("\n"):
                                s = ln.strip().rstrip(",").strip()
                                if not s or any(k in s.upper() for k in _SKIP_MARK): continue
                                if re.match(r"^[A-Za-z]{0,3}\d{5,9}$", s) and s not in pos: pos.append(s)
                        if di is not None and di < len(row) and row[di] and "PO#" in row[di]:
                            for blk in re.findall(r"PO#\s*(.*?)(?:Q'ty|HS code|In Gate|Total NW|$)", row[di], re.DOTALL):
                                for n in re.findall(r"\b(\d{6})\b", blk):
                                    if n not in pos: pos.append(n)
        for c, p, w in re.findall(r"\b([A-Z]{4}\d{7})\b\s+\d+\s+([\d,]+)\s+([\d,\.]+)", full):
            containers.setdefault(c, None); containers[c] = int(p.replace(",", ""))
        m = re.search(r"\b(\d{11})\b", full); ref = m.group(1) if m else None
        for p in re.findall(r"\b([A-Z]{2}\s[A-Z]{3})\b", full):
            if p not in ports: ports.append(p)
        for d in re.findall(r"\b(20\d\d-\d\d-\d\d)\b", full):
            if d not in dates: dates.append(d)
    return {"dachser_reference": ref, "pol": ports[0] if ports else None,
            "pod": ports[1] if len(ports) > 1 else None, "eta": dates[-1] if dates else None,
            "containers": [{"container": c, "pieces": containers[c]} for c in containers],
            "po_numbers": pos}

# ---------------- matching ----------------
def find_sales_orders(po):
    flt = f"substringof('{po}', CustomerOrderNbr) eq true and Status eq 'Open'"
    q = f"{ENTITY}/SalesOrder?$filter={flt}&$select=OrderType,OrderNbr,CustomerOrderNbr,Status,CustomerID"
    st, data = api("GET", q)
    matches = []
    if st == 200 and isinstance(data, list):
        for so in data:
            g = lambda k: (so.get(k) or {}).get("value")
            matches.append({"order_type": g("OrderType"), "order_nbr": g("OrderNbr"),
                            "cust_order": g("CustomerOrderNbr"), "customer": g("CustomerID"),
                            "status": g("Status")})
    return matches, st, data

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
         f"&$select=OrderType,OrderNbr,CustomerOrderNbr,CustomerID,Status")
    st, data = api("GET", q)
    if st == 200 and isinstance(data, list):
        for so in data:
            g = lambda k: (so.get(k) or {}).get("value")
            rows.append({"order_type": g("OrderType"), "order_nbr": g("OrderNbr"),
                         "cust_order": g("CustomerOrderNbr") or "", "customer": g("CustomerID"),
                         "status": g("Status")})
        _OPEN_ORDERS["rows"] = rows
        _OPEN_ORDERS["ts"] = now
    return rows

def find_sales_orders_batch(pos):
    """Match every PO# against the cached open-order list locally (instant)."""
    orders = load_open_orders()
    results = {p: [] for p in pos}
    for o in orders:
        co = o["cust_order"]
        if not co:
            continue
        for p in pos:
            if p in co:
                results[p].append(o)
    return results

# ---------------- shipment creation (validate via /diag first) ----------------
def _latest_shipment_for_order(order_nbr):
    st, data = api("GET", f"{ENTITY}/Shipment?$filter=substringof('{order_nbr}',OrderNbr) eq true&$select=ShipmentNbr&$top=1&$orderby=ShipmentNbr desc")
    if st == 200 and isinstance(data, list) and data:
        return (data[0].get("ShipmentNbr") or {}).get("value")
    return None

def create_shipment(order_type, order_nbr, container_ref=None, ship_date=None):
    params = {}
    if ship_date: params["ShipmentDate"] = {"value": ship_date}
    if CFG["warehouse"]: params["WarehouseID"] = {"value": CFG["warehouse"]}
    body = {"entity": {"OrderType": {"value": order_type}, "OrderNbr": {"value": order_nbr}}, "parameters": params}
    st, resp = api("POST", f"{ENTITY}/SalesOrder/CreateShipment", body)
    res = {"order": f"{order_type} {order_nbr}", "invoke_status": st, "created": st in (200, 202, 204)}
    if res["created"]:
        ship = _latest_shipment_for_order(order_nbr)
        res["shipment_nbr"] = ship
        if ship and container_ref and CFG["container_field"]:
            api("PUT", f"{ENTITY}/Shipment/{ship}",
                {"custom": {"Document": {CFG["container_field"]: {"type": "CustomStringField", "value": container_ref}}}})
        res["verified"] = bool(ship)
    else:
        res["error"] = resp if isinstance(resp, str) else json.dumps(resp)[:300]
    return res

# ---------------- run log ----------------
def log_run(entry):
    try:
        os.makedirs(TOKEN_DIR, exist_ok=True)
        entry["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(RUNS_PATH, "a") as f: f.write(json.dumps(entry) + "\n")
    except Exception: pass

def history():
    out = []
    try:
        with open(RUNS_PATH) as f:
            out = [json.loads(l) for l in f if l.strip()]
    except Exception: pass
    return list(reversed(out))[:50]

# ---------------- process a handover PDF ----------------
def process_file(path, dry_run=True, ship_date=None):
    parsed = parse_handover(path)
    containers = [c["container"] for c in parsed["containers"]]
    container_ref = ", ".join(containers)
    matched = find_sales_orders_batch(parsed["po_numbers"])
    rows = []; to_create = 0; created = 0
    for po in parsed["po_numbers"]:
        matches = matched.get(po, [])
        if not matches:
            rows.append({"po": po, "confidence": "flag", "note": "no open sales order", "orders": []})
            continue
        for m in matches:
            to_create += 1
            row = {"po": po, "confidence": "ok", "orders": [m], "note": ""}
            if not dry_run:
                res = create_shipment(m["order_type"], m["order_nbr"], container_ref, ship_date)
                row["result"] = res
                if res.get("created"): created += 1
            rows.append(row)
    summary = {"dachser_reference": parsed["dachser_reference"],
               "route": f'{parsed["pol"]} -> {parsed["pod"]}', "eta": parsed["eta"],
               "containers": containers, "po_count": len(parsed["po_numbers"]),
               "orders_matched": to_create, "created": created, "dry_run": dry_run, "rows": rows}
    if not dry_run:
        log_run({"reference": parsed["dachser_reference"], "orders_matched": to_create,
                 "created": created, "containers": container_ref})
    return summary

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

def diagnostics(sample_po=None):
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
    return out

# ================= Web UI =================
def make_session():
    tok = secrets.token_hex(16)
    sig = hmac.new(COOKIE_SECRET, tok.encode(), hashlib.sha256).hexdigest()[:16]
    SESSIONS[tok] = True
    return f"{tok}.{sig}"

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

LOGIN = """<!doctype html><meta charset=utf-8><title>Sign in</title><style>%s
.box{max-width:340px;margin:12vh auto}</style><div class=wrap><div class="card box">
<div class=brand>SAND + FOG</div><h1>Handover &#8594; Shipments</h1>
<form method=post action=/login><p><input type=password name=pw placeholder="Password" autofocus></p>
<button>Sign in</button></form></div></div>""" % CSS

def page(body):
    connected = bool(access_token())
    badge = ('<span class=pill style="border-color:#5a7d5a">Connected to Acumatica</span>'
             if connected else '<a class=pill href=/connect>Connect to Acumatica</a>')
    return """<!doctype html><meta charset=utf-8><title>Handover &#8594; Shipments</title><style>%s</style>
<div class=wrap><div class=brand>SAND + FOG</div><h1>Handover Advice &#8594; Acumatica Shipments</h1>
<p class=sub>%s &nbsp; <a class=pill href=/>Home</a> <a class=pill href=/history>History</a> <a class=pill href=/diag>Diagnostics</a></p>
%s</div>""" % (CSS, badge, body)

HOME = """<div class=card>
<h1 style="font-size:18px">Create shipments from a handover advice</h1>
<p class=sub>Drop a Dachser handover-advice PDF. Preview the matched sales orders, then create shipments (left unconfirmed for a person to confirm in Acumatica).</p>
<form id=f onsubmit="return false">
<p><input type=file id=pdf accept="application/pdf"></p>
<p style="max-width:240px"><label class=sub>Shipment date (optional)</label><input type=date id=sd></p>
<button class=fog onclick="go(true)">Preview</button>
<button onclick="go(false)" id=create disabled>Create shipments</button>
</form></div>
<div id=out></div>
<script>
let last=null;
async function go(dry){
 const f=document.getElementById('pdf').files[0]; if(!f){alert('Choose a PDF');return;}
 const fd=new FormData(); fd.append('pdf',f); fd.append('dry',dry?'1':'0'); fd.append('sd',document.getElementById('sd').value);
 document.getElementById('out').innerHTML='<div class=card>Working...</div>';
 const r=await fetch('/process',{method:'POST',body:fd}); const d=await r.json(); render(d,dry);
}
function render(d,dry){
 if(d.error){document.getElementById('out').innerHTML='<div class=card>Error: '+d.error+'</div>';return;}
 let h='<div class=card><h1 style="font-size:16px">'+(dry?'Preview':'Result')+' &mdash; ref '+(d.dachser_reference||'?')+'</h1>';
 h+='<p class=sub>'+d.route+' &nbsp; ETA '+(d.eta||'?')+'</p>';
 h+='<p>'+d.containers.map(c=>'<span class=pill>'+c+'</span>').join('')+'</p>';
 h+='<p class=sub>'+d.po_count+' PO#s parsed &middot; '+d.orders_matched+' open sales orders matched'+(dry?'':' &middot; '+d.created+' shipments created')+'</p>';
 h+='<table><tr><th></th><th>PO#</th><th>Sales order</th><th>Customer</th><th>Result</th></tr>';
 for(const row of d.rows){
   const dot='<span class="dot '+(row.confidence=='ok'?'ok':'flag')+'"></span>';
   if(!row.orders.length){h+='<tr>'+td(dot)+td(row.po)+td('&mdash;')+td('&mdash;')+td(row.note)+'</tr>';continue;}
   for(const o of row.orders){
     let res=row.note||'';
     if(row.result){res=row.result.created?('&#10003; '+(row.result.shipment_nbr||'created')):('&#9888; '+(row.result.error||'failed'));}
     h+='<tr>'+td(dot)+td(row.po)+td((o.order_type||'')+' '+(o.order_nbr||''))+td(o.customer||'')+td(res)+'</tr>';
   }
 }
 h+='</table></div>';
 document.getElementById('out').innerHTML=h;
 document.getElementById('create').disabled = !(dry && d.orders_matched>0);
}
function td(x){return '<td>'+x+'</td>';}
</script>"""

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
            if not want or qs.get("token", [""])[0] != want:
                return self._send(403, json.dumps({"error": "bad token"}), "application/json")
            pos = [p.strip() for p in qs.get("pos", [""])[0].split(",") if p.strip()][:250]
            out = {p: so_pipeline(p) for p in pos}
            return self._send(200, json.dumps(out), "application/json")
        if not self._authed():
            return self._send(200, LOGIN)
        if u.path == "/":
            return self._send(200, page(HOME))
        if u.path == "/connect":
            self.send_response(302); self.send_header("Location", build_authorize_url()); self.end_headers(); return
        if u.path == "/diag":
            qs = urllib.parse.parse_qs(u.query)
            d = diagnostics(qs.get("po", [None])[0])
            body = ('<div class=card><h1 style="font-size:16px">Diagnostics</h1>'
                    '<form method=get action=/diag><p style="max-width:260px"><input type=text name=po placeholder="test a PO# e.g. 117256"></p>'
                    '<button class=fog>Run</button></form><pre>' + json.dumps(d, indent=2) + "</pre></div>")
            return self._send(200, page(body))
        if u.path == "/history":
            rows = "".join(f"<tr><td>{h.get('ts','')}</td><td>{h.get('reference','')}</td><td>{h.get('created','')}/{h.get('orders_matched','')}</td><td>{h.get('containers','')}</td></tr>" for h in history())
            body = f'<div class=card><h1 style="font-size:16px">Run history</h1><table><tr><th>When</th><th>Reference</th><th>Created/Matched</th><th>Containers</th></tr>{rows}</table></div>'
            return self._send(200, page(body))
        return self._send(404, page("<div class=card>Not found</div>"))

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/login":
            ln = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(ln).decode())
            pw = data.get("pw", [""])[0]
            if CFG["app_password"] and hmac.compare_digest(pw, CFG["app_password"]):
                return self._send(302, "", cookie=make_session()) if False else self._redirect_with_cookie(make_session())
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
            dry = (fields.get("dry") or "1") == "1"
            sd = (fields.get("sd") or "") or None
            if not filedata:
                return self._send(400, json.dumps({"error": "no file"}), "application/json")
            tmp = os.path.join(TOKEN_DIR, "_ship_upload.pdf")
            with open(tmp, "wb") as f:
                f.write(filedata if isinstance(filedata, bytes) else filedata.encode())
            try:
                out = process_file(tmp, dry_run=dry, ship_date=sd)
                return self._send(200, json.dumps(out), "application/json")
            except Exception as e:
                return self._send(200, json.dumps({"error": str(e)}), "application/json")
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
