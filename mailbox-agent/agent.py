#!/usr/bin/env python3
"""
Mailbox Agent -- Phase C of the container-pickup automation.

A genuine LLM agent (Claude, via the Messages API with a manual tool-use loop)
that drains the /ingest queue on the `handover-shipments` service, reasons about
each NRT / FCR email, and PREPARES the corresponding Acumatica-adjacent action by
calling the same narrow, already-scoped endpoints a person or the deterministic
pipeline would. It never touches Acumatica directly and never releases anything
-- shipments are created On Hold / unconfirmed, a clerk confirms in Acumatica.

Why a manual tool-use loop (not the Agent SDK / Managed Agents): this is a
constrained decision agent feeding a financial pipeline. It must log every
decision in a human-reviewable way and support a shadow mode that intercepts the
write tools -- exactly the "approval gates / custom logging / conditional
execution" case the Claude API docs point at the manual loop for. Model:
claude-opus-4-8, adaptive thinking.

Runtime: a Render Cron Job (scheduled start -> drain queue -> exit), NOT an
always-on worker. Power Automate pushes emails into the queue; this drains it on
a schedule, so if the agent is down or mid-run, items just wait in the queue.

Deploy note: this is a SEPARATE Render service from handover-shipments (different
failure domain -- an agent bug must not redeploy the proven Acumatica service).
It lives in this repo only as a subdirectory; point a second Render service at
`mailbox-agent/` as its root, or split it to its own repo later. It talks to the
shipments service purely over HTTPS.

Dependency: the /ingest, /ingest/list, /ingest/delete, and /agent/log endpoints
this calls live on the `feature/agent-log` branch of the shipments service --
that must be merged and deployed (with AGENT_TOKEN / INGEST_TOKEN set) before
this agent works end to end.

Config (env vars):
    SHIPMENTS_BASE_URL   e.g. https://shipments-ynyx.onrender.com
    AGENT_TOKEN          bearer token for /agent/log, /ingest/list, /ingest/delete
    AUTOSHIP_TOKEN       bearer token for /autoship (create shipment on Hold)
    FCR_TOKEN            bearer token for /parsefcr (defaults to AGENT_TOKEN if unset)
    MAERSK_TOKEN         bearer token for /watchlist/add (defaults to AGENT_TOKEN if unset)
    ANTHROPIC_API_KEY    Claude API key
    SHADOW_MODE          "1" (default) = intercept the write tools, log what WOULD
                         have happened, create nothing. Flip to "0" to go live.
                         Keep this flag permanently -- re-use it after prompt/tool changes.
    MODEL                default "claude-opus-4-8"
    MAX_ITEMS_PER_RUN    safety cap on items processed per run (default 50)
"""
import os, re, json, base64, html, time
import urllib.request, urllib.error

import anthropic

# ---------------- config ----------------
BASE = os.environ.get("SHIPMENTS_BASE_URL", "").rstrip("/")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
AUTOSHIP_TOKEN = os.environ.get("AUTOSHIP_TOKEN", "")
FCR_TOKEN = os.environ.get("FCR_TOKEN", "") or AGENT_TOKEN
MAERSK_TOKEN = os.environ.get("MAERSK_TOKEN", "") or AGENT_TOKEN
SHADOW_MODE = os.environ.get("SHADOW_MODE", "1") != "0"
MODEL = os.environ.get("MODEL", "claude-opus-4-8")
MAX_ITEMS_PER_RUN = int(os.environ.get("MAX_ITEMS_PER_RUN", "50"))

def _require(name, val):
    if not val:
        raise SystemExit(f"ERROR: {name} is required (set the env var).")

# ---------------- HTTP to the shipments service ----------------
def _http(method, path, token, body=None, multipart=None, timeout=120):
    url = BASE + path
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data = None
    if multipart is not None:
        boundary = "----mailboxagent" + base64.urlsafe_b64encode(os.urandom(9)).decode()
        parts = []
        fname, content = multipart
        parts.append(("--" + boundary).encode())
        parts.append((f'Content-Disposition: form-data; name="pdf"; filename="{fname}"').encode())
        parts.append(b"Content-Type: application/pdf")
        parts.append(b"")
        parts.append(content)
        parts.append(("--" + boundary + "--").encode())
        data = b"\r\n".join(parts)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return 0, {"error": str(e)}

def queue_list():
    st, data = _http("GET", f"/ingest/list?token={AGENT_TOKEN}", AGENT_TOKEN)
    return data if st == 200 and isinstance(data, list) else []

def queue_delete(item_id):
    _http("POST", "/ingest/delete", AGENT_TOKEN, body={"id": item_id})

def already_processed(message_id):
    """Idempotency: has a decision already been logged for this source email?
    (Also backstopped at the Acumatica layer -- /autoship's CreateShipment fails
    with 'a shipment already exists' rather than double-creating.)"""
    if not message_id:
        return False
    from urllib.parse import quote
    st, data = _http("GET", f"/agent/log?token={AGENT_TOKEN}&message_id={quote(message_id)}", AGENT_TOKEN)
    return st == 200 and isinstance(data, list) and len(data) > 0

# ---------------- helpers ----------------
def strip_html(body):
    """NRT emails are HTML; the status ('Available for Pickup'), container #, and
    customer name are in the markup. Crude tag-strip to text keeps the signal and
    cuts tokens -- Claude reads the result fine."""
    if not body:
        return ""
    b = re.sub(r"(?is)<(script|style).*?</\1>", " ", body)
    b = re.sub(r"(?s)<[^>]+>", " ", b)
    b = html.unescape(b)
    b = re.sub(r"[ \t]+", " ", b)
    b = re.sub(r"\n\s*\n\s*\n+", "\n\n", b)
    return b.strip()

def first_pdf(item):
    for att in item.get("attachments") or []:
        name = (att.get("name") or "").lower()
        if name.endswith(".pdf") and att.get("content_b64"):
            return att["name"], base64.b64decode(att["content_b64"])
    return None, None

# ---------------- tool definitions (the agent's action surface) ----------------
# These are the ONLY side-effectful things the agent can do -- each maps to an
# already-scoped endpoint. parse_fcr is read-only; create_shipment and
# add_to_watchlist are the writes intercepted in shadow mode; finish records the
# decision and ends the loop.
TOOLS = [
    {
        "name": "parse_fcr",
        "description": "Extract container number, PO numbers, and Port of Loading from the "
                       "PDF attachment on the current email (a Forwarder's Cargo Receipt). "
                       "Read-only -- makes no Acumatica changes. Use this for FCR emails before "
                       "add_to_watchlist. Returns {container, pos, port_of_loading, receipt_no, vessel}.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "create_shipment",
        "description": "Create an UNCONFIRMED (On Hold) Acumatica shipment for the given container. "
                       "Use ONLY for NRT emails whose status is 'Available for Pickup'. ship_date "
                       "must be the date the email was received (provided in the email metadata). "
                       "Never releases/confirms -- a clerk does that in Acumatica.",
        "input_schema": {
            "type": "object",
            "properties": {
                "container": {"type": "string", "description": "ISO container number, e.g. CGMU6574694"},
                "ship_date": {"type": "string", "description": "YYYY-MM-DD; the email's received date"},
            },
            "required": ["container", "ship_date"],
            "additionalProperties": False,
        },
    },
    {
        "name": "add_to_watchlist",
        "description": "Add a container to the Maersk watch-list (for later origin vessel-loading "
                       "lookup). Use for FCR emails, after parse_fcr. Pass the values parse_fcr returned.",
        "input_schema": {
            "type": "object",
            "properties": {
                "container": {"type": "string"},
                "pos": {"type": "array", "items": {"type": "string"}},
                "port_of_loading": {"type": "string"},
                "receipt_no": {"type": "string"},
                "vessel": {"type": "string"},
            },
            "required": ["container"],
            "additionalProperties": False,
        },
    },
    {
        "name": "finish",
        "description": "Record the final decision for this email and end. Call this exactly once, "
                       "after any other tool calls (or immediately, if no action is warranted). "
                       "Set exception=true for anything a human should look at: ambiguous emails, "
                       "an NRT status you don't recognize, a create_shipment/parse failure, missing "
                       "data, or anything that didn't fit the normal path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "enum": ["nrt_available_for_pickup", "nrt_other_status", "fcr", "ambiguous", "skip"],
                },
                "action_summary": {"type": "string", "description": "One phrase, e.g. 'created shipment' / 'added to watchlist' / 'no action'"},
                "rationale": {"type": "string", "description": "1-2 sentences explaining the decision"},
                "exception": {"type": "boolean"},
                "exception_reason": {"type": "string"},
            },
            "required": ["classification", "action_summary", "rationale", "exception"],
            "additionalProperties": False,
        },
    },
]

SYSTEM_PROMPT = """\
You are the mailbox agent for Sand + Fog's container-pickup automation. Each turn you \
are given ONE email that landed in a shared Outlook folder (pushed to you by Power \
Automate). Your job: decide what it is, and PREPARE the right Acumatica-adjacent action \
by calling the provided tools. You never release or confirm anything -- shipments are \
created On Hold and a human confirms them in Acumatica. A clerk reviews your work.

Two email types matter:

1. NRT container-status emails (from noreply@nrsonline.com, subject "Status Update - \
Container # XXXX"). The subject is always generic -- the STATUS is only in the body. \
Read the body:
   - If the status is "Available for Pickup" (allow minor wording variants like \
"Available to Pickup"): this is the revenue/shipment trigger. Call create_shipment with \
the container number and ship_date = the email's received date (given in the metadata, \
NOT any date in the body, NOT today).
   - Any OTHER status (in transit, arrived, delayed, on hold, etc.): do NOT create a \
shipment. Classify as nrt_other_status, no action.

2. FCR emails (Forwarder's Cargo Receipt) with a PDF attachment. Call parse_fcr to \
extract the container / PO numbers / Port of Loading, then call add_to_watchlist with \
those values. These seed a later Maersk origin-vessel-loading lookup; they do NOT create \
a shipment now.

Anything else, or anything you're unsure about -- an unfamiliar sender, a malformed \
email, no container number where you expect one, a tool call that fails, conflicting \
signals -- classify as ambiguous or skip and set exception=true on finish. Err toward \
flagging for a human rather than guessing on financial records. Do not invent a \
container number or a date; if the required data isn't clearly present, flag it.

Always call finish exactly once to record your decision. Be concise in rationale.\
"""

# ---------------- tool execution (with shadow-mode interception) ----------------
def run_tool(name, args, item, decision):
    """Execute a tool call. Returns (result_for_model, did_write). Records enough on
    `decision` to build the audit-log row. In shadow mode, create_shipment and
    add_to_watchlist are intercepted: logged as 'would have called', nothing sent."""
    if name == "parse_fcr":
        fname, content = first_pdf(item)
        if not content:
            return {"error": "no PDF attachment on this email"}, False
        st, data = _http("POST", "/parsefcr", FCR_TOKEN, multipart=(fname, content))
        return (data if st == 200 else {"error": f"parsefcr HTTP {st}", "detail": data}), False

    if name == "create_shipment":
        decision["action_taken"] = "create_shipment"
        decision["tool_args"] = args
        if SHADOW_MODE:
            decision["shadow_intercepted"] = True
            return {"shadow_mode": True, "note": "would have created shipment on Hold; nothing sent"}, False
        body = {"container": args.get("container"), "ship_date": args.get("ship_date"), "source": "nrt-agent"}
        st, data = _http("POST", "/autoship", AUTOSHIP_TOKEN, body=body)
        decision["tool_result"] = {"status": st, "data": data}
        return (data if st == 200 else {"error": f"autoship HTTP {st}", "detail": data}), True

    if name == "add_to_watchlist":
        decision["action_taken"] = "add_to_watchlist"
        decision["tool_args"] = args
        if SHADOW_MODE:
            decision["shadow_intercepted"] = True
            return {"shadow_mode": True, "note": "would have added to watch-list; nothing sent"}, False
        st, data = _http("POST", "/watchlist/add", MAERSK_TOKEN, body={
            "container": args.get("container"), "pos": args.get("pos"),
            "port_of_loading": args.get("port_of_loading"), "receipt_no": args.get("receipt_no"),
            "vessel": args.get("vessel"), "source": "fcr-agent"})
        decision["tool_result"] = {"status": st, "data": data}
        return (data if st == 200 else {"error": f"watchlist/add HTTP {st}", "detail": data}), True

    return {"error": f"unknown tool {name}"}, False

# ---------------- process one queued email ----------------
def process_item(client, item):
    msg_id = item.get("message_id")
    if already_processed(msg_id):
        print(f"  skip (already logged): {msg_id}")
        queue_delete(item["id"])
        return

    body_text = strip_html(item.get("body") or "")
    atts = item.get("attachments") or []
    att_summary = ", ".join(f"{a.get('name')} ({'pdf' if (a.get('name') or '').lower().endswith('.pdf') else 'other'})"
                            for a in atts) or "none"
    email_blob = (
        f"Source mailbox: {item.get('source_mailbox')}\n"
        f"Message-ID: {msg_id}\n"
        f"Subject: {item.get('subject')}\n"
        f"Received date: {item.get('received_date')}\n"
        f"Attachments: {att_summary}\n"
        f"---- body (HTML stripped to text) ----\n{body_text[:6000]}"
    )

    decision = {
        "run_id": RUN_ID, "source_mailbox": item.get("source_mailbox"), "message_id": msg_id,
        "subject": item.get("subject"), "message_date": item.get("received_date"),
        "mode": "shadow" if SHADOW_MODE else "live",
    }

    messages = [{"role": "user", "content": email_blob}]
    finished = False
    for _turn in range(8):  # bounded loop; finish normally ends it well before this
        resp = client.messages.create(
            model=MODEL, max_tokens=4096,
            thinking={"type": "adaptive"},
            system=SYSTEM_PROMPT, tools=TOOLS, messages=messages,
        )
        if resp.stop_reason != "tool_use":
            # Model ended without calling finish -- treat as an exception, don't guess.
            decision.setdefault("classification", "ambiguous")
            decision["action_taken"] = decision.get("action_taken") or "none"
            decision["rationale"] = "Model ended the turn without calling finish."
            decision["exception_flag"] = True
            decision["exception_reason"] = "no finish tool call"
            break
        messages.append({"role": "assistant", "content": resp.content})
        tool_results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            if block.name == "finish":
                a = block.input
                decision["classification"] = a.get("classification")
                decision["action_summary"] = a.get("action_summary")
                decision["rationale"] = a.get("rationale")
                decision["exception_flag"] = bool(a.get("exception"))
                decision["exception_reason"] = a.get("exception_reason")
                decision.setdefault("action_taken", "none")
                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": "recorded"})
                finished = True
            else:
                result, _ = run_tool(block.name, block.input, item, decision)
                tool_results.append({"type": "tool_result", "tool_use_id": block.id,
                                     "content": json.dumps(result)})
        messages.append({"role": "user", "content": tool_results})
        if finished:
            break

    # Record the decision (always -- this is the audit trail + idempotency marker),
    # then remove the item from the queue.
    _http("POST", "/agent/log", AGENT_TOKEN, body=decision)
    queue_delete(item["id"])
    flag = " [EXCEPTION]" if decision.get("exception_flag") else ""
    print(f"  {decision.get('classification')} / {decision.get('action_taken')}{flag}: {msg_id}")

# ---------------- main ----------------
RUN_ID = None
def main():
    global RUN_ID
    _require("SHIPMENTS_BASE_URL", BASE)
    _require("AGENT_TOKEN", AGENT_TOKEN)
    _require("ANTHROPIC_API_KEY", os.environ.get("ANTHROPIC_API_KEY"))
    RUN_ID = base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("=")
    client = anthropic.Anthropic()

    items = queue_list()
    mode = "SHADOW" if SHADOW_MODE else "LIVE"
    print(f"[mailbox-agent run {RUN_ID}] mode={mode} model={MODEL} queued={len(items)}")
    if not items:
        print("  nothing to do.")
        return
    for i, item in enumerate(items[:MAX_ITEMS_PER_RUN]):
        try:
            process_item(client, item)
        except Exception as e:
            print(f"  ERROR on item {item.get('id')}: {e}")
            # leave it in the queue for the next run rather than dropping it
    if len(items) > MAX_ITEMS_PER_RUN:
        print(f"  capped at {MAX_ITEMS_PER_RUN}; {len(items) - MAX_ITEMS_PER_RUN} remain for next run.")
    print("done.")

if __name__ == "__main__":
    main()
