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
    ANTHROPIC_API_KEY    Claude API key
    SHADOW_MODE          "1" (default) = intercept the write tool, log what WOULD
                         have happened, create nothing. Flip to "0" to go live.
                         Keep this flag permanently -- re-use it after prompt/tool changes.
    MODEL                default "claude-opus-4-8"
    MAX_ITEMS_PER_RUN    safety cap on items processed per run (default 50)
"""
import os, re, json, base64, html, time, datetime
import urllib.request, urllib.error, urllib.parse

import anthropic

# ---------------- config ----------------
BASE = os.environ.get("SHIPMENTS_BASE_URL", "").rstrip("/")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
AUTOSHIP_TOKEN = os.environ.get("AUTOSHIP_TOKEN", "")
SHADOW_MODE = os.environ.get("SHADOW_MODE", "1") != "0"
MODEL = os.environ.get("MODEL", "claude-opus-4-8")
MAX_ITEMS_PER_RUN = int(os.environ.get("MAX_ITEMS_PER_RUN", "50"))

def _require(name, val):
    if not val:
        raise SystemExit(f"ERROR: {name} is required (set the env var).")

# ---------------- HTTP to the shipments service ----------------
def _http(method, path, token, body=None, timeout=120):
    url = BASE + path
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data = None
    if body is not None:
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

# ---------------- tool definitions (the agent's action surface) ----------------
# The ONLY things the agent can do. create_shipment is the single write (maps to the
# already-scoped /autoship; intercepted in shadow mode); finish records the decision to
# /agent/log and ends the loop. This narrow surface means the NRT agent literally cannot
# create a PO receipt or anything else -- the overseas PO-receipt path is a separate agent.
TOOLS = [
    {
        "name": "check_container_status",
        "description": "Check whether a shipment has ALREADY been created off this "
                       "container, from an earlier email (possibly a previous run). Call "
                       "this for EVERY email about a container, regardless of status -- "
                       "including 'Scheduled for Pickup', 'Picked Up', 'Empty returned', "
                       "not just 'Available for Pickup'. Returns shipped=true/false and, "
                       "if true, when and which Master PO(s). The container lifecycle order "
                       "is: Available for Pickup < Scheduled for Pickup < Picked Up < Empty "
                       "returned -- 'Available for Pickup' is the FIRST tracked stage, so "
                       "any OTHER status arriving after a shipment already exists is the "
                       "normal, expected continuation, not an anomaly -- do not flag it. "
                       "The one genuinely suspicious case is a SECOND 'Available for "
                       "Pickup' email for a container that's already shipped (a duplicate "
                       "or resend) -- but create_shipment already detects and flags that "
                       "server-side on its own (reason=pickup_after_already_shipped), so "
                       "you don't need to re-derive it here either. Use this tool mainly "
                       "for accurate logging/context, not as a trigger for exception=true.",
        "input_schema": {
            "type": "object",
            "properties": {
                "container": {"type": "string", "description": "ISO container number"},
            },
            "required": ["container"],
            "additionalProperties": False,
        },
    },
    {
        "name": "create_shipment",
        "description": "Create an UNCONFIRMED (On Hold) Acumatica shipment for the given container. "
                       "Use for NRT emails whose status is 'Available for Pickup', OR a later status "
                       "(Scheduled for Pickup/Picked Up/Empty returned) when check_container_status "
                       "shows no shipment exists yet -- see the system prompt's missed-trigger-backfill "
                       "case. ship_date must be the date the email was received (provided in the email "
                       "metadata). "
                       "Never releases/confirms -- a clerk does that in Acumatica. The result can come "
                       "back three ways: (1) created -- done, call finish normally; (2) "
                       "waiting_on_containers=true -- this order's Purchase Order isn't fully received "
                       "yet (its containers are still arriving across separate shipments); this is "
                       "NORMAL, not an error -- call finish with exception=false and classification "
                       "nrt_waiting_on_containers, no further action needed, it'll ship automatically "
                       "once complete; (3) needs_review=true (e.g. no open sales order resolved, or a "
                       "pickup arrived for an order already shipped) -- this DOES need a human, call "
                       "finish with exception=true and explain.",
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
        "name": "finish",
        "description": "Record the final decision for this email and end. Call this exactly once, "
                       "after create_shipment (or immediately, if no action is warranted). "
                       "Set exception=true for anything a human should look at: an NRT status you don't "
                       "recognize, a create_shipment that came back needs_review or created nothing, "
                       "missing/unclear data, a non-NRT email that landed in this folder, or anything "
                       "that didn't fit the normal path. Do NOT set exception=true for "
                       "waiting_on_containers=true -- that's a normal, expected state, not a problem.",
        "input_schema": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "enum": ["nrt_available_for_pickup", "nrt_late_pickup_confirmation",
                              "nrt_waiting_on_containers", "nrt_other_status",
                              "not_nrt", "ambiguous", "skip"],
                },
                "action_summary": {"type": "string", "description": "One phrase, e.g. 'created shipment' / 'no action'"},
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
You are the NRT mailbox agent for Sand + Fog's container-pickup automation. Each turn \
you are given ONE email that landed in the NRT container-status folder (pushed to you by \
Power Automate). Your job: read it and, when it's a pickup trigger, PREPARE an unconfirmed \
Acumatica shipment by calling create_shipment. You never release or confirm anything -- \
shipments are created On Hold and a clerk confirms them in Acumatica.

These are NRT container-status emails (from noreply@nrsonline.com, subject "Status Update \
- Container # XXXX"). The subject is ALWAYS the generic "Status Update" line -- the actual \
STATUS is only in the email body, so you must read the body to know what this email means.

For EVERY email, after you've read the container number and status, call \
check_container_status for that container BEFORE calling finish -- regardless of what the \
status is. This is a read-only check (safe to call every time, no side effects): it tells \
you whether a shipment already exists for this container from an earlier email. The \
container lifecycle order is: Available for Pickup < Scheduled for Pickup < Picked Up < \
Empty returned -- "Available for Pickup" is the FIRST tracked stage.

- If the body status is "Available for Pickup" (allow minor wording variants like \
"Available to Pickup"): this is the revenue/shipment trigger. Call create_shipment with \
the container number (from the subject/body) and ship_date = the email's received date \
(given in the metadata -- NOT any date in the body, NOT today). Then call finish. \
Acumatica resolves which sales orders that container maps to; you don't need to.
   - If create_shipment comes back with waiting_on_containers=true: this order's \
Purchase Order isn't fully received yet (more containers for it are still arriving, \
possibly weeks apart). This is EXPECTED, not an error -- call finish with \
classification nrt_waiting_on_containers, exception=false. It'll ship automatically \
once complete; nothing more for you to do.
   - If create_shipment comes back with needs_review=true instead (e.g. no open sales \
order resolved, or a pickup arrived for an order already marked shipped), that DOES \
need a human -- call finish with exception=true and explain.
- Any OTHER status (Scheduled for Pickup, in transit, arrived at port, delayed, on hold, \
Picked Up, Empty returned, etc.): do NOT create a shipment by default. Since "Available \
for Pickup" is the first stage, any of these arriving AFTER a shipment already exists \
(per check_container_status) is the normal, expected continuation -- NOT an anomaly, \
don't flag it. Call finish with classification nrt_other_status, exception=false, no \
action.
   - EXCEPTION -- missed-trigger backfill: if the status is specifically "Scheduled for \
Pickup", "Picked Up", or "Empty returned" (NOT "in transit"/"arrived at port"/"delayed"/ \
"on hold", which don't reliably imply this) AND check_container_status shows \
shipped=false (no shipment exists yet for this container): treat this the same as \
"Available for Pickup". Reaching any of these later stages necessarily means the \
container WAS available at some point, even though NRT apparently never sent that \
specific email -- a real, confirmed gap on NRT's side (Parker confirmed this directly, \
2026-07-28), not something to second-guess. Call create_shipment with the container \
number and ship_date = the email's received date, exactly as in the normal trigger case, \
then call finish with classification nrt_late_pickup_confirmation and a rationale noting \
the intermediate "Available for Pickup" email was missed. Handle \
waiting_on_containers=true / needs_review=true exactly as in the normal trigger case \
above.

If the email isn't an NRT status email at all (wrong sender, no container number, some \
other message that landed in this folder), or anything is unclear or conflicting: do NOT \
guess. Call finish with classification not_nrt or ambiguous and exception=true. Never \
invent a container number or a date -- if the required data isn't clearly present, flag it.

Always call finish exactly once to record your decision. Keep rationale to 1-2 sentences.\
"""

# ---------------- tool execution (with shadow-mode interception) ----------------
def run_tool(name, args, item, decision):
    """Execute a tool call. Returns (result_for_model, did_write). Records enough on
    `decision` to build the audit-log row. In shadow mode the write (create_shipment) is
    intercepted: logged as 'would have called', nothing sent."""
    if name == "check_container_status":
        # Read-only -- runs even in shadow mode, same as any other read. Not gated behind
        # SHADOW_MODE at all; only WRITES (create_shipment) are intercepted there.
        container = urllib.parse.quote((args.get("container") or "").strip())
        st, data = _http("GET", f"/containerstatus?container={container}&token={AGENT_TOKEN}", AGENT_TOKEN)
        return (data if st == 200 else {"error": f"containerstatus HTTP {st}", "detail": data}), False

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

RECHECK_HOUR_UTC = int(os.environ.get("RECHECK_HOUR_UTC", "15"))  # ~8am Pacific (PDT)

def ledger_recheck():
    """Re-check every 'waiting'/'partial' master (Phase 2 / Tier 2 completeness ledger) for
    whether its Purchase Order has since become fully received. Needed, not optional --
    without this, a master whose LAST container's NRT email fires before its receipt posts
    in Acumatica has no future event to re-trigger it and would sit stuck forever. Piggybacks
    on this cron's existing schedule/token rather than a separate service (no new secrets).

    RUNS ONCE A DAY, not every cron cycle: this endpoint calls process_manual (and its live
    Acumatica resolution chain) for EVERY active master. Running it every 3-hour cycle scales
    with however many masters are currently split -- confirmed real: 28+ active masters meant
    60-100+ extra Acumatica calls every single cycle, on top of normal email processing, purely
    to re-check something that only changes as fast as a clerk processes packing lists (days,
    not hours). This cron job has no persistent disk between runs, so the gate is wall-clock
    time-of-day (matches one of this cron's own fire hours), not a saved "last ran" timestamp.
    Same write stakes as create_shipment -- skipped entirely in shadow mode, not intercepted
    like the LLM's tool calls, since this is a direct endpoint call outside the agent loop."""
    if datetime.datetime.now(datetime.timezone.utc).hour != RECHECK_HOUR_UTC:
        print(f"  [ledger recheck] skipped -- only runs at hour {RECHECK_HOUR_UTC} UTC")
        return
    if SHADOW_MODE:
        print("  [ledger recheck] skipped -- SHADOW_MODE on")
        return
    st, data = _http("POST", "/ledger/recheck", AUTOSHIP_TOKEN)
    if st == 200 and isinstance(data, dict):
        print(f"  [ledger recheck] checked={data.get('checked')}")
    else:
        print(f"  [ledger recheck] failed: status={st} body={data}")

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
    else:
        for i, item in enumerate(items[:MAX_ITEMS_PER_RUN]):
            try:
                process_item(client, item)
            except Exception as e:
                print(f"  ERROR on item {item.get('id')}: {e}")
                # leave it in the queue for the next run rather than dropping it
        if len(items) > MAX_ITEMS_PER_RUN:
            print(f"  capped at {MAX_ITEMS_PER_RUN}; {len(items) - MAX_ITEMS_PER_RUN} remain for next run.")
    # Runs every cron cycle regardless of queue state -- a stuck ledger entry isn't tied to
    # whether new mail arrived this run.
    ledger_recheck()
    print("done.")

if __name__ == "__main__":
    main()
