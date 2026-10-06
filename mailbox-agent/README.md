# Mailbox Agent — NRT (Phase C)

An LLM agent (Claude, `claude-opus-4-8`) that reads **NRT container-status emails** from a queue, and when the status is "Picked Up" (since Oct 2026 -- see [CHANGELOG](CHANGELOG.md)), **prepares an unconfirmed Acumatica Shipment** — never releasing it. A clerk confirms in Acumatica. Full background: the [container-pickup-tracking-project](../../.claude/projects/C--Users-ParkerRodman-Documents/memory/container-pickup-tracking-project.md) memory.

**Scope: NRT → Shipments only.** The overseas / FCR → *PO Receipt* path is a **separate agent** (different Acumatica record type, different app, different scoped user) — not built yet (blocked on the Maersk origin-loading trigger and a PO-receipt-creation endpoint). This agent's only power is `create_shipment`; it literally cannot create a PO receipt.

## How it fits together

```
Power Automate (your O365 login)          handover-shipments (Render web svc)        mailbox-agent (Render cron)
  new NRT/FCR email ──POST /ingest──▶  queue on persistent disk        ◀──GET /ingest/list── drains queue
                                        /parsefcr /autoship /watchlist/add ◀── calls (its only powers)
                                        /agent/log  ◀── one decision row per email ──
```

The agent is a **separate Render service** from `handover-shipments` (different failure domain — an agent bug must not redeploy the proven Acumatica service). It talks to the shipments service only over HTTPS, using the same bearer tokens. It can never touch Acumatica directly — its entire power is the four endpoints above, all already scoped so nothing it does can release/confirm a record.

## What it does per email
- **Status "Picked Up"** (the customer's logistics partner has taken custody) → calls `/autoship` with `nrt_status=picked_up` (shipment On Hold, ship_date = email received date). Acumatica resolves the container → sales orders, and a master ships only once every one of its containers is picked up and its PO is fully received. If a container's Picked Up email never arrives, **"Empty returned"** is accepted as proof of pickup (`nrt_status=empty_returned`, classified `nrt_late_pickup_confirmation`).
- **"Available for Pickup", "Scheduled for Pickup", and any other status** → NOT a trigger, no action, logged. A deterministic check in `run_tool` also rejects any `create_shipment` whose claimed status doesn't actually appear in the email body.
- **Not an NRT email / unclear / no container** → no action, flagged as an exception.
- Every email → one decision row to `/agent/log` (reviewable at `GET /agent/log?view=html` on the shipments service).

## Shadow mode (default ON)
With `SHADOW_MODE=1`, the agent reasons exactly as in production but the write tools (`/autoship`, `/watchlist/add`) are intercepted: it logs *what it would have done* and creates nothing. Review the decision log for a couple of weeks / 20+ real emails with zero disagreements, then flip `SHADOW_MODE=0` to go live — do `/watchlist/add` first, `/autoship` last. Keep the flag; re-use it after any prompt/tool change.

## Deploy (Render)
1. New **Cron Job** service, Root Directory `mailbox-agent/`, from this repo (see `render.yaml`). Separate service from handover-shipments.
2. Set env vars: `SHIPMENTS_BASE_URL`, `AGENT_TOKEN`, `AUTOSHIP_TOKEN`, `ANTHROPIC_API_KEY` (tokens must match the shipments service). `SHADOW_MODE=1`, `MODEL=claude-opus-4-8`.
3. **Prerequisite**: the shipments service must have the `/ingest` + `/agent/log` endpoints live (merged to main; set `AGENT_TOKEN`/`INGEST_TOKEN` on that service) before this agent has anything to talk to.

## Run locally (against the deployed shipments service)
```
pip install -r requirements.txt
export SHIPMENTS_BASE_URL=... AGENT_TOKEN=... AUTOSHIP_TOKEN=... ANTHROPIC_API_KEY=...
python agent.py          # SHADOW_MODE defaults on
```

## Status (2026-07-11)
Built, NRT-only. Harness wiring verified with mocked LLM + HTTP (shadow interception, live-mode autoship, idempotency, no-finish exception path, multi-container refusal guard all pass) and HTML-strip verified against a real NRT email. **Not yet run against the live Claude API or shipments service** — decision quality gets validated in shadow mode after deploy.
