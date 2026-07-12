# Mailbox Agent (Phase C)

An LLM agent (Claude, `claude-opus-4-8`) that reads NRT/FCR emails from a queue, decides what each one is, and **prepares** the matching Acumatica-adjacent action — never releasing anything. A clerk confirms shipments in Acumatica. Full background: the [container-pickup-tracking-project](../../.claude/projects/C--Users-ParkerRodman-Documents/memory/container-pickup-tracking-project.md) memory.

## How it fits together

```
Power Automate (your O365 login)          handover-shipments (Render web svc)        mailbox-agent (Render cron)
  new NRT/FCR email ──POST /ingest──▶  queue on persistent disk        ◀──GET /ingest/list── drains queue
                                        /parsefcr /autoship /watchlist/add ◀── calls (its only powers)
                                        /agent/log  ◀── one decision row per email ──
```

The agent is a **separate Render service** from `handover-shipments` (different failure domain — an agent bug must not redeploy the proven Acumatica service). It talks to the shipments service only over HTTPS, using the same bearer tokens. It can never touch Acumatica directly — its entire power is the four endpoints above, all already scoped so nothing it does can release/confirm a record.

## What it does per email
- **NRT status email** → reads the body; if status is **"Available for Pickup"**, calls `/autoship` (shipment On Hold, ship_date = email received date). Any other status → no action, logged.
- **FCR email** (PDF) → `/parsefcr` then `/watchlist/add` (seeds the later Maersk lookup). No shipment now.
- **Anything ambiguous** → no action, flagged as an exception for a human.
- Every email → one decision row to `/agent/log` (reviewable at `GET /agent/log?view=html` on the shipments service).

## Shadow mode (default ON)
With `SHADOW_MODE=1`, the agent reasons exactly as in production but the write tools (`/autoship`, `/watchlist/add`) are intercepted: it logs *what it would have done* and creates nothing. Review the decision log for a couple of weeks / 20+ real emails with zero disagreements, then flip `SHADOW_MODE=0` to go live — do `/watchlist/add` first, `/autoship` last. Keep the flag; re-use it after any prompt/tool change.

## Deploy (Render)
1. New **Cron Job** service, Root Directory `mailbox-agent/`, from this repo (see `render.yaml`). Separate service from handover-shipments.
2. Set env vars: `SHIPMENTS_BASE_URL`, `AGENT_TOKEN`, `AUTOSHIP_TOKEN`, `FCR_TOKEN`, `MAERSK_TOKEN`, `ANTHROPIC_API_KEY` (tokens must match the shipments service). `SHADOW_MODE=1`, `MODEL=claude-opus-4-8`.
3. **Prerequisite**: the shipments service must have the `/ingest` + `/agent/log` endpoints live (they're on the `feature/agent-log` branch — merge + deploy it, and set `AGENT_TOKEN`/`INGEST_TOKEN` there) before this agent has anything to talk to.

## Run locally (against the deployed shipments service)
```
pip install -r requirements.txt
export SHIPMENTS_BASE_URL=... AGENT_TOKEN=... AUTOSHIP_TOKEN=... ANTHROPIC_API_KEY=...
python agent.py          # SHADOW_MODE defaults on
```

## Status (2026-07-11)
Built; harness wiring verified with mocked LLM + HTTP (shadow interception, live-mode autoship, idempotency, no-finish exception path all pass) and HTML-strip verified against a real NRT email. **Not yet run against the live Claude API or shipments service** — decision quality gets validated in shadow mode after deploy. Depends on `feature/agent-log` being merged first.
