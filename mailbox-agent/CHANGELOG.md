# Changelog — NRT mailbox agent / shipment trigger

## 2026-10-06 — Shipment trigger moves from "Available for Pickup" to "Picked Up"

**What changed.** The agent now creates a shipment when NRT reports a container **Picked Up**
(custody taken by the customer's designated logistics partner), not when it becomes
**Available for Pickup**. Revenue-recognition policy section 5.3 was amended to match
(`ASC606_Revenue_Recognition_Policy_v2.1.docx`).

**Why.** (1) Policy 5.3 recognizes revenue when the partner "takes custody"; Available for
Pickup is a notice, not custody. (2) Picked Up is the date NRT itself records and the one the
monthly cutoff test validates against, so dating shipments at Available built a systematic
month-end variance (Jul–Sep 2026 log: median Available→Picked Up lag 3 days; 7 containers /
56 shipments Available 8/28–8/31 but Picked Up 9/1–9/3). (3) Two bases were already in use by
accident: 310 of 1,620 shipments (19%) were missed-trigger backfills dated at a later
Picked Up / Empty Returned email, the rest at Available.

**Go-live / effective date: 2026-10-06.** Policy v2.1 revision history carries the same date.

**Not retroactive.** September 2026 and earlier stay on the Available basis. Shipments already
created are unchanged.

**Behavior now.**
- Trigger: "Picked Up" email, `ship_date` = email received date, `nrt_status=picked_up`.
- Fallback: "Empty returned" when the Picked Up email never arrived and the pickup was not
  already counted (`nrt_status=empty_returned`, classification `nrt_late_pickup_confirmation`).
- Available / Scheduled / everything else: logged as `nrt_other_status`, no shipment.
- A master still ships only when every container is confirmed AND its PO is fully received;
  the master's shipment date is the latest container's Picked Up date.
- `run_tool` rejects any `create_shipment` whose claimed status is not in the email body.
- Server (`app.py`): `_confirmed_pickup_detail()` ranks Picked Up > Empty Returned > legacy
  (Available) per container and keeps the earliest date within the new basis, so a later
  Empty Returned or resend can't push a pickup date later. `/containerstatus` now also returns
  `pickup_recorded`. New classification `nrt_picked_up`.

**Transition cohort (grandfathered).** Containers confirmed at Available before go-live and not
yet shipped stay confirmed on the legacy basis so nothing is stranded. If their Picked Up email
arrives after go-live it supersedes the Available date; if it already arrived before go-live,
the master ships on the legacy date. This is a small, one-time cohort.

**Shipment date is now the Pacific date (same release).** Power Automate sends `received_date` as the UTC
date, so NRT emails sent 5pm-midnight Pacific were dated the next day (21% of emails, Jul-Sep 2026). The agent
now derives the Pacific date from the UTC send time embedded in NRT's Message-ID
(`<yyyymmddhhmmss.hash@nrsonline.com>`; matched the logged date on all 1,227 emails that carry one),
overrides the model's `ship_date` with it in `run_tool`, shows it to the model as "Received date (Pacific)",
and logs it as `message_date`. It falls back to the raw date when there is no usable id or the two disagree by
more than a day, and never converts `received_date` itself, so fixing the Power Automate flow later can't
double-convert. Needs `tzdata` (added to `mailbox-agent/requirements.txt`). Replay of the Jul-Sep log: 118 of
1,620 shipments would have been dated a day earlier, none moving to a different month. Log rows before
2026-10-06 have UTC `message_date`; rows after have Pacific -- keep that in mind when comparing across the switch.

**Deploy order.** (1) `shipments` web service (backward compatible: ignores a missing
`nrt_status`), (2) then the `mailbox-agent` cron. Do not deploy the agent first.

**Rollback.** Revert the agent commit and redeploy the cron; the server change is harmless
to the old agent.
