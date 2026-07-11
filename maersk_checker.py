#!/usr/bin/env python3
"""
Maersk Watch-List Checker (local script -- run via Windows Task Scheduler)
---------------------------------------------------------------------------
Render can't reliably reach maersk.com itself: its outbound IP range gets
blocked by Akamai's bot mitigation (confirmed live -- the browser launches
fine, the page load just times out). This script runs from a normal network
instead. It:
  1. Pulls the current watch-list from the handover-shipments Render app
     (containers added there by the FCR-intake Power Automate flow).
  2. For each "watching" container, loads its Maersk tracking page locally
     and looks for the "Load on [vessel]" event at the location matching
     that container's recorded Port of Loading (not just the first Load-on
     event -- transshipping containers show a second, later one at the hub
     port that must be ignored).
  3. When found, calls /autoship to create the (unconfirmed) shipment, then
     marks the watch-list entry resolved on Render -- or "alert" if the
     /autoship call didn't actually create anything, so a mismatch doesn't
     just silently vanish.
  4. Containers that sit "watching" too long get flipped to "alert" on the
     Render side automatically (WATCHLIST_SLA_DAYS) -- this script just
     reports them, it doesn't need its own separate SLA logic.

Setup:
    1. Copy maersk_checker_config.example.json -> maersk_checker_config.json, fill in
       your Render app's URL + the MAERSK_TOKEN and AUTOSHIP_TOKEN values you set there.
       Keep this file private -- it holds bearer tokens.
    2. pip install -r requirements.txt   (same deps as app.py)
       python -m playwright install chromium   (downloads the local browser once)
    3. Run:
         python maersk_checker.py                run for real
         python maersk_checker.py --dry-run       check + print, create nothing

Scheduling (Windows Task Scheduler): daily is plenty -- transit from origin
loading to when a clerk needs the shipment takes days at minimum. Create a
Basic Task, trigger Daily, action "Start a program":
    Program: (path to python.exe, e.g. from `where python`)
    Arguments: "C:\\Users\\ParkerRodman\\Documents\\shipments\\maersk_checker.py"
    Start in: C:\\Users\\ParkerRodman\\Documents\\shipments
"""
import os, sys, json, time
import urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from app import check_maersk_container, sync_playwright  # reuse the proven parser/driver

CONFIG_PATH = os.path.join(HERE, "maersk_checker_config.json")
CHECK_DELAY_SEC = 4  # space out consecutive lookups rather than hammering Maersk sequentially

def load_config():
    if not os.path.exists(CONFIG_PATH):
        sys.exit(f"ERROR: {CONFIG_PATH} not found. Copy maersk_checker_config.example.json -> "
                 f"maersk_checker_config.json and fill it in.")
    cfg = json.load(open(CONFIG_PATH, encoding="utf-8"))
    for k in ("base_url", "maersk_token", "autoship_token"):
        if not cfg.get(k):
            sys.exit(f"ERROR: '{k}' missing in {CONFIG_PATH}")
    cfg["base_url"] = cfg["base_url"].rstrip("/")
    return cfg

def http_json(method, url, token, body=None, timeout=60):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": e.reason}
    except Exception as e:
        return 0, {"error": str(e)}

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    if sync_playwright is None:
        sys.exit("ERROR: playwright not installed locally. "
                 "pip install -r requirements.txt && python -m playwright install chromium")
    dry = "--dry-run" in sys.argv
    cfg = load_config()

    status, watchlist = http_json(
        "GET", f"{cfg['base_url']}/watchlist/list?status=watching&token={cfg['maersk_token']}",
        cfg["maersk_token"])
    if status != 200:
        sys.exit(f"ERROR fetching watch-list ({status}): {watchlist}")
    if not watchlist:
        log("Watch-list empty (nothing watching). Nothing to do.")
        return

    log(f"{len(watchlist)} container(s) watching.")
    checked = found = errors = 0
    for i, (container, entry) in enumerate(watchlist.items()):
        if i:
            time.sleep(CHECK_DELAY_SEC)
        checked += 1
        port = entry.get("port_of_loading")
        if not port:
            log(f"{container}: SKIP -- no port_of_loading recorded, can't anchor the Load-on event")
            continue
        try:
            result = check_maersk_container(container, port)
        except Exception as e:
            errors += 1
            log(f"{container}: ERROR checking Maersk -- {e}")
            continue
        if not result.get("found"):
            log(f"{container}: still watching (no Load-on event at {port} yet)")
            continue

        match = result["match"]
        found += 1
        log(f"{container}: FOUND -- {match['event']} at {match['matched_location']} on {match['date']}")
        if dry:
            log(f"{container}: dry-run, not calling /autoship")
            continue

        st, out = http_json("POST", f"{cfg['base_url']}/autoship", cfg["autoship_token"],
                             body={"container": container, "ship_date": match["date"],
                                   "pos": entry.get("pos"), "source": "maersk-fcr"})
        if st != 200 or out.get("error"):
            errors += 1
            log(f"{container}: /autoship call FAILED ({st}): {out}")
            http_json("POST", f"{cfg['base_url']}/watchlist/resolve", cfg["maersk_token"],
                      body={"container": container, "status": "alert",
                            "note": f"/autoship call failed: {out}"})
            continue

        log(f"{container}: /autoship OK -- created {out.get('created')}/{out.get('orders_matched')} shipment(s)")
        resolve_status = "resolved" if out.get("created", 0) > 0 else "alert"
        resolve_note = None if resolve_status == "resolved" else (
            f"/autoship matched {out.get('orders_matched')} order(s) but created 0 -- check {cfg['base_url']}/history")
        http_json("POST", f"{cfg['base_url']}/watchlist/resolve", cfg["maersk_token"],
                  body={"container": container, "status": resolve_status, "ship_date": match["date"],
                        "note": resolve_note})

    log(f"Done. Checked {checked}, found {found}, errors {errors}.")

if __name__ == "__main__":
    main()
