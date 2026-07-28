<#
Manually triggers the Phase-2 completeness-ledger recheck -- the same POST
/ledger/recheck the mailbox-agent's own cron calls automatically once a day
(RECHECK_HOUR_UTC). Re-evaluates every "waiting"/"partial" master against
Acumatica's current state and creates a shipment for any that are now fully
ready (both gates pass). A sibling master that's still short stays "waiting"
on its own -- see app.py's process_manual() for the per-master gating logic.

Prompts for AUTOSHIP_TOKEN each run instead of storing it in this file, so
the token never sits in plaintext on disk or in shell history.

Usage: powershell -File scripts\ledger-recheck.ps1
#>

$BaseUrl = "https://shipments-ynyx.onrender.com"

$secureToken = Read-Host -Prompt "AUTOSHIP_TOKEN" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

if (-not $token) {
    Write-Error "No token entered -- aborting."
    exit 1
}

try {
    $resp = Invoke-RestMethod -Method Post -Uri "$BaseUrl/ledger/recheck" `
        -Headers @{ Authorization = "Bearer $token" }
} catch {
    Write-Error "Request failed: $_"
    exit 1
} finally {
    $token = $null
}

Write-Output "Checked $($resp.checked) master(s)."
Write-Output ""
foreach ($r in $resp.results) {
    $res = $r.result
    if ($res.error) {
        Write-Output ("- Master {0} (via {1}): ERROR -- {2}" -f $r.master, $r.container_used, $res.error)
        continue
    }
    if ($res.waiting_on_containers) {
        Write-Output ("- Master {0} (via {1}): still waiting -- {2}" -f $r.master, $r.container_used, $res.note)
        continue
    }
    $created = $res.created
    $line = "- Master {0} (via {1}): created={2}" -f $r.master, $r.container_used, $created
    if ($res.still_waiting_masters) {
        $line += " (sibling master(s) still waiting: $($res.still_waiting_masters -join ', '))"
    }
    Write-Output $line
}
