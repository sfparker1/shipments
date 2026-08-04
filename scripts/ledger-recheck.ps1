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

Write-Output "Checked $($resp.checked) container(s)."
Write-Output ""
foreach ($r in $resp.results) {
    $res = $r.result
    if ($res.error) {
        Write-Output ("- Container {0}: ERROR -- {1}" -f $r.container, $res.error)
        continue
    }
    if ($res.waiting_on_containers) {
        Write-Output ("- Container {0}: still waiting -- {1}" -f $r.container, $res.note)
        continue
    }
    $created = $res.created
    $line = "- Container {0}: created={1}" -f $r.container, $created
    if ($res.still_waiting_masters) {
        $line += " (sibling master(s) still waiting: $($res.still_waiting_masters -join ', '))"
    }
    if ($res.anomalies) {
        $line += " -- $($res.anomalies.Count) ANOMALY(IES), needs review"
    }
    Write-Output $line
}
