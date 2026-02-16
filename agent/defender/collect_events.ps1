# collect_events.ps1

# FastAPI endpoint
$endpoint = "http://127.0.0.1:8000/api/defender/events"

# Collect recent Defender threats
$eventsRaw = Get-MpThreat | Select-Object ThreatID, ThreatName, Resources, ActionSuccess, ExecutionTime

# Initialize payload
$payload = @{ events = @() }

# Populate events array
foreach ($e in $eventsRaw) {
    $payload.events += @{
        source     = "defender"
        threat     = if ($e.ThreatName) { $e.ThreatName } else { "unknown" }
        verdict    = if ($e.ActionSuccess -eq $true) { "quarantined" } else { "malicious" }
        confidence = 0.8
        severity   = "high"
    }
}

# Convert payload to JSON
$jsonPayload = $payload | ConvertTo-Json -Depth 5

# Output JSON for debugging
Write-Output $jsonPayload

# POST to FastAPI with try/catch
try {
    Invoke-RestMethod -Uri $endpoint -Method POST -Body $jsonPayload -ContentType "application/json"
    Write-Host "Events sent successfully!"
} catch {
    Write-Error "Error sending events: $_"
}
