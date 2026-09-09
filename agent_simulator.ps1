$api = "http://127.0.0.1:9000/api/threats/"

$headers = @{
    "Content-Type" = "application/json"
}

$threatTypes = @(
"malware",
"ransomware",
"trojan",
"spyware",
"keylogger"
)

$severities = @(
"low",
"medium",
"high",
"critical"
)

Write-Host "Starting endpoint threat simulator..."

while ($true) {

    $hash = [guid]::NewGuid().ToString()

    $threat = Get-Random $threatTypes
    $severity = Get-Random $severities

    $body = @{
        file_hash = $hash
        threat_type = $threat
        severity = $severity
    } | ConvertTo-Json

    try {

        Invoke-WebRequest `
        -Uri $api `
        -Method POST `
        -Headers $headers `
        -Body $body | Out-Null

        Write-Host "Threat sent:" $hash $threat $severity

    }
    catch {

        Write-Host "API not reachable..."

    }

    Start-Sleep -Seconds 3
}
