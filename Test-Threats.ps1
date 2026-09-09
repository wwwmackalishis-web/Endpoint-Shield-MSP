Write-Host "Starting FastAPI test..."

$headers = @{ "Content-Type" = "application/json" }

$body = @{
    file_hash = "powershellhash999"
    threat_type = "spyware"
    severity = "medium"
} | ConvertTo-Json

$response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/threats/" -Method POST -Headers $headers -Body $body -UseBasicParsing

Write-Host "Threat Added:"
$response.Content

Write-Host "`nAll Threats:"
Invoke-WebRequest -Uri "http://127.0.0.1:8000/threats/" -UseBasicParsing
