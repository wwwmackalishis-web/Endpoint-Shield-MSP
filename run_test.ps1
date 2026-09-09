cd "C:\Users\Anthony McNeill\antivirus-orchestrator"

Write-Host "Activating virtual environment..."
.\venv\Scripts\Activate.ps1

Write-Host "Starting FastAPI server..."
$uvicornProcess = Start-Process python -ArgumentList "-m uvicorn main:app --host 127.0.0.1 --port 9000" -PassThru

Write-Host "Waiting for FastAPI to start..."

$serverReady = $false
for ($i = 0; $i -lt 15; $i++) {
    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:9000" -UseBasicParsing -TimeoutSec 2 | Out-Null
        $serverReady = $true
        break
    }
    catch {
        Start-Sleep -Seconds 1
    }
}

if (-not $serverReady) {
    Write-Host "Server did not start."
    Stop-Process -Id $uvicornProcess.Id
    exit
}

Write-Host "Server is running. Sending test threat..."

$headers = @{ "Content-Type" = "application/json" }

$body = @{
    file_hash   = "abc123hash"
    threat_type = "malware"
    severity    = "high"
} | ConvertTo-Json

$response = Invoke-WebRequest -Uri "http://127.0.0.1:9000/api/threats/" -Method POST -Headers $headers -Body $body

Write-Host "Response from API:"
Write-Host $response.Content
