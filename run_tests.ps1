Write-Host "Running Mackalishis Antivirus Test Suite..." -ForegroundColor Cyan

$env:PYTHONPATH = Get-Location

python -m pytest

if ($LASTEXITCODE -eq 0) {
    Write-Host "All tests passed ✅" -ForegroundColor Green
} else {
    Write-Host "Tests failed ❌" -ForegroundColor Red
}
