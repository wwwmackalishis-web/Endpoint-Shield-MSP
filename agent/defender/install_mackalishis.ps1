# Mackalishis AV Installer
# Run this as Administrator

$installPath = "C:\Program Files\MackalishisAV\Agent"
$folders     = @("logs", "uploads", "quarantine")
$taskName    = "MackalishisAV-Agent"

# 1. Create install directory if it doesn't exist
if (-not (Test-Path $installPath)) {
    New-Item -ItemType Directory -Path $installPath -Force | Out-Null
}

# 2. Set full control for SYSTEM and Administrators
icacls $installPath /grant "SYSTEM:(OI)(CI)F" /T | Out-Null
icacls $installPath /grant "Administrators:(OI)(CI)F" /T | Out-Null

# 3. Copy all .ps1 and .py files
Copy-Item -Path "*.ps1" -Destination $installPath -Force
Copy-Item -Path "*.py"  -Destination $installPath -Force

# 4. Copy subfolders (logs, uploads, quarantine)
foreach ($f in $folders) {
    $sourceFolder = Join-Path (Get-Location) $f
    if (Test-Path $sourceFolder) {
        Copy-Item -Path $sourceFolder -Destination $installPath -Recurse -Force
    }
}

# 5. Register scheduled task to run agent every 5 minutes
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installPath\collect_events.ps1`""
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -RepeatIndefinitely -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

# Remove existing task if it exists
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal

Write-Host "Scheduled Task registered: $taskName"
Write-Host "Mackalishis AV agent installation complete!"
