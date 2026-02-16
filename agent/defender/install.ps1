# Mackalishis AV Installer

$installPath = "C:\Program Files\MackalishisAV\Agent"

Write-Host "Installing Mackalishis AV Agent..."

# Create install directory
New-Item -ItemType Directory -Path $installPath -Force

# Copy agent files
Copy-Item ".\collect_events.ps1" $installPath -Force
Copy-Item ".\execute_action.ps1" $installPath -Force
Copy-Item ".\config.json" $installPath -Force

# Register Scheduled Task
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File `"$installPath\collect_events.ps1`""

$trigger = New-ScheduledTaskTrigger -AtStartup

Register-ScheduledTask `
    -TaskName "MackalishisAVAgent" `
    -Action $action `
    -Trigger $trigger `
    -Force

Write-Host "Installation complete."
