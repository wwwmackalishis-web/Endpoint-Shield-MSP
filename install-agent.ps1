# Installs agent.ps1 as a self-healing Scheduled Task: starts at boot, runs
# as SYSTEM (survives logout), and restarts automatically if it ever exits
# or crashes. Requires an elevated PowerShell prompt.
#
# Before running this on ANY machine you do not own - a client's, for a
# paid technical audit or otherwise - get written consent first and be
# ready to explain what it does: it is unsigned custom software that some
# third-party AV/EDR products may flag or block on sight, and a client's IT
# staff (if any) may reasonably object to an unfamiliar Scheduled Task
# appearing without warning. See uninstall-agent.ps1, its companion script,
# for how to take it back off cleanly when a scoped/time-boxed audit ends -
# this installer sets up something meant to run indefinitely by default and
# does not remove itself.
#
# Usage:
#   .\install-agent.ps1 -ServerUrl "https://endpoint-shield-msp.onrender.com" -ApiKey "<key>"
param(
    [string]$ServerUrl = "http://127.0.0.1:9000",
    [string]$ApiKey = "",
    [int]$HeartbeatSeconds = 60
)

$installPath = "C:\ProgramData\MackalishisMSP"
New-Item -ItemType Directory -Force -Path $installPath | Out-Null
Copy-Item ".\agent.ps1" "$installPath\agent.ps1" -Force

# Persist config where the task's own env-var block can read it back, since
# a Scheduled Task doesn't inherit the installer's process environment.
[Environment]::SetEnvironmentVariable("MSP_SERVER_URL", $ServerUrl, "Machine")
[Environment]::SetEnvironmentVariable("MSP_HEARTBEAT_SEC", $HeartbeatSeconds, "Machine")
if ($ApiKey) {
    [Environment]::SetEnvironmentVariable("MSP_API_KEY", $ApiKey, "Machine")
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installPath\agent.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 0)  # 0 = no time limit; agent.ps1 loops forever by design

Register-ScheduledTask -TaskName "Mackalishis MSP Agent" `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName "Mackalishis MSP Agent"

Write-Host "Installed. Task restarts on crash/logoff/reboot (up to 999 times, 1 min apart)."
Write-Host "Log: C:\ProgramData\MackalishisMSP\agent.log"
Write-Host "To remove everything this installed, run: .\uninstall-agent.ps1"
