# Removes everything install-agent.ps1 put on this machine: the Scheduled
# Task (stopped and unregistered, so it does not restart itself one more
# time on the way out), the installed copy of agent.ps1 and its logs under
# C:\ProgramData\MackalishisMSP, and the machine-level environment
# variables the installer set (MSP_SERVER_URL, MSP_HEARTBEAT_SEC,
# MSP_API_KEY). Requires an elevated PowerShell prompt, same as install.
#
# This exists specifically for the case install-agent.ps1 never accounted
# for: a short, consented technical audit on a client's network that ends
# with the agent actually coming off, not "the task nobody remembered to
# remove." Safe to re-run - every step below tolerates "already gone."
#
# Usage:
#   .\uninstall-agent.ps1

$ErrorActionPreference = "Continue"
$taskName = "Mackalishis MSP Agent"
$installPath = "C:\ProgramData\MackalishisMSP"

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "Stopping and removing scheduled task '$taskName'..."
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
} else {
    Write-Host "Scheduled task '$taskName' not found - already removed."
}

# Belt-and-suspenders: if the task was somehow removed without stopping the
# running process (e.g. a previous partial uninstall), stop any agent.ps1
# process still running from the installed path.
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -like "*$installPath\agent.ps1*" } |
    ForEach-Object {
        Write-Host "Stopping running agent process (PID $($_.ProcessId))..."
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }

if (Test-Path $installPath) {
    Write-Host "Removing installed files at $installPath..."
    Remove-Item -Path $installPath -Recurse -Force
} else {
    Write-Host "$installPath not found - already removed."
}

foreach ($varName in @("MSP_SERVER_URL", "MSP_HEARTBEAT_SEC", "MSP_API_KEY")) {
    if ([Environment]::GetEnvironmentVariable($varName, "Machine")) {
        [Environment]::SetEnvironmentVariable($varName, $null, "Machine")
    }
}

Write-Host ""
Write-Host "Uninstall complete. No Mackalishis MSP Agent components remain on this machine."
