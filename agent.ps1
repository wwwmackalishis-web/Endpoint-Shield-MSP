# ----------------------------------------
# Mackalishis MSP Agent - canonical endpoint agent.
# Sends a full system heartbeat to app/main.py's /agents/heartbeat every
# interval. This is the only agent in the repo whose payload shape matches
# the backend; agent.py (Python) talks to a retired, incompatible API and
# should not be run.
#
# Configure per-machine via environment variables (set them in the
# Scheduled Task action, or via `[Environment]::SetEnvironmentVariable(...,
# 'Machine')` during install) rather than editing this file per deployment:
#   MSP_SERVER_URL   e.g. https://endpoint-shield-msp.onrender.com  (default: http://127.0.0.1:9000)
#   MSP_API_KEY      must match the backend's MSP_API_KEY once auth is enabled (default: none)
#   MSP_HEARTBEAT_SEC   interval in seconds (default: 60)
#   MSP_TENANT_ID    which client this device belongs to, e.g. "Riverside Dental"
#                    (default: none - the backend files it under the "Default" tenant)
# ----------------------------------------

$server = if ($env:MSP_SERVER_URL) { $env:MSP_SERVER_URL } else { "http://127.0.0.1:9000" }
$apiKey = $env:MSP_API_KEY
$tenant = $env:MSP_TENANT_ID
$intervalSec = if ($env:MSP_HEARTBEAT_SEC) { [int]$env:MSP_HEARTBEAT_SEC } else { 60 }
$hostname = $env:COMPUTERNAME

$logDir = Join-Path $env:ProgramData "MackalishisMSP"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir "agent.log"

function Write-AgentLog {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logFile -Value $line
    Write-Host $line
}

function Get-AntivirusStatus {
    # Patch & Vulnerability Compliance Agent, subagent 3b. Get-MpComputerStatus
    # is Windows Defender-specific and throws if Defender is disabled/absent
    # (a third-party AV replaced it, a locked-down build removed it, this
    # isn't Windows at all) - caught here so a heartbeat still goes out with
    # av fields simply omitted rather than failing the whole heartbeat over
    # a status check nobody asked to be required.
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        return @{
            av_enabled = [bool]($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled)
            av_signature_updated_at = $mp.AntivirusSignatureLastUpdated.ToUniversalTime().ToString("o")
        }
    } catch {
        Write-AgentLog "Could not read Defender status: $($_.Exception.Message)" "WARN"
        return @{}
    }
}

function Get-SystemInfo {
    $cpu = (Get-CimInstance Win32_Processor | Select-Object -ExpandProperty LoadPercentage)
    $ram = [math]::Round((Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize / 1024) # MB
    $disk = [math]::Round((Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Measure-Object -Property Size -Sum).Sum / 1GB)
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "169.*" } | Select-Object -First 1).IPAddress
    $info = @{
        hostname = $hostname
        ip = $ip
        cpu = $cpu
        ram = $ram
        disk = $disk
        os = $os
    }
    if ($tenant) { $info["tenant"] = $tenant }
    (Get-AntivirusStatus).GetEnumerator() | ForEach-Object { $info[$_.Key] = $_.Value }
    return $info
}

Write-AgentLog "Agent starting. server=$server interval=${intervalSec}s auth=$(if ($apiKey) { 'on' } else { 'off' })"

# Infinite heartbeat loop. Left as a loop (not a one-shot) so a Scheduled
# Task with "Restart on failure" can supervise the whole process - see
# install-agent.ps1. A crash here just means the task restarts the script;
# it does not lose heartbeats beyond the one in flight.
while ($true) {
    try {
        $body = Get-SystemInfo | ConvertTo-Json
        $headers = @{}
        if ($apiKey) { $headers["X-API-Key"] = $apiKey }
        Invoke-RestMethod -Method POST -Uri "$server/agents/heartbeat" -Body $body -ContentType "application/json" -Headers $headers -TimeoutSec 15 | Out-Null
        Write-AgentLog "Heartbeat sent for $hostname"
    } catch {
        Write-AgentLog "Heartbeat failed: $($_.Exception.Message)" "ERROR"
    }
    Start-Sleep -Seconds $intervalSec
}
