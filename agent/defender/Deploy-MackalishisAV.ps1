# ==============================================
# Mackalishis AV Agent - Production Deployment
# ==============================================

# Configuration
\C:\Program Files\MackalishisAV\Agent   = "C:\Program Files\MackalishisAV\Agent"
\logs   = "logs"
\MackalishisAV-Agent    = "MackalishisAV-Agent"
\collect_events.ps1  = "collect_events.ps1"
\collect_events.ps1 execute_action.ps1 config.json = @("collect_events.ps1","execute_action.ps1","config.json")

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator!"
    exit
}

# Create Agent folder if missing
try {
    if (-not (Test-Path \C:\Program Files\MackalishisAV\Agent)) {
        New-Item -Path \C:\Program Files\MackalishisAV\Agent -ItemType Directory -Force | Out-Null
        Write-Host "Created Agent folder: \C:\Program Files\MackalishisAV\Agent"
    } else {
        Write-Host "Agent folder already exists: \C:\Program Files\MackalishisAV\Agent"
    }
} catch {
    Write-Error "Failed to create/access \C:\Program Files\MackalishisAV\Agent. Error: \"
    exit
}

# Create logs folder if missing
\C:\Program Files\MackalishisAV\Agent\logs = Join-Path \C:\Program Files\MackalishisAV\Agent \logs
try {
    if (-not (Test-Path \C:\Program Files\MackalishisAV\Agent\logs)) {
        New-Item -Path \C:\Program Files\MackalishisAV\Agent\logs -ItemType Directory -Force | Out-Null
        Write-Host "Created logs folder: \C:\Program Files\MackalishisAV\Agent\logs"
    } else {
        Write-Host "Logs folder already exists: \C:\Program Files\MackalishisAV\Agent\logs"
    }
} catch {
    Write-Warning "Failed to create logs folder \C:\Program Files\MackalishisAV\Agent\logs. Error: \"
}

# Set folder permissions
try {
    icacls \C:\Program Files\MackalishisAV\Agent /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    icacls \C:\Program Files\MackalishisAV\Agent\logs /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    Write-Host "Folder permissions set for SYSTEM and Administrators."
} catch {
    Write-Warning "Failed to set permissions. Error: \"
}

# Copy required files
foreach (\config.json in \collect_events.ps1 execute_action.ps1 config.json) {
    \ = Join-Path \ \config.json
    \C:\Program Files\MackalishisAV\Agent\config.json   = Join-Path \C:\Program Files\MackalishisAV\Agent \config.json
    try {
        if (Test-Path \) {
            Copy-Item \ \C:\Program Files\MackalishisAV\Agent\config.json -Force
            Write-Host "Copied \config.json to \C:\Program Files\MackalishisAV\Agent"
        } else {
            Write-Warning "Source file missing: \"
        }
    } catch {
        Write-Warning "Failed to copy \config.json. Error: \"
    }
}

# Validate main script exists
\C:\Program Files\MackalishisAV\Agent\collect_events.ps1 = Join-Path \C:\Program Files\MackalishisAV\Agent \collect_events.ps1
if (-not (Test-Path \C:\Program Files\MackalishisAV\Agent\collect_events.ps1)) {
    Write-Error "Main script '\collect_events.ps1' not found in \C:\Program Files\MackalishisAV\Agent. Cannot register task."
    exit
}

# Remove old task if exists
try {
    if (Get-ScheduledTask -TaskName \MackalishisAV-Agent -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName \MackalishisAV-Agent -Confirm:\False
        Write-Host "Old scheduled task removed: \MackalishisAV-Agent"
    }
} catch {
    Write-Warning "Failed to remove old task. Error: \"
}

# Create persistent 15-minute scheduled task
try {
    \MSFT_TaskExecAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File "\C:\Program Files\MackalishisAV\Agent\collect_events.ps1""
    \MSFT_TaskTimeTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue)
    Register-ScheduledTask -TaskName \MackalishisAV-Agent -Action \MSFT_TaskExecAction -Trigger \MSFT_TaskTimeTrigger -User "SYSTEM" -RunLevel Highest -Force
    Write-Host "15-minute persistent task created successfully: \MackalishisAV-Agent"
} catch {
    Write-Error "Failed to create scheduled task. Error: \"
}

# Start task immediately
try {
    Start-ScheduledTask -TaskName \MackalishisAV-Agent
    Write-Host "Task started immediately: \MackalishisAV-Agent"
} catch {
    Write-Warning "Failed to start scheduled task. Error: \"
}

# Display recent log files
if (Test-Path \C:\Program Files\MackalishisAV\Agent\logs) {
    Write-Host "
Recent log files in \C:\Program Files\MackalishisAV\Agent\logs:
"
    try {
        Get-ChildItem \C:\Program Files\MackalishisAV\Agent\logs -File | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime | Format-Table -AutoSize
    } catch {
        Write-Warning "Failed to list log files. Error: \"
    }
} else {
    Write-Warning "Logs folder does not exist: \C:\Program Files\MackalishisAV\Agent\logs"
}

Write-Host "
Deployment Complete."
