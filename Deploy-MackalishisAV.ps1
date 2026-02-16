$SourceRoot = "C:\Users\Anthony McNeill\antivirus-orchestrator\dist"
$AgentRoot  = "C:\Program Files\MackalishisAV"

$ExeName    = "MackalishisAVAgent.exe"
$XmlName    = "MackalishisAVAgent.xml"
$ServiceName = "MackalishisAVAgent"

Write-Host "Starting Clean Deployment..."

# Must be admin
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run PowerShell as Administrator."
    exit
}

# Create folder
if (!(Test-Path $AgentRoot)) {
    New-Item -ItemType Directory -Path $AgentRoot -Force | Out-Null
}

# Copy EXE
Copy-Item "$SourceRoot\$ExeName" -Destination "$AgentRoot\$ExeName" -Force

# Copy XML (adjust path if needed)
Copy-Item "C:\Users\Anthony McNeill\antivirus-orchestrator\$XmlName" `
          -Destination "$AgentRoot\$XmlName" -Force

Write-Host "Files copied."

# Service reinstall logic
$ExePath = Join-Path $AgentRoot $ExeName

$existingService = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath $ExePath -ArgumentList "uninstall" -Wait
}

Start-Process -FilePath $ExePath -ArgumentList "install" -Wait
Start-Service $ServiceName

$svc = Get-Service $ServiceName
Write-Host "Service Status: $($svc.Status)"



