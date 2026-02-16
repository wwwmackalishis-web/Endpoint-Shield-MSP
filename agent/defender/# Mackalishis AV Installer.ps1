# ================================
# Mackalishis AV Installer
# ================================

$SourceRoot  = "C:\Users\Anthony McNeill\antivirus-orchestrator\dist"
$XmlSource   = "C:\Users\Anthony McNeill\antivirus-orchestrator\dist\MackalishisAVAgent.xml"
$InstallPath = "C:\Program Files\MackalishisAV"

$ExeName     = "MackalishisAVAgent.exe"
$XmlName     = "MackalishisAVAgent.xml"
$ServiceName = "MackalishisAVAgent"

Write-Host "Starting Mackalishis AV Installation..."
Write-Host ""

# ====================================
# Ensure Running As Administrator
# ====================================
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {

    Write-Error "You must run this script as Administrator."
    exit
}

# ====================================
# Create Install Directory
# ====================================
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

# ====================================
# Copy Files
# ====================================
Copy-Item "$SourceRoot\$ExeName" -Destination "$InstallPath\$ExeName" -Force
Copy-Item $XmlSource -Destination "$InstallPath\$XmlName" -Force

Write-Host "Files copied successfully."

# ====================================
# Service Reinstall Logic
# ====================================
$ExePath = Join-Path $InstallPath $ExeName
$existingService = Get-Service $ServiceName -ErrorAction SilentlyContinue

if ($existingService) {
    Write-Host "Stopping existing service..."
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue

    Write-Host "Uninstalling previous service..."
    Start-Process -FilePath $ExePath -ArgumentList "uninstall" -Wait
}

# ====================================
# Install Service
# ====================================
Write-Host "Installing service..."
Start-Process -FilePath $ExePath -ArgumentList "install" -Wait

# ====================================
# Start Service
# ====================================
Write-Host "Starting service..."
Start-Service $ServiceName

# ====================================
# Confirm Status
# ====================================
$svc = Get-Service $ServiceName -ErrorAction SilentlyContinue

if ($svc -and $svc.Status -eq "Running") {
    Write-Host ""
    Write-Host "✅ Mackalishis AV Service Installed and Running Successfully!"
} else {
    Write-Host ""
    Write-Host "⚠️ Service did not start. Check XML configuration or logs."
}
