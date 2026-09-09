# ----------------------------------------
# Mackalishis MSP Production Setup
# ----------------------------------------

$basePath = "C:\Users\Anthony McNeill\antivirus-orchestrator"
$venvPath = "$basePath\venv"

Write-Host "Starting MSP Setup..."

# STEP 1 — Ensure folders exist
New-Item -ItemType Directory -Force -Path "$basePath\templates" | Out-Null
New-Item -ItemType Directory -Force -Path "$basePath\logs" | Out-Null

Write-Host "Project folders verified"

# STEP 2 — Create dashboard
$dashboard = @"
<!DOCTYPE html>
<html>
<head>
<title>Mackalishis MSP Dashboard</title>
<style>
body { font-family: Arial; margin:20px;}
table { border-collapse:collapse; width:100%;}
th,td { border:1px solid #ddd; padding:8px;}
th { background:#4CAF50; color:white;}
.online{color:green;font-weight:bold}
.offline{color:red;font-weight:bold}
button{padding:6px 12px;}
</style>
</head>

<body>

<h1>Mackalishis MSP Dashboard</h1>

<p>
Devices: {{ device_count }} |
Threats: {{ threat_count }}
</p>

<h2>Devices</h2>

<table>
<tr>
<th>ID</th>
<th>Hostname</th>
<th>IP</th>
<th>Status</th>
<th>Actions</th>
</tr>

{% for d in devices %}
<tr>
<td>{{ d.id }}</td>
<td>{{ d.hostname }}</td>
<td>{{ d.ip_address }}</td>
<td class="{{ d.status }}">{{ d.status }}</td>

<td>
<form method="post" action="/scan/{{ d.hostname }}">
<button>Scan</button>
</form>
</td>

</tr>
{% endfor %}

</table>

<h2>Threats</h2>

<table>
<tr>
<th>ID</th>
<th>Hash</th>
<th>Type</th>
<th>Severity</th>
</tr>

{% for t in threats %}
<tr>
<td>{{ t.id }}</td>
<td>{{ t.file_hash }}</td>
<td>{{ t.threat_type }}</td>
<td>{{ t.severity }}</td>
</tr>
{% endfor %}

</table>

</body>
</html>
"@

$dashboard | Set-Content "$basePath\templates\dashboard.html"

Write-Host "Dashboard template created"

# STEP 3 — Create Python venv
if (-Not (Test-Path "$venvPath\Scripts\python.exe")) {
    Write-Host "Creating Python virtual environment..."
    python -m venv $venvPath
}

# STEP 4 — Install dependencies
Write-Host "Installing Python packages..."

& "$venvPath\Scripts\pip.exe" install --upgrade pip
& "$venvPath\Scripts\pip.exe" install fastapi uvicorn jinja2 sqlalchemy pydantic python-multipart

# STEP 5 — Create DB tables
$createTables = @"
from database import Base, engine
import models
Base.metadata.create_all(bind=engine)
print("Database tables created")
"@

$createTables | Set-Content "$basePath\create_tables.py"

& "$venvPath\Scripts\python.exe" "$basePath\create_tables.py"

# STEP 6 — Start backend
Start-Process powershell -ArgumentList "-NoExit","-Command","cd `"$basePath`"; & `"$venvPath\Scripts\python.exe`" -m uvicorn app.main:app --host 127.0.0.1 --port 9000 --reload"

Start-Sleep 5

# STEP 7 — Open dashboard
Start-Process "http://127.0.0.1:9000/dashboard"

Write-Host ""
Write-Host "MSP Backend Running"
Write-Host "Dashboard: http://127.0.0.1:9000/dashboard"
Write-Host ""
