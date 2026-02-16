import requests

url = "http://127.0.0.1:8000/scan/file"
file_path = r"C:\Windows\System32\notepad.exe"

with open(file_path, "rb") as f:
    response = requests.post(url, files={"file": f})

print(response.status_code)
print(response.json())




function avroot {
    Set-Location "C:\Users\Anthony McNeill\antivirus-orchestrator"
}

