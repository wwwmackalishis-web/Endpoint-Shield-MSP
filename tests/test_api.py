import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# ✅ Test GET / root endpoint
def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "service" in data
    assert "app_version" in data
    assert "policy_version" in data

# ✅ Test POST /scan endpoint
def test_scan_endpoint_file_upload():
    # Create dummy file content
    file_content = b"dummy content"
    files = {"file": ("dummy.txt", file_content)}

    response = client.post("/scan", files=files)
    assert response.status_code == 200

    data = response.json()
    assert "filename" in data
    assert "verdict" in data
    assert "reason" in data
    assert "confidence" in data
