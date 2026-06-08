"""Tests for the web dashboard: auth gating, login flow, and API routes."""

from __future__ import annotations

import pytest

flask = pytest.importorskip("flask")
pytest.importorskip("flask_socketio")

from zorksec.config import get_settings
from zorksec.web.app import create_app


@pytest.fixture()
def client(zorksec_home):
    settings = get_settings()
    app, _socketio = create_app(settings)
    app.config.update(TESTING=True)
    return app.test_client()


def test_dashboard_requires_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_page_shows_default_credentials(client):
    resp = client.get("/login")
    body = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "zorksec" in body  # default creds displayed


def test_login_then_redirected_to_change_password(client):
    resp = client.post("/login", data={"username": "zorksec", "password": "zorksec"})
    assert resp.status_code == 302
    # First login must change password.
    follow = client.get("/")
    assert follow.status_code == 302
    assert "/change-password" in follow.headers["Location"]


def test_bad_login_shows_error(client):
    resp = client.post("/login", data={"username": "zorksec", "password": "nope"})
    assert resp.status_code == 200
    assert "Invalid" in resp.get_data(as_text=True)


def test_change_password_unlocks_dashboard(client):
    client.post("/login", data={"username": "zorksec", "password": "zorksec"})
    resp = client.post("/change-password", data={
        "old_password": "zorksec",
        "new_password": "StrongPass1!",
        "confirm_password": "StrongPass1!",
    })
    assert resp.status_code == 302
    dash = client.get("/")
    assert dash.status_code == 200
    assert "ZorkSec" in dash.get_data(as_text=True)


def test_api_metrics_requires_login(client):
    assert client.get("/api/metrics").status_code == 302


def _login_full(client):
    client.post("/login", data={"username": "zorksec", "password": "zorksec"})
    client.post("/change-password", data={
        "old_password": "zorksec", "new_password": "StrongPass1!",
        "confirm_password": "StrongPass1!"})


def test_api_tools_returns_catalog(client):
    _login_full(client)
    data = client.get("/api/tools").get_json()
    assert "tools" in data and len(data["tools"]) > 0


def test_api_ai_offline_answer(client):
    _login_full(client)
    data = client.post("/api/ai", json={"prompt": "explain phishing"}).get_json()
    assert data["source"] == "offline"
    assert "phishing" in data["reply"].lower()


def test_api_lab_rejects_unsafe_target(client):
    _login_full(client)
    data = client.post("/api/lab/vm", json={
        "name": "Metasploitable", "role": "target",
        "hypervisor": "virtualbox", "network_mode": "bridged"}).get_json()
    assert data["safe"] is False
    assert "host-only" in data["message"].lower() or "internal" in data["message"].lower()


def test_api_threatintel_returns_feeds(client):
    _login_full(client)
    data = client.get("/api/threatintel").get_json()
    assert "counts" in data and "feeds" in data
    assert "sources" in data and len(data["sources"]) > 0


def test_api_ti_lookup(client):
    _login_full(client)
    client.get("/api/threatintel")  # seed sample feed
    data = client.post("/api/threatintel/lookup", json={"indicator": "203.0.113.45"}).get_json()
    assert data["type"] == "ip"


def test_api_attack_coverage(client):
    _login_full(client)
    data = client.get("/api/attack").get_json()
    assert len(data["tactics"]) == 14
    assert any(t["covered"] > 0 for t in data["tactics"])


def test_api_dfir_playbooks(client):
    _login_full(client)
    data = client.get("/api/dfir").get_json()
    assert len(data["playbooks"]) >= 4


def test_api_detection_validate(client):
    _login_full(client)
    templates = client.get("/api/detection/templates").get_json()["templates"]
    rule = templates["failed_logins"]
    result = client.post("/api/detection/validate",
                         json={"rule": rule, "event": {"EventID": 4625}}).get_json()
    assert result["valid"] is True
    assert result["fired"] is True


def test_api_report_export(client):
    _login_full(client)
    data = client.post("/api/report", json={
        "type": "incident", "title": "Web Incident", "format": "markdown",
        "context": {"summary": "via API"}}).get_json()
    assert data["path"].endswith(".md")
