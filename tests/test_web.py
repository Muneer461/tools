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
    # CSRF is disabled for the form-flow tests (Flask-WTF style); dedicated
    # tests below verify CSRF enforcement explicitly.
    app.config.update(TESTING=True, CSRF_ENABLED=False)
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



# ---------------------------------------------------------------------------
# Auto-port selection + interactive terminal (Kali fixes)
# ---------------------------------------------------------------------------
import socket as _socket

from zorksec.web.app import _find_free_port
from zorksec.web.terminal import TerminalManager


def test_find_free_port_returns_open_port(zorksec_home):
    port = _find_free_port("127.0.0.1", 8765)
    # We should be able to bind whatever it returned.
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    finally:
        s.close()


def test_find_free_port_switches_when_busy(zorksec_home):
    blocker = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    blocker.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 8765))
    blocker.listen(1)
    try:
        chosen = _find_free_port("127.0.0.1", 8765)
        assert chosen != 8765, "should switch away from a busy preferred port"
    finally:
        blocker.close()


def test_interactive_terminal_runs_initial_command_and_accepts_input(zorksec_home):
    """The web terminal must stay interactive: initial command runs AND the
    live shell accepts further typed input (the Kali 'can't type' fix)."""
    import threading
    import time

    collected: list[str] = []
    done = threading.Event()
    mgr = TerminalManager()
    sess = mgr.start("t1", ["echo", "x"], shell=False,
                     interactive=True, initial_command="echo INITIAL_OK")

    def pump():
        mgr.pump("t1", collected.append,
                 lambda code: done.set(), time.sleep)

    threading.Thread(target=pump, daemon=True).start()
    time.sleep(0.8)
    sess.write("echo FOLLOWUP_OK\n")
    time.sleep(0.8)
    sess.write("exit\n")
    done.wait(timeout=5)

    text = "".join(collected)
    assert "INITIAL_OK" in text       # the tool/initial command ran
    assert "FOLLOWUP_OK" in text      # the user can still type and execute



# ---------------------------------------------------------------------------
# Password recovery + usage/docs + run-target (new features)
# ---------------------------------------------------------------------------
def test_login_page_has_forgot_link(client):
    body = client.get("/login").get_data(as_text=True)
    assert "/forgot-password" in body


def test_forgot_password_unknown_user_shows_error(client):
    resp = client.post("/forgot-password", data={"username": "ghost"})
    body = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "No security question" in body or "unknown" in body.lower()


def test_security_question_set_then_recover(client):
    _login_full(client)
    # Set a recovery question.
    resp = client.post("/security-question", data={
        "question": "First pet?", "answer": "Whiskers"})
    assert resp.status_code == 200
    assert "Saved" in resp.get_data(as_text=True)
    # Log out, then the forgot flow should reveal the question.
    client.get("/logout")
    step1 = client.post("/forgot-password", data={"username": "zorksec"})
    assert "First pet?" in step1.get_data(as_text=True)
    # Reset with the correct answer.
    step2 = client.post("/reset-password", data={
        "username": "zorksec", "answer": "whiskers",
        "new_password": "RecoveredPass1!", "confirm_password": "RecoveredPass1!"})
    assert step2.status_code == 302  # redirected to login
    # New password works.
    login = client.post("/login", data={"username": "zorksec", "password": "RecoveredPass1!"})
    assert login.status_code == 302


def test_api_usage_returns_info(client):
    _login_full(client)
    data = client.get("/api/usage?tool=nmap").get_json()
    assert data["slug"] == "nmap"
    assert "binary" in data and "usage_text" in data


def test_usage_page_renders(client):
    _login_full(client)
    resp = client.get("/usage?tool=nmap")
    assert resp.status_code == 200
    assert "usage" in resp.get_data(as_text=True).lower()


def test_run_target_headless_falls_back(client, monkeypatch):
    _login_full(client)
    # No DISPLAY in CI -> should report not launched (graceful fallback).
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    data = client.post("/api/run-target", json={"tool": "nmap"}).get_json()
    assert data["launched"] is False



# ---------------------------------------------------------------------------
# Security hardening: CSRF, restricted CORS, persistent secret key, socket auth
# ---------------------------------------------------------------------------
import re as _re

from flask_socketio import SocketIO


@pytest.fixture()
def csrf_client(zorksec_home):
    """A client with CSRF protection ENABLED (default production behaviour)."""
    settings = get_settings()
    app, _sio = create_app(settings)
    app.config.update(CSRF_ENABLED=True)
    return app.test_client()


def _csrf_token_from(html: str) -> str:
    m = _re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "CSRF token not found in form"
    return m.group(1)


def test_login_post_without_csrf_token_rejected(csrf_client):
    resp = csrf_client.post("/login", data={"username": "zorksec", "password": "zorksec"})
    assert resp.status_code == 400


def test_login_post_with_csrf_token_succeeds(csrf_client):
    page = csrf_client.get("/login").get_data(as_text=True)
    token = _csrf_token_from(page)
    resp = csrf_client.post("/login", data={
        "username": "zorksec", "password": "zorksec", "csrf_token": token})
    assert resp.status_code == 302  # accepted -> redirect


def test_login_form_renders_csrf_field(client):
    body = client.get("/login").get_data(as_text=True)
    assert 'name="csrf_token"' in body


def test_cors_origins_are_restricted_not_wildcard(zorksec_home):
    settings = get_settings()
    origins = settings.allowed_origins()
    assert "*" not in origins
    assert any("127.0.0.1" in o for o in origins)
    assert all(o.startswith("http://") or o.startswith("https://") for o in origins)


def test_secret_key_is_persistent_across_app_instances(zorksec_home):
    settings = get_settings()
    app1, _ = create_app(settings)
    app2, _ = create_app(settings)
    # A freshly minted key each restart would differ; persistence keeps it stable.
    assert app1.config["SECRET_KEY"] == app2.config["SECRET_KEY"]
    assert len(app1.config["SECRET_KEY"]) >= 32


def test_secret_key_env_override(zorksec_home, monkeypatch):
    monkeypatch.setenv("ZORKSEC_SECRET_KEY", "fixed-test-secret-value")
    settings = get_settings()
    app, _ = create_app(settings)
    assert app.config["SECRET_KEY"] == "fixed-test-secret-value"


def test_socketio_rejects_unauthenticated_connection(zorksec_home):
    settings = get_settings()
    app, socketio = create_app(settings)
    app.config.update(TESTING=True, CSRF_ENABLED=False)
    sio_client = socketio.test_client(app, flask_test_client=app.test_client())
    # No login -> the connect handler returns False and refuses the socket.
    assert sio_client.is_connected() is False


def test_socketio_allows_authenticated_connection(zorksec_home):
    settings = get_settings()
    app, socketio = create_app(settings)
    app.config.update(TESTING=True, CSRF_ENABLED=False)
    flask_client = app.test_client()
    flask_client.post("/login", data={"username": "zorksec", "password": "zorksec"})
    flask_client.post("/change-password", data={
        "old_password": "zorksec", "new_password": "StrongPass1!",
        "confirm_password": "StrongPass1!"})
    sio_client = socketio.test_client(app, flask_test_client=flask_client)
    assert sio_client.is_connected() is True
    sio_client.disconnect()


# ---------------------------------------------------------------------------
# Diagnostic Center + SOC utility web routes
# ---------------------------------------------------------------------------
def test_diagnostics_page_requires_login(client):
    assert client.get("/diagnostics").status_code == 302


def test_api_diagnostics_returns_report(client):
    _login_full(client)
    data = client.get("/api/diagnostics").get_json()
    assert "checks" in data and "overall" in data
    assert "root_cause" in data
    assert any(c["key"] == "python" for c in data["checks"])


def test_api_diagnostics_guide(client):
    _login_full(client)
    data = client.get("/api/diagnostics/guide").get_json()
    assert "guide" in data and "disk" in data["guide"]


def test_api_soc_ioc_parse(client):
    _login_full(client)
    data = client.post("/api/soc/ioc-parse",
                       json={"text": "evil at 203.0.113.45 hxxp://x[.]test"}).get_json()
    assert "203.0.113.45" in data["ips"]
    assert "http://x.test" in data["urls"]


def test_api_soc_ioc_generate(client):
    _login_full(client)
    data = client.post("/api/soc/ioc-generate",
                       json={"indicators": ["1.2.3.4"], "format": "csv"}).get_json()
    assert "1.2.3.4,ip" in data["output"]


def test_api_soc_log_parse(client):
    _login_full(client)
    data = client.post("/api/soc/log-parse",
                       json={"text": '{"a":1}\nuser=bob'}).get_json()
    assert data["count"] == 2


def test_api_soc_integrations(client):
    _login_full(client)
    data = client.get("/api/soc/integrations").get_json()
    assert "cyberchef" in data
