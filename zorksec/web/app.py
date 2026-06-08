"""ZorkSec web dashboard (Flask + Flask-SocketIO, gevent async mode).

Security posture (beginner-safe defaults):
  * binds to 127.0.0.1 until the default password is changed
  * login required for every page and API route
  * forced password change on first login
  * tool execution is allow-listed: the browser sends a tool *slug* and an
    action (install/run); the server builds the command from the trusted
    catalog. The free-form command runner is explicitly flagged and audited.
  * graceful Ctrl+C shutdown.
"""

from __future__ import annotations

import functools
import secrets
import shlex
from typing import Callable

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session as flask_session,
    url_for,
)
from flask_socketio import SocketIO

from zorksec.config import Settings, get_settings
from zorksec.db.session import init_db, session_scope
from zorksec.services.ai_service import AiService
from zorksec.services.auth_service import AuthError, AuthService
from zorksec.services.dependency_service import DependencyService
from zorksec.services.discovery_service import DiscoveryService
from zorksec.services.executor_service import (
    ExecutionError,
    build_install_command,
    build_run_command,
)
from zorksec.services.lab_service import HYPERVISORS, VM_TEMPLATES, LabService
from zorksec.services.metrics_service import MetricsService
from zorksec.services.registry_service import RegistryService
from zorksec.repositories.audit_repository import AuditRepository
from zorksec.repositories.history_repository import HistoryRepository
from zorksec.repositories.tool_repository import ToolRepository
from zorksec.utils.logging import get_logger
from zorksec.web.terminal import TerminalManager

logger = get_logger(__name__)

# Theme colours applied by templates based on the active team profile.
THEMES = {
    "blue": {"name": "Blue Team", "accent": "#3da9fc", "bg": "#0a0f1e", "panel": "#101a33"},
    "red": {"name": "Red Team", "accent": "#ff4d4d", "bg": "#160a0a", "panel": "#241010"},
    "both": {"name": "Purple (Both)", "accent": "#b06cf0", "bg": "#120a1e", "panel": "#1d1030"},
}


def _login_required(view: Callable) -> Callable:
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not flask_session.get("user_id"):
            return redirect(url_for("login"))
        if flask_session.get("must_change_password") and request.endpoint not in (
            "change_password", "logout", "static",
        ):
            return redirect(url_for("change_password"))
        return view(*args, **kwargs)

    return wrapped


def create_app(settings: Settings | None = None) -> tuple[Flask, SocketIO]:
    settings = settings or get_settings()
    init_db(settings)

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    app.config["ZORKSEC_SETTINGS"] = settings

    socketio = SocketIO(app, async_mode="gevent", cors_allowed_origins="*")
    terminals = TerminalManager()

    # ------------------------------------------------------------------ helpers
    def current_team() -> str:
        return flask_session.get("team", "both")

    def theme() -> dict:
        return THEMES.get(current_team(), THEMES["both"])

    # ------------------------------------------------------------------ auth
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            with session_scope(settings) as db:
                auth = AuthService(db, settings)
                auth.ensure_default_user()
                try:
                    result = auth.login(username, password, ip_address=request.remote_addr)
                    flask_session["user_id"] = result.user_id
                    flask_session["username"] = result.username
                    flask_session["must_change_password"] = result.must_change_password
                    flask_session.setdefault("team", "both")
                    return redirect(url_for("dashboard"))
                except AuthError as exc:
                    error = str(exc)
        return render_template(
            "login.html",
            error=error,
            default_user=settings.default_username,
            default_pass=settings.default_password,
        )

    @app.route("/logout")
    def logout():
        username = flask_session.get("username")
        flask_session.clear()
        if username:
            with session_scope(settings) as db:
                AuditRepository(db).record("logout", username=username)
        return redirect(url_for("login"))

    @app.route("/change-password", methods=["GET", "POST"])
    @_login_required
    def change_password():
        error = None
        if request.method == "POST":
            old = request.form.get("old_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if new != confirm:
                error = "New passwords do not match."
            else:
                with session_scope(settings) as db:
                    try:
                        AuthService(db, settings).change_password(
                            flask_session["username"], old, new
                        )
                        flask_session["must_change_password"] = False
                        return redirect(url_for("dashboard"))
                    except AuthError as exc:
                        error = str(exc)
        return render_template("change_password.html", error=error, theme=theme())

    # ------------------------------------------------------------------ profile
    @app.route("/profile", methods=["POST"])
    @_login_required
    def set_profile():
        team = request.form.get("team", "both")
        if team in THEMES:
            flask_session["team"] = team
        return redirect(url_for("dashboard"))

    # ------------------------------------------------------------------ pages
    @app.route("/")
    @_login_required
    def dashboard():
        with session_scope(settings) as db:
            svc = RegistryService(db)
            if svc.tools.count() == 0:
                svc.seed_catalog()
            DiscoveryService(db).sync_installed_status()
            rows = svc.snapshot(current_team())
            categories = svc.list_categories(current_team())
            history = HistoryRepository(db).recent(8)
            history_view = [
                {"tool": h.tool_slug, "action": h.action, "success": h.success,
                 "code": h.exit_code, "when": h.created_at.strftime("%Y-%m-%d %H:%M")}
                for h in history
            ]
        installed = sum(1 for r in rows if r.installed)
        return render_template(
            "dashboard.html",
            theme=theme(),
            team=current_team(),
            themes=THEMES,
            username=flask_session.get("username"),
            categories=categories,
            tools=rows,
            tool_count=len(rows),
            installed_count=installed,
            history=history_view,
        )

    @app.route("/lab")
    @_login_required
    def lab():
        with session_scope(settings) as db:
            lab_svc = LabService(db)
            vms = [
                {"id": v.id, "name": v.name, "role": v.role, "hypervisor": v.hypervisor,
                 "network": v.network_mode, "isolated": v.isolated}
                for v in lab_svc.list_vms()
            ]
        return render_template(
            "lab.html",
            theme=theme(),
            team=current_team(),
            hypervisors=HYPERVISORS,
            templates=VM_TEMPLATES,
            vms=vms,
        )

    @app.route("/terminal")
    @_login_required
    def terminal():
        slug = request.args.get("tool", "")
        action = request.args.get("action", "run")
        custom = request.args.get("cmd", "")
        title = custom or f"{action}: {slug}" or "terminal"
        return render_template(
            "terminal.html",
            theme=theme(),
            slug=slug,
            action=action,
            custom=custom,
            title=title,
        )

    # ------------------------------------------------------------------ API
    @app.route("/api/threatintel")
    @_login_required
    def api_threatintel():
        from zorksec.services.ti_service import ThreatIntelService
        with session_scope(settings) as db:
            svc = ThreatIntelService(db)
            svc.seed_sample_feed()
            dash = svc.dashboard()
            payload = {
                "counts": dash["counts"],
                "feeds": {
                    key: [{"source": i.source, "indicator": i.indicator,
                           "description": i.description} for i in dash[key]]
                    for key in ("ioc", "malware", "url", "domain")
                },
                "sources": [{"name": s.name, "category": s.category,
                             "note": s.beginner_note, "url": s.url} for s in svc.sources()],
            }
        return payload

    @app.route("/api/threatintel/lookup", methods=["POST"])
    @_login_required
    def api_ti_lookup():
        from zorksec.services.ti_service import ThreatIntelService
        data = request.get_json(silent=True) or {}
        with session_scope(settings) as db:
            return ThreatIntelService(db).lookup(data.get("indicator", ""))

    @app.route("/api/attack")
    @_login_required
    def api_attack():
        from zorksec.services.attack_service import AttackService
        with session_scope(settings) as db:
            svc = RegistryService(db)
            if svc.tools.count() == 0:
                svc.seed_catalog()
            coverage = AttackService(db).coverage_by_tactic()
            techniques = AttackService(db).coverage_by_technique()
            return {
                "tactics": [{"id": t.tactic_id, "name": t.tactic, "note": t.explanation,
                             "covered": t.covered_count, "total": t.technique_count}
                            for t in coverage],
                "techniques": [{"id": tc.technique_id, "name": tc.name, "tactic": tc.tactic,
                                "explanation": tc.explanation, "tools": tc.tools}
                               for tc in techniques],
            }

    @app.route("/api/dfir")
    @_login_required
    def api_dfir():
        from zorksec.services.dfir_service import DfirService
        return {"playbooks": [
            {"key": p.key, "name": p.name, "summary": p.summary,
             "steps": [{"title": s.title, "detail": s.detail, "tools": s.tools}
                       for s in p.steps]}
            for p in DfirService.playbooks()
        ]}

    @app.route("/api/detection/validate", methods=["POST"])
    @_login_required
    def api_detection_validate():
        from zorksec.services.detection_service import DetectionService
        data = request.get_json(silent=True) or {}
        rule_text = data.get("rule", "")
        event = data.get("event") or {}
        return DetectionService.test_rule(rule_text, event)

    @app.route("/api/detection/templates")
    @_login_required
    def api_detection_templates():
        from zorksec.services.detection_service import DetectionService
        return {"templates": DetectionService.templates()}

    @app.route("/api/report", methods=["POST"])
    @_login_required
    def api_report():
        from zorksec.services.report_service import ReportService
        data = request.get_json(silent=True) or {}
        with session_scope(settings) as db:
            svc = ReportService(db, settings)
            try:
                path = svc.export_to_file(
                    data.get("type", "incident"),
                    data.get("title", "ZorkSec Report"),
                    data.get("context", {"summary": data.get("summary", "")}),
                    data.get("format", "markdown"),
                )
            except ValueError as exc:
                return {"error": str(exc)}, 400
            return {"path": path, "formats": ReportService.formats()}

    @app.route("/api/metrics")
    @_login_required
    def api_metrics():
        return MetricsService().collect().to_dict()

    @app.route("/api/dependencies")
    @_login_required
    def api_dependencies():
        deps = DependencyService().detect()
        return {"dependencies": [
            {"key": d.key, "name": d.name, "present": d.present,
             "version": d.version, "hint": d.install_hint}
            for d in deps
        ]}

    @app.route("/api/tools")
    @_login_required
    def api_tools():
        with session_scope(settings) as db:
            svc = RegistryService(db)
            if svc.tools.count() == 0:
                svc.seed_catalog()
            rows = svc.snapshot(current_team())
        return {"tools": [
            {"slug": r.slug, "name": r.name, "category": r.category, "team": r.team,
             "installed": r.installed, "health": r.health_status, "note": r.beginner_note,
             "isolation": r.requires_isolation, "docs": r.docs_url}
            for r in rows
        ]}

    @app.route("/api/ai", methods=["POST"])
    @_login_required
    def api_ai():
        data = request.get_json(silent=True) or {}
        prompt = data.get("prompt", "")
        with session_scope(settings) as db:
            reply = AiService(db).ask(prompt, user_id=flask_session.get("user_id"))
        return {"reply": reply.text, "source": reply.source}

    @app.route("/api/lab/vm", methods=["POST"])
    @_login_required
    def api_lab_add():
        data = request.get_json(silent=True) or {}
        with session_scope(settings) as db:
            vm, check = LabService(db).add_vm(
                name=data.get("name", "Unnamed"),
                role=data.get("role", "target"),
                hypervisor=data.get("hypervisor", "virtualbox"),
                network_mode=data.get("network_mode", "hostonly"),
                notes=data.get("notes", ""),
            )
            return {"id": vm.id, "safe": check.ok, "message": check.message}

    # ------------------------------------------------------------------ socket
    @socketio.on("start")
    def on_start(data):
        """Begin a terminal session for a tool action or a flagged custom cmd."""
        from flask import request as sock_request  # sid lives on the request

        sid = sock_request.sid  # type: ignore[attr-defined]
        slug = (data or {}).get("tool", "")
        action = (data or {}).get("action", "run")
        custom = (data or {}).get("cmd", "")

        argv: list[str] | None = None
        shell = False
        cwd = None
        username = flask_session.get("username")

        with session_scope(settings) as db:
            audit = AuditRepository(db)
            if custom:
                # Free-form runner: explicitly flagged and fully audited.
                audit.record("exec", username=username,
                             detail=f"custom command: {custom}", success=True)
                argv = [custom]
                shell = True
            elif slug:
                tool = ToolRepository(db).get_by_slug(slug)
                if tool is None:
                    socketio.emit("output", {"data": f"Unknown tool '{slug}'.\r\n"}, to=sid)
                    socketio.emit("exit", {"code": 1}, to=sid)
                    return
                try:
                    if action == "install":
                        cmd = build_install_command(
                            tool.install_method, tool.install_target, slug
                        )
                        if cmd is None:
                            socketio.emit("output",
                                          {"data": f"{tool.name} is built-in; nothing to install.\r\n"},
                                          to=sid)
                            socketio.emit("exit", {"code": 0}, to=sid)
                            return
                    else:
                        cmd = build_run_command(tool)
                except ExecutionError as exc:
                    socketio.emit("output", {"data": f"{exc}\r\n"}, to=sid)
                    socketio.emit("exit", {"code": 1}, to=sid)
                    return
                argv = cmd.argv
                shell = cmd.shell
                cwd = cmd.cwd
                audit.record("exec", username=username,
                             detail=f"{action} {slug}: {cmd.display()}", success=True)

        if argv is None:
            socketio.emit("output", {"data": "Nothing to run.\r\n"}, to=sid)
            socketio.emit("exit", {"code": 1}, to=sid)
            return

        # Build the command line to seed into an interactive shell. This keeps a
        # live prompt open so the user can type and run more commands in the
        # browser terminal (fixing the "can't type / process exits" problem).
        initial = argv[0] if shell else " ".join(shlex.quote(a) for a in argv)
        terminals.start(sid, argv, shell=shell, cwd=cwd,
                        interactive=True, initial_command=initial)
        banner = ("\r\n\x1b[1;36m[ZorkSec terminal]\x1b[0m running: "
                  f"{initial}\r\n"
                  "\x1b[2mType commands below. Use 'exit' to close this terminal.\x1b[0m\r\n")
        socketio.emit("output", {"data": banner}, to=sid)

        def on_output(text: str) -> None:
            socketio.emit("output", {"data": text}, to=sid)

        def on_exit(code: int) -> None:
            socketio.emit("output", {"data": f"\r\n[process exited with code {code}]\r\n"}, to=sid)
            socketio.emit("exit", {"code": code}, to=sid)

        socketio.start_background_task(
            terminals.pump, sid, on_output, on_exit, socketio.sleep
        )

    @socketio.on("input")
    def on_input(data):
        from flask import request as sock_request

        sid = sock_request.sid  # type: ignore[attr-defined]
        sess = terminals.get(sid)
        if sess:
            sess.write((data or {}).get("data", ""))

    @socketio.on("resize")
    def on_resize(data):
        from flask import request as sock_request

        sid = sock_request.sid  # type: ignore[attr-defined]
        sess = terminals.get(sid)
        if sess:
            sess.set_winsize(int((data or {}).get("rows", 24)),
                             int((data or {}).get("cols", 80)))

    @socketio.on("disconnect")
    def on_disconnect():
        from flask import request as sock_request

        sid = sock_request.sid  # type: ignore[attr-defined]
        terminals.stop(sid)

    return app, socketio


def _find_free_port(host: str, preferred: int, attempts: int = 12) -> int:
    """Return a free TCP port.

    Tries the preferred port first, then a handful of nearby/random ports so a
    busy port (e.g. another server on 8765) never blocks startup.
    """
    import random
    import socket

    candidates = [preferred, preferred + 1, preferred + 2, 8080, 8000, 5000]
    # Top up with random high ports for the remaining attempts.
    while len(candidates) < attempts:
        candidates.append(random.randint(20000, 59999))

    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                continue
    # Last resort: let the OS pick any free port.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def _open_browser_when_ready(url: str, host: str, port: int) -> None:
    """Open the default browser once the server is accepting connections.

    Runs in a short-lived daemon thread so it never blocks the server. Failures
    (e.g. headless host) are silently ignored - the URL is always printed too.
    """
    import socket
    import threading
    import time
    import webbrowser

    def _worker() -> None:
        for _ in range(40):  # up to ~10s
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.25)
                if sock.connect_ex((host, port)) == 0:
                    break
            time.sleep(0.25)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()


def run_web(host: str | None = None, port: int | None = None,
            settings: Settings | None = None, open_browser: bool = True) -> int:
    """Run the dashboard: auto-pick a free port, open the browser, graceful Ctrl+C."""
    settings = settings or get_settings()
    app, socketio = create_app(settings)

    # Beginner-safe binding: stay on localhost until the default password is changed.
    bind_host = host or settings.web_host
    preferred_port = port or settings.web_port

    with session_scope(settings) as db:
        auth = AuthService(db, settings)
        user = auth.ensure_default_user()
        still_default = user.must_change_password
    if still_default and bind_host not in ("127.0.0.1", "localhost"):
        logger.warning("Refusing to bind to %s with default password; using 127.0.0.1.",
                       bind_host)
        bind_host = "127.0.0.1"

    # Auto-select a free port so a busy port never blocks startup.
    bind_port = _find_free_port(bind_host, preferred_port)
    if bind_port != preferred_port:
        logger.info("Port %s busy; using free port %s instead.", preferred_port, bind_port)

    url = f"http://{bind_host}:{bind_port}"
    print(f"ZorkSec dashboard: {url}  (Ctrl+C to stop)")
    if bind_port != preferred_port:
        print(f"(port {preferred_port} was busy - automatically switched to {bind_port})")
    print(f"Login: {settings.default_username} / {settings.default_password}")

    if open_browser:
        _open_browser_when_ready(url, bind_host, bind_port)

    try:
        socketio.run(app, host=bind_host, port=bind_port)
    except KeyboardInterrupt:
        print("\nShutting down ZorkSec dashboard.")
    return 0
