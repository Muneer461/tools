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

import datetime as _dt
import functools
import hmac
import os
import secrets
import shlex
from typing import Callable

from flask import (
    Flask,
    abort,
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


# Endpoints whose state-changing (POST) form submissions must carry a valid
# CSRF token: login, password recovery/reset, settings, and admin forms.
_CSRF_PROTECTED_ENDPOINTS = frozenset({
    "login",
    "change_password",
    "forgot_password",
    "reset_password",
    "security_question",
    "set_profile",
})


def create_app(settings: Settings | None = None) -> tuple[Flask, SocketIO]:
    settings = settings or get_settings()
    init_db(settings)

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    # Persistent secret key (env / .env / on-disk file) so sessions survive
    # restarts instead of being invalidated by a freshly minted key each boot.
    app.config["SECRET_KEY"] = settings.resolve_secret_key()
    app.config["ZORKSEC_SETTINGS"] = settings
    # CSRF protection is on by default; tests may disable it explicitly.
    app.config.setdefault("CSRF_ENABLED", True)
    # Harden the session cookie.
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=_dt.timedelta(
            minutes=settings.session_timeout_minutes),
    )

    # CORS is restricted to localhost + any configured ZorkSec origins; the
    # previous wildcard ("*") allowed any site to drive the Socket.IO terminal.
    socketio = SocketIO(
        app,
        async_mode="gevent",
        cors_allowed_origins=settings.allowed_origins(),
    )
    terminals = TerminalManager()

    # ------------------------------------------------------------------ CSRF
    def _csrf_token() -> str:
        """Return the per-session CSRF token, creating one on first use."""
        token = flask_session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            flask_session["_csrf_token"] = token
        return token

    # Make ``csrf_token()`` callable from every template.
    app.jinja_env.globals["csrf_token"] = _csrf_token

    # Cache-busting stamp for static assets: derived from the CSS file's mtime
    # so a stale browser cache can never keep serving an old stylesheet/JS
    # after an upgrade (a real cause of "the new UI didn't take effect").
    try:
        _css_path = os.path.join(app.static_folder or "", "zorksec.css")
        app.jinja_env.globals["asset_v"] = str(int(os.path.getmtime(_css_path)))
    except OSError:
        app.jinja_env.globals["asset_v"] = "1"

    def _csrf_enabled() -> bool:
        return bool(app.config.get("CSRF_ENABLED", True))

    @app.before_request
    def _enforce_csrf():
        if not _csrf_enabled():
            return None
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        if request.endpoint not in _CSRF_PROTECTED_ENDPOINTS:
            return None
        sent = (request.form.get("csrf_token")
                or request.headers.get("X-CSRFToken", ""))
        expected = flask_session.get("_csrf_token", "")
        if not expected or not sent or not hmac.compare_digest(sent, expected):
            logger.warning("Rejected %s %s: missing/invalid CSRF token",
                           request.method, request.path)
            abort(400, description="Invalid or missing CSRF token.")
        return None

    # ------------------------------------------------------------------ helpers
    def current_team() -> str:
        return flask_session.get("team", "both")

    def theme() -> dict:
        return THEMES.get(current_team(), THEMES["both"])

    def _socket_authenticated() -> bool:
        """True when the Socket.IO client has a valid, fully-provisioned session."""
        if not flask_session.get("user_id"):
            return False
        if flask_session.get("must_change_password"):
            return False
        return True

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
                    flask_session.permanent = True
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
        must_change = bool(flask_session.get("must_change_password"))
        if request.method == "POST":
            old = request.form.get("old_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            question = request.form.get("question", "")
            answer = request.form.get("answer", "")
            if new != confirm:
                error = "New passwords do not match."
            elif must_change and (not question.strip() or not answer.strip()):
                # First-login wizard: a recovery question is mandatory so the
                # account is never left without a way to self-recover.
                error = "Set a recovery question and answer to finish setup."
            else:
                try:
                    # Both writes share one transaction: if the security
                    # question is rejected, the password change rolls back too,
                    # so the account is never left half-provisioned.
                    with session_scope(settings) as db:
                        auth = AuthService(db, settings)
                        auth.change_password(flask_session["username"], old, new)
                        if must_change or question.strip() or answer.strip():
                            auth.set_security_question(
                                flask_session["username"], question, answer)
                    flask_session["must_change_password"] = False
                    return redirect(url_for("dashboard"))
                except AuthError as exc:
                    error = str(exc)
        return render_template("change_password.html", error=error, theme=theme(),
                               must_change=must_change)

    # ------------------------------------------------------------------ password recovery
    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        """Step 1: user enters their username; we show their security question."""
        error = None
        question = None
        username = ""
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            with session_scope(settings) as db:
                question = AuthService(db, settings).get_security_question(username)
            if not question:
                error = ("No security question is set for that account, or the "
                         "username is unknown. Ask an admin to reset it.")
        return render_template("forgot_password.html", error=error,
                               question=question, username=username)

    @app.route("/reset-password", methods=["POST"])
    def reset_password():
        """Step 2: verify the answer and set a new password."""
        username = request.form.get("username", "").strip()
        answer = request.form.get("answer", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        error = None
        question = None
        with session_scope(settings) as db:
            auth = AuthService(db, settings)
            question = auth.get_security_question(username)
            if new != confirm:
                error = "New passwords do not match."
            else:
                try:
                    auth.reset_password_with_answer(username, answer, new)
                    return redirect(url_for("login"))
                except AuthError as exc:
                    error = str(exc)
        return render_template("forgot_password.html", error=error,
                               question=question, username=username)

    @app.route("/security-question", methods=["GET", "POST"])
    @_login_required
    def security_question():
        """Let a logged-in user set/update their recovery question + answer."""
        error = None
        saved = False
        current = None
        username = flask_session.get("username")
        with session_scope(settings) as db:
            current = AuthService(db, settings).get_security_question(username)
        if request.method == "POST":
            q = request.form.get("question", "")
            a = request.form.get("answer", "")
            with session_scope(settings) as db:
                try:
                    AuthService(db, settings).set_security_question(username, q, a)
                    saved = True
                    current = q.strip()
                except AuthError as exc:
                    error = str(exc)
        return render_template("security_question.html", theme=theme(),
                               error=error, saved=saved, current=current)

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

    @app.route("/usage")
    @_login_required
    def usage():
        """Documentation/usage page for a tool, auto-opened in a new tab.

        Shows the official docs link plus live, locally-generated usage
        (``<tool> --help`` / ``man``) so it works for catalog tools, tools
        pre-installed on Kali, and tools the user installed manually.
        """
        slug = request.args.get("tool", "")
        with session_scope(settings) as db:
            svc = RegistryService(db)
            if svc.tools.count() == 0:
                svc.seed_catalog()
            tool = svc.get(slug)
            from zorksec.services.usage_service import UsageService
            info = UsageService.usage_for(tool, slug_override=slug)
        return render_template("usage.html", theme=theme(), info=info)

    @app.route("/api/usage")
    @_login_required
    def api_usage():
        slug = request.args.get("tool", "")
        binary = request.args.get("binary", "")
        from zorksec.services.usage_service import UsageService
        with session_scope(settings) as db:
            svc = RegistryService(db)
            tool = svc.get(slug)
            # Build the usage info while the ORM object is still attached.
            return UsageService.usage_for(tool, binary_override=binary,
                                          slug_override=slug)

    @app.route("/api/run-target", methods=["POST"])
    @_login_required
    def api_run_target():
        """Launch a tool in a NATIVE Kali terminal window (option B).

        The browser-terminal option (A) is handled by the SocketIO flow; this
        endpoint covers "open in a real Kali terminal" by spawning a desktop
        terminal emulator running the tool. Returns whether a terminal was
        launched (it won't be on a headless host).
        """
        data = request.get_json(silent=True) or {}
        slug = data.get("tool", "")
        with session_scope(settings) as db:
            tool = ToolRepository(db).get_by_slug(slug)
            if tool is None:
                return {"launched": False, "error": f"Unknown tool '{slug}'."}, 404
            try:
                cmd = build_run_command(tool)
            except ExecutionError as exc:
                return {"launched": False, "error": str(exc)}, 400
            username = flask_session.get("username")
            AuditRepository(db).record(
                "exec", username=username,
                detail=f"native-terminal run {slug}: {cmd.display()}", success=True)
        from zorksec.services.usage_service import launch_native_terminal
        launched, detail = launch_native_terminal(cmd.argv, cmd.shell, cmd.cwd)
        return {"launched": launched, "detail": detail}

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

    # ------------------------------------------------------------------ SOC utilities
    @app.route("/api/soc/integrations")
    @_login_required
    def api_soc_integrations():
        from zorksec.services.soc_utils_service import SocUtilsService
        return SocUtilsService.integrations()

    @app.route("/api/soc/ioc-parse", methods=["POST"])
    @_login_required
    def api_soc_ioc_parse():
        from zorksec.services.soc_utils_service import SocUtilsService
        data = request.get_json(silent=True) or {}
        return SocUtilsService.parse_iocs(data.get("text", ""))

    @app.route("/api/soc/ioc-generate", methods=["POST"])
    @_login_required
    def api_soc_ioc_generate():
        from zorksec.services.soc_utils_service import SocUtilsService
        data = request.get_json(silent=True) or {}
        indicators = data.get("indicators") or []
        if isinstance(indicators, str):
            indicators = [ln for ln in indicators.splitlines() if ln.strip()]
        try:
            output = SocUtilsService.generate_iocs(
                indicators, data.get("format", "csv"), data.get("context", ""))
        except ValueError as exc:
            return {"error": str(exc)}, 400
        return {"output": output, "format": data.get("format", "csv")}

    @app.route("/api/soc/log-parse", methods=["POST"])
    @_login_required
    def api_soc_log_parse():
        from zorksec.services.soc_utils_service import SocUtilsService
        data = request.get_json(silent=True) or {}
        return SocUtilsService.parse_logs(data.get("text", ""))

    @app.route("/api/soc/pcap", methods=["POST"])
    @_login_required
    def api_soc_pcap():
        from zorksec.services.soc_utils_service import SocUtilsService
        data = request.get_json(silent=True) or {}
        return SocUtilsService.analyze_pcap(data.get("path", ""))

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

    @app.route("/api/tools/<slug>/resource-check")
    @_login_required
    def api_resource_check(slug):
        """Return the high-resource install warning for a tool (if any)."""
        from zorksec.services.resource_check_service import ResourceCheckService
        warning = ResourceCheckService.warning_for(slug)
        if warning is None:
            return {"slug": slug, "requires_confirmation": False}
        payload = warning.to_dict()
        payload["requires_confirmation"] = True
        return payload

    # ------------------------------------------------------------------ diagnostics
    @app.route("/diagnostics")
    @_login_required
    def diagnostics():
        return render_template("diagnostics.html", theme=theme(),
                               team=current_team())

    @app.route("/api/diagnostics")
    @_login_required
    def api_diagnostics():
        from zorksec.services.diagnostic_service import DiagnosticService
        report = DiagnosticService().run_full_diagnostic()
        payload = report.to_dict()
        payload["root_cause"] = DiagnosticService().root_cause_analysis(report)
        return payload

    @app.route("/api/diagnostics/repair", methods=["POST"])
    @_login_required
    def api_diagnostics_repair():
        from zorksec.services.diagnostic_service import DiagnosticService
        data = request.get_json(silent=True) or {}
        keys = data.get("keys")  # optional list of check keys
        username = flask_session.get("username")
        results = DiagnosticService().auto_repair(keys)
        with session_scope(settings) as db:
            AuditRepository(db).record(
                "diagnostic_repair", username=username,
                detail=f"auto-repair {keys or 'all failing'}", success=True)
        return {"results": [r.to_dict() for r in results]}

    @app.route("/api/diagnostics/guide")
    @_login_required
    def api_diagnostics_guide():
        from zorksec.services.diagnostic_service import DiagnosticService
        return {"guide": DiagnosticService().manual_repair_guide()}

    @app.route("/api/diagnostics/export", methods=["POST"])
    @_login_required
    def api_diagnostics_export():
        from zorksec.services.diagnostic_service import DiagnosticService
        data = request.get_json(silent=True) or {}
        fmt = data.get("format", "markdown")
        with session_scope(settings) as db:
            svc = DiagnosticService()
            report = svc.run_full_diagnostic()
            try:
                path = svc.export_report(report, fmt, session=db)
            except ValueError as exc:
                return {"error": str(exc)}, 400
        return {"path": path}

    # ------------------------------------------------------------------ Kali diagnostics
    @app.route("/kali-diagnostics")
    @_login_required
    def kali_diagnostics():
        return render_template("kali_diagnostics.html", theme=theme(),
                               team=current_team())

    @app.route("/api/kali/scan")
    @_login_required
    def api_kali_scan():
        from zorksec.services.kali_diagnostics_service import KaliDiagnosticsService
        svc = KaliDiagnosticsService()
        report = svc.scan()
        payload = report.to_dict()
        payload["root_cause"] = svc.root_cause_analysis(report)
        return payload

    @app.route("/api/kali/repair", methods=["POST"])
    @_login_required
    def api_kali_repair():
        """Auto or manual repair. mode=auto runs safe fixes; mode=manual returns steps."""
        from zorksec.services.kali_diagnostics_service import KaliDiagnosticsService
        data = request.get_json(silent=True) or {}
        mode = data.get("mode", "auto")
        keys = data.get("keys")
        username = flask_session.get("username")
        svc = KaliDiagnosticsService()
        if mode == "manual":
            return {"mode": "manual", "guide": svc.manual_guide()}
        results = svc.auto_repair(keys)
        with session_scope(settings) as db:
            AuditRepository(db).record(
                "kali_repair", username=username,
                detail=f"auto-repair {keys or 'all failing'}", success=True)
        return {"mode": "auto", "results": [r.to_dict() for r in results]}

    # ------------------------------------------------------------------ Help Center
    @app.route("/help")
    @_login_required
    def help_center():
        return render_template("help_center.html", theme=theme(),
                               team=current_team())

    @app.route("/api/help/ask", methods=["POST"])
    @_login_required
    def api_help_ask():
        """Answer a help question using internet search (with offline fallback)."""
        from zorksec.services.help_center_service import HelpCenterService
        data = request.get_json(silent=True) or {}
        answer = HelpCenterService().ask(data.get("query", ""))
        return answer.to_dict()

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

    # ------------------------------------------------------------------ errors
    def _render_error(code: int, title: str, message: str, ref: str | None = None):
        """Render the themed error page, falling back to plain text if Jinja fails."""
        try:
            html = render_template(
                "error.html", code=code, title=title, message=message,
                ref=ref, theme=theme(),
            )
            return html, code
        except Exception:  # pragma: no cover - last-resort fallback
            return f"{code} {title}: {message}", code

    @app.errorhandler(400)
    def _err_400(exc):
        desc = getattr(exc, "description", "") or "The request could not be processed."
        return _render_error(400, "Bad Request", desc)

    @app.errorhandler(403)
    def _err_403(exc):
        return _render_error(
            403, "Forbidden",
            "You do not have permission to access this resource.")

    @app.errorhandler(404)
    def _err_404(exc):
        return _render_error(
            404, "Page Not Found",
            "The page you requested does not exist. Check the address or head "
            "back to the dashboard.")

    @app.errorhandler(500)
    def _err_500(exc):
        # Log the full stack trace so raw 500s never leak to the browser while
        # operators still get the detail they need to debug.
        ref = secrets.token_hex(4)
        logger.exception("Internal server error [ref=%s]: %s", ref, exc)
        return _render_error(
            500, "Internal Server Error",
            "Something went wrong on the server. The error has been logged; "
            "quote the reference below if you report it.", ref=ref)

    @app.errorhandler(Exception)
    def _err_unhandled(exc):
        # Let Werkzeug HTTP exceptions (404/403/abort) flow to their own
        # handlers; only truly unexpected exceptions are turned into a 500.
        from werkzeug.exceptions import HTTPException

        if isinstance(exc, HTTPException):
            return exc
        ref = secrets.token_hex(4)
        logger.exception("Unhandled exception [ref=%s]", ref)
        return _render_error(
            500, "Internal Server Error",
            "Something went wrong on the server. The error has been logged; "
            "quote the reference below if you report it.", ref=ref)

    # ------------------------------------------------------------------ socket
    @socketio.on("connect")
    def on_connect():
        """Reject unauthenticated Socket.IO connections outright.

        Returning ``False`` from the connect handler refuses the websocket, so
        only logged-in users with a fully provisioned session (password already
        changed) can open a terminal channel.
        """
        if not _socket_authenticated():
            logger.warning("Rejected unauthenticated Socket.IO connection")
            return False
        return True

    @socketio.on("start")
    def on_start(data):
        """Begin a terminal session for a tool action or a flagged custom cmd."""
        from flask import request as sock_request  # sid lives on the request

        sid = sock_request.sid  # type: ignore[attr-defined]
        # Defence-in-depth: validate the session on every command, not just at
        # connect time, so a session that expired mid-connection cannot run.
        if not _socket_authenticated():
            socketio.emit("output",
                          {"data": "Authentication required. Please log in again.\r\n"},
                          to=sid)
            socketio.emit("exit", {"code": 1}, to=sid)
            return
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
                        # Heavy tools need an explicit YES confirmation first.
                        from zorksec.services.resource_check_service import (
                            ResourceCheckService,
                        )
                        confirmed = bool((data or {}).get("confirmed"))
                        if (ResourceCheckService.requires_confirmation(slug)
                                and not confirmed):
                            warning = ResourceCheckService.warning_for(slug)
                            box = warning.render_box() if warning else ""
                            socketio.emit("output",
                                          {"data": box.replace("\n", "\r\n") + "\r\n"},
                                          to=sid)
                            socketio.emit("output",
                                          {"data": "Confirmation required: re-run install "
                                                   "with YES to proceed.\r\n"}, to=sid)
                            socketio.emit("exit", {"code": 125}, to=sid)
                            return
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
        if not _socket_authenticated():
            return
        sess = terminals.get(sid)
        if sess:
            sess.write((data or {}).get("data", ""))

    @socketio.on("resize")
    def on_resize(data):
        from flask import request as sock_request

        sid = sock_request.sid  # type: ignore[attr-defined]
        if not _socket_authenticated():
            return
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


def _whitelist_bound_origins(host: str, port: int) -> None:
    """Ensure the exact bound origin is in the Socket.IO CORS allow-list.

    ``allowed_origins()`` covers common/loopback ports, but ``_find_free_port``
    can fall back to a random high port. We append the precise origins (for the
    bound host plus the loopback aliases) to ``ZORKSEC_ALLOWED_ORIGINS`` so the
    browser's WebSocket ``Origin`` always matches and the terminal connects.
    """
    hosts = {host, "127.0.0.1", "localhost", "[::1]"}
    new_origins: list[str] = []
    for h in hosts:
        new_origins.append(f"http://{h}:{port}")
        new_origins.append(f"https://{h}:{port}")
    existing = os.environ.get("ZORKSEC_ALLOWED_ORIGINS", "")
    parts = [p.strip() for p in existing.split(",") if p.strip()]
    for origin in new_origins:
        if origin not in parts:
            parts.append(origin)
    os.environ["ZORKSEC_ALLOWED_ORIGINS"] = ",".join(parts)


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

    # Beginner-safe binding: stay on localhost until the default password is changed.
    bind_host = host or settings.web_host
    preferred_port = port or settings.web_port

    # Resolve the final bind port BEFORE building the app so we can guarantee
    # the exact origin is in the Socket.IO CORS allow-list. Without this, an
    # auto-selected port (when the default is busy) would not be allow-listed
    # and the in-browser terminal's WebSocket would be silently rejected,
    # leaving the terminal stuck on "connecting...".
    bind_port = _find_free_port(bind_host, preferred_port)
    _whitelist_bound_origins(bind_host, bind_port)

    app, socketio = create_app(settings)

    with session_scope(settings) as db:
        auth = AuthService(db, settings)
        user = auth.ensure_default_user()
        still_default = user.must_change_password
    if still_default and bind_host not in ("127.0.0.1", "localhost"):
        logger.warning("Refusing to bind to %s with default password; using 127.0.0.1.",
                       bind_host)
        bind_host = "127.0.0.1"
        # Host changed -> re-resolve the port and re-whitelist for the new host.
        bind_port = _find_free_port(bind_host, preferred_port)
        _whitelist_bound_origins(bind_host, bind_port)
        app, socketio = create_app(settings)

    if bind_port != preferred_port:
        logger.info("Port %s busy; using free port %s instead.", preferred_port, bind_port)

    url = f"http://{bind_host}:{bind_port}"
    print(f"ZorkSec dashboard: {url}  (Ctrl+C to stop)")
    if bind_port != preferred_port:
        print(f"(port {preferred_port} was busy - automatically switched to {bind_port})")
    print(f"Login: {settings.default_username} / {settings.default_password}")

    if open_browser:
        _open_browser_when_ready(url, bind_host, bind_port)

    # Kick off a non-blocking repository-health refresh (cached, 60-min TTL) so
    # the dashboard shows live scores without delaying startup.
    try:
        from zorksec.services.health_service import start_background_refresh
        start_background_refresh(settings)
    except Exception as exc:  # pragma: no cover - never block startup on this
        logger.warning("Could not start background health refresh: %s", exc)

    try:
        socketio.run(app, host=bind_host, port=bind_port)
    except KeyboardInterrupt:
        print("\nShutting down ZorkSec dashboard.")
    return 0
