"""Authentication service.

Responsibilities:
  * bcrypt password hashing / verification
  * default first-login user provisioning (``zorksec`` / ``zorksec``)
  * forced password rotation on first login
  * account lockout after repeated failures
  * audit logging of every login attempt and password change

The service is constructed with a SQLAlchemy ``Session`` (dependency
injection) so it can be reused by the TUI, the web app, and tests.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

import bcrypt

from zorksec.config import Settings, get_settings
from zorksec.db.models import User
from zorksec.repositories.audit_repository import AuditRepository
from zorksec.repositories.user_repository import UserRepository
from zorksec.utils.logging import get_logger

logger = get_logger(__name__)


class AuthError(Exception):
    """Base class for authentication failures."""


class AccountLockedError(AuthError):
    """Raised when an account is temporarily locked."""


@dataclass
class LoginResult:
    """Outcome of a successful authentication."""

    user_id: int
    username: str
    must_change_password: bool


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


class AuthService:
    def __init__(self, session, settings: Settings | None = None) -> None:
        self._users = UserRepository(session)
        self._audit = AuditRepository(session)
        self._settings = settings or get_settings()

    # ----- password helpers -------------------------------------------------
    def hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt(rounds=self._settings.bcrypt_rounds)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("ascii")

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
        except (ValueError, TypeError):
            return False

    # ----- provisioning -----------------------------------------------------
    def ensure_default_user(self) -> User:
        """Create the default first-login user if no users exist (idempotent)."""
        existing = self._users.get_by_username(self._settings.default_username)
        if existing is not None:
            return existing
        user = User(
            username=self._settings.default_username,
            password_hash=self.hash_password(self._settings.default_password),
            role="admin",
            must_change_password=True,
        )
        self._users.add(user)
        self._audit.record("user_created", username=user.username, detail="default user provisioned")
        logger.info("Provisioned default user '%s'", user.username)
        return user

    # ----- authentication ---------------------------------------------------
    def login(self, username: str, password: str, ip_address: str | None = None) -> LoginResult:
        user = self._users.get_by_username(username)
        if user is None or not user.is_active:
            self._audit.record("login", username=username, detail="unknown or inactive user",
                               success=False, ip_address=ip_address)
            raise AuthError("Invalid username or password.")

        if user.locked_until and user.locked_until > _utcnow():
            self._audit.record("login", username=username, detail="account locked",
                               success=False, ip_address=ip_address)
            raise AccountLockedError(
                f"Account locked until {user.locked_until.isoformat()} UTC."
            )

        if not self.verify_password(password, user.password_hash):
            user.failed_login_count += 1
            if user.failed_login_count >= self._settings.max_failed_logins:
                user.locked_until = _utcnow() + _dt.timedelta(minutes=15)
                user.failed_login_count = 0
                self._audit.record("login", username=username,
                                   detail="locked after repeated failures",
                                   success=False, ip_address=ip_address)
                raise AccountLockedError("Too many failed attempts; account locked for 15 minutes.")
            self._audit.record("login", username=username, detail="bad password",
                               success=False, ip_address=ip_address)
            raise AuthError("Invalid username or password.")

        # Success.
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = _utcnow()
        self._audit.record("login", username=username, detail="success",
                           success=True, ip_address=ip_address)
        logger.info("User '%s' logged in", username)
        return LoginResult(
            user_id=user.id,
            username=user.username,
            must_change_password=user.must_change_password,
        )

    # ----- password change --------------------------------------------------
    def change_password(self, username: str, old_password: str, new_password: str) -> None:
        if len(new_password) < 8:
            raise AuthError("New password must be at least 8 characters.")
        if new_password == self._settings.default_password:
            raise AuthError("New password must differ from the default password.")

        user = self._users.get_by_username(username)
        if user is None or not self.verify_password(old_password, user.password_hash):
            self._audit.record("password_change", username=username,
                               detail="verification failed", success=False)
            raise AuthError("Current password is incorrect.")

        user.password_hash = self.hash_password(new_password)
        user.must_change_password = False
        self._audit.record("password_change", username=username, detail="success", success=True)
        logger.info("User '%s' changed password", username)

    # ----- security question / password recovery ---------------------------
    @staticmethod
    def _normalise_answer(answer: str) -> str:
        """Normalise an answer so matching is case/space-insensitive."""
        return " ".join((answer or "").strip().lower().split())

    def set_security_question(self, username: str, question: str, answer: str) -> None:
        """Set (or update) a user's recovery question and bcrypt-hashed answer."""
        if not question.strip():
            raise AuthError("Security question cannot be empty.")
        if len(self._normalise_answer(answer)) < 2:
            raise AuthError("Security answer is too short.")
        user = self._users.get_by_username(username)
        if user is None:
            raise AuthError("Unknown user.")
        user.security_question = question.strip()
        user.security_answer_hash = self.hash_password(self._normalise_answer(answer))
        self._audit.record("security_question_set", username=username,
                           detail="recovery question configured", success=True)
        logger.info("Security question set for '%s'", username)

    def get_security_question(self, username: str) -> str | None:
        """Return the user's security question, or None if not set / unknown user."""
        user = self._users.get_by_username(username)
        if user is None or not user.security_answer_hash:
            return None
        return user.security_question

    def verify_security_answer(self, username: str, answer: str) -> bool:
        """Check a recovery answer against the stored bcrypt hash."""
        user = self._users.get_by_username(username)
        if user is None or not user.security_answer_hash:
            return False
        ok = self.verify_password(self._normalise_answer(answer), user.security_answer_hash)
        self._audit.record("security_answer_check", username=username,
                           detail="correct" if ok else "incorrect", success=ok)
        return ok

    def reset_password_with_answer(self, username: str, answer: str,
                                   new_password: str) -> None:
        """Reset a forgotten password after verifying the security answer."""
        if len(new_password) < 8:
            raise AuthError("New password must be at least 8 characters.")
        if new_password == self._settings.default_password:
            raise AuthError("New password must differ from the default password.")
        user = self._users.get_by_username(username)
        if user is None or not user.security_answer_hash:
            raise AuthError("Password recovery is not set up for this account.")
        if not self.verify_password(self._normalise_answer(answer), user.security_answer_hash):
            self._audit.record("password_reset", username=username,
                               detail="wrong security answer", success=False)
            raise AuthError("Security answer is incorrect.")
        user.password_hash = self.hash_password(new_password)
        user.must_change_password = False
        # Recovering access also clears any lockout.
        user.failed_login_count = 0
        user.locked_until = None
        self._audit.record("password_reset", username=username,
                           detail="reset via security question", success=True)
        logger.info("User '%s' reset password via security question", username)
