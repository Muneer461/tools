"""Tests for AuthService: provisioning, login, lockout, password change."""

from __future__ import annotations

import pytest

from zorksec.config import get_settings
from zorksec.db.session import init_db, session_scope
from zorksec.services.auth_service import (
    AccountLockedError,
    AuthError,
    AuthService,
)


@pytest.fixture()
def settings(zorksec_home):
    init_db()
    return get_settings()


def test_default_user_provisioned(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        user = auth.ensure_default_user()
        assert user.username == settings.default_username
        assert user.must_change_password is True


def test_login_success_requires_password_change(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        result = auth.login(settings.default_username, settings.default_password)
        assert result.must_change_password is True


def test_login_bad_password_rejected(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        with pytest.raises(AuthError):
            auth.login(settings.default_username, "wrong-password")


def test_account_locks_after_max_failures(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        # Trigger lockout (max_failed_logins attempts).
        for _ in range(settings.max_failed_logins - 1):
            with pytest.raises(AuthError):
                auth.login(settings.default_username, "nope")
        with pytest.raises(AccountLockedError):
            auth.login(settings.default_username, "nope")
        # Even the correct password is refused while locked.
        with pytest.raises(AccountLockedError):
            auth.login(settings.default_username, settings.default_password)


def test_change_password_clears_must_change_flag(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        auth.change_password(
            settings.default_username, settings.default_password, "NewStr0ngPass!"
        )
    with session_scope() as session:
        auth = AuthService(session, settings)
        result = auth.login(settings.default_username, "NewStr0ngPass!")
        assert result.must_change_password is False


def test_change_password_rejects_default_value(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        with pytest.raises(AuthError):
            auth.change_password(
                settings.default_username,
                settings.default_password,
                settings.default_password,
            )



# ---------------------------------------------------------------------------
# Security question / password recovery
# ---------------------------------------------------------------------------
def test_set_and_verify_security_question(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        auth.set_security_question(settings.default_username,
                                   "First pet?", "Mr Whiskers")
    with session_scope() as session:
        auth = AuthService(session, settings)
        assert auth.get_security_question(settings.default_username) == "First pet?"
        # case/space-insensitive match
        assert auth.verify_security_answer(settings.default_username, "  mr   whiskers ") is True
        assert auth.verify_security_answer(settings.default_username, "wrong") is False


def test_get_security_question_none_when_unset(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        assert auth.get_security_question(settings.default_username) is None
        assert auth.get_security_question("ghost-user") is None


def test_reset_password_with_correct_answer(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        auth.set_security_question(settings.default_username, "City?", "Hyderabad")
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.reset_password_with_answer(settings.default_username, "hyderabad", "BrandNew99!")
    with session_scope() as session:
        auth = AuthService(session, settings)
        result = auth.login(settings.default_username, "BrandNew99!")
        assert result.username == settings.default_username


def test_reset_password_wrong_answer_rejected(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        auth.set_security_question(settings.default_username, "City?", "Hyderabad")
        with pytest.raises(AuthError):
            auth.reset_password_with_answer(settings.default_username, "nope", "BrandNew99!")


def test_reset_password_without_question_setup_rejected(settings):
    with session_scope() as session:
        auth = AuthService(session, settings)
        auth.ensure_default_user()
        with pytest.raises(AuthError):
            auth.reset_password_with_answer(settings.default_username, "x", "BrandNew99!")
