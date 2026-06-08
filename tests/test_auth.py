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
