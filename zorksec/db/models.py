"""SQLAlchemy ORM models for ZorkSec (SQLite v1).

Fifteen tables cover users, settings, the tool catalog/lifecycle, reporting,
encrypted API keys, ATT&CK mappings, threat feeds, alerts, plugins, the
virtual lab, learner progress, and the security audit log.
"""

from __future__ import annotations

import datetime as _dt

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> _dt.datetime:
    """Timezone-aware UTC now (stored naive-UTC for SQLite portability)."""
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="admin", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[_dt.datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_at: Mapped[_dt.datetime | None] = mapped_column(DateTime, nullable=True)
    # Password recovery: security question + bcrypt-hashed answer (optional).
    security_question: Mapped[str | None] = mapped_column(String(255), nullable=True)
    security_answer_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Password-recovery throttling (security-question reset flow).
    recovery_failed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    recovery_locked_until: Mapped[_dt.datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)

    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Setting(Base):
    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow, nullable=False)


class ToolRegistry(Base):
    __tablename__ = "tool_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(96), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    team: Mapped[str] = mapped_column(String(16), default="both", nullable=False)  # blue|red|both
    beginner_note: Mapped[str] = mapped_column(Text, default="", nullable=False)
    install_method: Mapped[str] = mapped_column(String(32), default="apt", nullable=False)
    install_target: Mapped[str] = mapped_column(Text, default="", nullable=False)  # pkg name / repo url
    run_command: Mapped[str] = mapped_column(Text, default="", nullable=False)
    docs_url: Mapped[str] = mapped_column(Text, default="", nullable=False)
    license: Mapped[str] = mapped_column(String(64), default="Unknown", nullable=False)
    requires_isolation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    status: Mapped["ToolStatus"] = relationship(back_populates="tool", uselist=False, cascade="all, delete-orphan")
    health: Mapped["ToolHealth"] = relationship(back_populates="tool", uselist=False, cascade="all, delete-orphan")


class ToolStatus(Base):
    __tablename__ = "tool_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("tool_registry.id", ondelete="CASCADE"), unique=True)
    installed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    install_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[_dt.datetime | None] = mapped_column(DateTime, nullable=True)

    tool: Mapped[ToolRegistry] = relationship(back_populates="status")


class InstallHistory(Base):
    __tablename__ = "install_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool_slug: Mapped[str] = mapped_column(String(96), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # install|update|remove|run
    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)


class ToolHealth(Base):
    __tablename__ = "tool_health"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("tool_registry.id", ondelete="CASCADE"), unique=True)
    score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 0-100
    status: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)  # healthy|warning|deprecated
    stars: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_commit_at: Mapped[_dt.datetime | None] = mapped_column(DateTime, nullable=True)
    last_release: Mapped[str | None] = mapped_column(String(64), nullable=True)
    checked_at: Mapped[_dt.datetime | None] = mapped_column(DateTime, nullable=True)

    tool: Mapped[ToolRegistry] = relationship(back_populates="health")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="", nullable=False)
    fmt: Mapped[str] = mapped_column(String(16), default="markdown", nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)


class ApiKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = (UniqueConstraint("user_id", "provider", name="uq_apikey_user_provider"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)  # openai|anthropic|gemini|openrouter|ollama
    encrypted_key: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)

    user: Mapped[User] = relationship(back_populates="api_keys")


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool_slug: Mapped[str] = mapped_column(String(96), index=True, nullable=False)
    technique_id: Mapped[str] = mapped_column(String(16), nullable=False)  # e.g. T1059
    technique_name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    tactic: Mapped[str] = mapped_column(String(64), default="", nullable=False)


class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    feed_type: Mapped[str] = mapped_column(String(32), nullable=False)  # ioc|malware|url|domain
    indicator: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    fetched_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="low", nullable=False)  # low|medium|high|critical
    source: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="", nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)


class Plugin(Base):
    __tablename__ = "plugins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="0.0.0", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    trusted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    path: Mapped[str] = mapped_column(Text, default="", nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    installed_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)


class LabVm(Base):
    __tablename__ = "lab_vms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="target", nullable=False)  # analyst|target
    hypervisor: Mapped[str] = mapped_column(String(32), default="virtualbox", nullable=False)  # vmware|virtualbox
    network_mode: Mapped[str] = mapped_column(String(32), default="hostonly", nullable=False)
    isolated: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)


class LearningProgress(Base):
    __tablename__ = "learning_progress"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    track: Mapped[str] = mapped_column(String(64), nullable=False)
    lesson: Mapped[str] = mapped_column(String(128), nullable=False)
    completed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    completed_at: Mapped[_dt.datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False)  # login|logout|exec|install|config_change
    detail: Mapped[str] = mapped_column(Text, default="", nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow, nullable=False)


__all__ = [
    "Base",
    "User",
    "Setting",
    "ToolRegistry",
    "ToolStatus",
    "InstallHistory",
    "ToolHealth",
    "Report",
    "ApiKey",
    "MitreMapping",
    "ThreatFeed",
    "Alert",
    "Plugin",
    "LabVm",
    "LearningProgress",
    "AuditLog",
]
