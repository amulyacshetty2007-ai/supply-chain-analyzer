from datetime import datetime, timezone
from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer,
                        String, Text, UniqueConstraint)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))          # developer | auditor
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    owner = relationship("User")


class Manifest(Base):
    __tablename__ = "manifests"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(100))
    sha256: Mapped[str] = mapped_column(String(64))
    spec_version: Mapped[str] = mapped_column(String(16))
    root_ref: Mapped[str] = mapped_column(String(255))
    root_name: Mapped[str] = mapped_column(String(255))
    component_count: Mapped[int] = mapped_column(Integer)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    __table_args__ = (UniqueConstraint("project_id", "sha256"),)


class Package(Base):
    __tablename__ = "packages"
    id: Mapped[int] = mapped_column(primary_key=True)
    manifest_id: Mapped[int] = mapped_column(ForeignKey("manifests.id", ondelete="CASCADE"))
    ref: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(128))
    ecosystem: Mapped[str] = mapped_column(String(32))
    purl: Mapped[str] = mapped_column(String(1024), default="")
    is_direct: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (UniqueConstraint("manifest_id", "ref"),)


class Edge(Base):
    __tablename__ = "dependency_edges"
    id: Mapped[int] = mapped_column(primary_key=True)
    manifest_id: Mapped[int] = mapped_column(ForeignKey("manifests.id", ondelete="CASCADE"))
    parent_ref: Mapped[str] = mapped_column(String(255))
    child_ref: Mapped[str] = mapped_column(String(255))
    __table_args__ = (Index("ix_edge_manifest", "manifest_id"),)


class Vulnerability(Base):
    """Local cache of OSV records."""
    __tablename__ = "vulnerabilities"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    summary: Mapped[str] = mapped_column(String(512), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    affected: Mapped[list] = mapped_column(JSON, default=list)
    published: Mapped[str] = mapped_column(String(32), default="")
    source: Mapped[str] = mapped_column(String(32), default="osv.dev")
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    manifest_id: Mapped[int] = mapped_column(ForeignKey("manifests.id"))
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(16), default="running")   # running|done|failed
    source: Mapped[str] = mapped_column(String(32), default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    vuln_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(String(300), default="")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id"))
    vuln_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"))
    severity: Mapped[str] = mapped_column(String(16))
    cvss: Mapped[float] = mapped_column(Float)
    fixed_versions: Mapped[list] = mapped_column(JSON, default=list)
    blast_radius: Mapped[int] = mapped_column(Integer, default=0)
