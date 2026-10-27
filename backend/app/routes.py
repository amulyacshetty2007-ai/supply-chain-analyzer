import json
import re
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import config
from .db import get_db
from .models import Edge, Manifest, Package, Project, Scan, User
from .parser import validate_upload
from .security import (auth_limiter, client_ip, current_user, hash_password, make_token,
                       require_role, scan_limiter, upload_limiter, verify_password)
from .service import run_scan

router = APIRouter()
SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample-sbom.json"


class RegisterIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,32}$")
    password: str = Field(min_length=8, max_length=72)
    role: Literal["developer", "auditor"] = "developer"
    invite_code: str | None = None


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)


class ScanIn(BaseModel):
    manifest_id: int | None = None


# ---------------- auth ----------------
@router.post("/auth/register", tags=["auth"], status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    auth_limiter.check("reg:" + client_ip(request))
    if body.role == "auditor" and (not config.AUDITOR_INVITE_CODE or body.invite_code != config.AUDITOR_INVITE_CODE):
        raise HTTPException(403, "A valid invite code is required for the auditor role")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Username already taken")
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/auth/login", tags=["auth"])
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    auth_limiter.check("login:" + client_ip(request))
    user = db.scalar(select(User).where(User.username == form.username))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(401, "Incorrect username or password")
    return {"access_token": make_token(user), "token_type": "bearer", "role": user.role, "username": user.username}


@router.get("/auth/me", tags=["auth"])
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}


# ---------------- helpers ----------------
def get_project(db: Session, pid: int, user: User) -> Project:
    p = db.get(Project, pid)
    if not p or (user.role != "auditor" and p.owner_id != user.id):
        raise HTTPException(404, "Project not found")      # 404, not 403: don't reveal existence
    return p


def project_out(db: Session, p: Project):
    last = db.scalar(select(Scan).where(Scan.project_id == p.id, Scan.status == "done")
                     .order_by(Scan.id.desc()).limit(1))
    return {"id": p.id, "name": p.name, "description": p.description, "owner": p.owner.username,
            "created_at": p.created_at, "last_scan_id": last.id if last else None,
            "risk_score": last.risk_score if last else None}


def store_manifest(db: Session, project: Project, parsed: dict) -> tuple[Manifest, bool]:
    dup = db.scalar(select(Manifest).where(Manifest.project_id == project.id,
                                           Manifest.sha256 == parsed["sha256"]))
    if dup:
        return dup, False
    m = Manifest(project_id=project.id, filename=parsed["filename"], sha256=parsed["sha256"],
                 spec_version=parsed["spec_version"], root_ref=parsed["root_ref"],
                 root_name=parsed["root_name"], component_count=len(parsed["packages"]))
    db.add(m)
    db.flush()
    db.add_all(Package(manifest_id=m.id, **{k: p[k] for k in
              ("ref", "name", "version", "ecosystem", "purl", "is_direct")}) for p in parsed["packages"])
    db.add_all(Edge(manifest_id=m.id, parent_ref=a, child_ref=b) for a, b in parsed["edges"])
    db.commit()
    return m, True


# ---------------- projects ----------------
@router.post("/projects", tags=["projects"], status_code=201)
def create_project(body: ProjectIn, user: User = Depends(require_role("developer")), db: Session = Depends(get_db)):
    p = Project(owner_id=user.id, name=body.name.strip(), description=body.description.strip())
    db.add(p)
    db.commit()
    return project_out(db, p)


@router.get("/projects", tags=["projects"])
def list_projects(user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = select(Project).order_by(Project.id.desc())
    if user.role != "auditor":
        q = q.where(Project.owner_id == user.id)
    return [project_out(db, p) for p in db.scalars(q)]


@router.post("/projects/demo", tags=["projects"], status_code=201)
def demo_project(user: User = Depends(require_role("developer")), db: Session = Depends(get_db)):
    """One click: project + bundled sample SBOM that contains vulnerable packages and a cycle."""
    p = Project(owner_id=user.id, name="shop-api (demo)", description="Bundled sample CycloneDX SBOM")
    db.add(p)
    db.commit()
    parsed = validate_upload("sample-sbom.json", "application/json", SAMPLE.read_bytes())
    m, _ = store_manifest(db, p, parsed)
    return {**project_out(db, p), "manifest_id": m.id}


@router.get("/projects/{pid}", tags=["projects"])
def project_detail(pid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = get_project(db, pid, user)
    mans = db.scalars(select(Manifest).where(Manifest.project_id == pid).order_by(Manifest.id.desc())).all()
    scans = db.scalars(select(Scan).where(Scan.project_id == pid).order_by(Scan.id.desc()).limit(50)).all()
    return {**project_out(db, p),
            "manifests": [{"id": m.id, "filename": m.filename, "sha256": m.sha256,
                           "components": m.component_count, "uploaded_at": m.uploaded_at} for m in mans],
            "scans": [{"id": s.id, "status": s.status, "risk_score": s.risk_score, "findings": s.vuln_count,
                       "source": s.source, "manifest_id": s.manifest_id, "error": s.error,
                       "started_at": s.started_at, "finished_at": s.finished_at} for s in scans]}


@router.delete("/projects/{pid}", tags=["projects"], status_code=204)
def delete_project(pid: int, user: User = Depends(require_role("developer")), db: Session = Depends(get_db)):
    p = get_project(db, pid, user)
    db.delete(p)
    db.commit()


# ---------------- manifest upload ----------------
@router.post("/projects/{pid}/manifest", tags=["scanning"], status_code=201)
async def upload_manifest(pid: int, request: Request, file: UploadFile = File(...),
                          user: User = Depends(require_role("developer")), db: Session = Depends(get_db)):
    upload_limiter.check(f"up:{user.id}")
    p = get_project(db, pid, user)
    if int(request.headers.get("content-length") or 0) > config.MAX_UPLOAD_BYTES + 4096:
        raise HTTPException(413, "File too large")
    raw = b""
    while chunk := await file.read(64 * 1024):              # bounded streaming read, memory only
        raw += chunk
        if len(raw) > config.MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"File exceeds {config.MAX_UPLOAD_BYTES} bytes")
    parsed = validate_upload(file.filename, file.content_type, raw)
    m, created = store_manifest(db, p, parsed)
    return {"manifest_id": m.id, "components": m.component_count, "new": created,
            "root": m.root_name, "sha256": m.sha256}


# ---------------- scanning & reports ----------------
@router.post("/projects/{pid}/scan", tags=["scanning"], status_code=201)
def scan_project(pid: int, body: ScanIn | None = None, user: User = Depends(require_role("developer")),
                 db: Session = Depends(get_db)):
    scan_limiter.check(f"scan:{user.id}")
    p = get_project(db, pid, user)
    q = select(Manifest).where(Manifest.project_id == pid)
    mid = body.manifest_id if body else None
    m = db.scalar(q.where(Manifest.id == mid) if mid else q.order_by(Manifest.id.desc()).limit(1))
    if not m:
        raise HTTPException(409, "Upload a CycloneDX manifest before scanning")
    scan = run_scan(db, p, m, user)
    if scan.status == "failed":
        raise HTTPException(502, f"Scan failed: {scan.error}")
    return {"scan_id": scan.id, "status": scan.status, "risk_score": scan.risk_score,
            "findings": scan.vuln_count, "source": scan.source}


@router.get("/scans/{sid}/report", tags=["reports"])
def report(sid: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.get(Scan, sid)
    if not s:
        raise HTTPException(404, "Scan not found")
    get_project(db, s.project_id, user)
    if s.status != "done" or not s.report:
        raise HTTPException(409, f"Scan is {s.status}")
    return s.report


@router.get("/audit/scans", tags=["reports"])
def audit_scans(user: User = Depends(require_role("auditor")), db: Session = Depends(get_db)):
    rows = db.execute(select(Scan, Project, User).join(Project, Scan.project_id == Project.id)
                      .join(User, Project.owner_id == User.id).order_by(Scan.id.desc()).limit(200)).all()
    return [{"scan_id": s.id, "project": p.name, "owner": u.username, "status": s.status,
             "risk_score": s.risk_score, "findings": s.vuln_count, "started_at": s.started_at}
            for s, p, u in rows]
