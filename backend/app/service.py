from sqlalchemy import select
from sqlalchemy.orm import Session

from . import osv
from .graph import analyze_project
from .models import Edge, Finding, Manifest, Package, Project, Scan, User, now


def run_scan(db: Session, project: Project, manifest: Manifest, user: User) -> Scan:
    scan = Scan(project_id=project.id, manifest_id=manifest.id, requested_by=user.id)
    db.add(scan)
    db.commit()
    try:
        pkgs = db.scalars(select(Package).where(Package.manifest_id == manifest.id)).all()
        edges = db.execute(select(Edge.parent_ref, Edge.child_ref)
                           .where(Edge.manifest_id == manifest.id)).all()
        matches, source = osv.lookup(db, pkgs)
        by_ref, pkg_by_ref = {}, {p.ref: p for p in pkgs}
        for p in pkgs:
            vs = []
            for v in matches.get(p.id, []):
                vs.append({"id": v.id, "severity": v.severity, "cvss": v.cvss, "summary": v.summary,
                           "aliases": v.aliases, "published": v.published,
                           "fixed": osv.fixed_versions(v.affected, p.ecosystem, p.name)})
            if vs:
                by_ref[p.ref] = vs
        report = analyze_project(
            {"ref": manifest.root_ref, "name": manifest.root_name},
            [{"ref": p.ref, "name": p.name, "version": p.version, "ecosystem": p.ecosystem,
              "is_direct": p.is_direct} for p in pkgs],
            [tuple(e) for e in edges], by_ref)
        for item in report["vulnerable"]:
            for v in item["vulns"]:
                db.add(Finding(scan_id=scan.id, package_id=pkg_by_ref[item["ref"]].id, vuln_id=v["id"],
                               severity=v["severity"], cvss=v["cvss"], fixed_versions=v["fixed"],
                               blast_radius=item["blast_radius"]))
        report["meta"] = {"scan_id": scan.id, "project": project.name, "manifest": manifest.filename,
                          "source": source}
        scan.report, scan.source, scan.status = report, source, "done"
        scan.risk_score = report["summary"]["risk_score"]
        scan.vuln_count = report["summary"]["findings"]
    except Exception as exc:                                # never leak internals to the client
        db.rollback()
        scan = db.get(Scan, scan.id)
        scan.status, scan.error = "failed", f"{exc.__class__.__name__}: {str(exc)[:200]}"
    scan.finished_at = now()
    db.commit()
    return scan
