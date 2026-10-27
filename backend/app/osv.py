"""OSV integration: online (api.osv.dev), offline sample, and a local DB cache."""
import json
import math
import re
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from . import config
from .models import Vulnerability

OSV = "https://api.osv.dev/v1"
OFFLINE = Path(__file__).resolve().parent.parent / "data" / "osv_offline.json"
GHSA_SEV = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}


def label(score: float) -> str:
    return ("CRITICAL" if score >= 9 else "HIGH" if score >= 7 else
            "MEDIUM" if score >= 4 else "LOW" if score > 0 else "UNKNOWN")


def cvss3(vector: str) -> float:
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        ch = m["S"] == "C"
        AV = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
        AC = {"L": .77, "H": .44}[m["AC"]]
        PR = {"N": .85, "L": .68 if ch else .62, "H": .5 if ch else .27}[m["PR"]]
        UI = {"N": .85, "R": .62}[m["UI"]]
        c, i, a = ({"H": .56, "L": .22, "N": 0}[m[k]] for k in "CIA")
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if ch else 6.42 * iss
        if imp <= 0:
            return 0.0
        return math.ceil(min((imp + 8.22 * AV * AC * PR * UI) * (1.08 if ch else 1), 10) * 10) / 10
    except (KeyError, ValueError):
        return 0.0


def normalize(rec: dict, source: str) -> dict:
    score = 0.0
    for s in rec.get("severity", []) or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = max(score, cvss3(str(s.get("score", ""))))
    if not score:
        txt = str((rec.get("database_specific") or {}).get("severity", "")).upper()
        score = GHSA_SEV.get(txt, 0.0)
    return {"id": rec["id"][:64], "summary": (rec.get("summary") or rec.get("details") or "")[:500],
            "details": (rec.get("details") or "")[:6000], "severity": label(score), "cvss": score,
            "aliases": (rec.get("aliases") or [])[:20], "affected": rec.get("affected") or [],
            "published": (rec.get("published") or "")[:32], "source": source}


# ---------- version matching (offline) ----------
def vkey(v: str):
    nums = [int(x) for x in re.findall(r"\d+", re.split(r"[-+]", v, 1)[0])] or [0]
    return nums + [0] * (6 - len(nums))


def norm_name(eco: str, name: str) -> str:
    return name.lower().replace("_", "-") if eco == "PyPI" else name


def affects(affected: list, eco: str, name: str, ver: str) -> bool:
    v = vkey(ver)
    for a in affected:
        p = a.get("package") or {}
        if p.get("ecosystem") != eco or norm_name(eco, p.get("name", "")) != norm_name(eco, name):
            continue
        if ver in (a.get("versions") or []):
            return True
        for r in a.get("ranges") or []:
            if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            start = None
            for e in r.get("events", []):
                if "introduced" in e:
                    start = vkey(e["introduced"])
                elif "fixed" in e and start is not None:
                    if start <= v < vkey(e["fixed"]):
                        return True
                    start = None
            if start is not None and v >= start:
                return True
    return False


def fixed_versions(affected: list, eco: str, name: str) -> list[str]:
    out = []
    for a in affected:
        p = a.get("package") or {}
        if p.get("ecosystem") == eco and norm_name(eco, p.get("name", "")) == norm_name(eco, name):
            for r in a.get("ranges") or []:
                out += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    return sorted(set(out), key=vkey)


# ---------- lookup ----------
def _offline_records():
    return json.loads(OFFLINE.read_text())


def _online(keys: list[tuple]) -> dict[tuple, list[str]]:
    res: dict[tuple, list[str]] = {}
    with httpx.Client(timeout=20) as c:
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            body = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]}
            r = c.post(f"{OSV}/querybatch", json=body)
            r.raise_for_status()
            for k, item in zip(chunk, r.json().get("results", [])):
                res[k] = [x["id"] for x in item.get("vulns", [])]
    return res


def _fetch_detail(vid: str) -> dict:
    r = httpx.get(f"{OSV}/vulns/{vid}", timeout=20)
    r.raise_for_status()
    return r.json()


def lookup(db: Session, packages) -> tuple[dict[int, list[Vulnerability]], str]:
    """packages: Package rows. Returns ({package_id: [Vulnerability]}, source)."""
    groups: dict[tuple, list[int]] = {}                       # hash map: (eco,name,ver) -> package ids
    for p in packages:
        if p.ecosystem != "unknown" and p.version:
            groups.setdefault((p.ecosystem, p.name, p.version), []).append(p.id)
    keys = list(groups)
    records: dict[str, dict] = {}
    hits: dict[tuple, list[str]] = {}
    source = "osv.dev"
    mode = config.OSV_MODE
    if mode in ("online", "auto"):
        try:
            hits = _online(keys)
            for vid in {x for ids in hits.values() for x in ids}:
                cached = db.get(Vulnerability, vid)
                if cached:
                    records[vid] = {"id": vid, "_row": cached}
                else:
                    records[vid] = normalize(_fetch_detail(vid), "osv.dev")
        except Exception as exc:
            if mode == "online":
                raise RuntimeError(f"OSV request failed: {exc.__class__.__name__}") from exc
            hits, records, source = {}, {}, "offline-sample"
    else:
        source = "offline-sample"
    if source == "offline-sample":
        for rec in _offline_records():
            records[rec["id"]] = normalize(rec, "offline-sample")
        for k in keys:
            hits[k] = [rid for rid, r in records.items() if affects(r["affected"], k[0], k[1], k[2])]

    rows: dict[str, Vulnerability] = {}
    for vid, rec in records.items():
        row = rec.get("_row") or db.get(Vulnerability, vid)
        if not row:
            row = Vulnerability(**{k: v for k, v in rec.items()})
            db.add(row)
        rows[vid] = row
    db.flush()
    out: dict[int, list[Vulnerability]] = {}
    for k, ids in hits.items():
        for pid in groups[k]:
            out[pid] = [rows[i] for i in ids if i in rows]
    return out, source
