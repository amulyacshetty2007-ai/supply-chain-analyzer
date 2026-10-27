"""CycloneDX SBOM validation + parsing. Nothing from the upload ever touches the filesystem."""
import hashlib
import json
import re
from urllib.parse import unquote

from fastapi import HTTPException

from . import config

ALLOWED_CT = {"application/json", "text/json", "application/octet-stream",
              "application/vnd.cyclonedx+json", "text/plain"}
SPEC_RE = re.compile(r"^1\.[0-9]$")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PURL_RE = re.compile(r"^pkg:([a-z0-9.+-]+)/([^@?#]+)(?:@([^?#]+))?")
OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go",
                 "cargo": "crates.io", "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist"}
MAX_DEPTH, MAX_STR, MAX_EDGES = 20, 512, 50_000


def bad(msg: str, code: int = 422):
    raise HTTPException(code, msg)


def clean(s, field: str, limit: int = MAX_STR) -> str:
    if not isinstance(s, str):
        bad(f"'{field}' must be a string")
    if len(s) > limit or CTRL_RE.search(s):
        bad(f"'{field}' is too long or contains control characters")
    return s.strip()


def safe_filename(name: str | None) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", (name or "sbom.json").split("/")[-1].split("\\")[-1])
    return base[:100] or "sbom.json"


def depth_of(obj, limit=MAX_DEPTH) -> bool:
    stack = [(obj, 1)]
    while stack:
        o, d = stack.pop()
        if d > limit:
            return False
        if isinstance(o, dict):
            stack.extend((v, d + 1) for v in o.values() if isinstance(v, (dict, list)))
        elif isinstance(o, list):
            stack.extend((v, d + 1) for v in o if isinstance(v, (dict, list)))
    return True


def parse_purl(purl: str):
    m = PURL_RE.match(purl)
    if not m:
        return None
    typ, path, ver = m.group(1), unquote(m.group(2)), unquote(m.group(3) or "")
    parts = [p for p in path.split("/") if p]
    if not parts:
        return None
    if typ == "maven" and len(parts) >= 2:
        name = f"{parts[0]}:{parts[1]}"
    elif typ == "pypi":
        name = parts[-1].lower().replace("_", "-")
    elif typ in ("npm", "golang"):
        name = "/".join(parts)
    else:
        name = parts[-1]
    return OSV_ECOSYSTEM.get(typ, typ), name, ver


def validate_upload(filename: str | None, content_type: str | None, raw: bytes) -> dict:
    fname = safe_filename(filename)
    if not fname.lower().endswith(".json"):
        bad("Only CycloneDX JSON (.json) files are accepted", 415)
    if content_type and content_type.split(";")[0].strip().lower() not in ALLOWED_CT:
        bad(f"Unsupported content type {content_type}", 415)
    if not raw:
        bad("Empty file", 400)
    if len(raw) > config.MAX_UPLOAD_BYTES:
        bad(f"File exceeds {config.MAX_UPLOAD_BYTES} bytes", 413)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        bad("File is not valid UTF-8 text")
    if "\x00" in text:
        bad("Binary content rejected")
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        bad("File is not valid JSON")
    if not isinstance(doc, dict) or not depth_of(doc):
        bad("JSON must be an object with nesting depth <= %d" % MAX_DEPTH)
    if doc.get("bomFormat") != "CycloneDX":
        bad("Not a CycloneDX document (bomFormat must be 'CycloneDX')")
    spec = str(doc.get("specVersion", ""))
    if not SPEC_RE.match(spec):
        bad("Unsupported or missing specVersion")
    comps = doc.get("components", [])
    if not isinstance(comps, list):
        bad("'components' must be an array")

    packages: dict[str, dict] = {}

    def walk(items, level=0):
        if level > 5:
            bad("Components nested too deeply")
        for c in items:
            if not isinstance(c, dict):
                bad("Each component must be an object")
            name = clean(c.get("name"), "component.name", 255)
            if not name:
                bad("Component without a name")
            version = clean(c.get("version", ""), "component.version", 128)
            purl = clean(c.get("purl", ""), "component.purl", 1024)
            ref = clean(c.get("bom-ref") or purl or f"{name}@{version}", "bom-ref", 255)
            if ref in packages:
                bad(f"Duplicate bom-ref: {ref[:60]}")
            parsed = parse_purl(purl) if purl else None
            eco, pname, pver = parsed if parsed else ("unknown", name, version)
            packages[ref] = {"ref": ref, "name": pname, "version": version or pver,
                             "ecosystem": eco, "purl": purl}
            if len(packages) > config.MAX_COMPONENTS:
                bad(f"More than {config.MAX_COMPONENTS} components")
            if c.get("components"):
                if not isinstance(c["components"], list):
                    bad("Nested 'components' must be an array")
                walk(c["components"], level + 1)

    walk(comps)

    meta = (doc.get("metadata") or {}).get("component") or {}
    root_name = clean(meta.get("name", "application"), "metadata.component.name", 255) or "application"
    root_ref = clean(meta.get("bom-ref") or "__root__", "metadata.component.bom-ref", 255)
    if root_ref in packages:
        bad("metadata.component bom-ref collides with a component")

    edges: set[tuple[str, str]] = set()
    deps = doc.get("dependencies", [])
    if not isinstance(deps, list):
        bad("'dependencies' must be an array")
    for d in deps:
        if not isinstance(d, dict):
            bad("Each dependency entry must be an object")
        ref = clean(d.get("ref"), "dependency.ref", 255)
        if ref not in packages and ref != root_ref:
            bad(f"dependency.ref refers to unknown component: {ref[:60]}")
        for ch in d.get("dependsOn", []) or []:
            ch = clean(ch, "dependsOn", 255)
            if ch not in packages:
                bad(f"dependsOn refers to unknown component: {ch[:60]}")
            edges.add((ref, ch))
            if len(edges) > MAX_EDGES:
                bad("Too many dependency edges")

    # No explicit tree for the root: attach every component that nobody depends on
    # (or everything, when there are no edges at all).
    if not any(p == root_ref for p, _ in edges):
        has_parent = {c for _, c in edges}
        for r in packages:
            if r not in has_parent:
                edges.add((root_ref, r))
    direct = {c for p, c in edges if p == root_ref}
    for r, p in packages.items():
        p["is_direct"] = r in direct

    return {"filename": fname, "sha256": hashlib.sha256(raw).hexdigest(), "spec_version": spec,
            "root_ref": root_ref, "root_name": root_name,
            "packages": list(packages.values()), "edges": sorted(edges)}
