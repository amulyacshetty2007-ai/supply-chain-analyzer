import os
os.environ.update(DATABASE_URL="sqlite:///./test.db", OSV_MODE="offline", AUDITOR_INVITE_CODE="inv")
from pathlib import Path
from fastapi.testclient import TestClient
from app.graph import Graph
from app.main import app
from app.db import init_db

SAMPLE = Path(__file__).resolve().parents[1] / "data" / "sample-sbom.json"


def test_graph_algorithms():
    g = Graph("ABCDE", [("A", "B"), ("B", "C"), ("C", "B"), ("A", "D"), ("D", "C"), ("C", "E")])
    assert [sorted(c) for c in g.cycles()] == [["B", "C"]]
    assert g.dependents("E") == {"A", "B", "C", "D"}
    assert g.path_to(g.bfs("A")[1], "E") == ["A", "B", "C", "E"] or len(g.path_to(g.bfs("A")[1], "E")) == 4
    order = g.topo_order()
    assert order.index("A") < order.index("C") < order.index("E")


def test_end_to_end():
    init_db()
    c = TestClient(app)
    c.post("/api/auth/register", json={"username": "dev1", "password": "password123"})
    tok = c.post("/api/auth/login", data={"username": "dev1", "password": "password123"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    pid = c.post("/api/projects/demo", headers=h).json()["id"]
    r = c.post(f"/api/projects/{pid}/scan", headers=h)
    assert r.status_code == 201, r.text
    rep = c.get(f"/api/scans/{r.json()['scan_id']}/report", headers=h).json()
    names = {v["name"] for v in rep["vulnerable"]}
    assert {"lodash", "minimist", "log4j-core"} <= {n.split(":")[-1] for n in names}
    assert rep["summary"]["cycles"] == 1 and rep["fix_first"]
    # security: bad uploads
    bad = c.post(f"/api/projects/{pid}/manifest", headers=h, files={"file": ("x.exe", b"MZ", "application/octet-stream")})
    assert bad.status_code == 415
    bad = c.post(f"/api/projects/{pid}/manifest", headers=h, files={"file": ("x.json", b'{"bomFormat":"nope"}', "application/json")})
    assert bad.status_code == 422
    # RBAC
    c.post("/api/auth/register", json={"username": "aud1", "password": "password123", "role": "auditor", "invite_code": "inv"})
    at = c.post("/api/auth/login", data={"username": "aud1", "password": "password123"}).json()["access_token"]
    ah = {"Authorization": f"Bearer {at}"}
    assert c.post(f"/api/projects/{pid}/scan", headers=ah).status_code == 403
    assert c.get(f"/api/scans/{r.json()['scan_id']}/report", headers=ah).status_code == 200
    assert c.get("/api/audit/scans", headers=h).status_code == 403
    # rate limit
    codes = [c.post(f"/api/projects/{pid}/scan", headers=h).status_code for _ in range(8)]
    assert 429 in codes
