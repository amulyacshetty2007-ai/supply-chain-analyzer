# Supply-Chain Risk & Dependency Analyzer

Upload a CycloneDX SBOM → match every package against OSV → see how one vulnerable library spreads
through your dependency graph, which paths matter most, and the smallest set of packages to fix first.

## Run
```bash
cp .env.example .env        # edit secrets
docker compose up --build
```
- App + UI: http://localhost:8000 · API docs (Swagger): http://localhost:8000/docs
- **Beekeeper Studio**: MySQL, host `127.0.0.1`, port `3307`, user/password/db from `.env` (default `sca`/`change-me-db`/`sca`).
- `OSV_MODE=auto` calls api.osv.dev and falls back to a bundled 4-advisory sample if offline (`offline` forces it, so the demo always works).

## Demo (2 minutes)
1. Register as **developer** → **Load demo project** (uploads `sample/sample-sbom.json` and scans it).
2. Pick `lodash` in *Blast radius*: red node = vulnerable, orange = every package that depends on it, red line = shortest path from the app.
3. Show *Investigate these first*, *Most critical paths*, and the `@acme/ui-kit ⇄ @acme/utils` cycle.
4. Register as **auditor** (invite code from `.env`) → read-only access to all projects; `GET /api/audit/scans`.
5. In Beekeeper: `SELECT * FROM findings;`, `SELECT * FROM dependency_edges;`, `SELECT id,status,risk_score FROM scans;`.
6. Try uploading a `.exe` or `{"bomFormat":"x"}` to show validation, or scan 7× in a minute to see HTTP 429.

## API (`/api`)
| Method & path | Role | Purpose |
|---|---|---|
| POST `/auth/register`, `/auth/login`, GET `/auth/me` | any | JWT auth (auditor needs invite code) |
| POST/GET `/projects`, GET/DELETE `/projects/{id}`, POST `/projects/demo` | developer (read: auditor too) | Projects |
| POST `/projects/{id}/manifest` | developer | Upload CycloneDX JSON |
| POST `/projects/{id}/scan` | developer | Scan latest (or given `manifest_id`) manifest |
| GET `/scans/{id}/report` | owner / auditor | Full risk report + graph |
| GET `/audit/scans` | auditor | Every scan across projects |

## Database (MySQL)
`users, projects, manifests, packages, dependency_edges, vulnerabilities (OSV cache), scans (history + JSON report), findings`.

## Data structures & algorithms (`backend/app/graph.py`)
| Need | Technique |
|---|---|
| Dependency graph, reverse graph | Hash-map adjacency lists |
| Blast radius (who depends on X) | Reverse BFS |
| Hops from your app | BFS shortest path + parent pointers |
| Circular dependencies | Tarjan SCC (iterative) |
| Safe remediation ordering | Kahn topological sort on the SCC condensation |
| Hub-weighted critical path | Dijkstra (edges into widely shared packages are cheaper) |
| Ranked paths per vulnerability | Pruned DFS enumeration, ranked by CVSS × exposure ÷ length |
| Minimal fix-first set | Greedy weighted set cover over direct dependencies |
| Rate limiting | Hash map of sliding-window deques |

Risk per package = `CVSS × (1 + ln(1 + dependents)) / (1 + 0.15·(depth−1))`; project score = `100·(1 − e^(−Σ/40))`.

## Security
- Uploads: `.json` only, content-type allow-list, 2 MB cap with bounded streaming read, strict UTF-8, no NUL/control chars, JSON depth ≤ 20, ≤ 5000 components, CycloneDX schema checks, reference integrity, duplicate refs rejected. Files are parsed in memory and **never written to disk**; filenames are sanitised and stored only as labels.
- bcrypt password hashing, JWT with expiry, role checks on every route, 404 (not 403) for other users' projects.
- Rate limits: scans (`SCANS_PER_MINUTE`), uploads, login/register per IP. SQLAlchemy ORM (no raw SQL).
- CSP, `nosniff`, `X-Frame-Options`; UI escapes all package data; container runs as non-root.
- Before production: set a real `SECRET_KEY`, serve over HTTPS, move rate limiting to Redis if running several workers.

## Tests
`cd backend && python -m pytest tests` (graph algorithms, end-to-end flow, RBAC, bad uploads, rate limit).
