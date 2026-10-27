from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .db import init_db
from .routes import router

FRONT = next((p for p in (Path(__file__).resolve().parent.parent / "frontend", Path(__file__).resolve().parents[2] / "frontend") if p.exists()), Path("frontend"))
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Supply-Chain Risk & Dependency Analyzer", version="1.0.0",
              description="Upload a CycloneDX SBOM, scan it against OSV, and get blast-radius, "
                          "ranked dependency paths and a minimal fix-first set.", lifespan=lifespan)
app.include_router(router, prefix="/api")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                         "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
        resp.headers["Content-Security-Policy"] = CSP      # Swagger UI needs CDN scripts, so skip it there
    return resp


@app.get("/health", include_in_schema=False)
def health():
    return {"ok": True}


if FRONT.exists():
    app.mount("/", StaticFiles(directory=FRONT, html=True), name="ui")
