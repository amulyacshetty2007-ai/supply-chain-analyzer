import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./dev.db")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
AUDITOR_INVITE_CODE = os.getenv("AUDITOR_INVITE_CODE", "")
OSV_MODE = os.getenv("OSV_MODE", "auto")          # auto | online | offline
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(2 * 1024 * 1024)))
MAX_COMPONENTS = int(os.getenv("MAX_COMPONENTS", "5000"))
SCANS_PER_MINUTE = int(os.getenv("SCANS_PER_MINUTE", "6")) 
