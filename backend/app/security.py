import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from . import config
from .db import get_db
from .models import User

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode()[:72], bcrypt.gensalt(rounds=12)).decode()


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode()[:72], hashed.encode())
    except ValueError:
        return False


def make_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=config.ACCESS_TOKEN_MINUTES)
    return jwt.encode({"sub": str(user.id), "role": user.role, "exp": exp},
                      config.SECRET_KEY, algorithm="HS256")


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    try:
        data = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
        user = db.get(User, int(data["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        user = None
    if not user:
        raise HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    return user


def require_role(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, f"Requires role: {', '.join(roles)}")
        return user
    return dep


class RateLimiter:
    """Sliding-window limiter: hash map of key -> deque of timestamps."""

    def __init__(self, limit: int, window: int):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, key: str):
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                retry = int(self.window - (now - q[0])) + 1
                raise HTTPException(429, f"Rate limit exceeded. Retry in {retry}s.",
                                    headers={"Retry-After": str(retry)})
            q.append(now)


scan_limiter = RateLimiter(config.SCANS_PER_MINUTE, 60)
upload_limiter = RateLimiter(20, 60)
auth_limiter = RateLimiter(10, 60)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
