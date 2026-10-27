import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from . import config
from .models import Base

engine = create_engine(config.DATABASE_URL, pool_pre_ping=True, pool_recycle=1800)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(retries: int = 30):
    for i in range(retries):
        try:
            Base.metadata.create_all(engine)
            return
        except Exception:
            if i == retries - 1:
                raise
            time.sleep(2)
