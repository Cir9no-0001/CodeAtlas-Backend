from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.routers import auth
from app.routers.auth import limiter
from app.core.config import settings
from app.db import models  # noqa: F401  (registers the tables)
from app.db.database import Base, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.environment == "development":
        Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="CodeAtlas Backend", lifespan=lifespan)

app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)


@app.get("/")
def root():
    return {"status": "CodeAtlas backend is running"}