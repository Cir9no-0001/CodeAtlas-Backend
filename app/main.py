# main.py

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.routers import auth
from app.routers.auth import limiter
from app.core.config import settings

app = FastAPI(title="CodeAtlas Backend")

app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)


@app.get("/")
def root():
    return {"status": "CodeAtlas backend is running"}
