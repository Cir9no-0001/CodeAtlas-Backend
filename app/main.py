from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.routers import auth
from app.routers.auth import limiter

app = FastAPI(title="CodeAtlas Backend")

# Wire up rate limiting at the app level — required for @limiter.limit(...)
# decorators in auth.py to actually be enforced, not just decorative
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)


@app.get("/")
def root():
    return {"status": "CodeAtlas backend is running"}
