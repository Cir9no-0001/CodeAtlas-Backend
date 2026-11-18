from fastapi import Depends, HTTPException, Cookie, Header
from datetime import datetime, timezone
from sqlalchemy.orm import Session as DBSession

from app.db.database import get_db
from app.db.models import User, Session
from app.core.security import hash_session_token


def get_current_user(
    session_token: str | None = Cookie(default=None),
    authorization: str | None = Header(default=None),
    db: DBSession = Depends(get_db),
) -> User:
    token = session_token
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ")

    if token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session = db.query(Session).filter(Session.token_hash == hash_session_token(token)).first()
    if session is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if session.expires_at < datetime.now(timezone.utc):
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expired")

    return session.user
