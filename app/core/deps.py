from datetime import datetime, timezone
from fastapi import Depends, HTTPException, Cookie
from sqlalchemy.orm import Session as DBSession

from app.db.database import get_db
from app.db.models import User, Session


def get_current_user(
    session_token: str | None = Cookie(default=None),
    db: DBSession = Depends(get_db),
) -> User:
    if session_token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session = db.query(Session).filter(Session.token == session_token).first()

    if session is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if session.expires_at < datetime.now(timezone.utc):
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expired")

    return session.user
