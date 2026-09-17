# routers/auth.py

import hashlib
import httpx
import re
from datetime import datetime, timedelta, timezone
from fastapi.concurrency import run_in_threadpool
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Cookie
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, EmailStr, Field, AfterValidator
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.oauth import oauth
from fastapi.responses import RedirectResponse
from app.core.config import settings

from app.db.database import get_db

# IMPORTANT: renamed to avoid clashing with SQLAlchemy's Session type
from app.db.models import User, Session as SessionModel

from app.core.security import hash_password, verify_password, generate_session_token

router = APIRouter(prefix="/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)


def check_not_breached(password: str) -> str:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = httpx.get(
            f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
        response.raise_for_status()
    except httpx.HTTPError:
        return password

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            raise ValueError(
                "This password has appeared in a known data breach. Please choose a different one."
            )
    return password


def verify_password_strength(v: str) -> str:
    if len(v) >= 16:
        return v

    if not any(char.isupper() for char in v):
        raise ValueError(
            "Password must contain at least one uppercase letter.")
    if not any(char.islower() for char in v):
        raise ValueError(
            "Password must contain at least one lowercase letter.")
    if not any(char.isdigit() for char in v):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_]", v):
        raise ValueError(
            "Password must contain at least one special character.")
    return v


StrongPassword = Annotated[
    str,
    Field(min_length=10, max_length=128),
    AfterValidator(check_not_breached),
    AfterValidator(verify_password_strength),
]


class SignupRequest(BaseModel):
    email: EmailStr
    password: StrongPassword


class LoginRequest(BaseModel):
    identifier: str
    password: str


@router.post("/signup", status_code=201)
@limiter.limit("5/minute")
def signup(request: Request, payload: SignupRequest, db: Session = Depends(get_db)):
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        account_setup_complete=True,
    )
    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400, detail="Unable to create account with these details")

    return {"message": "Account created", "user_id": user.id}


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, response: Response, payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        (User.email == payload.identifier) | (
            User.username == payload.identifier)
    ).first()

    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$dGVzdGhhc2g"
    password_hash_to_check = user.password_hash if (
        user and user.password_hash) else dummy_hash

    valid = await run_in_threadpool(verify_password, payload.password, password_hash_to_check)

    if not user or not user.password_hash or not valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    session_token = generate_session_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    db_session = SessionModel(
        token=session_token, user_id=user.id, expires_at=expires_at)
    db.add(db_session)
    db.commit()

    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
    )

    return {"message": "Login successful"}


@router.post("/logout")
def logout(request: Request, response: Response, session_token: str | None = Cookie(default=None), db: Session = Depends(get_db)):
    if session_token:
        db.query(SessionModel).filter(
            SessionModel.token == session_token).delete()
        db.commit()

    response.delete_cookie("session_token")
    return {"message": "Logged out"}


@router.get("/github/login")
async def github_login(request: Request):
    redirect_uri = f"{settings.oauth_redirect_base_url}/auth/github/callback"
    return await oauth.github.authorize_redirect(request, redirect_uri)


@router.get("/github/callback")
async def github_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.github.authorize_access_token(request)
    profile = (await oauth.github.get("user", token=token)).json()

    emails = (await oauth.github.get("user/emails", token=token)).json()
    primary = next((e for e in emails if e.get("primary")),
                   emails[0] if emails else None)
    if primary is None:
        raise HTTPException(
            status_code=400, detail="GitHub account has no accessible email")

    user = _find_or_create_oauth_user(
        db, provider_field="github_id", provider_id=str(profile["id"]),
        email=primary["email"], email_verified=primary.get("verified", False),
    )
    return _issue_session_and_redirect(db, user)


@router.get("/google/login")
async def google_login(request: Request):
    redirect_uri = f"{settings.oauth_redirect_base_url}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.google.authorize_access_token(request)
    profile = token.get("userinfo")

    user = _find_or_create_oauth_user(
        db, provider_field="google_id", provider_id=profile["sub"],
        email=profile["email"], email_verified=profile.get(
            "email_verified", False),
    )
    return _issue_session_and_redirect(db, user)


def _find_or_create_oauth_user(
    db: Session, provider_field: str, provider_id: str, email: str, email_verified: bool
) -> User:
    existing_by_provider = db.query(User).filter(
        getattr(User, provider_field) == provider_id).first()
    if existing_by_provider:
        return existing_by_provider

    existing_by_email = db.query(User).filter(User.email == email).first()
    if existing_by_email:
        if not email_verified:
            raise HTTPException(
                status_code=409,
                detail="An account with this email already exists. Log in with your password first to link this provider.",
            )
        setattr(existing_by_email, provider_field, provider_id)
        db.commit()
        db.refresh(existing_by_email)
        return existing_by_email

    user = User(
        email=email,
        password_hash=None,
        account_setup_complete=False,
        **{provider_field: provider_id},
    )
    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400, detail="Unable to create account with these details")
    return user


def _issue_extension_redirect(db: Session, user: User) -> RedirectResponse:
    session_token = generate_session_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    db_session = SessionModel(
        token=session_token, user_id=user.id, expires_at=expires_at)
    db.add(db_session)
    db.commit()

    return RedirectResponse(url=f"{settings.extension_oauth_redirect_url}#session_token={session_token}")
