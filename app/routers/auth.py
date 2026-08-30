import hashlib
import httpx
import re
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, Field, AfterValidator
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.db.database import get_db
from app.db.models import User
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
    """
    Long passphrases (16+ chars) are exempt from composition rules —
    length alone gives them sufficient entropy (NIST SP 800-63B).
    Shorter passwords must satisfy character-class complexity to
    compensate for their shorter length.
    """
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
