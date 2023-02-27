from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt
from models.user import User
import os
from dotenv import load_dotenv

load_dotenv()

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="api/auth/login")


def get_password_hash(password) -> str:
    return bcrypt_context.hash(password)


def verify_password(plain_pass, hashed_pass) -> bool:
    return bcrypt_context.verify(plain_pass, hashed_pass)


def authenticate(username: str, password: str, db: Session) -> Optional[User]:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_token(
    token_type: str,
    sub: str,
    lifetime: Optional[timedelta] = None,
) -> str:
    payload = {}
    if lifetime:
        expire = datetime.utcnow() + lifetime
    else:
        expire = datetime.utcnow() + timedelta(minutes=300)
    payload["type"] = token_type
    payload["exp"] = expire
    payload["iat"] = datetime.utcnow()
    payload["sub"] = str(sub)
    return jwt.encode(payload, os.getenv("TOKEN"), algorithm=os.getenv("ALGORYTM"))


def create_access_token(*, sub: str, expires_delta: Optional[timedelta] = None) -> str:
    return create_token(token_type="access_token", sub=sub, lifetime=expires_delta)
