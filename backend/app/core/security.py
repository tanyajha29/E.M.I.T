import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import uuid4
from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import settings
from app.schemas.user import UserOut, UserRole
from app.db.repositories.user_repository import UserRepository
from app.db.repositories.session_repository import SessionRepository

security_bearer = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def create_access_token(user_id: str, email: str, role: str) -> tuple[str, str, datetime]:
    session_id = str(uuid4())
    expires_delta = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_at = datetime.utcnow() + expires_delta
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "jti": session_id,
        "exp": expires_at
    }
    encoded_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt, session_id, expires_at

def decode_access_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except Exception:
        return None

def extract_token(request: Request, auth_creds: Optional[HTTPAuthorizationCredentials] = None) -> Optional[str]:
    if auth_creds and auth_creds.credentials:
        return auth_creds.credentials
    # Fallback to Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    # Fallback to HttpOnly cookie
    cookie_token = request.cookies.get("emit_session")
    if cookie_token:
        return cookie_token.strip()
    return None

def get_current_user(
    request: Request,
    auth_creds: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> UserOut:
    token = extract_token(request, auth_creds)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    session_id = payload.get("jti")
    if session_id:
        session_repo = SessionRepository()
        if not session_repo.is_session_valid(session_id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been revoked or expired",
                headers={"WWW-Authenticate": "Bearer"}
            )

    user_repo = UserRepository()
    user_doc = user_repo.get_by_id(payload["sub"])
    if not user_doc or not user_doc.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account disabled",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return UserOut(
        user_id=user_doc["user_id"],
        email=user_doc["email"],
        full_name=user_doc.get("full_name", ""),
        role=UserRole(user_doc.get("role", UserRole.INVESTIGATOR)),
        badge_id=user_doc.get("badge_id", f"EMIT-IR-{user_doc['user_id'][:4].upper()}"),
        is_active=user_doc.get("is_active", True),
        created_at=user_doc.get("created_at", datetime.utcnow())
    )

def get_optional_current_user(
    request: Request,
    auth_creds: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> Optional[UserOut]:
    try:
        return get_current_user(request, auth_creds)
    except HTTPException:
        return None

def require_role(allowed_roles: List[UserRole]):
    def role_checker(current_user: UserOut = Depends(get_current_user)) -> UserOut:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this operation"
            )
        return current_user
    return role_checker
