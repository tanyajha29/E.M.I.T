from pydantic import BaseModel, Field, EmailStr
from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import uuid4

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    INVESTIGATOR = "INVESTIGATOR"
    VIEWER = "VIEWER"

class UserCreate(BaseModel):
    email: str = Field(..., min_length=3, max_length=150)
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=1, max_length=100)

class UserLogin(BaseModel):
    email: str = Field(..., min_length=3, max_length=150)
    password: str = Field(..., min_length=1)

class UserOut(BaseModel):
    user_id: str
    email: str
    full_name: str
    role: UserRole
    badge_id: str
    is_active: bool = True
    created_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut

class CaseAssignmentUpdate(BaseModel):
    assigned_user_ids: List[str] = Field(default_factory=list)
