from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from uuid import uuid4

class CaseStatus(str, Enum):
    OPEN = "OPEN"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"

class CaseBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field("", max_length=1000)

class CaseCreate(CaseBase):
    pass

class CaseUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: CaseStatus | None = None

class Case(CaseBase):
    case_id: str = Field(default_factory=lambda: str(uuid4()))
    status: CaseStatus = CaseStatus.OPEN
    owner_id: str | None = None
    owner_name: str | None = None
    assigned_user_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
