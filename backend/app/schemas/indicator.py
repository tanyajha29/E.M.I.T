from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from uuid import uuid4

class IndicatorType(str, Enum):
    DOMAIN = "DOMAIN"
    IP = "IP"
    URL = "URL"
    HASH = "HASH"
    PACKAGE = "PACKAGE"
    API = "API"
    PERMISSION = "PERMISSION"
    PORT = "PORT"
    PROTOCOL = "PROTOCOL"
    CERTIFICATE = "CERTIFICATE"
    CAPABILITY = "CAPABILITY"

class IndicatorBase(BaseModel):
    type: IndicatorType
    value: str
    normalized_value: str
    source: str | None = None
    confidence: float = 1.0
    evidence_id: str | None = None
    timestamp: datetime | None = None
    metadata: dict = Field(default_factory=dict)

class IndicatorCreate(IndicatorBase):
    pass

class Indicator(IndicatorBase):
    indicator_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
