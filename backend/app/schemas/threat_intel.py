from pydantic import BaseModel, Field
from datetime import datetime
from uuid import uuid4

class ThreatIntelligenceBase(BaseModel):
    indicator_id: str
    indicator: str | None = None
    indicator_type: str | None = None
    provider: str
    verdict: str
    score: float | None = None
    categories: list[str] = Field(default_factory=list)
    raw_result: dict = Field(default_factory=dict)
    checked_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    metadata: dict = Field(default_factory=dict)

class ThreatIntelligenceCreate(ThreatIntelligenceBase):
    case_id: str

class ThreatIntelligence(ThreatIntelligenceBase):
    threat_intel_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
