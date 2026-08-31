from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from uuid import uuid4

class CorrelationStrength(str, Enum):
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"

class CorrelationBase(BaseModel):
    source_observation_ids: list[str] = Field(default_factory=list)
    target_observation_ids: list[str] = Field(default_factory=list)
    source_evidence_id: str | None = None
    target_evidence_id: str | None = None
    relationship_type: str
    strength: CorrelationStrength
    reason: str
    evidence_class: str = "CORRELATED"
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)

class CorrelationCreate(CorrelationBase):
    case_id: str

class Correlation(CorrelationBase):
    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
