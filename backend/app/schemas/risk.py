from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from uuid import uuid4

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RiskAssessmentBase(BaseModel):
    risk_level: RiskLevel
    evidence_strength: str = "MODERATE"
    confidence: float
    summary: str
    observed_facts: list[str] = Field(default_factory=list)
    inferences: list[str] = Field(default_factory=list)
    possible_interpretations: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    analyst_guidance: list[str] = Field(default_factory=list)
    supporting_observation_ids: list[str] = Field(default_factory=list)
    supporting_correlation_ids: list[str] = Field(default_factory=list)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    category_scores: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)

class RiskAssessmentCreate(RiskAssessmentBase):
    case_id: str

class RiskAssessment(RiskAssessmentBase):
    risk_assessment_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
