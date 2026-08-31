from pydantic import BaseModel, Field
from datetime import datetime
from uuid import uuid4

class ObservationBase(BaseModel):
    indicator_id: str
    evidence_id: str
    observation_type: str
    source: str
    value: str
    confidence: float = 1.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict = Field(default_factory=dict)

class ObservationCreate(ObservationBase):
    case_id: str

class Observation(ObservationBase):
    observation_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
