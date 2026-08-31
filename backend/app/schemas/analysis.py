from pydantic import BaseModel, Field
from datetime import datetime
from uuid import uuid4

class AnalysisBase(BaseModel):
    provider: str  # e.g. "mobsf" or "tshark"
    provider_version: str
    analysis_type: str  # e.g. "APK_STATIC" or "PCAP_NETWORK"
    status: str = "pending"
    tool_results: dict = Field(default_factory=dict)
    normalized_summary: dict = Field(default_factory=dict)
    error: str | None = None

class AnalysisCreate(AnalysisBase):
    case_id: str
    evidence_id: str

class Analysis(AnalysisBase):
    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    evidence_id: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
