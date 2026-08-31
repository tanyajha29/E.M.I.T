from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from uuid import uuid4
from typing import Dict, List, Optional

class AnalysisType(str, Enum):
    APK = "APK"
    PCAP = "PCAP"

class AnalysisStatus(str, Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"

class AnalysisStage(str, Enum):
    PENDING = "PENDING"
    VALIDATING = "VALIDATING"
    ANALYZING = "ANALYZING"
    NORMALIZING = "NORMALIZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ProviderStatus(str, Enum):
    DISABLED = "DISABLED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ProviderExecutionRecord(BaseModel):
    provider: str
    provider_version: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: ProviderStatus
    duration: Optional[float] = None
    error: Optional[str] = None
    output_metadata: dict = Field(default_factory=dict)

class AnalysisRunBase(BaseModel):
    case_id: str
    evidence_id: str
    analysis_type: AnalysisType

class AnalysisRunCreate(AnalysisRunBase):
    pass

class AnalysisRun(AnalysisRunBase):
    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    status: AnalysisStatus = AnalysisStatus.PENDING
    current_stage: AnalysisStage = AnalysisStage.PENDING
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    provider_results: Dict[str, ProviderExecutionRecord] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
