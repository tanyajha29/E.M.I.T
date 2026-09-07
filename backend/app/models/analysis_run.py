from pydantic import BaseModel, Field, model_validator
from datetime import datetime
from enum import Enum
from uuid import uuid4
from typing import Dict, List, Optional, Any

class AnalysisType(str, Enum):
    APK = "APK"
    PCAP = "PCAP"

class AnalysisStatus(str, Enum):
    PENDING = "PENDING"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    ANALYZING = "ANALYZING"
    NORMALIZING = "NORMALIZING"
    CORRELATING = "CORRELATING"
    BUILDING_GRAPH = "BUILDING_GRAPH"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class AnalysisStage(str, Enum):
    PENDING = "PENDING"
    STARTING = "STARTING"
    VALIDATING = "VALIDATING"
    ANALYZING = "ANALYZING"
    NORMALIZING = "NORMALIZING"
    CORRELATING = "CORRELATING"
    BUILDING_GRAPH = "BUILDING_GRAPH"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ProviderStatus(str, Enum):
    PENDING = "PENDING"
    STARTING = "STARTING"
    EXECUTING = "EXECUTING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"
    DISABLED = "DISABLED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"

class ProviderExecutionRecord(BaseModel):
    provider: str
    provider_version: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: ProviderStatus = ProviderStatus.PENDING
    duration: Optional[float] = None
    duration_seconds: Optional[float] = None
    message: Optional[str] = None
    error: Optional[str] = None
    output_metadata: dict = Field(default_factory=dict)
    execution_mode: Optional[str] = None  # "CONTAINER" or "HOST"
    container_name: Optional[str] = None  # e.g., "emit-mobsf"

    @model_validator(mode='after')
    def sync_duration_fields(self):
        if self.duration is not None and self.duration_seconds is None:
            self.duration_seconds = self.duration
        elif self.duration_seconds is not None and self.duration is None:
            self.duration = self.duration_seconds
        return self

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
    progress_percent: int = Field(default=0, ge=0, le=100)
    elapsed_seconds: Optional[float] = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    provider_results: Dict[str, ProviderExecutionRecord] = Field(default_factory=dict)
    providers: Dict[str, ProviderExecutionRecord] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    @model_validator(mode='after')
    def sync_providers_map(self):
        # Synchronize provider_results and providers dictionary for maximum client compatibility
        if self.provider_results and not self.providers:
            self.providers = self.provider_results
        elif self.providers and not self.provider_results:
            self.provider_results = self.providers
        return self
