from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from uuid import uuid4

class EvidenceType(str, Enum):
    APK = "APK"
    PCAP = "PCAP"
    PCAPNG = "PCAPNG"

class EvidenceFileBase(BaseModel):
    file_name: str
    file_type: EvidenceType
    mime_type: str
    file_size: int

class EvidenceFileCreate(EvidenceFileBase):
    pass

class EvidenceFile(EvidenceFileBase):
    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    sha256: str
    storage_provider: str
    storage_path: str
    status: str = "uploaded"
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    deleted_at: datetime | None = None
