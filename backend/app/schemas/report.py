from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from uuid import uuid4

class ReportStatus(str, Enum):
    PENDING = "PENDING"
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ReportFormat(str, Enum):
    HTML = "HTML"
    PDF = "PDF"
    BOTH = "BOTH"

class ReportBase(BaseModel):
    report_type: str = "FULL_FORENSIC_DOSSIER"
    report_format: ReportFormat = ReportFormat.BOTH
    title: str = "E.M.I.T. Forensic Investigation Report"
    storage_path: str = ""
    html_path: Optional[str] = None
    pdf_path: Optional[str] = None
    status: ReportStatus = ReportStatus.PENDING
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ReportCreate(ReportBase):
    case_id: str

class Report(ReportBase):
    report_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    generated_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
