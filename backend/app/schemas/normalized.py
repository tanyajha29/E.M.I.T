from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field
from app.schemas.indicator import IndicatorType

class SourceType(str, Enum):
    APK = "APK"
    PCAP = "PCAP"
    MOBSF = "MOBSF"
    ANDROGUARD = "ANDROGUARD"
    JADX = "JADX"
    APKTOOL = "APKTOOL"
    TSHARK = "TSHARK"
    SCAPY = "SCAPY"
    UNKNOWN = "UNKNOWN"

class ObservationType(str, Enum):
    EMBEDDED_DOMAIN = "EMBEDDED_DOMAIN"
    DNS_QUERY = "DNS_QUERY"
    DNS_RESPONSE = "DNS_RESPONSE"
    EMBEDDED_URL = "EMBEDDED_URL"
    EMBEDDED_IP = "EMBEDDED_IP"
    NETWORK_IP = "NETWORK_IP"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    REPEATED_COMMUNICATION = "REPEATED_COMMUNICATION"
    DECLARED_PERMISSION = "DECLARED_PERMISSION"
    SUSPICIOUS_PERMISSION = "SUSPICIOUS_PERMISSION"
    PACKAGE_NAME = "PACKAGE_NAME"
    APPLICATION_NAME = "APPLICATION_NAME"
    SIGNING_CERTIFICATE = "SIGNING_CERTIFICATE"
    SUSPICIOUS_API = "SUSPICIOUS_API"
    SUSPICIOUS_STRING = "SUSPICIOUS_STRING"
    NETWORK_PORT = "NETWORK_PORT"
    NETWORK_PROTOCOL = "NETWORK_PROTOCOL"
    CAPABILITY = "CAPABILITY"

class EvidenceReference(BaseModel):
    evidence_id: str
    case_id: str
    source_type: SourceType
    file_name: Optional[str] = None
    sha256: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class RawObservationItem(BaseModel):
    indicator_type: IndicatorType
    value: str
    observation_type: str
    source: str
    tool: str
    confidence: float = 1.0
    timestamp: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
