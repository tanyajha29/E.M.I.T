from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from uuid import uuid4

class RelationshipClass(str, Enum):
    OBSERVED = "OBSERVED"
    CORRELATED = "CORRELATED"
    INFERRED = "INFERRED"

class NodeType(str, Enum):
    APPLICATION = "APPLICATION"
    CAPABILITY = "CAPABILITY"
    PERMISSION = "PERMISSION"
    API = "API"
    DOMAIN = "DOMAIN"
    IP = "IP"
    DNS_EVENT = "DNS_EVENT"
    NETWORK_EVENT = "NETWORK_EVENT"
    THREAT_INTEL = "THREAT_INTEL"

class RelationshipType(str, Enum):
    CONTAINS = "CONTAINS"
    USES = "USES"
    EMBEDS = "EMBEDS"
    RESOLVES_TO = "RESOLVES_TO"
    OBSERVED_IN = "OBSERVED_IN"
    CONNECTS_TO = "CONNECTS_TO"
    REPEATS = "REPEATS"
    CORRELATED_WITH = "CORRELATED_WITH"
    SUPPORTED_BY = "SUPPORTED_BY"

class AttackNodeBase(BaseModel):
    node_type: str
    label: str
    entity_reference: str
    timestamp: datetime | None = None
    metadata: dict = Field(default_factory=dict)

class AttackNodeCreate(AttackNodeBase):
    case_id: str

class AttackNode(AttackNodeBase):
    node_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AttackEdgeBase(BaseModel):
    source_node_id: str
    target_node_id: str
    relationship_type: str
    relationship_class: RelationshipClass
    strength: str
    reason: str
    timestamp: datetime | None = None
    sequence_index: int | None = None
    supporting_observation_ids: list[str] = Field(default_factory=list)
    supporting_correlation_ids: list[str] = Field(default_factory=list)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)

class AttackEdgeCreate(AttackEdgeBase):
    case_id: str

class AttackEdge(AttackEdgeBase):
    edge_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
