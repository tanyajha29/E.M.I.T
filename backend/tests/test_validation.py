import pytest
from pydantic import ValidationError
from app.schemas.case import CaseCreate
from app.schemas.evidence import EvidenceFileCreate

def test_case_validation():
    # Empty name must fail validation
    with pytest.raises(ValidationError):
        CaseCreate(name="", description="Description")

    # Excessively long name should fail validation
    with pytest.raises(ValidationError):
        CaseCreate(name="a" * 101, description="Description")

    # Correct model should validate successfully
    case = CaseCreate(name="Trojan Analysis", description="Static analysis")
    assert case.name == "Trojan Analysis"

def test_evidence_validation():
    # Malformed file_type Enum must fail validation
    with pytest.raises(ValidationError):
        EvidenceFileCreate(
            file_name="malware.apk",
            file_type="INVALID_TYPE",  # type: ignore
            mime_type="application/vnd.android.package-archive",
            file_size=1024
        )
