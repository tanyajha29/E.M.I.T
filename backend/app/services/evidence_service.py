import hashlib
from app.db.repositories.evidence_repository import EvidenceRepository
from app.db.repositories.case_repository import CaseRepository
from app.services.storage import LocalStorageProvider
from app.schemas.evidence import EvidenceFile
from app.core.config import settings
from datetime import datetime

class DuplicateEvidenceError(Exception):
    pass

class CaseNotFoundError(Exception):
    pass

class EvidenceService:
    def __init__(self, storage_provider=None):
        self.repository = EvidenceRepository()
        self.case_repo = CaseRepository()
        self.storage = storage_provider or LocalStorageProvider(base_dir="storage")

    def _calculate_sha256(self, file_content: bytes) -> str:
        sha256_hash = hashlib.sha256()
        sha256_hash.update(file_content)
        return sha256_hash.hexdigest()

    def upload_evidence(self, case_id: str, file_name: str, file_content: bytes, mime_type: str) -> EvidenceFile:
        # 1. Verify case exists
        case_dict = self.case_repo.find_one({"case_id": case_id})
        if not case_dict:
            raise CaseNotFoundError(f"Case with ID {case_id} not found")

        # 2. Calculate SHA-256 from actual uploaded bytes (never trust client)
        sha256 = self._calculate_sha256(file_content)

        # 3. Detect duplicates within the case context
        duplicate = self.repository.find_one({"case_id": case_id, "sha256": sha256})
        if duplicate:
            raise DuplicateEvidenceError(f"File with hash {sha256} already uploaded for case {case_id}")

        # 4. Infer type based on extension & validate file signatures / content (magic bytes)
        file_size = len(file_content)
        if file_size < 4:
            raise ValueError("File content is truncated or too small to be valid")

        if file_size > settings.MAX_EVIDENCE_SIZE_BYTES:
            raise ValueError(f"File size exceeds maximum allowed limit of {settings.MAX_EVIDENCE_SIZE_BYTES} bytes")

        magic = file_content[:4]
        file_name_lower = file_name.lower()
        
        if file_name_lower.endswith(".apk"):
            if magic != b"PK\x03\x04":
                raise ValueError("Invalid APK file signature (magic bytes mismatch)")
            file_type = "APK"
        elif file_name_lower.endswith(".pcap"):
            if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
                raise ValueError("Invalid PCAP file signature (magic bytes mismatch)")
            file_type = "PCAP"
        elif file_name_lower.endswith(".pcapng"):
            if magic != b"\x0a\x0d\x0d\x0a":
                raise ValueError("Invalid PCAPNG file signature (magic bytes mismatch)")
            file_type = "PCAPNG"
        else:
            raise ValueError("Unsupported evidence file format. Supported extensions: .apk, .pcap, .pcapng")

        # Save binary file payload first using StorageProvider
        storage_path = self.storage.save_file(file_name, file_content)

        # 5. Write metadata record
        evidence_data = EvidenceFile(
            case_id=case_id,
            file_name=file_name,
            file_type=file_type,
            mime_type=mime_type,
            file_size=file_size,
            sha256=sha256,
            storage_provider="local",
            storage_path=storage_path,
            status="uploaded"
        )

        try:
            inserted = self.repository.insert_one(evidence_data.model_dump())
            return EvidenceFile(**inserted)
        except Exception as e:
            # Consistency Rollback: delete storage file if metadata write fails to prevent orphans
            self.storage.delete_file(storage_path)
            raise e

    def get_evidence(self, case_id: str, evidence_id: str) -> EvidenceFile | None:
        evidence_dict = self.repository.find_one({"case_id": case_id, "evidence_id": evidence_id})
        return EvidenceFile(**evidence_dict) if evidence_dict else None

    def get_all_evidence_for_case(self, case_id: str) -> list[EvidenceFile]:
        evidence_list = self.repository.find_all({"case_id": case_id})
        return [EvidenceFile(**e) for e in evidence_list]

    def delete_evidence(self, case_id: str, evidence_id: str) -> bool:
        evidence_dict = self.repository.find_one({"case_id": case_id, "evidence_id": evidence_id})
        if not evidence_dict:
            return False

        # Delete database metadata
        success = self.repository.delete_one({"case_id": case_id, "evidence_id": evidence_id})
        if success:
            # Delete physical storage binary file to prevent orphans
            self.storage.delete_file(evidence_dict["storage_path"])
            return True
        return False
