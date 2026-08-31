import os
import re
import uuid
from abc import ABC, abstractmethod

class StorageProvider(ABC):
    @abstractmethod
    def save_file(self, file_name: str, file_content: bytes) -> str:
        """Saves a binary file and returns a storage path reference."""
        pass

    @abstractmethod
    def read_file(self, storage_path: str) -> bytes:
        """Reads and returns the binary content from the storage path."""
        pass

    @abstractmethod
    def delete_file(self, storage_path: str) -> None:
        """Deletes the binary file associated with the storage path."""
        pass


class LocalStorageProvider(StorageProvider):
    def __init__(self, base_dir: str = "storage"):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def _sanitize_filename(self, file_name: str) -> str:
        """
        Sanitizes user-controlled filenames to prevent directory traversal,
        null-byte injection, and filesystem corruption.
        """
        base = os.path.basename(file_name)
        base = base.replace('\0', '').strip()
        # Keep only safe alphanumeric, dots, underscores, and hyphens
        sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', base)
        if not sanitized or sanitized.startswith('.'):
            sanitized = f"evidence_{sanitized}"
        return sanitized

    def save_file(self, file_name: str, file_content: bytes) -> str:
        safe_name = self._sanitize_filename(file_name)
        unique_name = f"{uuid.uuid4()}_{safe_name}"
        abs_target_path = os.path.join(self.base_dir, unique_name)
        with open(abs_target_path, "wb") as f:
            f.write(file_content)
        # Store relative storage reference to avoid leaking host absolute paths
        return os.path.join("storage", unique_name).replace("\\", "/")

    def _resolve_path(self, storage_path: str) -> str:
        resolved = os.path.abspath(storage_path)
        if not resolved.startswith(self.base_dir):
            raise PermissionError("Access denied: path escapes storage boundaries")
        return resolved

    def read_file(self, storage_path: str) -> bytes:
        resolved_path = self._resolve_path(storage_path)
        if not os.path.exists(resolved_path):
            raise FileNotFoundError(f"File not found in local storage: {os.path.basename(storage_path)}")
        with open(resolved_path, "rb") as f:
            return f.read()

    def delete_file(self, storage_path: str) -> None:
        try:
            resolved_path = self._resolve_path(storage_path)
            if os.path.exists(resolved_path):
                os.remove(resolved_path)
        except Exception:
            pass
