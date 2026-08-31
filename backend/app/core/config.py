from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional

class Settings(BaseSettings):
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    
    # MongoDB settings
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DATABASE: str = "emit"
    MONGODB_TEST_URI: str = "mongodb://localhost:27017"
    MONGODB_TEST_DATABASE: str = "emit_test"
    
    # CORS settings
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    
    # Provider Enable/Disable settings
    ENABLE_PROVIDER_MOBSF: bool = True
    ENABLE_PROVIDER_ANDROGUARD: bool = True
    ENABLE_PROVIDER_JADX: bool = True
    ENABLE_PROVIDER_APKTOOL: bool = True
    ENABLE_PROVIDER_TSHARK: bool = True
    ENABLE_PROVIDER_SCAPY: bool = True
    
    # Specific tool configurations (for NOT_CONFIGURED state validation)
    MOBSF_URL: Optional[str] = None
    MOBSF_API_KEY: Optional[str] = None
    
    # Threat Intelligence Provider Settings
    ENABLE_THREAT_INTEL_VIRUSTOTAL: Optional[bool] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ENABLE_THREAT_INTEL_URLHAUS: Optional[bool] = None
    URLHAUS_API_KEY: Optional[str] = None
    ENABLE_THREAT_INTEL_ABUSEIPDB: Optional[bool] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    ENABLE_THREAT_INTEL_OTX: Optional[bool] = None
    OTX_API_KEY: Optional[str] = None
    THREAT_INTEL_CACHE_HOURS: int = 24
    THREAT_INTEL_TIMEOUT_SECONDS: int = 10
    
    # Execution timeouts
    ANALYSIS_TIMEOUT_SECONDS: int = 30
    
    # File upload constraints
    MAX_EVIDENCE_SIZE_BYTES: int = 500 * 1024 * 1024  # 500 MB limit

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
