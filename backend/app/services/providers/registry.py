from app.services.providers.base import AnalysisProvider
from typing import Dict, List, Optional

class ProviderRegistry:
    def __init__(self):
        self._providers: Dict[str, AnalysisProvider] = {}

    def register_provider(self, provider: AnalysisProvider) -> None:
        self._providers[provider.provider_name] = provider

    def get_provider(self, name: str) -> Optional[AnalysisProvider]:
        return self._providers.get(name)

    def get_enabled_providers(self, provider_type: str) -> List[AnalysisProvider]:
        """Returns all registered providers matching the type (APK or PCAP) that are enabled in configuration."""
        return [
            provider for provider in self._providers.values()
            if provider.provider_type == provider_type and provider.is_enabled()
        ]

# Instantiate and register default providers
provider_registry = ProviderRegistry()

from app.services.providers.mobsf import MobSFProvider
from app.services.providers.androguard import AndroguardProvider
from app.services.providers.jadx import JADXProvider
from app.services.providers.apktool import APKToolProvider
from app.services.providers.tshark import TsharkProvider
from app.services.providers.scapy import ScapyProvider

provider_registry.register_provider(MobSFProvider())
provider_registry.register_provider(AndroguardProvider())
provider_registry.register_provider(JADXProvider())
provider_registry.register_provider(APKToolProvider())
provider_registry.register_provider(TsharkProvider())
provider_registry.register_provider(ScapyProvider())
