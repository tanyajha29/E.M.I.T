import logging
import ipaddress
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlsplit, urlunsplit

from app.db.repositories.indicator_repository import IndicatorRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.schemas.indicator import Indicator, IndicatorType
from app.schemas.observation import Observation
from app.schemas.normalized import SourceType, ObservationType, RawObservationItem, EvidenceReference

logger = logging.getLogger("emit.normalizer")

# Set of standard suspicious permissions that pose potential risk to monitor
SUSPICIOUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED"
}

class ValueNormalizer:
    """
    Deterministic normalization utility for all supported Indicator types.
    Ensures consistent representation across heterogeneous data sources.
    """
    @staticmethod
    def normalize(ind_type: IndicatorType, value: str) -> str:
        if not value:
            return ""
        val = str(value).strip()

        if ind_type == IndicatorType.DOMAIN:
            # Strip scheme if present
            if "://" in val:
                val = urlsplit(val).netloc or val
            # Strip port if present (e.g. host:80)
            if ":" in val and not val.startswith("["):
                val = val.split(":")[0]
            # Strip path/query if present
            if "/" in val:
                val = val.split("/")[0]
            # Lowercase and strip trailing dot
            return val.lower().rstrip(".")

        elif ind_type == IndicatorType.IP:
            # Strip port if attached to IPv4 (e.g. 1.2.3.4:80)
            if ":" in val and "." in val:
                val = val.split(":")[0]
            # Strip leading zeros in IPv4 octets if present
            if "." in val:
                parts = val.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    try:
                        val = ".".join(str(int(p)) for p in parts)
                    except ValueError:
                        pass
            try:
                # Canonical representation for IPv4 / IPv6
                ip_obj = ipaddress.ip_address(val)
                return str(ip_obj)
            except ValueError:
                return val.lower()

        elif ind_type == IndicatorType.URL:
            try:
                parts = urlsplit(val)
                scheme = parts.scheme.lower() or "http"
                netloc = parts.netloc.lower()
                # Remove default standard ports
                if scheme == "http" and netloc.endswith(":80"):
                    netloc = netloc[:-3]
                elif scheme == "https" and netloc.endswith(":443"):
                    netloc = netloc[:-4]
                path = parts.path or "/"
                return urlunsplit((scheme, netloc, path, parts.query, parts.fragment))
            except Exception:
                return val.lower().rstrip("/")

        elif ind_type in [IndicatorType.HASH, IndicatorType.CERTIFICATE]:
            return val.lower()

        elif ind_type == IndicatorType.PACKAGE:
            return val.lower()

        elif ind_type in [IndicatorType.PERMISSION, IndicatorType.PROTOCOL, IndicatorType.CAPABILITY]:
            return val.upper()

        elif ind_type == IndicatorType.PORT:
            try:
                return str(int(val))
            except ValueError:
                return val

        elif ind_type == IndicatorType.API:
            return val.strip()

        return val


class EvidenceNormalizer:
    """
    Evidence Normalization Layer.
    Converts heterogeneous outputs from MobSF, Androguard, JADX/APKTool,
    tshark, and Scapy into one common evidence model with full provenance.
    """
    @staticmethod
    def normalize(
        provider_results: dict, 
        case_id: str, 
        evidence_id: str,
        indicator_repo: Optional[IndicatorRepository] = None,
        observation_repo: Optional[ObservationRepository] = None
    ) -> dict:
        logger.info(f"EvidenceNormalizer starting normalization for case {case_id}, evidence {evidence_id}")

        if indicator_repo is None:
            indicator_repo = IndicatorRepository()
        if observation_repo is None:
            observation_repo = ObservationRepository()

        raw_items: List[RawObservationItem] = []

        # 0. Clean stale observations for this specific evidence in this case
        observation_repo.delete_many({"case_id": case_id, "evidence_id": evidence_id})

        # 1. Extract from all available completed provider records
        for provider_name, record in provider_results.items():
            status = record.get("status") if isinstance(record, dict) else getattr(record, "status", None)
            # Accept COMPLETED or string "COMPLETED"
            status_val = status.value if hasattr(status, "value") else str(status)
            if status_val != "COMPLETED":
                continue

            meta = record.get("output_metadata", {}) if isinstance(record, dict) else getattr(record, "output_metadata", {})

            if provider_name == "mobsf":
                raw_items.extend(EvidenceNormalizer._extract_from_mobsf(meta))
            elif provider_name == "androguard":
                raw_items.extend(EvidenceNormalizer._extract_from_androguard(meta))
            elif provider_name in ["jadx", "apktool"]:
                raw_items.extend(EvidenceNormalizer._extract_from_decompiler(meta, provider_name))
            elif provider_name == "scapy":
                raw_items.extend(EvidenceNormalizer._extract_from_scapy(meta))
            elif provider_name == "tshark":
                raw_items.extend(EvidenceNormalizer._extract_from_tshark(meta))

        # 2. Persist normalized items into common evidence model
        normalized_indicators: Dict[str, str] = {}  # key: (type, norm_val) -> indicator_id
        observations_created = []

        for item in raw_items:
            norm_val = ValueNormalizer.normalize(item.indicator_type, item.value)
            if not norm_val:
                continue

            # Check / Create Indicator
            key = f"{item.indicator_type.value}:{norm_val}"
            if key not in normalized_indicators:
                existing_ind = indicator_repo.find_one({
                    "case_id": case_id,
                    "type": item.indicator_type.value,
                    "normalized_value": norm_val
                })

                if existing_ind:
                    ind_id = existing_ind["indicator_id"]
                else:
                    ind_obj = Indicator(
                        case_id=case_id,
                        type=item.indicator_type,
                        value=item.value,
                        normalized_value=norm_val,
                        source=item.source,
                        confidence=item.confidence,
                        evidence_id=evidence_id,
                        timestamp=item.timestamp or datetime.utcnow(),
                        metadata=item.metadata
                    )
                    indicator_repo.insert_one(ind_obj.model_dump())
                    ind_id = ind_obj.indicator_id

                normalized_indicators[key] = ind_id
            else:
                ind_id = normalized_indicators[key]

            # Create distinct Observation for this specific piece of evidence
            obs_obj = Observation(
                case_id=case_id,
                indicator_id=ind_id,
                evidence_id=evidence_id,
                observation_type=item.observation_type,
                source=item.source,
                value=item.value,
                confidence=item.confidence,
                timestamp=item.timestamp or datetime.utcnow(),
                metadata={**item.metadata, "tool": item.tool}
            )
            observation_repo.insert_one(obs_obj.model_dump())
            observations_created.append(obs_obj.model_dump())

        # 3. Assemble normalized report structure
        return {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "indicators_count": len(normalized_indicators),
            "observations_count": len(observations_created),
            "indicators": list(normalized_indicators.keys()),
            "timestamp": datetime.utcnow().isoformat()
        }

    # =========================================================================
    # PROVIDER-SPECIFIC EXTRACTORS
    # =========================================================================

    @staticmethod
    def _extract_from_mobsf(meta: dict) -> List[RawObservationItem]:
        items: List[RawObservationItem] = []
        source = SourceType.APK.value
        tool = "mobsf"

        # Application / Package
        app_meta = meta.get("application", {}) or {}
        pkg = meta.get("package_name") or app_meta.get("package_name")
        if pkg:
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PACKAGE,
                value=pkg,
                observation_type=ObservationType.PACKAGE_NAME.value,
                source=source,
                tool=tool
            ))

        # Permissions
        raw_perms = meta.get("permissions", {})
        perm_list = list(raw_perms.keys()) if isinstance(raw_perms, dict) else (raw_perms or [])
        for perm in perm_list:
            obs_type = ObservationType.SUSPICIOUS_PERMISSION.value if perm in SUSPICIOUS_PERMISSIONS else ObservationType.DECLARED_PERMISSION.value
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PERMISSION,
                value=str(perm),
                observation_type=obs_type,
                source=source,
                tool=tool
            ))

        # URLs & Domains
        for u in meta.get("urls", []):
            url_str = u if isinstance(u, str) else u.get("url")
            if url_str:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.URL,
                    value=url_str,
                    observation_type=ObservationType.EMBEDDED_URL.value,
                    source=source,
                    tool=tool
                ))
                # Derive embedded domain
                dom = ValueNormalizer.normalize(IndicatorType.DOMAIN, url_str)
                if dom and "." in dom:
                    items.append(RawObservationItem(
                        indicator_type=IndicatorType.DOMAIN,
                        value=dom,
                        observation_type=ObservationType.EMBEDDED_DOMAIN.value,
                        source=source,
                        tool=tool
                    ))

        # Domains
        for d in meta.get("domains", []):
            dom_str = d if isinstance(d, str) else d.get("domain")
            if dom_str:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.DOMAIN,
                    value=dom_str,
                    observation_type=ObservationType.EMBEDDED_DOMAIN.value,
                    source=source,
                    tool=tool
                ))

        # IPs
        for ip in meta.get("ips", []):
            ip_str = ip if isinstance(ip, str) else ip.get("ip")
            if ip_str:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.IP,
                    value=ip_str,
                    observation_type=ObservationType.EMBEDDED_IP.value,
                    source=source,
                    tool=tool
                ))

        # Certificates
        cert_info = meta.get("certificate_info", {}) or {}
        sha256_val = cert_info.get("sha256") or cert_info.get("certificate_sha256")
        if sha256_val:
            items.append(RawObservationItem(
                indicator_type=IndicatorType.CERTIFICATE,
                value=sha256_val,
                observation_type=ObservationType.SIGNING_CERTIFICATE.value,
                source=source,
                tool=tool,
                metadata={"issuer": cert_info.get("issuer"), "subject": cert_info.get("subject")}
            ))

        # APIs & Capabilities
        for api in meta.get("api_analysis", []):
            api_str = api if isinstance(api, str) else api.get("api")
            if api_str:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.API,
                    value=api_str,
                    observation_type=ObservationType.SUSPICIOUS_API.value,
                    source=source,
                    tool=tool
                ))

        for cap in meta.get("network_capabilities", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.CAPABILITY,
                value=str(cap),
                observation_type=ObservationType.CAPABILITY.value,
                source=source,
                tool=tool
            ))

        return items

    @staticmethod
    def _extract_from_androguard(meta: dict) -> List[RawObservationItem]:
        items: List[RawObservationItem] = []
        source = SourceType.APK.value
        tool = "androguard"

        # Package
        pkg = meta.get("package_name")
        if pkg:
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PACKAGE,
                value=pkg,
                observation_type=ObservationType.PACKAGE_NAME.value,
                source=source,
                tool=tool
            ))

        # Permissions
        for perm in meta.get("permissions", []):
            obs_type = ObservationType.SUSPICIOUS_PERMISSION.value if perm in SUSPICIOUS_PERMISSIONS else ObservationType.DECLARED_PERMISSION.value
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PERMISSION,
                value=str(perm),
                observation_type=obs_type,
                source=source,
                tool=tool
            ))

        # URLs & Derived Domains
        for url_str in meta.get("urls", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.URL,
                value=url_str,
                observation_type=ObservationType.EMBEDDED_URL.value,
                source=source,
                tool=tool
            ))
            dom = ValueNormalizer.normalize(IndicatorType.DOMAIN, url_str)
            if dom and "." in dom:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.DOMAIN,
                    value=dom,
                    observation_type=ObservationType.EMBEDDED_DOMAIN.value,
                    source=source,
                    tool=tool
                ))

        # Domains
        for dom_str in meta.get("domains", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.DOMAIN,
                value=dom_str,
                observation_type=ObservationType.EMBEDDED_DOMAIN.value,
                source=source,
                tool=tool
            ))

        # IPs
        for ip_str in meta.get("ips", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.IP,
                value=ip_str,
                observation_type=ObservationType.EMBEDDED_IP.value,
                source=source,
                tool=tool
            ))

        # Certificates
        for cert in meta.get("certificates", []):
            sha = cert.get("sha256")
            if sha:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.CERTIFICATE,
                    value=sha,
                    observation_type=ObservationType.SIGNING_CERTIFICATE.value,
                    source=source,
                    tool=tool,
                    metadata={"issuer": cert.get("issuer"), "subject": cert.get("subject")}
                ))

        return items

    @staticmethod
    def _extract_from_decompiler(meta: dict, tool: str) -> List[RawObservationItem]:
        items: List[RawObservationItem] = []
        source = SourceType.APK.value

        pkg = meta.get("package_name")
        if pkg:
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PACKAGE,
                value=pkg,
                observation_type=ObservationType.PACKAGE_NAME.value,
                source=source,
                tool=tool
            ))

        for perm in meta.get("permissions", []):
            obs_type = ObservationType.SUSPICIOUS_PERMISSION.value if perm in SUSPICIOUS_PERMISSIONS else ObservationType.DECLARED_PERMISSION.value
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PERMISSION,
                value=str(perm),
                observation_type=obs_type,
                source=source,
                tool=tool
            ))

        for u in meta.get("urls", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.URL,
                value=u,
                observation_type=ObservationType.EMBEDDED_URL.value,
                source=source,
                tool=tool
            ))
            dom = ValueNormalizer.normalize(IndicatorType.DOMAIN, u)
            if dom and "." in dom:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.DOMAIN,
                    value=dom,
                    observation_type=ObservationType.EMBEDDED_DOMAIN.value,
                    source=source,
                    tool=tool
                ))

        for d in meta.get("domains", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.DOMAIN,
                value=d,
                observation_type=ObservationType.EMBEDDED_DOMAIN.value,
                source=source,
                tool=tool
            ))

        for ip in meta.get("ips", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.IP,
                value=ip,
                observation_type=ObservationType.EMBEDDED_IP.value,
                source=source,
                tool=tool
            ))

        for api in meta.get("apis", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.API,
                value=api,
                observation_type=ObservationType.SUSPICIOUS_API.value,
                source=source,
                tool=tool
            ))

        for p in meta.get("packages", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PACKAGE,
                value=p,
                observation_type=ObservationType.SUSPICIOUS_STRING.value,
                source=source,
                tool=tool
            ))

        return items

    @staticmethod
    def _extract_from_scapy(meta: dict) -> List[RawObservationItem]:
        items: List[RawObservationItem] = []
        source = SourceType.PCAP.value
        tool = "scapy"

        # IPs
        for ip in meta.get("ips", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.IP,
                value=str(ip),
                observation_type=ObservationType.NETWORK_IP.value,
                source=source,
                tool=tool
            ))

        # DNS Queries
        for q in meta.get("dns_queries", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.DOMAIN,
                value=str(q),
                observation_type=ObservationType.DNS_QUERY.value,
                source=source,
                tool=tool
            ))

        # DNS Responses (A records)
        for resp in meta.get("dns_responses", []):
            qname = resp.get("query")
            if qname:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.DOMAIN,
                    value=qname,
                    observation_type=ObservationType.DNS_QUERY.value,
                    source=source,
                    tool=tool
                ))
            for ans_ip in resp.get("answers", []):
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.IP,
                    value=ans_ip,
                    observation_type=ObservationType.DNS_RESPONSE.value,
                    source=source,
                    tool=tool,
                    metadata={"resolved_for": qname}
                ))

        # Protocols
        for proto in meta.get("protocols", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PROTOCOL,
                value=str(proto),
                observation_type=ObservationType.NETWORK_PROTOCOL.value,
                source=source,
                tool=tool
            ))

        # Ports
        meta_ports = meta.get("ports", {})
        for port in meta_ports.get("tcp", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PORT,
                value=str(port),
                observation_type=ObservationType.NETWORK_PORT.value,
                source=source,
                tool=tool,
                metadata={"layer": "TCP"}
            ))
        for port in meta_ports.get("udp", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PORT,
                value=str(port),
                observation_type=ObservationType.NETWORK_PORT.value,
                source=source,
                tool=tool,
                metadata={"layer": "UDP"}
            ))

        # Repeated communications (Observed pattern without collapsing into C2 inference)
        for comm in meta.get("repeated_communications", []):
            dest_ip = comm.get("destination_ip")
            if dest_ip:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.IP,
                    value=dest_ip,
                    observation_type=ObservationType.REPEATED_COMMUNICATION.value,
                    source=source,
                    tool=tool,
                    metadata={
                        "source_ip": comm.get("source_ip"),
                        "protocol": comm.get("protocol"),
                        "port": comm.get("destination_port"),
                        "packet_count": comm.get("packet_count"),
                        "mean_interval_seconds": comm.get("mean_interval_seconds"),
                        "std_interval_seconds": comm.get("std_interval_seconds"),
                        "pattern_classification": comm.get("pattern_classification")
                    }
                ))

        return items

    @staticmethod
    def _extract_from_tshark(meta: dict) -> List[RawObservationItem]:
        # tshark produces equivalent structure to scapy with tool="tshark"
        items: List[RawObservationItem] = []
        source = SourceType.PCAP.value
        tool = "tshark"

        for ip in meta.get("ips", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.IP,
                value=str(ip),
                observation_type=ObservationType.NETWORK_IP.value,
                source=source,
                tool=tool
            ))

        for q in meta.get("dns_queries", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.DOMAIN,
                value=str(q),
                observation_type=ObservationType.DNS_QUERY.value,
                source=source,
                tool=tool
            ))

        for resp in meta.get("dns_responses", []):
            qname = resp.get("query")
            if qname:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.DOMAIN,
                    value=qname,
                    observation_type=ObservationType.DNS_QUERY.value,
                    source=source,
                    tool=tool
                ))
            for ans_ip in resp.get("answers", []):
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.IP,
                    value=ans_ip,
                    observation_type=ObservationType.DNS_RESPONSE.value,
                    source=source,
                    tool=tool,
                    metadata={"resolved_for": qname}
                ))

        for proto in meta.get("protocols", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PROTOCOL,
                value=str(proto),
                observation_type=ObservationType.NETWORK_PROTOCOL.value,
                source=source,
                tool=tool
            ))

        meta_ports = meta.get("ports", {})
        for port in meta_ports.get("tcp", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PORT,
                value=str(port),
                observation_type=ObservationType.NETWORK_PORT.value,
                source=source,
                tool=tool,
                metadata={"layer": "TCP"}
            ))
        for port in meta_ports.get("udp", []):
            items.append(RawObservationItem(
                indicator_type=IndicatorType.PORT,
                value=str(port),
                observation_type=ObservationType.NETWORK_PORT.value,
                source=source,
                tool=tool,
                metadata={"layer": "UDP"}
            ))

        for comm in meta.get("repeated_communications", []):
            dest_ip = comm.get("destination_ip")
            if dest_ip:
                items.append(RawObservationItem(
                    indicator_type=IndicatorType.IP,
                    value=dest_ip,
                    observation_type=ObservationType.REPEATED_COMMUNICATION.value,
                    source=source,
                    tool=tool,
                    metadata={
                        "source_ip": comm.get("source_ip"),
                        "protocol": comm.get("protocol"),
                        "port": comm.get("destination_port"),
                        "packet_count": comm.get("packet_count"),
                        "mean_interval_seconds": comm.get("mean_interval_seconds"),
                        "std_interval_seconds": comm.get("std_interval_seconds"),
                        "pattern_classification": comm.get("pattern_classification")
                    }
                ))

        return items
