import os
import shutil
import subprocess
import logging
from datetime import datetime
from collections import defaultdict
from app.services.providers.base import NetworkAnalysisProvider
from app.models.analysis_run import ProviderExecutionRecord, ProviderStatus
from app.core.config import settings

logger = logging.getLogger("emit.providers.tshark")

class TsharkProvider(NetworkAnalysisProvider):
    @property
    def provider_name(self) -> str:
        return "tshark"

    @property
    def version(self) -> str:
        return "4.2.0"

    def is_enabled(self) -> bool:
        return settings.ENABLE_PROVIDER_TSHARK

    def is_configured(self) -> bool:
        return True

    def is_available(self) -> bool:
        return bool(shutil.which("tshark") or shutil.which("tshark.exe"))

    def analyze_pcap(self, evidence_path: str) -> ProviderExecutionRecord:
        started = datetime.utcnow()
        if not self.is_enabled():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                status=ProviderStatus.DISABLED,
                output_metadata={"tool_version": self.version}
            )
        if not self.is_available():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                status=ProviderStatus.UNAVAILABLE,
                error="Tshark command is not available in PATH",
                output_metadata={"tool_version": self.version}
            )

        try:
            # Construct tshark command to extract key packet parameters
            # Fields:
            # - %m: frame number
            # - %e: epoch time
            # - %s: IP source
            # - %d: IP destination
            # - %p: Protocol name
            # - %S: TCP source port
            # - %D: TCP destination port
            # - %uS: UDP source port
            # - %uD: UDP destination port
            # - %dns: DNS Query Name
            tshark_cmd = [
                "tshark", "-n", "-r", evidence_path,
                "-T", "fields",
                "-e", "frame.number",
                "-e", "frame.time_epoch",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "ip.proto",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.srcport",
                "-e", "udp.dstport",
                "-e", "dns.qry.name",
                "-e", "dns.a"
            ]

            logger.info(f"Spawning tshark command: {' '.join(tshark_cmd)}")
            proc = subprocess.run(
                tshark_cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=float(settings.ANALYSIS_TIMEOUT_SECONDS)
            )

            lines = proc.stdout.strip().split("\n")
            packet_count = len(lines) if lines and lines[0] else 0

            if packet_count == 0:
                return ProviderExecutionRecord(
                    provider=self.provider_name,
                    provider_version=self.version,
                    started_at=started,
                    completed_at=datetime.utcnow(),
                    status=ProviderStatus.COMPLETED,
                    duration=float((datetime.utcnow() - started).total_seconds()),
                    output_metadata={
                        "packet_count": 0,
                        "capture_start": None,
                        "capture_end": None,
                        "ips": [],
                        "protocols": [],
                        "ports": [],
                        "dns_queries": [],
                        "dns_responses": [],
                        "connections": [],
                        "repeated_communications": []
                    }
                )

            capture_start = None
            capture_end = None
            ips = set()
            protocols = set()
            tcp_ports = set()
            udp_ports = set()
            dns_queries = set()
            dns_responses = []

            # Track connections and packet counts/intervals
            connection_intervals = defaultdict(list)
            connection_volumes = defaultdict(int)

            for line in lines:
                parts = line.split("\t")
                # Pad list to prevent IndexErrors
                parts += [""] * (12 - len(parts))
                
                frame_num = parts[0]
                time_epoch_str = parts[1]
                ip_src = parts[2]
                ip_dst = parts[3]
                ip_proto = parts[4]
                tcp_sport = parts[5]
                tcp_dport = parts[6]
                udp_sport = parts[7]
                udp_dport = parts[8]
                dns_name = parts[9]
                dns_ans = parts[10]

                if not time_epoch_str or not ip_src or not ip_dst:
                    continue

                pkt_time = float(time_epoch_str)
                if capture_start is None or pkt_time < capture_start:
                    capture_start = pkt_time
                if capture_end is None or pkt_time > capture_end:
                    capture_end = pkt_time

                ips.add(ip_src)
                ips.add(ip_dst)

                proto = "IP"
                dport = 0
                if tcp_dport:
                    proto = "TCP"
                    tcp_ports.add(int(tcp_sport))
                    tcp_ports.add(int(tcp_dport))
                    dport = int(tcp_dport)
                elif udp_dport:
                    proto = "UDP"
                    udp_ports.add(int(udp_sport))
                    udp_ports.add(int(udp_dport))
                    dport = int(udp_dport)

                protocols.add(proto)

                # Track connection intervals
                conn_key = (ip_src, ip_dst, dport, proto)
                connection_intervals[conn_key].append(pkt_time)

                # DNS queries
                if dns_name:
                    protocols.add("DNS")
                    # Handle comma-separated multiple queries/answers
                    for name in dns_name.split(","):
                        dns_queries.add(name.strip().strip('.'))
                    if dns_ans:
                        dns_responses.append({
                            "query": dns_name.split(",")[0].strip().strip('.'),
                            "answers": [ans.strip() for ans in dns_ans.split(",")],
                            "timestamp": pkt_time
                        })

            # Detect repeated periodic beacons
            repeated_comms = []
            for conn_key, timestamps in connection_intervals.items():
                ip_src, ip_dst, dport, proto = conn_key
                count = len(timestamps)
                if count >= 3:
                    timestamps.sort()
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(count - 1)]
                    mean_int = float(sum(intervals) / len(intervals))
                    variance = float(sum((x - mean_int) ** 2 for x in intervals) / len(intervals))
                    std_int = float(variance ** 0.5)

                    pattern_type = "repeated communication"
                    if std_int < 1.5 and mean_int > 0.5:
                        pattern_type = "possible periodic communication"
                    elif std_int < 0.5:
                        pattern_type = "suspicious communication pattern"

                    repeated_comms.append({
                        "source_ip": ip_src,
                        "destination_ip": ip_dst,
                        "destination_port": dport,
                        "protocol": proto,
                        "packet_count": count,
                        "mean_interval_seconds": mean_int,
                        "std_interval_seconds": std_int,
                        "pattern_classification": pattern_type
                    })

            serialized_connections = []
            for conn_key, timestamps in connection_intervals.items():
                ip_src, ip_dst, dport, proto = conn_key
                serialized_connections.append({
                    "source_ip": ip_src,
                    "destination_ip": ip_dst,
                    "destination_port": dport,
                    "protocol": proto,
                    "packet_count": len(timestamps),
                    "first_packet_time": min(timestamps),
                    "last_packet_time": max(timestamps)
                })

            metadata = {
                "packet_count": packet_count,
                "capture_start": capture_start,
                "capture_end": capture_end,
                "ips": list(ips),
                "protocols": list(protocols),
                "ports": {
                    "tcp": list(tcp_ports),
                    "udp": list(udp_ports)
                },
                "dns_queries": list(dns_queries),
                "dns_responses": dns_responses,
                "connections": serialized_connections[:200],
                "repeated_communications": repeated_comms[:50]
            }

            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.COMPLETED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                output_metadata=metadata
            )

        except Exception as e:
            logger.error(f"Tshark analysis failed: {e}", exc_info=True)
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.FAILED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                error=f"Tshark analysis execution failed: {str(e)}",
                output_metadata={"tool_version": self.version}
            )
