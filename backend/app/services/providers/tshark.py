import os
import re
import uuid
import shutil
import subprocess
import logging
from datetime import datetime
from collections import defaultdict
from typing import Optional

from app.services.providers.base import NetworkAnalysisProvider
from app.models.analysis_run import ProviderExecutionRecord, ProviderStatus
from app.core.config import settings

logger = logging.getLogger("emit.providers.tshark")

class TsharkProvider(NetworkAnalysisProvider):
    CONTAINER_NAME = "emit-mobsf"

    def __init__(self):
        self._cached_version: Optional[str] = None

    @property
    def provider_name(self) -> str:
        return "tshark"

    @property
    def version(self) -> str:
        return self._get_version()

    def _get_version(self) -> str:
        if self._cached_version:
            return self._cached_version

        # 1. Try host binary
        host_bin = shutil.which("tshark") or shutil.which("tshark.exe")
        if host_bin:
            try:
                proc = subprocess.run([host_bin, "-v"], capture_output=True, text=True, timeout=3.0)
                m = re.search(r"TShark \(Wireshark\)\s+([0-9]+\.[0-9]+\.[0-9]+)", proc.stdout)
                if m:
                    self._cached_version = m.group(1)
                    return self._cached_version
            except Exception as e:
                logger.debug(f"Failed to query host tshark version: {e}")

        # 2. Try Docker container
        try:
            proc = subprocess.run(
                ["docker", "exec", self.CONTAINER_NAME, "tshark", "-v"],
                capture_output=True,
                text=True,
                timeout=5.0
            )
            m = re.search(r"TShark \(Wireshark\)\s+([0-9]+\.[0-9]+\.[0-9]+)", proc.stdout)
            if m:
                self._cached_version = m.group(1)
                return self._cached_version
        except Exception as e:
            logger.debug(f"Failed to query docker container tshark version: {e}")

        return "4.0.17"

    def is_enabled(self) -> bool:
        return settings.ENABLE_PROVIDER_TSHARK

    def is_configured(self) -> bool:
        return True

    def _is_docker_available(self) -> bool:
        try:
            ps_res = subprocess.run(
                ["docker", "ps", "-q", "-f", f"name={self.CONTAINER_NAME}", "-f", "status=running"],
                capture_output=True,
                text=True,
                timeout=5.0
            )
            if not ps_res.stdout.strip():
                return False

            check_res = subprocess.run(
                ["docker", "exec", self.CONTAINER_NAME, "which", "tshark"],
                capture_output=True,
                text=True,
                timeout=5.0
            )
            return check_res.returncode == 0
        except Exception:
            return False

    def is_available(self) -> bool:
        if shutil.which("tshark") or shutil.which("tshark.exe"):
            return True
        return self._is_docker_available()

    def analyze_pcap(self, evidence_path: str) -> ProviderExecutionRecord:
        started = datetime.utcnow()
        tool_ver = self.version

        if not self.is_enabled():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=tool_ver,
                status=ProviderStatus.DISABLED,
                output_metadata={"tool_version": tool_ver}
            )
        if not self.is_available():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=tool_ver,
                status=ProviderStatus.UNAVAILABLE,
                error="TShark is not available on host or in analysis container",
                output_metadata={"tool_version": tool_ver}
            )

        container_pcap: Optional[str] = None
        use_docker = False

        try:
            host_bin = shutil.which("tshark") or shutil.which("tshark.exe")
            if host_bin:
                tshark_cmd = [
                    host_bin, "-n", "-r", evidence_path,
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
            else:
                use_docker = True
                tag = uuid.uuid4().hex[:12]
                container_pcap = f"/tmp/tshark_{tag}.pcap"
                abs_evidence = os.path.abspath(evidence_path)

                # Stage evidence inside container
                cp_proc = subprocess.run(
                    ["docker", "cp", abs_evidence, f"{self.CONTAINER_NAME}:{container_pcap}"],
                    capture_output=True,
                    text=True,
                    timeout=30.0
                )
                if cp_proc.returncode != 0:
                    raise RuntimeError(f"Failed to stage PCAP in container: {cp_proc.stderr}")

                tshark_cmd = [
                    "docker", "exec", self.CONTAINER_NAME,
                    "tshark", "-n", "-r", container_pcap,
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

            logger.info(f"Running TShark command: {' '.join(tshark_cmd)}")
            proc = subprocess.run(
                tshark_cmd,
                capture_output=True,
                text=True,
                timeout=float(settings.ANALYSIS_TIMEOUT_SECONDS)
            )

            if proc.returncode != 0:
                err_msg = proc.stderr.strip() or f"TShark exited with status {proc.returncode}"
                raise RuntimeError(err_msg)

            lines = proc.stdout.strip().split("\n")
            lines = [l for l in lines if l.strip()]
            packet_count = len(lines)

            if packet_count == 0:
                return ProviderExecutionRecord(
                    provider=self.provider_name,
                    provider_version=tool_ver,
                    started_at=started,
                    completed_at=datetime.utcnow(),
                    status=ProviderStatus.COMPLETED,
                    duration=float((datetime.utcnow() - started).total_seconds()),
                    output_metadata={
                        "tool_version": tool_ver,
                        "packet_count": 0,
                        "capture_start": None,
                        "capture_end": None,
                        "ips": [],
                        "protocols": [],
                        "ports": {"tcp": [], "udp": []},
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

            connection_intervals = defaultdict(list)

            for line in lines:
                parts = line.split("\t")
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

                try:
                    pkt_time = float(time_epoch_str)
                except ValueError:
                    continue

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
                    if tcp_sport.isdigit():
                        tcp_ports.add(int(tcp_sport))
                    if tcp_dport.isdigit():
                        tcp_ports.add(int(tcp_dport))
                        dport = int(tcp_dport)
                elif udp_dport:
                    proto = "UDP"
                    if udp_sport.isdigit():
                        udp_ports.add(int(udp_sport))
                    if udp_dport.isdigit():
                        udp_ports.add(int(udp_dport))
                        dport = int(udp_dport)

                protocols.add(proto)

                conn_key = (ip_src, ip_dst, dport, proto)
                connection_intervals[conn_key].append(pkt_time)

                if dns_name:
                    protocols.add("DNS")
                    for name in dns_name.split(","):
                        cleaned_name = name.strip().strip('.')
                        if cleaned_name:
                            dns_queries.add(cleaned_name)
                    if dns_ans:
                        dns_responses.append({
                            "query": dns_name.split(",")[0].strip().strip('.'),
                            "answers": [ans.strip() for ans in dns_ans.split(",") if ans.strip()],
                            "timestamp": pkt_time
                        })

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
                "tool_version": tool_ver,
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
                provider_version=tool_ver,
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
                provider_version=tool_ver,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.FAILED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                error=f"Tshark analysis execution failed: {str(e)}",
                output_metadata={"tool_version": tool_ver}
            )

        finally:
            if use_docker and container_pcap:
                try:
                    subprocess.run(
                        ["docker", "exec", "-u", "0", self.CONTAINER_NAME, "rm", "-f", container_pcap],
                        capture_output=True,
                        text=True,
                        timeout=5.0
                    )
                except Exception as e:
                    logger.warning(f"Failed to clean up container PCAP {container_pcap}: {e}")
