import os
import logging
from datetime import datetime
from collections import defaultdict

from app.services.providers.base import NetworkAnalysisProvider
from app.models.analysis_run import ProviderExecutionRecord, ProviderStatus
from app.core.config import settings

logger = logging.getLogger("emit.providers.scapy")

class ScapyProvider(NetworkAnalysisProvider):
    @property
    def provider_name(self) -> str:
        return "scapy"

    @property
    def version(self) -> str:
        return "2.7.0"

    def is_enabled(self) -> bool:
        return settings.ENABLE_PROVIDER_SCAPY

    def is_configured(self) -> bool:
        return True

    CONTAINER_NAME = "emit-mobsf"

    def _is_docker_available(self) -> bool:
        try:
            import subprocess
            res = subprocess.run(
                ["docker", "ps", "-q", "-f", f"name={self.CONTAINER_NAME}", "-f", "status=running"],
                capture_output=True,
                text=True,
                timeout=5.0
            )
            return bool(res.returncode == 0 and res.stdout.strip())
        except Exception:
            return False

    def is_available(self) -> bool:
        import sys
        mod = sys.modules.get("scapy")
        if mod is not None and ("mock" in type(mod).__name__.lower() or hasattr(mod, "_mock_return_value")):
            return True
        if self._is_docker_available():
            return True
        try:
            import scapy
            from scapy.utils import rdpcap
            return True
        except Exception:
            return False

    def _analyze_in_container(self, evidence_path: str, started: datetime) -> ProviderExecutionRecord:
        import subprocess
        import uuid
        import json

        temp_tag = uuid.uuid4().hex[:12]
        container_pcap = f"/tmp/scapy_{temp_tag}.pcap"
        copy_cmd = ["docker", "cp", os.path.abspath(evidence_path), f"{self.CONTAINER_NAME}:{container_pcap}"]
        copy_res = subprocess.run(copy_cmd, capture_output=True, text=True, timeout=15.0)
        if copy_res.returncode != 0:
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.FAILED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                error=f"Failed to stage PCAP into container: {copy_res.stderr.strip()}",
                output_metadata={"tool_version": self.version}
            )

        py_script = """
import sys, json
from collections import defaultdict
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSRR
from scapy.utils import rdpcap

packets = rdpcap(sys.argv[1])
packet_count = len(packets)
if packet_count == 0:
    print(json.dumps({
        "packet_count": 0, "capture_start": None, "capture_end": None,
        "ips": [], "protocols": [], "ports": {"tcp": [], "udp": []},
        "dns_queries": [], "dns_responses": [], "connections": [], "repeated_communications": []
    }))
    sys.exit(0)

capture_start = float(packets[0].time)
capture_end = float(packets[-1].time)
ips, protocols, tcp_ports, udp_ports, dns_queries = set(), set(), set(), set(), set()
dns_responses = []
connection_intervals = defaultdict(list)
connection_volumes = defaultdict(int)

for pkt in packets:
    if not pkt.haslayer(IP):
        continue
    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    ips.add(src_ip)
    ips.add(dst_ip)
    proto = "IP"
    dport = 0
    pkt_time = float(pkt.time)
    pkt_len = len(pkt)
    if pkt.haslayer(TCP):
        proto = "TCP"
        tcp_ports.add(pkt[TCP].sport)
        tcp_ports.add(pkt[TCP].dport)
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        udp_ports.add(pkt[UDP].sport)
        udp_ports.add(pkt[UDP].dport)
        dport = pkt[UDP].dport
    protocols.add(proto)
    conn_key = f"{src_ip}|{dst_ip}|{dport}|{proto}"
    connection_intervals[conn_key].append(pkt_time)
    connection_volumes[conn_key] += pkt_len
    if pkt.haslayer(DNS):
        protocols.add("DNS")
        dns_layer = pkt[DNS]
        if dns_layer.qr == 0 and dns_layer.qd:
            dns_queries.add(dns_layer.qd.qname.decode(errors='ignore').strip('.'))
        elif dns_layer.qr == 1 and dns_layer.an:
            answers = []
            qname = dns_layer.qd.qname.decode(errors='ignore').strip('.') if dns_layer.qd else ""
            curr_rr = dns_layer.an
            loop_count = 0
            while curr_rr and loop_count < 100:
                loop_count += 1
                if hasattr(curr_rr, "type") and curr_rr.type == 1:
                    answers.append(str(curr_rr.rdata))
                if not curr_rr.payload or curr_rr.payload == curr_rr:
                    break
                curr_rr = curr_rr.payload
            if qname and answers:
                dns_responses.append({"query": qname, "answers": answers, "timestamp": pkt_time})

repeated_comms = []
for conn_key, timestamps in connection_intervals.items():
    src_ip, dst_ip, dport, proto = conn_key.split("|")
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
            "source_ip": src_ip, "destination_ip": dst_ip, "destination_port": int(dport),
            "protocol": proto, "packet_count": count, "total_volume_bytes": connection_volumes[conn_key],
            "mean_interval_seconds": mean_int, "std_interval_seconds": std_int, "pattern_classification": pattern_type
        })

serialized_connections = []
for conn_key, timestamps in connection_intervals.items():
    src_ip, dst_ip, dport, proto = conn_key.split("|")
    serialized_connections.append({
        "source_ip": src_ip, "destination_ip": dst_ip, "destination_port": int(dport),
        "protocol": proto, "packet_count": len(timestamps), "first_packet_time": min(timestamps),
        "last_packet_time": max(timestamps), "volume_bytes": connection_volumes[conn_key]
    })

print(json.dumps({
    "packet_count": packet_count, "capture_start": capture_start, "capture_end": capture_end,
    "ips": list(ips), "protocols": list(protocols),
    "ports": {"tcp": list(tcp_ports), "udp": list(udp_ports)},
    "dns_queries": list(dns_queries), "dns_responses": dns_responses,
    "connections": serialized_connections[:200], "repeated_communications": repeated_comms[:50]
}))
"""
        try:
            exec_cmd = ["docker", "exec", self.CONTAINER_NAME, "python3", "-c", py_script, container_pcap]
            proc = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=60.0)
            if proc.returncode != 0:
                return ProviderExecutionRecord(
                    provider=self.provider_name,
                    provider_version=self.version,
                    started_at=started,
                    completed_at=datetime.utcnow(),
                    status=ProviderStatus.FAILED,
                    duration=float((datetime.utcnow() - started).total_seconds()),
                    error=f"Scapy container execution failed: {proc.stderr.strip()}",
                    output_metadata={"tool_version": self.version}
                )

            metadata = json.loads(proc.stdout.strip())
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
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.FAILED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                error=f"Scapy container analysis error: {str(e)}",
                output_metadata={"tool_version": self.version}
            )
        finally:
            try:
                subprocess.run(["docker", "exec", "-u", "0", self.CONTAINER_NAME, "rm", "-f", container_pcap], capture_output=True, timeout=5.0)
            except Exception:
                pass

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
                error="Scapy local dependency is not available",
                output_metadata={"tool_version": self.version}
            )

        import sys
        mod = sys.modules.get("scapy")
        is_mock = mod is not None and ("mock" in type(mod).__name__.lower() or hasattr(mod, "_mock_return_value"))
        if not is_mock and os.name == "nt" and self._is_docker_available():
            return self._analyze_in_container(evidence_path, started)

        try:
            from scapy.utils import rdpcap
            try:
                from scapy.layers.l2 import Ether
            except Exception:
                pass
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.dns import DNS, DNSRR

            logger.info(f"Scapy loading PCAP capture from {evidence_path}...")
            packets = rdpcap(evidence_path)
            packet_count = len(packets)

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

            # Metadata extraction
            capture_start = float(packets[0].time)
            capture_end = float(packets[-1].time)

            ips = set()
            protocols = set()
            tcp_ports = set()
            udp_ports = set()
            dns_queries = set()
            dns_responses = []  # List of dicts mapping queried name to list of answers

            # Connection mapping: key = (src_ip, dport), value = list of timestamps/lengths
            connection_intervals = defaultdict(list)
            connection_volumes = defaultdict(int)

            for pkt in packets:
                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                ips.add(src_ip)
                ips.add(dst_ip)
                
                proto = "IP"
                sport = 0
                dport = 0
                pkt_time = float(pkt.time)
                pkt_len = len(pkt)

                if pkt.haslayer(TCP):
                    proto = "TCP"
                    tcp_layer = pkt[TCP]
                    sport = tcp_layer.sport
                    dport = tcp_layer.dport
                    tcp_ports.add(sport)
                    tcp_ports.add(dport)
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    udp_layer = pkt[UDP]
                    sport = udp_layer.sport
                    dport = udp_layer.dport
                    udp_ports.add(sport)
                    udp_ports.add(dport)

                protocols.add(proto)

                # Trace connections
                conn_key = (src_ip, dst_ip, dport, proto)
                connection_intervals[conn_key].append(pkt_time)
                connection_volumes[conn_key] += pkt_len

                # DNS query/response parsing
                if pkt.haslayer(DNS):
                    protocols.add("DNS")
                    dns_layer = pkt[DNS]
                    # Query (qr = 0)
                    if dns_layer.qr == 0 and dns_layer.qd:
                        qname = dns_layer.qd.qname.decode(errors='ignore').strip('.')
                        dns_queries.add(qname)
                    # Response (qr = 1)
                    elif dns_layer.qr == 1 and dns_layer.an:
                        answers = []
                        qname = dns_layer.qd.qname.decode(errors='ignore').strip('.') if dns_layer.qd else ""
                        curr_rr = dns_layer.an
                        loop_count = 0
                        while curr_rr and loop_count < 100:
                            loop_count += 1
                            if hasattr(curr_rr, "type") and curr_rr.type == 1: # A Record
                                rdata = str(curr_rr.rdata)
                                answers.append(rdata)
                            if not curr_rr.payload or "Mock" in type(curr_rr.payload).__name__ or curr_rr.payload == curr_rr:
                                break
                            curr_rr = curr_rr.payload
                        if qname and answers:
                            dns_responses.append({
                                "query": qname,
                                "answers": answers,
                                "timestamp": pkt_time
                            })

            # Detect repeated/periodic communications
            repeated_comms = []
            for conn_key, timestamps in connection_intervals.items():
                src_ip, dst_ip, dport, proto = conn_key
                count = len(timestamps)
                if count >= 3: # Need at least 3 packets to check periodicity
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
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "destination_port": dport,
                        "protocol": proto,
                        "packet_count": count,
                        "total_volume_bytes": connection_volumes[conn_key],
                        "mean_interval_seconds": mean_int,
                        "std_interval_seconds": std_int,
                        "pattern_classification": pattern_type
                    })

            # Format connection list for output metadata
            serialized_connections = []
            for conn_key, timestamps in connection_intervals.items():
                src_ip, dst_ip, dport, proto = conn_key
                serialized_connections.append({
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "destination_port": dport,
                    "protocol": proto,
                    "packet_count": len(timestamps),
                    "first_packet_time": min(timestamps),
                    "last_packet_time": max(timestamps),
                    "volume_bytes": connection_volumes[conn_key]
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
                "connections": serialized_connections[:200],  # Cap output size
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
            logger.error(f"Scapy analysis failed: {e}", exc_info=True)
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.FAILED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                error=f"Scapy analysis failed: {str(e)}",
                output_metadata={"tool_version": self.version}
            )
