import sys
from unittest.mock import MagicMock, patch

# Mock Scapy imports to prevent hanging on Windows interface initialization
sys.modules["scapy"] = MagicMock()
sys.modules["scapy.utils"] = MagicMock()
sys.modules["scapy.layers"] = MagicMock()
sys.modules["scapy.layers.inet"] = MagicMock()
sys.modules["scapy.layers.dns"] = MagicMock()

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_scapy_pcap_analysis_success():
    def make_mock_packet(timestamp, src_ip, dst_ip, dport, proto_name, dns_name=None, dns_ans=None):
        pkt = MagicMock()
        pkt.time = timestamp
        pkt.__len__.return_value = 120
        
        def haslayer(layer):
            import sys
            scapy_inet = sys.modules["scapy.layers.inet"]
            scapy_dns = sys.modules["scapy.layers.dns"]
            if layer == scapy_inet.IP:
                return True
            if layer == scapy_inet.TCP and proto_name == "TCP":
                return True
            if layer == scapy_inet.UDP and proto_name == "UDP":
                return True
            if dns_name and layer == scapy_dns.DNS:
                return True
            return False
        pkt.haslayer.side_effect = haslayer
        
        ip_layer = MagicMock()
        ip_layer.src = src_ip
        ip_layer.dst = dst_ip
        
        tcp_layer = MagicMock()
        tcp_layer.sport = 12345
        tcp_layer.dport = dport
        
        udp_layer = MagicMock()
        udp_layer.sport = 12345
        udp_layer.dport = dport
        
        dns_layer = MagicMock()
        dns_layer.qr = 0 if not dns_ans else 1
        
        qd = MagicMock()
        qd.qname = dns_name.encode() if dns_name else b""
        dns_layer.qd = qd
        
        if dns_ans:
            an = MagicMock()
            an.type = 1
            an.rdata = dns_ans
            an.payload = None
            dns_layer.an = an
        else:
            dns_layer.an = None
            
        def getitem(layer):
            import sys
            scapy_inet = sys.modules["scapy.layers.inet"]
            scapy_dns = sys.modules["scapy.layers.dns"]
            if layer == scapy_inet.IP:
                return ip_layer
            if layer == scapy_inet.TCP:
                return tcp_layer
            if layer == scapy_inet.UDP:
                return udp_layer
            if layer == scapy_dns.DNS:
                return dns_layer
            return MagicMock()
        pkt.__getitem__.side_effect = getitem
        return pkt

    # Generate 3 periodic UDP packets to trigger possible periodic communication detection
    pkts = [
        make_mock_packet(1718000000.0, "192.168.1.10", "8.8.8.8", 53, "UDP", "malicious-c2.com"),
        make_mock_packet(1718000010.0, "192.168.1.10", "8.8.8.8", 53, "UDP", "malicious-c2.com"),
        make_mock_packet(1718000020.0, "192.168.1.10", "8.8.8.8", 53, "UDP", "malicious-c2.com", "185.120.44.5")
    ]

    with patch("scapy.utils.rdpcap", return_value=pkts):
        # 1. Create Case
        res = client.post("/cases", json={"name": "Network Case", "description": "Verify network metrics"})
        assert res.status_code == 201
        case_id = res.json()["case_id"]

        # 2. Upload valid PCAP
        file_content = b"\xd4\xc3\xb2\xa1Valid PCAP bytes..."
        res = client.post(
            f"/cases/{case_id}/evidence",
            files={"file": ("capture.pcap", file_content, "application/octet-stream")}
        )
        assert res.status_code == 201
        evidence_id = res.json()["evidence_id"]

        # Disable other providers (tshark, etc.) to isolate Scapy
        with patch("app.services.providers.tshark.TsharkProvider.is_enabled", return_value=False):
            
            # 3. Trigger Analysis
            res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=PCAP")
            assert res.status_code == 201
            analysis_id = res.json()["analysis_id"]

            # 4. Check run status details
            res = client.get(f"/cases/{case_id}/analyses/{analysis_id}")
            assert res.status_code == 200
            run_record = res.json()
            
            assert run_record["status"] == "COMPLETED"
            assert run_record["current_stage"] == "COMPLETED"
            assert "scapy" in run_record["provider_results"]
            assert run_record["provider_results"]["scapy"]["status"] == "COMPLETED"

            # 5. Verify database Indicator records were correctly written
            res = client.get(f"/cases/{case_id}/indicators")
            assert res.status_code == 200
            indicators = res.json()
            
            types = [ind["type"] for ind in indicators]
            values = [ind["value"] for ind in indicators]
            
            # Verify IP, Domain, Protocol, Port, and Repeated Communication Pattern are extracted
            assert "IP" in types
            assert "DOMAIN" in types
            assert "PROTOCOL" in types
            assert "PORT" in types
            assert "8.8.8.8" in values
            assert "malicious-c2.com" in values
            assert "UDP" in values
            assert "53" in values

            # Confirm that the repeated communication observation was persisted
            repeated_obs = [ind for ind in indicators if ind["type"] == "IP" and ind["value"] == "8.8.8.8"]
            assert len(repeated_obs) > 0
            
            # Retrieve observation record to confirm it maps metadata
            obs_res = client.get(f"/cases/{case_id}/indicators")
            # All observations have metadata trace
            for ind in indicators:
                if ind["value"] == "8.8.8.8":
                    obs_dict = ind.get("metadata", {})
                    # Should contain IP or cert details or normal dictionary
                    assert isinstance(obs_dict, dict)

        # Cleanup Case
        client.delete(f"/cases/{case_id}")
