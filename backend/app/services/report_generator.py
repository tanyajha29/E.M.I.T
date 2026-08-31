import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from uuid import uuid4

from jinja2 import Template
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

from app.core.config import settings
from app.db.repositories.case_repository import CaseRepository
from app.db.repositories.evidence_repository import EvidenceRepository
from app.db.repositories.analysis_run_repository import AnalysisRunRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.threat_intel_repository import ThreatIntelRepository
from app.db.repositories.risk_repository import RiskRepository
from app.db.repositories.report_repository import ReportRepository
from app.services.attack_reconstructor import AttackChainReconstructor
from app.services.risk_engine import RiskEngine
from app.schemas.report import Report, ReportFormat, ReportStatus

logger = logging.getLogger("emit.report_generator")


class NumberedCanvas(canvas.Canvas):
    """Custom canvas that adds page numbers in a second pass."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawRightString(
            letter[0] - 40,
            25,
            f"Page {self._pageNumber} of {page_count} | E.M.I.T. Forensic Report"
        )
        self.drawString(
            40,
            25,
            "CONFIDENTIAL — LAW ENFORCEMENT & FORENSIC INVESTIGATION USE ONLY"
        )
        self.restoreState()


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report.title }} - Case {{ case.case_id[:8] }}</title>
    <style>
        :root {
            --bg: #090d16;
            --surface: #0f172a;
            --surface-hover: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --cyan: #06b6d4;
            --amber: #f59e0b;
            --emerald: #10b981;
            --rose: #f43f5e;
            --purple: #a855f7;
        }
        @media print {
            body { background: #fff !important; color: #0f172a !important; font-size: 11pt; }
            .no-print { display: none !important; }
            .section { page-break-inside: avoid; border-color: #cbd5e1 !important; background: #f8fafc !important; }
            .badge-obs { border: 1px solid #0891b2 !important; color: #0891b2 !important; }
            .badge-intel { border: 1px solid #e11d48 !important; color: #e11d48 !important; }
            .badge-inf { border: 1px solid #7c3aed !important; color: #7c3aed !important; }
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 30px;
        }
        .container { max-width: 1100px; margin: 0 auto; }
        .header {
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        .header h1 { font-size: 24px; color: var(--text); font-weight: 800; }
        .header p { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
        .header-meta { text-align: right; font-family: monospace; font-size: 11px; color: var(--text-muted); }
        .section {
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }
        .section-title {
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--cyan);
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
            margin-bottom: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
        .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
        .stat-card {
            background-color: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border);
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
        }
        .stat-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; display: block; }
        .stat-value { font-size: 18px; font-weight: bold; margin-top: 4px; color: var(--text); }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }
        th { text-align: left; padding: 8px 10px; font-size: 11px; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border); }
        td { padding: 8px 10px; border-bottom: 1px solid rgba(51, 65, 85, 0.4); font-family: monospace; }
        tr:hover td { background-color: rgba(30, 41, 59, 0.4); }
        .badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-obs { background: rgba(6, 182, 212, 0.15); color: var(--cyan); border: 1px solid rgba(6, 182, 212, 0.4); }
        .badge-intel { background: rgba(244, 63, 94, 0.15); color: var(--rose); border: 1px solid rgba(244, 63, 94, 0.4); }
        .badge-inf { background: rgba(168, 85, 247, 0.15); color: var(--purple); border: 1px solid rgba(168, 85, 247, 0.4); }
        .badge-corr { background: rgba(245, 158, 11, 0.15); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.4); }
        .badge-risk-critical { background: rgba(244, 63, 94, 0.2); color: var(--rose); border: 1px solid var(--rose); }
        .badge-risk-high { background: rgba(245, 158, 11, 0.2); color: var(--amber); border: 1px solid var(--amber); }
        .badge-risk-medium { background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid #eab308; }
        .badge-risk-low { background: rgba(16, 185, 129, 0.2); color: var(--emerald); border: 1px solid var(--emerald); }
        .callout {
            background-color: rgba(15, 23, 42, 0.7);
            border-left: 4px solid var(--cyan);
            padding: 12px 16px;
            border-radius: 0 6px 6px 0;
            font-size: 12px;
            margin-top: 10px;
        }
        .callout-amber { border-left-color: var(--amber); }
        .callout-rose { border-left-color: var(--rose); }
        .list-items { padding-left: 20px; font-size: 12px; color: var(--text); }
        .list-items li { margin-bottom: 6px; }
        .timeline-item { position: relative; padding-left: 24px; margin-bottom: 16px; }
        .timeline-dot {
            position: absolute;
            left: 0;
            top: 4px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: var(--cyan);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <div class="header">
            <div>
                <h1>E.M.I.T. FORENSIC INVESTIGATION REPORT</h1>
                <p>Evidence-backed Mobile Investigation Tool &bull; Case: {{ case.name }}</p>
            </div>
            <div class="header-meta">
                <div>CASE ID: {{ case.case_id }}</div>
                <div>GENERATED: {{ generated_at }}</div>
                <div>CLASSIFICATION: STRICT FORENSIC DOSSIER</div>
            </div>
        </div>

        <!-- 1. INVESTIGATION SUMMARY -->
        <div class="section">
            <div class="section-title">
                <span>1. Investigation Summary</span>
                {% if risk %}
                <span class="badge badge-risk-{{ risk.risk_level.lower() }}">{{ risk.risk_level }} RISK</span>
                {% endif %}
            </div>
            <div class="grid-4">
                <div class="stat-card">
                    <span class="stat-label">Case Status</span>
                    <span class="stat-value" style="color: var(--cyan);">{{ case.status }}</span>
                </div>
                <div class="stat-card">
                    <span class="stat-label">Evidence Files</span>
                    <span class="stat-value">{{ evidence_files|length }}</span>
                </div>
                <div class="stat-card">
                    <span class="stat-label">Extracted IOCs</span>
                    <span class="stat-value">{{ indicators|length }}</span>
                </div>
                <div class="stat-card">
                    <span class="stat-label">Confidence</span>
                    <span class="stat-value">{% if risk %}{{ (risk.confidence * 100)|int }}%{% else %}N/A{% endif %}</span>
                </div>
            </div>
            {% if risk %}
            <div class="callout" style="margin-top: 16px;">
                <strong>Executive Synthesis:</strong> {{ risk.summary }}
            </div>
            {% endif %}
        </div>

        <!-- 2. EVIDENCE INVENTORY -->
        <div class="section">
            <div class="section-title">2. Evidence Inventory & Chain of Custody</div>
            <table>
                <thead>
                    <tr>
                        <th>File Name</th>
                        <th>Format</th>
                        <th>Size</th>
                        <th>SHA-256 Hash Provenance</th>
                        <th>Upload Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ev in evidence_files %}
                    <tr>
                        <td><strong>{{ ev.file_name }}</strong></td>
                        <td><span class="badge badge-obs">{{ ev.file_type }}</span></td>
                        <td>{{ (ev.file_size / 1024 / 1024)|round(2) }} MB</td>
                        <td style="font-size: 10px; word-break: break-all;">{{ ev.sha256 }}</td>
                        <td>{{ ev.uploaded_at }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No evidence files registered.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- 3. APK ANALYSIS -->
        <div class="section">
            <div class="section-title">
                <span>3. Android APK Static Analysis Findings</span>
                <span class="badge badge-obs">Observed Evidence</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Observation Type</th>
                        <th>Extracted Value / Parameter</th>
                        <th>Confidence</th>
                        <th>Evidence ID</th>
                    </tr>
                </thead>
                <tbody>
                    {% for obs in apk_observations %}
                    <tr>
                        <td><span class="badge badge-obs">{{ obs.observation_type }}</span></td>
                        <td style="word-break: break-all;">{{ obs.value }}</td>
                        <td>{{ obs.confidence }}</td>
                        <td style="font-size: 10px;">{{ obs.evidence_id[:12] }}...</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No static APK observations recorded.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- 4. NETWORK ANALYSIS -->
        <div class="section">
            <div class="section-title">
                <span>4. PCAP Network Traffic Analysis Findings</span>
                <span class="badge badge-obs">Observed Evidence</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Event Type</th>
                        <th>Observed Value</th>
                        <th>Timestamp</th>
                        <th>Traffic Metadata</th>
                    </tr>
                </thead>
                <tbody>
                    {% for obs in network_observations %}
                    <tr>
                        <td><span class="badge badge-obs">{{ obs.observation_type }}</span></td>
                        <td style="word-break: break-all;">{{ obs.value }}</td>
                        <td>{{ obs.timestamp or 'Static / Unspecified' }}</td>
                        <td style="font-size: 10px;">{{ obs.metadata }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No PCAP network observations recorded.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- 5. INDICATORS -->
        <div class="section">
            <div class="section-title">5. Normalized Indicators of Compromise (IOCs)</div>
            <table>
                <thead>
                    <tr>
                        <th>IOC Type</th>
                        <th>Normalized Indicator</th>
                        <th>Raw Value</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ind in indicators %}
                    <tr>
                        <td><span class="badge badge-obs">{{ ind.type }}</span></td>
                        <td><strong>{{ ind.normalized_value }}</strong></td>
                        <td style="color: var(--text-muted);">{{ ind.value }}</td>
                        <td>{{ ind.created_at }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No indicators extracted.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- 6. CORRELATIONS -->
        <div class="section">
            <div class="section-title">
                <span>6. Deterministic Evidence Correlations</span>
                <span class="badge badge-corr">Correlated Linkages</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Correlation Rule</th>
                        <th>Strength</th>
                        <th>Forensic Deduction / Reason</th>
                    </tr>
                </thead>
                <tbody>
                    {% for corr in correlations %}
                    <tr>
                        <td><span class="badge badge-corr">{{ corr.relationship_type }}</span></td>
                        <td><strong>{{ corr.strength }}</strong></td>
                        <td>{{ corr.reason }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No cross-evidence correlations established.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- 7. THREAT INTELLIGENCE -->
        <div class="section">
            <div class="section-title">
                <span>7. External Threat Intelligence Enrichment</span>
                <span class="badge badge-intel">External Intelligence</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Provider</th>
                        <th>Queried Indicator</th>
                        <th>Verdict</th>
                        <th>Score</th>
                        <th>Categories</th>
                        <th>Checked At</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ti in threat_intel %}
                    <tr>
                        <td><strong>{{ ti.provider }}</strong></td>
                        <td>{{ ti.indicator }}</td>
                        <td><span class="badge {% if ti.verdict == 'MALICIOUS' %}badge-risk-critical{% elif ti.verdict == 'SUSPICIOUS' %}badge-risk-high{% else %}badge-obs{% endif %}">{{ ti.verdict }}</span></td>
                        <td>{{ ti.score if ti.score is not none else 'N/A' }}</td>
                        <td style="font-size: 10px;">{{ ti.categories|join(', ') if ti.categories else 'None' }}</td>
                        <td>{{ ti.checked_at }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No external threat intelligence queried.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- 8. ATTACK CHAIN -->
        <div class="section">
            <div class="section-title">
                <span>8. Attack Chain Reconstruction</span>
                <span class="badge badge-inf">Inferred Relationships</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Seq</th>
                        <th>Relationship</th>
                        <th>Class</th>
                        <th>Strength</th>
                        <th>Evidence-Backed Reason</th>
                    </tr>
                </thead>
                <tbody>
                    {% for edge in attack_edges %}
                    <tr>
                        <td>{{ edge.sequence_index if edge.sequence_index is not none else '-' }}</td>
                        <td><strong>{{ edge.relationship_type }}</strong></td>
                        <td><span class="badge {% if edge.relationship_class == 'OBSERVED' %}badge-obs{% elif edge.relationship_class == 'CORRELATED' %}badge-corr{% else %}badge-inf{% endif %}">{{ edge.relationship_class }}</span></td>
                        <td>{{ edge.strength }}</td>
                        <td style="font-size: 11px;">{{ edge.reason }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No attack chain edges generated.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- 9. TIMELINE -->
        <div class="section">
            <div class="section-title">9. Forensic Chronological Timeline (Authentic Dates Only)</div>
            <div style="padding-top: 8px;">
                {% for ev in timeline_events %}
                <div class="timeline-item">
                    <div class="timeline-dot"></div>
                    <div style="font-size: 11px; font-weight: bold; color: var(--text);">{{ ev.title }}</div>
                    <div style="font-size: 11px; color: var(--text-muted);">{{ ev.desc }}</div>
                    <div style="font-size: 10px; font-family: monospace; color: var(--cyan); margin-top: 2px;">{{ ev.timestamp }}</div>
                </div>
                {% else %}
                <p style="color: var(--text-muted); font-size: 12px;">No timestamped events recorded.</p>
                {% endfor %}
            </div>
        </div>

        <!-- 10. RISK ASSESSMENT -->
        <div class="section">
            <div class="section-title">10. Deterministic Risk Assessment & Findings Separation</div>
            {% if risk %}
            <div class="grid-2">
                <div class="callout">
                    <h4 style="color: var(--cyan); margin-bottom: 8px;">OBSERVED GROUND-TRUTH FACTS</h4>
                    <ul class="list-items">
                        {% for fact in risk.observed_facts %}
                        <li>{{ fact }}</li>
                        {% else %}
                        <li>None recorded.</li>
                        {% endfor %}
                    </ul>
                </div>
                <div class="callout callout-amber">
                    <h4 style="color: var(--amber); margin-bottom: 8px;">ANALYTICAL INFERENCES</h4>
                    <ul class="list-items">
                        {% for inf in risk.inferences %}
                        <li>{{ inf }}</li>
                        {% else %}
                        <li>None established.</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
            {% else %}
            <p style="color: var(--text-muted); font-size: 12px;">No risk assessment record available.</p>
            {% endif %}
        </div>

        <!-- 11. SUPPORTING EVIDENCE -->
        <div class="section">
            <div class="section-title">11. Supporting Evidence Traceability</div>
            <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
                Every analytical conclusion in this report is mapped to underlying observation IDs and evidence files:
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Conclusion / Observation ID</th>
                        <th>Evidence Source File</th>
                        <th>SHA-256 Hash Integrity</th>
                    </tr>
                </thead>
                <tbody>
                    {% for obs in observations %}
                    <tr>
                        <td>{{ obs.observation_id }} ({{ obs.observation_type }})</td>
                        <td>{{ obs.source }} Package</td>
                        <td style="font-size: 10px;">{{ obs.evidence_id }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No supporting evidence links.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- 12. UNCERTAINTY & LIMITATIONS -->
        <div class="section">
            <div class="section-title">12. Technical Uncertainty & Operational Limitations</div>
            <ul class="list-items">
                {% if risk and risk.uncertainty %}
                    {% for u in risk.uncertainty %}
                    <li>{{ u }}</li>
                    {% endfor %}
                {% endif %}
                <li>TLS encrypted payloads were not decrypted; plaintext message content cannot be confirmed without private session keys.</li>
                <li>Analysis is passive and static; dynamic runtime behavior in an instrumented live sandbox was not executed.</li>
                <li>Periodic communications may represent legitimate background push notifications or analytics heartbeats.</li>
            </ul>
        </div>

        <!-- 13. ANALYST GUIDANCE -->
        <div class="section">
            <div class="section-title">13. Actionable Analyst Guidance & Next Steps</div>
            <ul class="list-items">
                {% if risk and risk.analyst_guidance %}
                    {% for g in risk.analyst_guidance %}
                    <li><strong>Action Item:</strong> {{ g }}</li>
                    {% endfor %}
                {% endif %}
                <li>Verify remote IP/domain ownership against corporate proxy logs and external WHOIS records.</li>
                <li>Decompile classes associated with flagged socket or reflection APIs to verify execution control flow.</li>
            </ul>
        </div>

        <div style="text-align: center; font-size: 10px; color: var(--text-muted); margin-top: 40px; font-family: monospace;">
            REPORT GENERATED BY E.M.I.T. FORENSIC ENGINE &bull; REPRODUCIBLE STORED STATE &bull; ALL RIGHTS RESERVED
        </div>
    </div>
</body>
</html>
"""


class ReportGeneratorService:
    """
    Forensic Investigation Report Generator Service.
    Generates reproducible HTML reports and PDF dossiers directly from MongoDB investigation records.
    Renders all 13 required forensic sections and strictly separates:
    - OBSERVED EVIDENCE
    - EXTERNAL INTELLIGENCE
    - INFERRED RELATIONSHIPS
    """

    @classmethod
    def generate_report(
        cls,
        case_id: str,
        report_format: ReportFormat = ReportFormat.BOTH,
        title: str = "E.M.I.T. Forensic Investigation Report",
        case_repo: Optional[CaseRepository] = None,
        ev_repo: Optional[EvidenceRepository] = None,
        run_repo: Optional[AnalysisRunRepository] = None,
        obs_repo: Optional[ObservationRepository] = None,
        ind_repo: Optional[IndicatorRepository] = None,
        corr_repo: Optional[CorrelationRepository] = None,
        threat_repo: Optional[ThreatIntelRepository] = None,
        risk_repo: Optional[RiskRepository] = None,
        report_repo: Optional[ReportRepository] = None
    ) -> Report:
        """
        Gathers stored case records, compiles HTML and/or PDF documents, saves them to disk,
        and registers the Report record in MongoDB.
        """
        logger.info(f"Starting report generation for case {case_id} (Format: {report_format.value})")

        case_repo = case_repo or CaseRepository()
        ev_repo = ev_repo or EvidenceRepository()
        run_repo = run_repo or AnalysisRunRepository()
        obs_repo = obs_repo or ObservationRepository()
        ind_repo = ind_repo or IndicatorRepository()
        corr_repo = corr_repo or CorrelationRepository()
        threat_repo = threat_repo or ThreatIntelRepository()
        risk_repo = risk_repo or RiskRepository()
        report_repo = report_repo or ReportRepository()

        # 1. Fetch stored records
        case_data = case_repo.find_one({"case_id": case_id})
        if not case_data:
            raise ValueError(f"Case {case_id} not found in database.")

        evidence_files = ev_repo.find_all({"case_id": case_id})
        analysis_runs = run_repo.find_all({"case_id": case_id})
        observations = obs_repo.find_all({"case_id": case_id})
        indicators = ind_repo.find_all({"case_id": case_id})
        correlations = corr_repo.find_all({"case_id": case_id})
        threat_intel = threat_repo.find_all({"case_id": case_id})
        
        # Risk assessment (fetch or assess on demand if missing)
        risk_data = risk_repo.find_one({"case_id": case_id})
        if not risk_data and observations:
            risk_obj = RiskEngine.assess(case_id, risk_repo=risk_repo, obs_repo=obs_repo, corr_repo=corr_repo, threat_repo=threat_repo)
            risk_data = risk_obj.model_dump()

        # Graph reconstruction
        graph_data = AttackChainReconstructor.reconstruct(case_id)
        attack_nodes = graph_data.get("nodes", [])
        attack_edges = graph_data.get("edges", [])

        # Categorize observations
        apk_observations = [o for o in observations if o.get("source") == "APK"]
        network_observations = [o for o in observations if o.get("source") == "PCAP"]

        # Build real timeline (no fabricated timestamps)
        timeline_events = []
        if case_data.get("created_at"):
            timeline_events.append({
                "title": "Case Registered",
                "desc": f"Investigation formally created: {case_data.get('name')}",
                "timestamp": str(case_data.get("created_at")),
                "raw_date": case_data.get("created_at")
            })

        for ev in evidence_files:
            timeline_events.append({
                "title": f"Evidence Ingestion: {ev.get('file_name')}",
                "desc": f"Format {ev.get('file_type')} | SHA-256: {ev.get('sha256', '')[:16]}...",
                "timestamp": str(ev.get("uploaded_at") or ev.get("created_at")),
                "raw_date": ev.get("uploaded_at") or ev.get("created_at")
            })

        for run in analysis_runs:
            timeline_events.append({
                "title": f"Analysis Execution ({run.get('analysis_type')})",
                "desc": f"Run ID: {run.get('analysis_id', '')[:8]}... | Status: {run.get('status')}",
                "timestamp": str(run.get("started_at")),
                "raw_date": run.get("started_at")
            })

        for obs in network_observations:
            if obs.get("timestamp"):
                timeline_events.append({
                    "title": f"Network Observation: {obs.get('observation_type')}",
                    "desc": f"Observed Value: {obs.get('value')}",
                    "timestamp": str(obs.get("timestamp")),
                    "raw_date": obs.get("timestamp")
                })

        for ti in threat_intel:
            if ti.get("checked_at"):
                timeline_events.append({
                    "title": f"Threat Intel Query ({ti.get('provider')})",
                    "desc": f"Indicator: {ti.get('indicator')} | Verdict: {ti.get('verdict')}",
                    "timestamp": str(ti.get("checked_at")),
                    "raw_date": ti.get("checked_at")
                })

        # Sort chronological descending
        timeline_events.sort(key=lambda x: str(x.get("raw_date", "")), reverse=True)

        report_id = str(uuid4())
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Storage directory
        storage_base = getattr(settings, "STORAGE_BASE_DIR", "storage")
        reports_dir = os.path.join(storage_base, "reports", case_id)
        os.makedirs(reports_dir, exist_ok=True)

        html_path = None
        pdf_path = None

        template_context = {
            "case": case_data,
            "evidence_files": evidence_files,
            "analysis_runs": analysis_runs,
            "observations": observations,
            "apk_observations": apk_observations,
            "network_observations": network_observations,
            "indicators": indicators,
            "correlations": correlations,
            "threat_intel": threat_intel,
            "risk": risk_data,
            "attack_nodes": attack_nodes,
            "attack_edges": attack_edges,
            "timeline_events": timeline_events,
            "generated_at": generated_at,
            "report": {"title": title, "report_id": report_id}
        }

        # 2. Render HTML Report
        if report_format in [ReportFormat.HTML, ReportFormat.BOTH]:
            html_content = Template(HTML_TEMPLATE).render(**template_context)
            html_filename = f"report_{report_id}.html"
            html_path = os.path.join(reports_dir, html_filename)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report successfully written to {html_path}")

        # 3. Render PDF Report
        if report_format in [ReportFormat.PDF, ReportFormat.BOTH]:
            pdf_filename = f"report_{report_id}.pdf"
            pdf_path = os.path.join(reports_dir, pdf_filename)
            cls._generate_pdf(pdf_path, template_context)
            logger.info(f"PDF report successfully written to {pdf_path}")

        # 4. Register in Database
        report_record = Report(
            report_id=report_id,
            case_id=case_id,
            title=title,
            report_type="FULL_FORENSIC_DOSSIER",
            report_format=report_format,
            storage_path=html_path or pdf_path or "",
            html_path=html_path,
            pdf_path=pdf_path,
            status=ReportStatus.COMPLETED,
            generated_at=datetime.utcnow(),
            metadata={
                "evidence_count": len(evidence_files),
                "indicator_count": len(indicators),
                "risk_level": risk_data.get("risk_level") if risk_data else "UNKNOWN"
            }
        )

        report_repo.insert_one(report_record.model_dump())
        logger.info(f"Report {report_id} registered in database.")
        return report_record

    @classmethod
    def _generate_pdf(cls, output_path: str, context: Dict[str, Any]):
        """Generates executive PDF dossier using ReportLab."""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()
        normal = styles["Normal"]
        normal.fontSize = 8
        normal.leading = 10

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Title"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            alignment=0
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#64748b")
        )
        h1_style = ParagraphStyle(
            "SectionH1",
            parent=styles["Heading2"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#0284c7"),
            spaceBefore=12,
            spaceAfter=6
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading3"],
            fontSize=9,
            leading=11,
            textColor=colors.HexColor("#334155"),
            spaceBefore=6,
            spaceAfter=4
        )
        table_cell = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#1e293b")
        )
        table_cell_bold = ParagraphStyle(
            "TableCellBold",
            parent=table_cell,
            fontName="Helvetica-Bold"
        )

        story = []

        # Title Banner
        story.append(Paragraph("E.M.I.T. FORENSIC INVESTIGATION REPORT", title_style))
        case = context["case"]
        story.append(Paragraph(
            f"Case: <b>{case.get('name', 'Investigation')}</b> | ID: {case.get('case_id')} | Generated: {context['generated_at']}",
            subtitle_style
        ))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12))

        # 1. Investigation Summary
        story.append(Paragraph("1. Investigation Summary", h1_style))
        risk = context.get("risk") or {}
        summary_data = [
            [
                Paragraph("<b>Case Name</b>", table_cell), Paragraph(case.get("name", ""), table_cell),
                Paragraph("<b>Deterministic Risk</b>", table_cell), Paragraph(f"<b>{risk.get('risk_level', 'LOW')}</b>", table_cell)
            ],
            [
                Paragraph("<b>Status</b>", table_cell), Paragraph(case.get("status", ""), table_cell),
                Paragraph("<b>Confidence</b>", table_cell), Paragraph(f"{(risk.get('confidence', 0.5) * 100):.0f}%", table_cell)
            ],
            [
                Paragraph("<b>Evidence Files</b>", table_cell), Paragraph(str(len(context["evidence_files"])), table_cell),
                Paragraph("<b>Indicators (IOCs)</b>", table_cell), Paragraph(str(len(context["indicators"])), table_cell)
            ]
        ]
        t_summary = Table(summary_data, colWidths=[1.3*inch, 2.3*inch, 1.3*inch, 2.3*inch])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_summary)

        if risk.get("summary"):
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"<b>Executive Synthesis:</b> {risk.get('summary')}", table_cell))

        story.append(Spacer(1, 10))

        # 2. Evidence Inventory
        story.append(Paragraph("2. Evidence Inventory & Chain of Custody", h1_style))
        ev_rows = [[
            Paragraph("<b>File Name</b>", table_cell_bold),
            Paragraph("<b>Type</b>", table_cell_bold),
            Paragraph("<b>Size</b>", table_cell_bold),
            Paragraph("<b>SHA-256 Hash Provenance</b>", table_cell_bold)
        ]]
        for ev in context["evidence_files"]:
            ev_rows.append([
                Paragraph(ev.get("file_name", ""), table_cell),
                Paragraph(ev.get("file_type", ""), table_cell),
                Paragraph(f"{(ev.get('file_size', 0)/1024/1024):.2f} MB", table_cell),
                Paragraph(ev.get("sha256", ""), table_cell)
            ])
        if len(ev_rows) == 1:
            ev_rows.append([Paragraph("No evidence files.", table_cell), Paragraph("", table_cell), Paragraph("", table_cell), Paragraph("", table_cell)])

        t_ev = Table(ev_rows, colWidths=[1.8*inch, 0.8*inch, 0.9*inch, 3.7*inch])
        t_ev.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_ev)
        story.append(Spacer(1, 10))

        # 3. APK Analysis Findings
        story.append(Paragraph("3. APK Static Findings (OBSERVED EVIDENCE)", h1_style))
        apk_rows = [[
            Paragraph("<b>Observation Type</b>", table_cell_bold),
            Paragraph("<b>Extracted Value</b>", table_cell_bold),
            Paragraph("<b>Confidence</b>", table_cell_bold)
        ]]
        for obs in context["apk_observations"][:15]:
            apk_rows.append([
                Paragraph(obs.get("observation_type", ""), table_cell),
                Paragraph(obs.get("value", ""), table_cell),
                Paragraph(str(obs.get("confidence", 1.0)), table_cell)
            ])
        if len(apk_rows) == 1:
            apk_rows.append([Paragraph("No static APK findings.", table_cell), Paragraph("", table_cell), Paragraph("", table_cell)])

        t_apk = Table(apk_rows, colWidths=[2.2*inch, 4.2*inch, 0.8*inch])
        t_apk.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_apk)
        story.append(Spacer(1, 10))

        # 4. Network Traffic Analysis Findings
        story.append(Paragraph("4. Network Findings (OBSERVED EVIDENCE)", h1_style))
        net_rows = [[
            Paragraph("<b>Event Type</b>", table_cell_bold),
            Paragraph("<b>Observed Flow / Value</b>", table_cell_bold),
            Paragraph("<b>Timestamp</b>", table_cell_bold)
        ]]
        for obs in context["network_observations"][:15]:
            net_rows.append([
                Paragraph(obs.get("observation_type", ""), table_cell),
                Paragraph(obs.get("value", ""), table_cell),
                Paragraph(str(obs.get("timestamp") or "Static"), table_cell)
            ])
        if len(net_rows) == 1:
            net_rows.append([Paragraph("No network findings.", table_cell), Paragraph("", table_cell), Paragraph("", table_cell)])

        t_net = Table(net_rows, colWidths=[2.2*inch, 3.6*inch, 1.4*inch])
        t_net.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_net)
        story.append(Spacer(1, 10))

        # 5. Correlations & Attack Chain
        story.append(Paragraph("5. Deterministic Correlations & Inferred Attack Chain", h1_style))
        corr_rows = [[
            Paragraph("<b>Relationship</b>", table_cell_bold),
            Paragraph("<b>Class</b>", table_cell_bold),
            Paragraph("<b>Strength</b>", table_cell_bold),
            Paragraph("<b>Evidence Deduction / Reason</b>", table_cell_bold)
        ]]
        for edge in context["attack_edges"][:12]:
            corr_rows.append([
                Paragraph(edge.get("relationship_type", ""), table_cell),
                Paragraph(edge.get("relationship_class", ""), table_cell),
                Paragraph(edge.get("strength", ""), table_cell),
                Paragraph(edge.get("reason", ""), table_cell)
            ])
        if len(corr_rows) == 1:
            corr_rows.append([Paragraph("No correlations established.", table_cell), Paragraph("", table_cell), Paragraph("", table_cell), Paragraph("", table_cell)])

        t_corr = Table(corr_rows, colWidths=[1.5*inch, 1.0*inch, 0.9*inch, 3.8*inch])
        t_corr.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_corr)
        story.append(Spacer(1, 10))

        # 6. External Threat Intelligence
        story.append(Paragraph("6. External Threat Intelligence (EXTERNAL INTEL)", h1_style))
        ti_rows = [[
            Paragraph("<b>Provider</b>", table_cell_bold),
            Paragraph("<b>Indicator</b>", table_cell_bold),
            Paragraph("<b>Verdict</b>", table_cell_bold),
            Paragraph("<b>Score / Details</b>", table_cell_bold)
        ]]
        for ti in context["threat_intel"][:10]:
            ti_rows.append([
                Paragraph(ti.get("provider", ""), table_cell),
                Paragraph(ti.get("indicator", ""), table_cell),
                Paragraph(f"<b>{ti.get('verdict', '')}</b>", table_cell),
                Paragraph(str(ti.get("score") or "N/A"), table_cell)
            ])
        if len(ti_rows) == 1:
            ti_rows.append([Paragraph("No threat intel queried.", table_cell), Paragraph("", table_cell), Paragraph("", table_cell), Paragraph("", table_cell)])

        t_ti = Table(ti_rows, colWidths=[1.4*inch, 3.2*inch, 1.2*inch, 1.4*inch])
        t_ti.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_ti)
        story.append(Spacer(1, 10))

        # 7. Timeline
        story.append(Paragraph("7. Chronological Timeline (Authentic Dates Only)", h1_style))
        tl_rows = [[
            Paragraph("<b>Event</b>", table_cell_bold),
            Paragraph("<b>Details</b>", table_cell_bold),
            Paragraph("<b>Timestamp</b>", table_cell_bold)
        ]]
        for tl in context["timeline_events"][:12]:
            tl_rows.append([
                Paragraph(tl.get("title", ""), table_cell),
                Paragraph(tl.get("desc", ""), table_cell),
                Paragraph(tl.get("timestamp", ""), table_cell)
            ])
        if len(tl_rows) == 1:
            tl_rows.append([Paragraph("No timeline events.", table_cell), Paragraph("", table_cell), Paragraph("", table_cell)])

        t_tl = Table(tl_rows, colWidths=[2.0*inch, 3.5*inch, 1.7*inch])
        t_tl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_tl)
        story.append(Spacer(1, 10))

        # 8. Technical Uncertainty, Limitations & Guidance
        story.append(Paragraph("8. Technical Uncertainty, Limitations & Analyst Guidance", h1_style))
        story.append(Paragraph("<b>Uncertainty Disclosures:</b>", h2_style))
        if risk.get("uncertainty"):
            for u in risk.get("uncertainty", []):
                story.append(Paragraph(f"&bull; {u}", table_cell))
        else:
            story.append(Paragraph("&bull; TLS encrypted payloads were not inspected; plaintext cannot be established.", table_cell))

        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Analyst Guidance & Next Steps:</b>", h2_style))
        if risk.get("analyst_guidance"):
            for g in risk.get("analyst_guidance", []):
                story.append(Paragraph(f"&gt; {g}", table_cell))
        else:
            story.append(Paragraph("&gt; Perform runtime instrumentation in Frida to intercept unencrypted traffic.", table_cell))

        doc.build(story, canvasmaker=NumberedCanvas)
