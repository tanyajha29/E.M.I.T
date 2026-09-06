import axios from 'axios';

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true,
});

// Attach Authorization Bearer token if present in localStorage
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('emit_auth_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 Unauthorized responses (token expired or revoked)
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('emit_auth_token');
      window.dispatchEvent(new CustomEvent('emit-auth-unauthorized'));
    }
    return Promise.reject(error);
  }
);

// =====================================================================
// TYPES & INTERFACES (Mapped directly to backend schemas)
// =====================================================================

export type UserRole = 'ADMIN' | 'INVESTIGATOR' | 'VIEWER';

export interface User {
  user_id: string;
  email: string;
  full_name: string;
  role: UserRole;
  badge_id: string;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface DatabaseHealth {
  status: string;
}

export interface HealthResponse {
  status: string;
  service: string;
  database: DatabaseHealth;
}

export type CaseStatus = 'OPEN' | 'ANALYZING' | 'COMPLETED' | 'ARCHIVED';

export interface Case {
  case_id: string;
  name: string;
  description: string;
  status: CaseStatus;
  owner_id?: string;
  owner_name?: string;
  assigned_user_ids?: string[];
  created_at: string;
  updated_at: string;
}

export interface CaseCreate {
  name: string;
  description: string;
}

export interface CaseUpdate {
  name?: string;
  description?: string;
  status?: CaseStatus;
}

export interface EvidenceFile {
  evidence_id: string;
  case_id: string;
  file_name: string;
  file_type: 'APK' | 'PCAP' | 'PCAPNG';
  mime_type: string;
  file_size: number;
  sha256: string;
  storage_provider: string;
  storage_path: string;
  status: string;
  uploaded_at: string;
  created_at: string;
}

export type ProviderStatus = 'DISABLED' | 'NOT_CONFIGURED' | 'UNAVAILABLE' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export interface ProviderExecutionRecord {
  provider: string;
  provider_version?: string;
  started_at?: string;
  completed_at?: string;
  status: ProviderStatus;
  duration?: number;
  error?: string;
  output_metadata: Record<string, any>;
}

export type AnalysisStatus = 'PENDING' | 'COMPLETED' | 'PARTIAL' | 'FAILED';
export type AnalysisStage = 'PENDING' | 'VALIDATING' | 'ANALYZING' | 'NORMALIZING' | 'COMPLETED' | 'FAILED';

export interface AnalysisRun {
  analysis_id: string;
  case_id: string;
  evidence_id: string;
  analysis_type: 'APK' | 'PCAP';
  status: AnalysisStatus;
  current_stage: AnalysisStage;
  started_at: string;
  completed_at?: string;
  provider_results: Record<string, ProviderExecutionRecord>;
  errors: string[];
  warnings: string[];
  created_at: string;
  updated_at: string;
}

export interface Indicator {
  indicator_id: string;
  case_id: string;
  type: string;
  value: string;
  normalized_value: string;
  metadata: Record<string, any>;
  created_at: string;
}

export interface Correlation {
  correlation_id: string;
  case_id: string;
  source_observation_ids: string[];
  target_observation_ids: string[];
  relationship_type: string;
  strength: 'WEAK' | 'MODERATE' | 'STRONG';
  reason: string;
  supporting_evidence_ids: string[];
  created_at: string;
}

export interface Observation {
  observation_id: string;
  case_id: string;
  indicator_id: string;
  evidence_id: string;
  observation_type: string;
  source: string;
  value: string;
  confidence: number;
  timestamp: string;
  metadata: Record<string, any>;
  created_at: string;
}

export interface AttackNode {
  node_id: string;
  case_id: string;
  node_type: string;
  label: string;
  entity_reference: string;
  timestamp?: string;
  metadata: Record<string, any>;
  created_at: string;
}

export interface AttackEdge {
  edge_id: string;
  case_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: string;
  relationship_class: 'OBSERVED' | 'CORRELATED' | 'INFERRED';
  strength: 'WEAK' | 'MODERATE' | 'STRONG';
  reason: string;
  timestamp?: string;
  sequence_index?: number;
  supporting_observation_ids: string[];
  supporting_correlation_ids: string[];
  supporting_evidence_ids: string[];
  metadata: Record<string, any>;
  created_at: string;
}

export interface AttackGraphResponse {
  nodes: AttackNode[];
  edges: AttackEdge[];
}

export interface ThreatIntelligence {
  threat_intel_id: string;
  case_id: string;
  indicator_id?: string;
  indicator: string;
  indicator_type: string;
  provider: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN';
  score?: number;
  categories: string[];
  raw_result: Record<string, any>;
  checked_at: string;
  expires_at: string;
  metadata: Record<string, any>;
}

export interface RiskAssessment {
  risk_assessment_id: string;
  case_id: string;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence_strength: string;
  confidence: number;
  summary: string;
  observed_facts: string[];
  inferences: string[];
  possible_interpretations: string[];
  uncertainty: string[];
  limitations: string[];
  analyst_guidance: string[];
  supporting_observation_ids: string[];
  supporting_correlation_ids: string[];
  supporting_evidence_ids: string[];
  category_scores: Record<string, any>;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface Report {
  report_id: string;
  case_id: string;
  title: string;
  report_type: string;
  report_format: 'HTML' | 'PDF' | 'BOTH';
  storage_path: string;
  html_path?: string;
  pdf_path?: string;
  status: 'PENDING' | 'GENERATING' | 'COMPLETED' | 'FAILED';
  metadata?: Record<string, any>;
  generated_at?: string;
  created_at: string;
}

// =====================================================================
// SERVICE API METHODS
// =====================================================================

export const apiService = {
  // Health
  getHealth: async (): Promise<HealthResponse> => {
    const res = await client.get<HealthResponse>('/health');
    return res.data;
  },

  // Cases
  getCases: async (): Promise<Case[]> => {
    const res = await client.get<Case[]>('/cases');
    return res.data;
  },
  getCase: async (caseId: string): Promise<Case> => {
    const res = await client.get<Case>(`/cases/${caseId}`);
    return res.data;
  },
  createCase: async (caseData: CaseCreate): Promise<Case> => {
    const res = await client.post<Case>('/cases', caseData);
    return res.data;
  },
  updateCase: async (caseId: string, caseData: CaseUpdate): Promise<Case> => {
    const res = await client.put<Case>(`/cases/${caseId}`, caseData);
    return res.data;
  },
  deleteCase: async (caseId: string): Promise<void> => {
    await client.delete(`/cases/${caseId}`);
  },

  // Evidence
  getEvidenceForCase: async (caseId: string): Promise<EvidenceFile[]> => {
    const res = await client.get<EvidenceFile[]>(`/cases/${caseId}/evidence`);
    return res.data;
  },
  uploadEvidence: async (caseId: string, file: File, onProgress?: (pct: number) => void): Promise<EvidenceFile> => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await client.post<EvidenceFile>(`/cases/${caseId}/evidence`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(percentCompleted);
        }
      }
    });
    return res.data;
  },
  deleteEvidence: async (caseId: string, evidenceId: string): Promise<void> => {
    await client.delete(`/cases/${caseId}/evidence/${evidenceId}`);
  },

  // Analysis Runs
  triggerAnalysis: async (caseId: string, evidenceId: string, type: 'APK' | 'PCAP'): Promise<AnalysisRun> => {
    const res = await client.post<AnalysisRun>(
      `/cases/${caseId}/evidence/${evidenceId}/analyze?analysis_type=${type}`
    );
    return res.data;
  },
  getAnalysesForCase: async (caseId: string): Promise<AnalysisRun[]> => {
    const res = await client.get<AnalysisRun[]>(`/cases/${caseId}/analyses`);
    return res.data;
  },
  getAnalysisRun: async (caseId: string, analysisId: string): Promise<AnalysisRun> => {
    const res = await client.get<AnalysisRun>(`/cases/${caseId}/analyses/${analysisId}`);
    return res.data;
  },

  // Observations
  getObservationsForCase: async (caseId: string): Promise<Observation[]> => {
    const res = await client.get<Observation[]>(`/cases/${caseId}/observations`);
    return res.data;
  },

  // Indicators
  getIndicatorsForCase: async (caseId: string): Promise<Indicator[]> => {
    const res = await client.get<Indicator[]>(`/cases/${caseId}/indicators`);
    return res.data;
  },

  // Correlations
  getCorrelationsForCase: async (caseId: string): Promise<Correlation[]> => {
    const res = await client.get<Correlation[]>(`/cases/${caseId}/correlations`);
    return res.data;
  },

  // Attack Graph
  getGraphForCase: async (caseId: string): Promise<AttackGraphResponse> => {
    const res = await client.get<AttackGraphResponse>(`/cases/${caseId}/graph`);
    return res.data;
  },

  // Threat Intelligence
  getThreatIntelForCase: async (caseId: string): Promise<ThreatIntelligence[]> => {
    const res = await client.get<ThreatIntelligence[]>(`/cases/${caseId}/threat-intel`);
    return res.data;
  },
  enrichThreatIntel: async (caseId: string): Promise<ThreatIntelligence[]> => {
    const res = await client.post<ThreatIntelligence[]>(`/cases/${caseId}/threat-intel/enrich`);
    return res.data;
  },

  // Risk Assessment
  getRiskAssessmentForCase: async (caseId: string): Promise<RiskAssessment> => {
    const res = await client.get<RiskAssessment>(`/cases/${caseId}/risk`);
    return res.data;
  },
  triggerRiskAssessment: async (caseId: string): Promise<RiskAssessment> => {
    const res = await client.post<RiskAssessment>(`/cases/${caseId}/risk/assess`);
    return res.data;
  },

  // Reports
  getReportsForCase: async (caseId: string): Promise<Report[]> => {
    const res = await client.get<Report[]>(`/cases/${caseId}/reports`);
    return res.data;
  },
  generateReport: async (caseId: string, format: string = 'BOTH', title?: string): Promise<Report> => {
    const params = new URLSearchParams({ format });
    if (title) params.append('title', title);
    const res = await client.post<Report>(`/cases/${caseId}/reports/generate?${params.toString()}`);
    return res.data;
  },
  getReportDownloadUrl: (caseId: string, reportId: string, format: 'html' | 'pdf'): string => {
    const baseURL = client.defaults.baseURL || 'http://localhost:8000';
    return `${baseURL}/cases/${caseId}/reports/${reportId}/download?format=${format}`;
  },

  // Case Assignment
  assignCase: async (caseId: string, assignedUserIds: string[]): Promise<Case> => {
    const res = await client.post<Case>(`/cases/${caseId}/assign`, { assigned_user_ids: assignedUserIds });
    return res.data;
  },

  // Authentication
  signup: async (data: { email: string; password: string; full_name: string }): Promise<TokenResponse> => {
    const res = await client.post<TokenResponse>('/auth/signup', data);
    return res.data;
  },
  login: async (data: { email: string; password: string }): Promise<TokenResponse> => {
    const res = await client.post<TokenResponse>('/auth/login', data);
    return res.data;
  },
  getMe: async (): Promise<User> => {
    const res = await client.get<User>('/auth/me');
    return res.data;
  },
  logout: async (): Promise<void> => {
    await client.post('/auth/logout');
  },
  listUsers: async (): Promise<User[]> => {
    const res = await client.get<User[]>('/auth/users');
    return res.data;
  }
};

