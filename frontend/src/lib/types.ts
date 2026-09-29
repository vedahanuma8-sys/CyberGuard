export type ThreatType = "PHISHING" | "SPAM" | "DOS";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface UnifiedThreatResponse {
  threat_type: ThreatType;
  category: string;
  risk_score: number;
  risk_level: RiskLevel;
  confidence: number;
  indicators: string[];
  mitigation: string[];
  metadata: Record<string, any>;
  latency_ms: number;
}

export interface PhishingRequest {
  url: string;
}

export interface SpamRequest {
  text: string;
}

export interface DoSRequest {
  flow_duration: number;
  tot_fwd_pkts: number;
  tot_bwd_pkts: number;
  tot_len_fwd_pkts: number;
  fwd_pkt_len_mean: number;
  syn_flag_cnt: number;
  ack_flag_cnt: number;
  flow_bytes_s: number;
  flow_pkts_s: number;
}

export interface UniversalThreatRequest {
  input_data: string;
  force_type?: "phishing" | "spam" | "dos";
}

export interface BackendHealthResponse {
  status: "healthy" | "degraded";
  all_engines_ready: boolean;
  engines: {
    phishing_engine: boolean;
    spam_engine: boolean;
    dos_engine: boolean;
  };
  artifacts: Record<string, { exists: boolean; size_bytes: number }>;
  artifacts_dir: string;
}
