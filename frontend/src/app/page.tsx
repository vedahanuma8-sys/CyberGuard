"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cpu,
  Database,
  ExternalLink,
  Flame,
  Globe,
  HelpCircle,
  Info,
  Mail,
  Network,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Waves,
  Zap,
} from "lucide-react";
import {
  BackendHealthResponse,
  DoSRequest,
  RiskLevel,
  UnifiedThreatResponse,
} from "@/lib/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export default function SOCDashboard() {
  // Navigation / Tabs
  const [activeTab, setActiveTab] = useState<"triage" | "phishing" | "spam" | "dos">("triage");

  // Health and System Monitoring
  const [health, setHealth] = useState<BackendHealthResponse | null>(null);
  const [healthStatus, setHealthStatus] = useState<"checking" | "online" | "offline">("checking");
  const [pingLatency, setPingLatency] = useState<number | null>(null);
  const [isRefreshingHealth, setIsRefreshingHealth] = useState<boolean>(false);

  // Form Inputs
  const [triageInput, setTriageInput] = useState<string>("");
  const [phishingUrl, setPhishingUrl] = useState<string>("");
  const [spamText, setSpamText] = useState<string>("");

  // DoS Form Metrics
  const [dosMetrics, setDosMetrics] = useState<DoSRequest>({
    flow_duration: 8500,
    tot_fwd_pkts: 18,
    tot_bwd_pkts: 20,
    tot_len_fwd_pkts: 6500,
    fwd_pkt_len_mean: 361,
    syn_flag_cnt: 1,
    ack_flag_cnt: 18,
    flow_bytes_s: 25000,
    flow_pkts_s: 22,
  });

  // Analysis State
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [result, setResult] = useState<UnifiedThreatResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [showRawTelemetry, setShowRawTelemetry] = useState<boolean>(false);

  // Poll backend health on mount
  const checkBackendHealth = async () => {
    setIsRefreshingHealth(true);
    const start = performance.now();
    try {
      const res = await fetch(`${API_BASE}/health`, { method: "GET" });
      const elapsed = Math.round(performance.now() - start);
      setPingLatency(elapsed);
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
        setHealthStatus(data.status === "healthy" ? "online" : "offline");
      } else {
        setHealthStatus("offline");
      }
    } catch {
      setHealthStatus("offline");
      setPingLatency(null);
    } finally {
      setIsRefreshingHealth(false);
    }
  };

  useEffect(() => {
    checkBackendHealth();
    const interval = setInterval(checkBackendHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  // Handlers for analysis
  const executeAnalysis = async (endpoint: string, payload: any) => {
    setIsAnalyzing(true);
    setErrorMessage(null);
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Analysis request failed with status ${res.status}`);
      }

      const data: UnifiedThreatResponse = await res.json();
      setResult(data);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to communicate with CyberGuard API engine.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleTriageSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!triageInput.trim()) return;
    executeAnalysis("/api/v1/analyze/triage", { input_data: triageInput });
  };

  const handlePhishingSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!phishingUrl.trim()) return;
    executeAnalysis("/api/v1/analyze/phishing", { url: phishingUrl });
  };

  const handleSpamSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!spamText.trim()) return;
    executeAnalysis("/api/v1/analyze/spam", { text: spamText });
  };

  const handleDosSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeAnalysis("/api/v1/analyze/dos", dosMetrics);
  };

  // DoS Preset Simulation Buttons
  const applyDosSimulation = (type: "normal" | "syn_flood" | "slowloris" | "udp_flood") => {
    if (type === "normal") {
      setDosMetrics({
        flow_duration: 9200,
        tot_fwd_pkts: 16,
        tot_bwd_pkts: 19,
        tot_len_fwd_pkts: 6200,
        fwd_pkt_len_mean: 387,
        syn_flag_cnt: 1,
        ack_flag_cnt: 17,
        flow_bytes_s: 28000,
        flow_pkts_s: 25,
      });
    } else if (type === "syn_flood") {
      setDosMetrics({
        flow_duration: 45,
        tot_fwd_pkts: 10,
        tot_bwd_pkts: 0,
        tot_len_fwd_pkts: 500,
        fwd_pkt_len_mean: 50,
        syn_flag_cnt: 10,
        ack_flag_cnt: 0,
        flow_bytes_s: 1800000,
        flow_pkts_s: 48000,
      });
    } else if (type === "slowloris") {
      setDosMetrics({
        flow_duration: 120000,
        tot_fwd_pkts: 32,
        tot_bwd_pkts: 2,
        tot_len_fwd_pkts: 640,
        fwd_pkt_len_mean: 20,
        syn_flag_cnt: 1,
        ack_flag_cnt: 4,
        flow_bytes_s: 5.2,
        flow_pkts_s: 0.15,
      });
    } else if (type === "udp_flood") {
      setDosMetrics({
        flow_duration: 850,
        tot_fwd_pkts: 5500,
        tot_bwd_pkts: 0,
        tot_len_fwd_pkts: 4400000,
        fwd_pkt_len_mean: 800,
        syn_flag_cnt: 0,
        ack_flag_cnt: 0,
        flow_bytes_s: 15000000,
        flow_pkts_s: 18000,
      });
    }
  };

  // Helper colors
  const getRiskColor = (level: RiskLevel) => {
    switch (level) {
      case "CRITICAL":
        return "text-rose-500 border-rose-500/40 bg-rose-500/10";
      case "HIGH":
        return "text-red-400 border-red-500/30 bg-red-500/10";
      case "MEDIUM":
        return "text-amber-400 border-amber-500/30 bg-amber-500/10";
      case "LOW":
      default:
        return "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";
    }
  };

  const getProgressBarColor = (score: number) => {
    if (score >= 80) return "bg-gradient-to-r from-red-500 to-rose-600";
    if (score >= 60) return "bg-gradient-to-r from-amber-500 to-red-500";
    if (score >= 30) return "bg-gradient-to-r from-yellow-400 to-amber-500";
    return "bg-gradient-to-r from-emerald-500 to-teal-400";
  };

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Top SOC Console Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-3">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Shield className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-lg font-bold tracking-wider text-slate-50 uppercase font-mono">
                  CyberGuard <span className="text-cyan-400">//</span> Threat Intelligence SOC
                </h1>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-cyan-950 border border-cyan-800 text-cyan-300">
                  v1.0 ML-PIPELINE
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Multi-Vector ML Engine (Phishing URL, NLP Spam, NetFlow DoS/DDoS)
              </p>
            </div>
          </div>

          {/* Live Telemetry Heartbeat & Backend Monitor */}
          <div className="flex items-center space-x-4 text-xs font-mono">
            {/* Heartbeat Status */}
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-md bg-slate-950 border border-slate-800">
              <div
                className={`w-2.5 h-2.5 rounded-full ${
                  healthStatus === "online"
                    ? "bg-emerald-400 animate-radar"
                    : healthStatus === "checking"
                    ? "bg-amber-400 animate-ping"
                    : "bg-rose-500"
                }`}
              />
              <span className="text-slate-400">API NODE:</span>
              <span
                className={`font-semibold uppercase ${
                  healthStatus === "online"
                    ? "text-emerald-400"
                    : healthStatus === "checking"
                    ? "text-amber-400"
                    : "text-rose-400"
                }`}
              >
                {healthStatus}
              </span>
            </div>

            {/* Latency Meter */}
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-md bg-slate-950 border border-slate-800">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-slate-400">RTT:</span>
              <span className="text-cyan-300 font-semibold">
                {pingLatency !== null ? `${pingLatency}ms` : "---"}
              </span>
            </div>

            {/* Refresh Button */}
            <button
              onClick={checkBackendHealth}
              disabled={isRefreshingHealth}
              className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              title="Ping Backend Health"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshingHealth ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Navigation Tabs */}
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3 overflow-x-auto">
          <button
            onClick={() => setActiveTab("triage")}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === "triage"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Zap className="w-4 h-4 text-cyan-400" />
            <span>Smart Triage</span>
          </button>

          <button
            onClick={() => setActiveTab("phishing")}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === "phishing"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Globe className="w-4 h-4 text-emerald-400" />
            <span>URL Phishing</span>
          </button>

          <button
            onClick={() => setActiveTab("spam")}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === "spam"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Mail className="w-4 h-4 text-amber-400" />
            <span>Message Spam</span>
          </button>

          <button
            onClick={() => setActiveTab("dos")}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === "dos"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Network className="w-4 h-4 text-rose-400" />
            <span>NetFlow DoS</span>
          </button>
        </div>

        {/* Tab 1: Smart Triage */}
        {activeTab === "triage" && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-slate-100 flex items-center space-x-2">
                  <Zap className="w-5 h-5 text-cyan-400" />
                  <span>Universal Threat Auto-Triage</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Submit any target URL, suspicious email/SMS text, or raw network flow JSON. The triage routing algorithm auto-classifies the attack vector and executes the appropriate ML model.
                </p>
              </div>

              {/* Sample Quick Injectors */}
              <div className="flex flex-wrap gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => setTriageInput("http://192.168.1.100/paypal/verify-account.php?token=93821")}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
                >
                  Load Phishing URL
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setTriageInput(
                      "URGENT: Your account is suspended! Claim your $50,000 cash lottery prize now at http://claim-prize.top"
                    )
                  }
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
                >
                  Load Spam SMS
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setTriageInput(
                      JSON.stringify({
                        flow_duration: 50,
                        tot_fwd_pkts: 10,
                        tot_bwd_pkts: 0,
                        tot_len_fwd_pkts: 500,
                        fwd_pkt_len_mean: 50,
                        syn_flag_cnt: 10,
                        ack_flag_cnt: 0,
                        flow_bytes_s: 1500000,
                        flow_pkts_s: 45000,
                      })
                    )
                  }
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-mono"
                >
                  Load NetFlow JSON
                </button>
              </div>
            </div>

            <form onSubmit={handleTriageSubmit} className="space-y-4">
              <textarea
                value={triageInput}
                onChange={(e) => setTriageInput(e.target.value)}
                placeholder="Paste URL, message text, or raw NetFlow JSON payload..."
                rows={4}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono resize-y"
              />

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={isAnalyzing || !triageInput.trim()}
                  className="flex items-center space-x-2 px-6 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-md shadow-cyan-900/30"
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                      <span>Triaging Artifact...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4 text-slate-950" />
                      <span>Execute Auto-Triage</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Tab 2: URL Phishing */}
        {activeTab === "phishing" && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-slate-100 flex items-center space-x-2">
                  <Globe className="w-5 h-5 text-emerald-400" />
                  <span>URL Phishing & Domain Deception Engine</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Computes 16 mathematical, structural, and Shannon entropy indicators over the domain and URI tokens.
                </p>
              </div>

              <div className="flex gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => setPhishingUrl("https://www.google.com/search?q=cyberguard+soc")}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700"
                >
                  Legitimate URL
                </button>
                <button
                  type="button"
                  onClick={() => setPhishingUrl("http://192.168.1.100/paypal/login.php?token=92831")}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-rose-400 border border-slate-700"
                >
                  Raw IP Phish
                </button>
                <button
                  type="button"
                  onClick={() => setPhishingUrl("http://secure-login-chase.account-update.xyz/auth")}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-rose-400 border border-slate-700"
                >
                  Typosquatted Domain
                </button>
              </div>
            </div>

            <form onSubmit={handlePhishingSubmit} className="space-y-4">
              <input
                type="text"
                value={phishingUrl}
                onChange={(e) => setPhishingUrl(e.target.value)}
                placeholder="https://example.com/login..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
              />

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={isAnalyzing || !phishingUrl.trim()}
                  className="flex items-center space-x-2 px-6 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-md shadow-emerald-900/30"
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                      <span>Scanning Entropy & Structure...</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="w-4 h-4 text-slate-950" />
                      <span>Analyze URL</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Tab 3: Message Spam */}
        {activeTab === "spam" && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-semibold text-slate-100 flex items-center space-x-2">
                  <Mail className="w-5 h-5 text-amber-400" />
                  <span>Email & SMS Social Engineering Classifier</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  NLP feature vectorization with Calibrated LinearSVC detects deceptive urgency, scams, and fraudulent messages.
                </p>
              </div>

              <div className="flex gap-2 text-xs">
                <button
                  type="button"
                  onClick={() =>
                    setSpamText("Hi Alex, please find attached the revised financial forecast for tomorrow's review.")
                  }
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700"
                >
                  Normal Ham
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setSpamText(
                      "URGENT: Your bank account is locked! Claim your $50,000 cash lottery prize now at http://claim-prize.top"
                    )
                  }
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-rose-400 border border-slate-700"
                >
                  Lottery Scam
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setSpamText("Double your Bitcoin in 24 hours! Send 1 BTC to smart contract and claim 2 BTC back.")
                  }
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-rose-400 border border-slate-700"
                >
                  Crypto Phish
                </button>
              </div>
            </div>

            <form onSubmit={handleSpamSubmit} className="space-y-4">
              <textarea
                value={spamText}
                onChange={(e) => setSpamText(e.target.value)}
                placeholder="Paste email body or SMS text message..."
                rows={4}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono resize-y"
              />

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={isAnalyzing || !spamText.trim()}
                  className="flex items-center space-x-2 px-6 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-slate-950 font-semibold text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-md shadow-amber-900/30"
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                      <span>Vectorizing Text...</span>
                    </>
                  ) : (
                    <>
                      <Mail className="w-4 h-4 text-slate-950" />
                      <span>Classify Message</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Tab 4: NetFlow DoS with Simulation Buttons */}
        {activeTab === "dos" && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-base font-semibold text-slate-100 flex items-center space-x-2">
                  <Network className="w-5 h-5 text-rose-400" />
                  <span>Network Flow DoS / DDoS Classifier</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Trained on CICIDS2017 distributions to classify BENIGN web traffic, SYN Floods, UDP Floods, and Slowloris exhaustion attacks.
                </p>
              </div>

              {/* Dedicated DoS Simulation Action Buttons */}
              <div className="flex flex-wrap gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => applyDosSimulation("normal")}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-emerald-950 border border-emerald-700/60 text-emerald-300 hover:bg-emerald-900 transition-colors font-medium"
                >
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Simulate Normal Traffic</span>
                </button>
                <button
                  type="button"
                  onClick={() => applyDosSimulation("syn_flood")}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-rose-950 border border-rose-700/60 text-rose-300 hover:bg-rose-900 transition-colors font-medium"
                >
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  <span>Simulate SYN Flood</span>
                </button>
                <button
                  type="button"
                  onClick={() => applyDosSimulation("slowloris")}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-amber-950 border border-amber-700/60 text-amber-300 hover:bg-amber-900 transition-colors font-medium"
                >
                  <Waves className="w-3.5 h-3.5 text-amber-400" />
                  <span>Simulate Slowloris</span>
                </button>
                <button
                  type="button"
                  onClick={() => applyDosSimulation("udp_flood")}
                  className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-purple-950 border border-purple-700/60 text-purple-300 hover:bg-purple-900 transition-colors font-medium"
                >
                  <AlertOctagon className="w-3.5 h-3.5 text-purple-400" />
                  <span>Simulate UDP Flood</span>
                </button>
              </div>
            </div>

            <form onSubmit={handleDosSubmit} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
                <div>
                  <label className="text-slate-400 block mb-1">Flow Duration (ms)</label>
                  <input
                    type="number"
                    step="any"
                    value={dosMetrics.flow_duration}
                    onChange={(e) => setDosMetrics({ ...dosMetrics, flow_duration: parseFloat(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Total Forward Packets</label>
                  <input
                    type="number"
                    step="any"
                    value={dosMetrics.tot_fwd_pkts}
                    onChange={(e) => setDosMetrics({ ...dosMetrics, tot_fwd_pkts: parseFloat(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Total Backward Packets</label>
                  <input
                    type="number"
                    step="any"
                    value={dosMetrics.tot_bwd_pkts}
                    onChange={(e) => setDosMetrics({ ...dosMetrics, tot_bwd_pkts: parseFloat(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Total Length Fwd Packets (bytes)</label>
                  <input
                    type="number"
                    step="any"
                    value={dosMetrics.tot_len_fwd_pkts}
                    onChange={(e) => setDosMetrics({ ...dosMetrics, tot_len_fwd_pkts: parseFloat(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Fwd Packet Length Mean (bytes)</label>
                  <input
                    type="number"
                    step="any"
                    value={dosMetrics.fwd_pkt_len_mean}
                    onChange={(e) => setDosMetrics({ ...dosMetrics, fwd_pkt_len_mean: parseFloat(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">SYN Flag Count</label>
                  <input
                    type="number"
                    value={dosMetrics.syn_flag_cnt}
                    onChange={(e) => setDosMetrics({ ...dosMetrics, syn_flag_cnt: parseInt(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">ACK Flag Count</label>
                  <input
                    type="number"
                    value={dosMetrics.ack_flag_cnt}
                    onChange={(e) => setDosMetrics({ ...dosMetrics, ack_flag_cnt: parseInt(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Flow Throughput (Bytes/s)</label>
                  <input
                    type="number"
                    step="any"
                    value={dosMetrics.flow_bytes_s}
                    onChange={(e) => setDosMetrics({ ...dosMetrics, flow_bytes_s: parseFloat(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Packet Rate (Pkts/s)</label>
                  <input
                    type="number"
                    step="any"
                    value={dosMetrics.flow_pkts_s}
                    onChange={(e) => setDosMetrics({ ...dosMetrics, flow_pkts_s: parseFloat(e.target.value) || 0 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="submit"
                  disabled={isAnalyzing}
                  className="flex items-center space-x-2 px-6 py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-slate-950 font-semibold text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-md shadow-rose-900/30"
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                      <span>Classifying Network Flow...</span>
                    </>
                  ) : (
                    <>
                      <Network className="w-4 h-4 text-slate-950" />
                      <span>Analyze NetFlow Record</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Error Notification */}
        {errorMessage && (
          <div className="bg-rose-950/50 border border-rose-800 rounded-lg p-4 flex items-start space-x-3 text-rose-300">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5 text-rose-400" />
            <div className="text-sm">
              <span className="font-semibold">Analysis Failed: </span>
              {errorMessage}
            </div>
          </div>
        )}

        {/* Detailed Threat Assessment Result Card */}
        {result && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl transition-all">
            {/* Card Header with Badges and Metrics */}
            <div className="border-b border-slate-800 bg-slate-950/60 p-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center space-x-4">
                  <div className={`p-3 rounded-xl border ${getRiskColor(result.risk_level)}`}>
                    {result.risk_level === "LOW" ? (
                      <ShieldCheck className="w-7 h-7" />
                    ) : result.risk_level === "MEDIUM" ? (
                      <AlertTriangle className="w-7 h-7" />
                    ) : (
                      <ShieldAlert className="w-7 h-7" />
                    )}
                  </div>

                  <div>
                    <div className="flex items-center space-x-3">
                      <span className="text-xs uppercase font-mono font-bold tracking-widest text-slate-400">
                        THREAT CLASSIFICATION
                      </span>
                      <span
                        className={`text-xs px-2.5 py-0.5 rounded-full font-mono font-bold border ${getRiskColor(
                          result.risk_level
                        )}`}
                      >
                        {result.risk_level} SEVERITY
                      </span>
                      <span className="text-xs px-2.5 py-0.5 rounded-full font-mono bg-slate-800 border border-slate-700 text-slate-300">
                        {result.threat_type} VECTOR
                      </span>
                    </div>
                    <h3 className="text-2xl font-bold font-mono text-slate-50 mt-1">
                      {result.category}
                    </h3>
                  </div>
                </div>

                <div className="flex items-center space-x-6 text-right font-mono">
                  <div>
                    <span className="text-xs text-slate-400 block">MODEL CONFIDENCE</span>
                    <span className="text-lg font-bold text-cyan-300">
                      {(result.confidence * 100).toFixed(1)}%
                    </span>
                  </div>

                  <div>
                    <span className="text-xs text-slate-400 block">LATENCY</span>
                    <span className="text-lg font-bold text-slate-300">
                      {result.latency_ms}ms
                    </span>
                  </div>
                </div>
              </div>

              {/* Colored Risk Index Score with Visual Progress Bar */}
              <div className="mt-6 pt-4 border-t border-slate-850">
                <div className="flex justify-between items-center text-xs font-mono mb-2">
                  <span className="text-slate-400 flex items-center space-x-1">
                    <span>RISK INDEX SCORE</span>
                    <span className="text-[10px] text-slate-500">(0.0 - 100.0)</span>
                  </span>
                  <span className="text-base font-bold text-slate-100">
                    {result.risk_score.toFixed(1)} / 100
                  </span>
                </div>
                <div className="w-full bg-slate-950 rounded-full h-3 overflow-hidden border border-slate-800">
                  <div
                    className={`h-full transition-all duration-700 ${getProgressBarColor(result.risk_score)}`}
                    style={{ width: `${Math.min(100, Math.max(2, result.risk_score))}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Assessment Breakdown: Indicators & Mitigation */}
            <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-800 p-6 gap-6">
              {/* Indicators Breakdown */}
              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <AlertOctagon className="w-4 h-4 text-amber-400" />
                  <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-200 font-mono">
                    Detected Indicators & Heuristics ({result.indicators.length})
                  </h4>
                </div>

                {result.indicators.length > 0 ? (
                  <ul className="space-y-2">
                    {result.indicators.map((ind, idx) => (
                      <li
                        key={idx}
                        className="text-xs text-slate-300 flex items-start space-x-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-850"
                      >
                        <span className="text-amber-400 font-mono font-bold mt-0.5">#{idx + 1}</span>
                        <span>{ind}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-slate-400 italic bg-slate-950/40 p-3 rounded-lg border border-slate-850">
                    No anomalous flags or malicious patterns detected. Behavioral attributes match baseline nominal thresholds.
                  </p>
                )}
              </div>

              {/* Actionable Incident Mitigation Playbook */}
              <div className="space-y-3 pt-6 md:pt-0">
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-200 font-mono">
                    Incident Mitigation Playbook ({result.mitigation.length})
                  </h4>
                </div>

                {result.mitigation.length > 0 ? (
                  <ul className="space-y-2">
                    {result.mitigation.map((step, idx) => (
                      <li
                        key={idx}
                        className="text-xs text-slate-300 flex items-start space-x-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-850"
                      >
                        <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-slate-400 italic bg-slate-950/40 p-3 rounded-lg border border-slate-850">
                    Standard continuous perimeter monitoring. No elevated incident response action required.
                  </p>
                )}
              </div>
            </div>

            {/* Collapsible Raw JSON Telemetry Panel */}
            <div className="border-t border-slate-800 bg-slate-950/80">
              <button
                onClick={() => setShowRawTelemetry(!showRawTelemetry)}
                className="w-full px-6 py-3 flex items-center justify-between text-xs text-slate-400 hover:text-slate-200 transition-colors font-mono"
              >
                <span className="flex items-center space-x-2">
                  <Terminal className="w-4 h-4 text-slate-500" />
                  <span>RAW INFERENCE TELEMETRY PAYLOAD</span>
                </span>
                {showRawTelemetry ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </button>

              {showRawTelemetry && (
                <div className="p-6 border-t border-slate-850 bg-slate-950">
                  <pre className="text-xs text-cyan-300 font-mono bg-slate-900/90 p-4 rounded-lg overflow-x-auto border border-slate-800 leading-relaxed">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-4 px-6 text-center text-xs text-slate-500 font-mono">
        CyberGuard Threat Intelligence Platform &bull; Security Operations Center &bull; High-Performance ML Inference
      </footer>
    </div>
  );
}
