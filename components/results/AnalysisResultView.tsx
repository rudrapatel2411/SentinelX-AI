"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import {
  CommonAnalysisResult,
  SecurityIndicator,
  FileMetadata,
} from "@/lib/types/security";
import { RiskScoreGauge } from "@/components/ui/RiskScoreGauge";
import { RiskBadge } from "@/components/ui/RiskBadge";
import { SourceBadge, SeverityPill } from "@/components/ui/SourceBadge";
import {
  Shield,
  AlertTriangle,
  FileText,
  Link as LinkIcon,
  MessageSquare,
  Copy,
  Check,
  Download,
  RotateCcw,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Cpu,
  Database,
  Lock,
  Sparkles,
  Info,
} from "lucide-react";
import confetti from "canvas-confetti";

interface AnalysisResultViewProps {
  analysis: CommonAnalysisResult;
  onReset: () => void;
  onNavigateToLinkScan?: (url: string) => void;
}

export const AnalysisResultView: React.FC<AnalysisResultViewProps> = ({
  analysis,
  onReset,
  onNavigateToLinkScan,
}) => {
  const [copiedId, setCopiedId] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);
  const [expandedIndicators, setExpandedIndicators] = useState<Record<string, boolean>>({});
  const [showMetadataModal, setShowMetadataModal] = useState(false);

  // Trigger celebration confetti if classified SAFE
  React.useEffect(() => {
    if (analysis.classification === "SAFE" && analysis.riskScore === 0) {
      try {
        confetti({
          particleCount: 30,
          spread: 60,
          origin: { y: 0.85 },
          colors: ["#10b981", "#00e5ff", "#6366f1"],
        });
      } catch {
        // ignore
      }
    }
  }, [analysis]);

  const handleCopyId = () => {
    navigator.clipboard.writeText(analysis.id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const handleCopySha256 = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(analysis, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `${analysis.id}_report.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const toggleIndicator = (id: string) => {
    setExpandedIndicators((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const fileMeta = analysis.type === "file" ? (analysis.metadata as unknown as FileMetadata) : null;
  const extractedUrls = (analysis.metadata?.extractedUrls as string[]) || [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="space-y-6"
    >
      {/* 1. Header Banner & Risk Overview */}
      <div className="cyber-panel rounded-2xl p-6 relative overflow-hidden border-slate-800">
        {/* Glow accent */}
        <div
          className={`absolute top-0 left-0 right-0 h-1 ${
            analysis.classification === "DANGEROUS"
              ? "bg-rose-500 shadow-[0_0_15px_#f43f5e]"
              : analysis.classification === "SUSPICIOUS"
              ? "bg-amber-500 shadow-[0_0_15px_#f59e0b]"
              : "bg-emerald-500 shadow-[0_0_15px_#10b981]"
          }`}
        />

        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 pb-6 border-b border-slate-800/80">
          <div className="space-y-2 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 font-mono text-xs">
                {analysis.type === "file" && <FileText className="w-3.5 h-3.5 text-cyan-400" />}
                {analysis.type === "url" && <LinkIcon className="w-3.5 h-3.5 text-cyan-400" />}
                {analysis.type === "message" && <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />}
                <span className="uppercase">{analysis.type} Analysis</span>
              </span>

              <button
                onClick={handleCopyId}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-300 font-mono text-xs transition-colors"
                title="Click to copy Analysis ID"
              >
                <span>{analysis.id}</span>
                {copiedId ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-slate-500" />}
              </button>

              <span className="text-xs text-slate-500">
                {new Date(analysis.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </span>

              {analysis.persistenceStatus === "DATABASE_OFFLINE" && (
                <span className="px-2 py-0.5 rounded bg-amber-950/40 border border-amber-800/60 text-amber-300 text-[10px] font-mono">
                  Session Only (DB Offline)
                </span>
              )}
            </div>

            <h2 className="text-xl md:text-2xl font-black text-slate-100 break-all flex items-center gap-3">
              <span>{analysis.target}</span>
            </h2>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <RiskBadge classification={analysis.classification} size="md" />
              <span className="text-xs text-slate-400 flex items-center gap-1">
                <span>Confidence:</span>
                <strong className="text-slate-200">{analysis.confidenceLabel} ({(analysis.confidence * 100).toFixed(0)}%)</strong>
              </span>
            </div>
          </div>

          <div className="flex items-center justify-center self-center md:self-auto bg-slate-950/50 p-4 rounded-2xl border border-slate-800/80">
            <RiskScoreGauge score={analysis.riskScore} size={120} />
          </div>
        </div>

        {/* Action button row */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-4 text-xs">
          <div className="flex items-center gap-2">
            <button
              onClick={onReset}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-semibold transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Scan Another Item
            </button>

            {analysis.type === "file" && fileMeta && (
              <button
                onClick={() => setShowMetadataModal(!showMetadataModal)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-medium transition-colors"
              >
                <Info className="w-3.5 h-3.5 text-slate-400" />
                File Metadata & Hashes
              </button>
            )}
          </div>

          <button
            onClick={handleExportJson}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON Report
          </button>
        </div>
      </div>

      {/* File Technical Metadata Drawer / Modal */}
      {showMetadataModal && fileMeta && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          exit={{ opacity: 0, height: 0 }}
          className="cyber-panel rounded-xl p-5 border-cyan-900/40 bg-slate-950/90 space-y-4"
        >
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <h4 className="text-sm font-bold text-cyan-300 flex items-center gap-2">
              <Lock className="w-4 h-4" />
              Cryptographic Signatures & File Architecture
            </h4>
            <button
              onClick={() => setShowMetadataModal(false)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Close ✕
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-1">
              <span className="text-slate-500 text-[10px] uppercase tracking-wider">SHA-256 Hash</span>
              <div className="flex items-center justify-between bg-slate-900 p-2 rounded border border-slate-800">
                <span className="text-slate-300 truncate mr-2">{fileMeta.sha256}</span>
                <button
                  onClick={() => handleCopySha256(fileMeta.sha256)}
                  className="text-slate-400 hover:text-cyan-300 p-1"
                  title="Copy SHA-256"
                >
                  {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-slate-500 text-[10px] uppercase tracking-wider">MD5 Hash</span>
              <div className="bg-slate-900 p-2 rounded border border-slate-800 text-slate-300">
                {fileMeta.md5}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-slate-500 text-[10px] uppercase tracking-wider">MIME Type Detected</span>
              <div className="bg-slate-900 p-2 rounded border border-slate-800 text-slate-300">
                {fileMeta.detectedMimeType}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-slate-500 text-[10px] uppercase tracking-wider">Magic Bytes Header (Hex)</span>
              <div className="bg-slate-900 p-2 rounded border border-slate-800 text-slate-300">
                0x{fileMeta.magicBytesHex}
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Extracted URLs in Message with 1-Click Link Analyzer Handoff */}
      {extractedUrls.length > 0 && (
        <div className="cyber-panel rounded-xl p-4 border-cyan-500/30 bg-cyan-950/10 space-y-3">
          <div className="flex items-center gap-2 text-cyan-300 text-sm font-bold">
            <LinkIcon className="w-4 h-4" />
            <span>Detected External Links in Message ({extractedUrls.length})</span>
          </div>
          <div className="space-y-2">
            {extractedUrls.map((url, idx) => (
              <div
                key={idx}
                className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 p-2.5 rounded-lg bg-slate-900/90 border border-slate-800"
              >
                <span className="font-mono text-xs text-slate-200 truncate max-w-lg">{url}</span>
                {onNavigateToLinkScan && (
                  <button
                    onClick={() => onNavigateToLinkScan(url)}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-colors shrink-0 shadow-cyan-glow"
                  >
                    <span>Analyze in Link Analyzer</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 2. "Why this score?" Risk Factor Breakdown */}
      {analysis.riskFactors && analysis.riskFactors.length > 0 && (
        <div className="cyber-panel rounded-xl p-5 border-slate-800 space-y-3">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            Risk Factor Contribution ("Why this score?")
          </h3>
          <div className="space-y-2.5">
            {analysis.riskFactors.map((factor, idx) => {
              const pct = Math.min(100, Math.round((factor.scoreContribution / 100) * 100));
              return (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium">
                      {factor.categoryName} ({factor.indicatorCount} indicator{factor.indicatorCount > 1 ? "s" : ""})
                    </span>
                    <span className="font-mono font-bold text-cyan-400">+{factor.scoreContribution} pts</span>
                  </div>
                  <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden border border-slate-800">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 0.8, delay: idx * 0.1 }}
                      className={`h-full rounded-full ${
                        factor.scoreContribution >= 30
                          ? "bg-rose-500"
                          : factor.scoreContribution >= 15
                          ? "bg-amber-500"
                          : "bg-cyan-500"
                      }`}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. 4-Quadrant Findings Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Quadrant 1: Technical Findings (Static analysis + heuristic indicators with Source badges) */}
        <div className="cyber-panel rounded-xl p-5 border-slate-800 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                Technical Findings ({analysis.indicators.length})
              </h3>
              <span className="text-[11px] text-slate-500 font-mono">Deterministic Rules</span>
            </div>

            {analysis.indicators.length === 0 ? (
              <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-800 text-center text-xs text-slate-400">
                No technical anomalies detected in performed checks.
              </div>
            ) : (
              <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
                {analysis.indicators.map((ind) => {
                  const isExpanded = expandedIndicators[ind.id];
                  return (
                    <div
                      key={ind.id}
                      className={`p-3 rounded-lg border transition-all ${
                        ind.mitigating
                          ? "bg-emerald-950/20 border-emerald-800/40"
                          : ind.severity === "CRITICAL"
                          ? "bg-rose-950/20 border-rose-800/50"
                          : ind.severity === "HIGH"
                          ? "bg-red-950/15 border-red-800/40"
                          : ind.severity === "MEDIUM"
                          ? "bg-amber-950/15 border-amber-800/40"
                          : "bg-slate-900/60 border-slate-800"
                      }`}
                    >
                      <div
                        onClick={() => toggleIndicator(ind.id)}
                        className="flex items-start justify-between gap-2 cursor-pointer select-none"
                      >
                        <div className="space-y-1 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <SeverityPill severity={ind.severity} mitigating={ind.mitigating} />
                            <SourceBadge source={ind.source} />
                          </div>
                          <h4 className="text-xs font-bold text-slate-200">{ind.title}</h4>
                        </div>
                        <button className="text-slate-400 hover:text-slate-200 mt-1">
                          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </button>
                      </div>

                      {isExpanded && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          className="mt-2 pt-2 border-t border-slate-800/60 text-xs text-slate-300 leading-relaxed font-sans"
                        >
                          <p>{ind.description}</p>
                          <div className="mt-1.5 flex items-center gap-3 text-[10px] text-slate-500 font-mono">
                            <span>ID: {ind.id}</span>
                            <span>Weight: {ind.mitigating ? `-${ind.weight}` : `+${ind.weight}`}</span>
                            <span>Confidence: {(ind.confidence * 100).toFixed(0)}%</span>
                          </div>
                        </motion.div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <p className="text-[11px] text-slate-500 italic pt-2 border-t border-slate-800/50">
            Bounded static analysis identifies technical indicators; it is not a guarantee of safety or maliciousness on its own.
          </p>
        </div>

        {/* Quadrant 2: Threat Intelligence Feeds */}
        <div className="cyber-panel rounded-xl p-5 border-slate-800 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                Threat Intelligence Telemetry
              </h3>
              <span className="text-[11px] text-slate-500 font-mono">Live Vendor Lookup</span>
            </div>

            <div className="space-y-3">
              {analysis.threatIntel && analysis.threatIntel.length > 0 ? (
                analysis.threatIntel.map((intel, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-200">{intel.name}</span>
                      {intel.status === "THREAT_DETECTED" ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-extrabold uppercase bg-rose-950 text-rose-300 border border-rose-700">
                          Threat Detected ({intel.positives}/{intel.total || "?"})
                        </span>
                      ) : intel.status === "CHECKED_CLEAN" ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-950 text-emerald-300 border border-emerald-800">
                          Checked Clean
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-medium uppercase bg-slate-800 text-slate-400 border border-slate-700">
                          Unavailable
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400">{intel.details}</p>

                    {intel.detectedThreats && intel.detectedThreats.length > 0 && (
                      <div className="pt-1 flex flex-wrap gap-1">
                        {intel.detectedThreats.map((threat, tIdx) => (
                          <span
                            key={tIdx}
                            className="px-1.5 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-[10px] font-mono"
                          >
                            {threat}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-400">
                  No external threat intelligence lookup was required for this input format.
                </div>
              )}
            </div>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-[11px] text-slate-400 flex items-start gap-2">
            <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
            <span>
              SentinelX reports actual threat intelligence responses. Unconfigured or unreachable APIs are explicitly marked as unavailable with zero fabricated data.
            </span>
          </div>
        </div>

        {/* Quadrant 3: AI Explanation & Context */}
        <div className="cyber-panel rounded-xl p-5 border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-indigo-400" />
              AI Contextualization & Explanation
            </h3>
            {analysis.aiExplanation.available ? (
              <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px] font-mono">
                AI Explanation Active
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px] font-mono">
                Technical Fallback
              </span>
            )}
          </div>

          <div className="space-y-3 text-xs leading-relaxed">
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-200">
              <p className="font-semibold text-slate-100 mb-1">
                Category: <span className="text-cyan-300">{analysis.aiExplanation.threatCategory}</span>
              </p>
              <p className="text-slate-300">{analysis.aiExplanation.summary}</p>
            </div>

            {analysis.aiExplanation.reasons && analysis.aiExplanation.reasons.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                  Key Contextual Drivers:
                </span>
                <ul className="space-y-1">
                  {analysis.aiExplanation.reasons.map((reason, rIdx) => (
                    <li key={rIdx} className="flex items-start gap-2 text-slate-300">
                      <span className="text-cyan-400 font-bold">•</span>
                      <span>{reason}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* AI-Written Linguistic Likelihood (Secondary Feature with Mandatory Disclaimer) */}
            {analysis.aiExplanation.aiWritingLikelihood !== null && analysis.aiExplanation.aiWritingLikelihood !== undefined && (
              <div className="mt-3 p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 font-medium">Linguistic AI-Writing Patterns:</span>
                  <span className="font-mono font-bold text-indigo-400">
                    {(analysis.aiExplanation.aiWritingLikelihood * 100).toFixed(0)}% Likelihood
                  </span>
                </div>
                {analysis.aiExplanation.aiWritingReasoning && (
                  <p className="text-slate-400 text-[11px]">{analysis.aiExplanation.aiWritingReasoning}</p>
                )}
                <p className="text-[10px] text-amber-400/90 italic pt-1 border-t border-slate-900">
                  ⚠️ Disclaimer: Linguistic pattern analysis is probabilistic and does not prove AI authorship.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Quadrant 4: Actionable Recommendations */}
        <div className="cyber-panel rounded-xl p-5 border-slate-800 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Actionable Recommendations
              </h3>
              <span className="text-[11px] text-slate-500 font-mono">Protective Protocol</span>
            </div>

            <div className="space-y-2.5 text-xs">
              {analysis.recommendations && analysis.recommendations.length > 0 ? (
                analysis.recommendations.map((rec, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 text-slate-200 flex items-start gap-2.5"
                  >
                    <span className="font-bold text-cyan-400 font-mono text-sm">{idx + 1}.</span>
                    <span className="leading-relaxed">{rec}</span>
                  </div>
                ))
              ) : (
                <div className="p-3 rounded-lg bg-slate-900 text-slate-400">
                  Follow general cybersecurity best practices.
                </div>
              )}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 text-[11px] text-slate-400">
            <strong>Security Notice:</strong> SentinelX provides automated threat analysis and cannot guarantee that an item is completely safe. Always verify senders and URLs independently.
          </div>
        </div>
      </div>
    </motion.div>
  );
};
