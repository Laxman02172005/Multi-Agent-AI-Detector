import { motion } from "framer-motion";
import { ShieldAlert, ShieldCheck, AlertTriangle, ArrowRight, RotateCcw, Clock, Activity } from "lucide-react";
import ThreatGauge from "../ThreatGauge";

const VERDICT_CONFIG = {
  phishing: {
    label: "PHISHING DETECTED",
    color: "#ef4444",
    glow: "glow-phish",
    bg: "rgba(239,68,68,0.08)",
    border: "rgba(239,68,68,0.35)",
    Icon: ShieldAlert,
  },
  legitimate: {
    label: "LEGITIMATE EMAIL",
    color: "#10b981",
    glow: "glow-safe",
    bg: "rgba(16,185,129,0.08)",
    border: "rgba(16,185,129,0.35)",
    Icon: ShieldCheck,
  },
  abstain: {
    label: "INCONCLUSIVE (ABSTAINED)",
    color: "#f59e0b",
    glow: "glow-warn",
    bg: "rgba(245,158,11,0.08)",
    border: "rgba(245,158,11,0.35)",
    Icon: AlertTriangle,
  },
};

function buildSummary(verdict, vr) {
  const probPct =
    typeof vr?.calibrated_probability === "number"
      ? `${(vr.calibrated_probability * 100).toFixed(1)}%`
      : null;

  if (verdict === "phishing") {
    const topMod = vr?.top_phishing_contributors?.[0]?.modality;
    return `High-confidence phishing indicators detected (${probPct} threat risk)${
      topMod ? `, led primarily by suspicious ${topMod} signals.` : "."
    } Do not click links or enter credentials.`;
  }
  if (verdict === "legitimate") {
    return `Email matches safe structural patterns (${probPct} phishing probability) with no high-risk phishing indicators outweighing legitimate signals.`;
  }
  if (vr?.abstention_reason === "insufficient_modality_health") {
    return "Analysis abstained safely because critical email modalities were missing or failed health checks. Inspect forensics for details.";
  }
  return `Threat probability (${probPct ?? "N/A"}) fell inside the uncertainty band. Human review is recommended before trusting this message.`;
}

export default function VerdictScreen({
  report,
  preview,
  onInspectForensics,
  onBackToPreview,
  onScanAnother,
}) {
  if (report?._error) {
    return (
      <div className="w-full max-w-xl mx-auto glass-card p-8 text-center space-y-5 my-8">
        <AlertTriangle size={36} className="text-red-400 mx-auto" />
        <div className="space-y-2">
          <h2 className="text-xl font-bold text-white">Scan Failed</h2>
          <p className="text-sm font-mono text-red-300">{report._error}</p>
        </div>
        <div className="flex justify-center gap-3">
          {onBackToPreview && (
            <button
              onClick={onBackToPreview}
              className="px-5 py-2.5 rounded-xl text-sm text-slate-300 hover:text-white cursor-pointer"
              style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.12)" }}
            >
              Back to Email
            </button>
          )}
          <button
            onClick={onScanAnother}
            className="px-5 py-2.5 rounded-xl text-sm font-semibold text-white cursor-pointer"
            style={{ background: "linear-gradient(135deg, #06b6d4, #6366f1)" }}
          >
            Scan Another Email
          </button>
        </div>
      </div>
    );
  }

  const vr = report?.verdict_result || {};
  const verdictKey = (vr.verdict || "abstain").toLowerCase();
  const cfg = VERDICT_CONFIG[verdictKey] || VERDICT_CONFIG.abstain;
  const { Icon } = cfg;

  const prob = vr.calibrated_probability;
  const confPct = typeof vr.confidence === "number" ? `${(vr.confidence * 100).toFixed(1)}%` : "—";
  const latencyMs =
    typeof report?.total_processing_time_ms === "number"
      ? `${report.total_processing_time_ms.toFixed(1)} ms`
      : "—";

  return (
    <motion.div
      className="w-full max-w-2xl mx-auto space-y-6 py-4"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
    >
      {/* Subject Context Pill */}
      {preview?.subject && (
        <div className="text-center">
          <span
            className="inline-block max-w-full truncate text-xs font-mono text-slate-400 px-3.5 py-1 rounded-full"
            style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)" }}
          >
            Scanned: {preview.subject}
          </span>
        </div>
      )}

      {/* Clean Prediction Score & Verdict Card */}
      <div
        className={`glass-card p-8 space-y-6 ${cfg.glow}`}
        style={{ background: cfg.bg, borderColor: cfg.border }}
      >
        <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
          {/* Left: Badge & Plain-English Summary */}
          <div className="space-y-3 text-center sm:text-left flex-1">
            <div className="inline-flex items-center gap-2.5">
              <div
                className="w-11 h-11 rounded-full flex items-center justify-center shrink-0"
                style={{ background: `${cfg.color}20`, border: `1.5px solid ${cfg.color}55` }}
              >
                <Icon size={22} style={{ color: cfg.color }} />
              </div>
              <div>
                <p className="font-mono text-[10px] tracking-widest text-slate-400 uppercase">
                  Final Classification Verdict
                </p>
                <h2 className="text-2xl font-bold tracking-tight" style={{ color: cfg.color }}>
                  {cfg.label}
                </h2>
              </div>
            </div>

            <p className="text-sm text-slate-300 leading-relaxed">
              {buildSummary(verdictKey, vr)}
            </p>
          </div>

          {/* Right: Threat Risk Gauge */}
          <div className="shrink-0 flex flex-col items-center">
            <ThreatGauge probability={prob} verdict={verdictKey} />
          </div>
        </div>

        {/* Clean 2-Metric Footer Strip */}
        <div
          className="grid grid-cols-2 gap-4 pt-4 border-t"
          style={{ borderColor: "rgba(255,255,255,0.09)" }}
        >
          <div className="flex items-center gap-2.5">
            <Activity size={16} className="text-cyan-400 shrink-0" />
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Confidence</p>
              <p className="text-base font-mono font-semibold text-white">{confPct}</p>
            </div>
          </div>
          <div className="flex items-center gap-2.5">
            <Clock size={16} className="text-indigo-400 shrink-0" />
            <div>
              <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Analysis Latency</p>
              <p className="text-base font-mono font-semibold text-white">{latencyMs}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Primary Action Buttons */}
      <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-1">
        <button
          onClick={onInspectForensics}
          className="w-full sm:w-auto flex items-center justify-center gap-2.5 px-7 py-3.5 rounded-xl font-semibold text-sm text-white transition-all cursor-pointer hover:brightness-110 shadow-lg"
          style={{
            background: "linear-gradient(135deg, #06b6d4, #6366f1)",
            boxShadow: "0 0 22px rgba(6,182,212,0.25)",
          }}
        >
          Inspect Forensics
          <ArrowRight size={16} />
        </button>

        <button
          onClick={onScanAnother}
          className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl text-sm font-medium text-slate-300 hover:text-white transition-all cursor-pointer"
          style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)" }}
        >
          <RotateCcw size={15} />
          Scan Another Email
        </button>
      </div>
    </motion.div>
  );
}
