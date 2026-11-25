import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ArrowLeft,
  ArrowRight,
  Cpu,
  TrendingUp,
  SearchCheck,
  RotateCcw,
} from "lucide-react";
import AgentGrid from "../AgentGrid";

const STEPS = [
  { id: 1, title: "Specialist Agents", subtitle: "Modality health & completeness", Icon: Cpu },
  { id: 2, title: "Key Risk Drivers", subtitle: "Top phishing vs. safe mathematical weights", Icon: TrendingUp },
  { id: 3, title: "Forensic Evidence", subtitle: "Exact anomalies, links & snippets extracted", Icon: SearchCheck },
];

function DriverBars({ contributors, color, emptyText }) {
  if (!contributors?.length) {
    return <p className="text-xs font-mono text-slate-500 py-2">{emptyText}</p>;
  }
  const maxScore = Math.max(...contributors.map((c) => Math.abs(c.contribution_score)), 0.001);

  return (
    <div className="space-y-3">
      {contributors.map((c, idx) => {
        const pct = (Math.abs(c.contribution_score) / maxScore) * 100;
        return (
          <div key={idx} className="space-y-1">
            <div className="flex items-center justify-between gap-2 text-xs font-mono">
              <div className="flex items-center gap-2 min-w-0">
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded uppercase shrink-0"
                  style={{ background: "rgba(255,255,255,0.06)", color: "#94a3b8" }}
                >
                  {c.modality}
                </span>
                <span className="text-slate-200 truncate">{c.feature_name}</span>
                <span className="text-slate-500 text-[10px] shrink-0">val={c.feature_value}</span>
              </div>
              <span className="shrink-0 font-semibold" style={{ color }}>
                {c.contribution_score > 0 ? `+${c.contribution_score.toFixed(3)}` : c.contribution_score.toFixed(3)}
              </span>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.06)" }}>
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: `${pct}%`, background: color }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

const SEV_STYLES = {
  critical: { bg: "rgba(239,68,68,0.14)", border: "rgba(239,68,68,0.4)", color: "#fca5a5" },
  high: { bg: "rgba(239,68,68,0.10)", border: "rgba(239,68,68,0.3)", color: "#f87171" },
  medium: { bg: "rgba(245,158,11,0.10)", border: "rgba(245,158,11,0.3)", color: "#fbbf24" },
  low: { bg: "rgba(16,185,129,0.08)", border: "rgba(16,185,129,0.25)", color: "#34d399" },
  info: { bg: "rgba(99,102,241,0.08)", border: "rgba(99,102,241,0.25)", color: "#a5b4fc" },
};

export default function ForensicStepper({
  report,
  onBackToVerdict,
  onScanAnother,
}) {
  const [step, setStep] = useState(1);

  const vr = report?.verdict_result || {};
  const agg = report?.aggregated_evidence || {};
  const evidenceItems = agg.unified_evidence || [];
  const overallCompPct =
    typeof agg.overall_completeness === "number" ? `${Math.round(agg.overall_completeness * 100)}%` : "—";

  return (
    <motion.div
      className="w-full max-w-4xl mx-auto space-y-6"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      {/* Top Bar */}
      <div className="flex items-center justify-between gap-4">
        <button
          onClick={onBackToVerdict}
          className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-white px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)" }}
        >
          <ArrowLeft size={14} />
          Back to Verdict
        </button>

        <button
          onClick={onScanAnother}
          className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-cyan-300 px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)" }}
        >
          <RotateCcw size={13} />
          Scan Another Email
        </button>
      </div>

      {/* Numbered Stepper Pills */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
        {STEPS.map((s) => {
          const active = step === s.id;
          const done = step > s.id;
          const { Icon } = s;
          return (
            <button
              key={s.id}
              onClick={() => setStep(s.id)}
              className="flex items-center gap-2.5 p-3 rounded-xl text-left transition-all cursor-pointer"
              style={{
                background: active
                  ? "rgba(6,182,212,0.14)"
                  : done
                  ? "rgba(16,185,129,0.08)"
                  : "rgba(255,255,255,0.03)",
                border: `1px solid ${
                  active
                    ? "rgba(6,182,212,0.45)"
                    : done
                    ? "rgba(16,185,129,0.28)"
                    : "rgba(255,255,255,0.08)"
                }`,
              }}
            >
              <span
                className="w-7 h-7 rounded-lg flex items-center justify-center text-xs font-mono font-bold shrink-0"
                style={{
                  background: active ? "#06b6d4" : done ? "#10b981" : "rgba(255,255,255,0.08)",
                  color: active || done ? "#050811" : "#94a3b8",
                }}
              >
                {s.id}
              </span>
              <div className="min-w-0">
                <p className={`text-xs font-semibold truncate ${active ? "text-cyan-300" : "text-slate-200"}`}>
                  {s.title}
                </p>
                <p className="text-[10px] text-slate-500 truncate flex items-center gap-1">
                  <Icon size={10} /> Step {s.id} of 3
                </p>
              </div>
            </button>
          );
        })}
      </div>

      {/* Step Content Card (One Step at a Time) */}
      <div className="glass-card p-6 sm:p-8 min-h-[360px] flex flex-col justify-between gap-6">
        <AnimatePresence mode="wait">
          <motion.div
            key={step}
            initial={{ opacity: 0, x: 12 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -12 }}
            transition={{ duration: 0.2 }}
            className="space-y-5"
          >
            {/* Step Header */}
            <div className="flex flex-wrap items-center justify-between gap-2 pb-4 border-b" style={{ borderColor: "rgba(255,255,255,0.08)" }}>
              <div>
                <p className="text-[11px] font-mono uppercase tracking-wider text-cyan-400">
                  Step {step} of 3
                </p>
                <h3 className="text-xl font-semibold text-white">{STEPS[step - 1].title}</h3>
                <p className="text-xs text-slate-400 mt-0.5">{STEPS[step - 1].subtitle}</p>
              </div>

              {step === 1 && (
                <span
                  className="text-xs font-mono px-3 py-1 rounded-full"
                  style={{ background: "rgba(6,182,212,0.1)", border: "1px solid rgba(6,182,212,0.28)", color: "#67e8f9" }}
                >
                  Overall Completeness: {overallCompPct}
                </span>
              )}
              {step === 3 && (
                <span
                  className="text-xs font-mono px-3 py-1 rounded-full"
                  style={{ background: "rgba(99,102,241,0.1)", border: "1px solid rgba(99,102,241,0.28)", color: "#a5b4fc" }}
                >
                  {evidenceItems.length} Findings Extracted
                </span>
              )}
            </div>

            {/* STEP 1: Specialist Agents */}
            {step === 1 && (
              <div className="space-y-4">
                <AgentGrid
                  modalityHealth={agg.modality_health || {}}
                  agentErrors={report?.agent_errors || {}}
                />
                {agg.warnings?.length > 0 && (
                  <div className="space-y-1.5 pt-2">
                    <p className="text-xs font-mono text-amber-400 uppercase">Aggregator Warnings</p>
                    {agg.warnings.map((w, i) => (
                      <p key={i} className="text-xs font-mono text-amber-300/90 bg-amber-500/10 px-3 py-2 rounded-lg">
                        {w}
                      </p>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* STEP 2: Key Risk Drivers */}
            {step === 2 && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-3 p-4 rounded-xl" style={{ background: "rgba(239,68,68,0.04)", border: "1px solid rgba(239,68,68,0.18)" }}>
                  <p className="text-xs font-mono text-red-400 tracking-wider uppercase">
                    Phishing Risk Drivers (+ log-odds)
                  </p>
                  <DriverBars
                    contributors={vr.top_phishing_contributors}
                    color="#ef4444"
                    emptyText="No positive phishing drivers contributed to this email."
                  />
                </div>

                <div className="space-y-3 p-4 rounded-xl" style={{ background: "rgba(16,185,129,0.04)", border: "1px solid rgba(16,185,129,0.18)" }}>
                  <p className="text-xs font-mono text-emerald-400 tracking-wider uppercase">
                    Legitimate / Safe Drivers (- log-odds)
                  </p>
                  <DriverBars
                    contributors={vr.top_legitimate_contributors}
                    color="#10b981"
                    emptyText="No negative (safe) drivers contributed to this email."
                  />
                </div>
              </div>
            )}

            {/* STEP 3: Forensic Evidence */}
            {step === 3 && (
              <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
                {evidenceItems.length === 0 ? (
                  <p className="text-sm font-mono text-slate-400 py-8 text-center">
                    No anomalous links, header mismatches, or suspicious snippets flagged by specialist agents.
                  </p>
                ) : (
                  evidenceItems.map((item, idx) => {
                    const sev = (item.severity || "info").toLowerCase();
                    const s = SEV_STYLES[sev] || SEV_STYLES.info;
                    return (
                      <div
                        key={item.finding_id || idx}
                        className="p-4 rounded-xl space-y-1.5"
                        style={{ background: s.bg, border: `1px solid ${s.border}` }}
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className="text-[10px] font-mono uppercase px-2 py-0.5 rounded font-semibold"
                            style={{ background: "rgba(0,0,0,0.3)", color: s.color }}
                          >
                            {sev}
                          </span>
                          <span className="text-[11px] font-mono uppercase text-slate-400">
                            [{item.source_modality}] {item.category}
                          </span>
                          <span className="text-[11px] font-mono text-slate-500 ml-auto">
                            {item.feature_name}
                          </span>
                        </div>
                        <p className="text-sm text-slate-100 font-medium">{item.description}</p>
                        {item.snippet_bounded && (
                          <p className="text-xs font-mono text-slate-300 bg-black/30 px-3 py-1.5 rounded-lg break-all">
                            {item.snippet_bounded}
                          </p>
                        )}
                      </div>
                    );
                  })
                )}

                {agg.omitted_evidence_count > 0 && (
                  <p className="text-xs font-mono text-slate-500 text-center pt-1">
                    + {agg.omitted_evidence_count} lower-priority evidence items omitted
                  </p>
                )}
              </div>
            )}

          </motion.div>
        </AnimatePresence>

        {/* Stepper Footer Navigation */}
        <div
          className="flex items-center justify-between pt-4 border-t"
          style={{ borderColor: "rgba(255,255,255,0.08)" }}
        >
          <button
            onClick={() => (step > 1 ? setStep((s) => s - 1) : onBackToVerdict())}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono text-slate-300 hover:text-white transition-colors cursor-pointer"
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)" }}
          >
            <ArrowLeft size={14} />
            {step > 1 ? "Back" : "Back to Verdict"}
          </button>

          {step < 3 ? (
            <button
              onClick={() => setStep((s) => s + 1)}
              className="inline-flex items-center gap-2 px-5 py-2 rounded-xl text-xs font-mono font-semibold text-white transition-all cursor-pointer hover:brightness-110"
              style={{ background: "linear-gradient(135deg, #06b6d4, #6366f1)" }}
            >
              Next: {STEPS[step].title}
              <ArrowRight size={14} />
            </button>
          ) : (
            <button
              onClick={onScanAnother}
              className="inline-flex items-center gap-2 px-5 py-2 rounded-xl text-xs font-mono font-semibold text-white transition-all cursor-pointer hover:brightness-110"
              style={{ background: "linear-gradient(135deg, #10b981, #06b6d4)" }}
            >
              <RotateCcw size={14} />
              Done · Scan Another
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
}
