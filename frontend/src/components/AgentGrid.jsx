import { MailCheck, Globe, FileText, Paperclip } from "lucide-react";

const AGENTS = [
  { key: "header", label: "Header Agent", desc: "SPF, DKIM, DMARC, hops & sender alignment", Icon: MailCheck },
  { key: "url", label: "URL Agent", desc: "Domain similarity, IP literals, shorteners & anchors", Icon: Globe },
  { key: "text", label: "Content Agent", desc: "Social engineering cues, urgency & HTML anomalies", Icon: FileText },
  { key: "attachment", label: "Attachment Agent", desc: "Executables, macros, double extensions & MIME types", Icon: Paperclip },
];

const STATUS_STYLES = {
  available: { color: "#10b981", bg: "rgba(16,185,129,0.10)", border: "rgba(16,185,129,0.28)", dot: "#10b981", label: "Active" },
  empty: { color: "#94a3b8", bg: "rgba(255,255,255,0.03)", border: "rgba(255,255,255,0.09)", dot: "#64748b", label: "No Artifacts" },
  degraded: { color: "#f59e0b", bg: "rgba(245,158,11,0.10)", border: "rgba(245,158,11,0.28)", dot: "#f59e0b", label: "Degraded" },
  failed: { color: "#ef4444", bg: "rgba(239,68,68,0.10)", border: "rgba(239,68,68,0.28)", dot: "#ef4444", label: "Failed" },
};

export default function AgentGrid({ modalityHealth = {}, agentErrors = {} }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      {AGENTS.map(({ key, label, desc, Icon }) => {
        const health = modalityHealth[key] || {};
        const statusKey = (health.status || "empty").toLowerCase();
        const s = STATUS_STYLES[statusKey] || STATUS_STYLES.empty;
        const completenessPct = typeof health.completeness === "number"
          ? Math.round(health.completeness * 100)
          : null;
        const activeCount = health.active_feature_count ?? "—";
        const missingCount = health.missing_feature_count ?? 0;
        const errMsg = agentErrors[key] || health.error_message;

        return (
          <div
            key={key}
            className="p-4 rounded-xl space-y-3"
            style={{ background: s.bg, border: `1px solid ${s.border}` }}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                  style={{ background: "rgba(255,255,255,0.05)" }}
                >
                  <Icon size={16} style={{ color: s.color }} />
                </div>
                <div>
                  <p className="text-sm font-semibold text-slate-200">{label}</p>
                  <p className="text-[11px] text-slate-500">{desc}</p>
                </div>
              </div>
              <span
                className="shrink-0 inline-flex items-center gap-1.5 text-[11px] font-mono px-2 py-0.5 rounded-full"
                style={{ background: "rgba(0,0,0,0.25)", color: s.color, border: `1px solid ${s.border}` }}
              >
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: s.dot }} />
                {s.label}
              </span>
            </div>

            {/* Completeness bar */}
            <div className="space-y-1">
              <div className="flex justify-between text-[11px] font-mono text-slate-400">
                <span>
                  {activeCount} active features{missingCount > 0 ? ` · ${missingCount} missing` : ""}
                </span>
                <span style={{ color: s.color }}>
                  {completenessPct !== null ? `${completenessPct}% complete` : "—"}
                </span>
              </div>
              {completenessPct !== null && (
                <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.07)" }}>
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${completenessPct}%`, background: s.color }}
                  />
                </div>
              )}
            </div>

            {errMsg && (
              <p className="text-[11px] font-mono text-red-400 bg-red-500/10 px-2.5 py-1.5 rounded-lg">
                {errMsg}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}
