import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  ArrowLeft,
  Play,
  Mail,
  Paperclip,
  RefreshCw,
  LogOut,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Inbox,
  AlertCircle,
} from "lucide-react";
import {
  listGmailMessages,
  previewGmailMessage,
  listSamples,
  previewSample,
  logoutGmail,
} from "../../api/client";

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

const DEMO_ICONS = {
  phishing: <ShieldAlert size={15} className="text-red-400 shrink-0" />,
  legitimate: <ShieldCheck size={15} className="text-emerald-400 shrink-0" />,
  synthetic: <Zap size={15} className="text-amber-400 shrink-0" />,
};

export default function PreviewScreen({
  mode, // "gmail" | "demo" | "file"
  initialPreview,
  initialSource,
  onStartScan,
  onBack,
  onGmailLoggedOut,
}) {
  const [items, setItems] = useState([]);
  const [loadingList, setLoadingList] = useState(mode === "gmail" || mode === "demo");
  const [selectedId, setSelectedId] = useState(initialPreview?.id || null);

  const [preview, setPreview] = useState(initialPreview || null);
  const [source, setSource] = useState(initialSource || null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [error, setError] = useState("");

  const fetchList = async () => {
    setError("");
    setLoadingList(true);
    try {
      if (mode === "gmail") {
        const msgs = await listGmailMessages(20);
        setItems(msgs);
      } else if (mode === "demo") {
        const samples = await listSamples();
        setItems(samples.filter((s) => s.exists));
      }
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Failed to load email list.");
    } finally {
      setLoadingList(false);
    }
  };

  useEffect(() => {
    if (mode === "gmail" || mode === "demo") {
      fetchList();
    } else {
      setPreview(initialPreview);
      setSource(initialSource);
    }
  }, [mode]);

  const handleSelectItem = async (item) => {
    setSelectedId(item.id);
    setError("");
    setLoadingPreview(true);
    try {
      if (mode === "gmail") {
        const full = await previewGmailMessage(item.id);
        setPreview(full);
        setSource({ type: "gmail", id: item.id });
      } else if (mode === "demo") {
        const full = await previewSample(item.id);
        setPreview(full);
        setSource({ type: "sample", id: item.id });
      }
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not load full email preview.");
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleLogout = async () => {
    await logoutGmail().catch(() => {});
    onGmailLoggedOut?.();
    onBack();
  };

  const hasSidebar = mode === "gmail" || mode === "demo";

  return (
    <motion.div
      className={`w-full ${hasSidebar ? "max-w-6xl" : "max-w-3xl"} mx-auto space-y-5`}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      {/* Top Bar */}
      <div className="flex items-center justify-between gap-4">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-white px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)" }}
        >
          <ArrowLeft size={14} />
          Back to Sources
        </button>

        <div className="flex items-center gap-2.5">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
            Stage 2 · Review Email Before Scanning
          </span>
          {mode === "gmail" && (
            <button
              onClick={handleLogout}
              className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-red-400 px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)" }}
            >
              <LogOut size={12} />
              Sign out
            </button>
          )}
        </div>
      </div>

      {error && (
        <div
          className="flex items-center gap-2 text-xs font-mono text-red-300 px-4 py-3 rounded-xl"
          style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)" }}
        >
          <AlertCircle size={15} className="shrink-0" />
          {error}
        </div>
      )}

      {/* Main Split or Single Preview Layout */}
      <div className={`grid gap-5 ${hasSidebar ? "grid-cols-1 lg:grid-cols-12" : "grid-cols-1"}`}>
        {/* Left Inbox / Sample List */}
        {hasSidebar && (
          <div className="lg:col-span-5 glass-card p-4 flex flex-col h-[560px]">
            <div className="flex items-center justify-between pb-3 mb-3 border-b" style={{ borderColor: "rgba(255,255,255,0.07)" }}>
              <div className="flex items-center gap-2">
                <Inbox size={15} className="text-cyan-400" />
                <span className="text-xs font-mono uppercase tracking-wider text-slate-300">
                  {mode === "gmail" ? "Gmail Inbox" : "Built-in Demo Corpus"}
                </span>
              </div>
              <button
                onClick={fetchList}
                disabled={loadingList}
                className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                title="Refresh list"
              >
                <RefreshCw size={13} className={loadingList ? "animate-spin" : ""} />
              </button>
            </div>

            {loadingList ? (
              <div className="flex-1 flex items-center justify-center gap-2 text-xs font-mono text-slate-400">
                <Loader2 size={16} className="animate-spin text-cyan-400" />
                Loading messages…
              </div>
            ) : items.length === 0 ? (
              <div className="flex-1 flex items-center justify-center text-xs font-mono text-slate-500">
                No messages found.
              </div>
            ) : (
              <div className="flex-1 overflow-y-auto space-y-2 pr-1">
                {items.map((item) => {
                  const isActive = selectedId === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => handleSelectItem(item)}
                      className="w-full text-left p-3.5 rounded-xl transition-all cursor-pointer"
                      style={{
                        background: isActive ? "rgba(6,182,212,0.12)" : "rgba(255,255,255,0.025)",
                        border: `1px solid ${isActive ? "rgba(6,182,212,0.45)" : "rgba(255,255,255,0.06)"}`,
                      }}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-sm font-medium text-slate-100 truncate">
                          {item.subject || item.filename || "(no subject)"}
                        </p>
                        {mode === "demo" && DEMO_ICONS[item.label]}
                      </div>
                      <p className="text-xs text-slate-400 truncate mt-0.5">
                        {item.from || (mode === "demo" ? item.filename : "Unknown sender")}
                      </p>
                      {(item.snippet || item.label) && (
                        <p className="text-[11px] text-slate-500 truncate mt-1">
                          {item.snippet || `Corpus label: ${item.label}`}
                        </p>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* Right Complete Email Preview Pane */}
        <div className={`${hasSidebar ? "lg:col-span-7 h-[560px]" : ""} glass-card p-6 flex flex-col justify-between gap-4`}>
          {loadingPreview ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 py-16 text-xs font-mono text-slate-400">
              <Loader2 size={24} className="animate-spin text-cyan-400" />
              Fetching full email headers, body & attachments…
            </div>
          ) : !preview ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-3 py-16 text-center">
              <div
                className="w-14 h-14 rounded-full flex items-center justify-center"
                style={{ background: "rgba(6,182,212,0.08)", border: "1px solid rgba(6,182,212,0.22)" }}
              >
                <Mail size={24} className="text-cyan-400" />
              </div>
              <p className="text-sm font-medium text-slate-200">Select an email to preview</p>
              <p className="text-xs text-slate-500 max-w-xs">
                Click any message on the left to inspect its sender, headers, body, and attachments before scanning.
              </p>
            </div>
          ) : (
            <>
              {/* Email Header Metadata + Prominent Start Scanning Button */}
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-4 border-b" style={{ borderColor: "rgba(255,255,255,0.08)" }}>
                  <div className="space-y-1 min-w-0">
                    <p className="text-[11px] font-mono uppercase tracking-wider text-cyan-400">
                      Complete Email Preview
                    </p>
                    <h2 className="text-lg font-semibold text-white break-words">
                      {preview.subject || "(no subject)"}
                    </h2>
                  </div>

                  <button
                    onClick={() => onStartScan(source, preview)}
                    className="shrink-0 inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-sm text-white transition-all cursor-pointer hover:brightness-110 shadow-lg"
                    style={{
                      background: "linear-gradient(135deg, #06b6d4, #6366f1)",
                      boxShadow: "0 0 20px rgba(6,182,212,0.25)",
                    }}
                  >
                    <Play size={15} fill="currentColor" />
                    Start Scanning
                  </button>
                </div>

                {/* Envelope fields */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                  <div className="px-3 py-2 rounded-lg" style={{ background: "rgba(255,255,255,0.03)" }}>
                    <span className="font-mono text-slate-500 block text-[10px] uppercase">From</span>
                    <span className="text-slate-200 break-all">{preview.from || "—"}</span>
                  </div>
                  <div className="px-3 py-2 rounded-lg" style={{ background: "rgba(255,255,255,0.03)" }}>
                    <span className="font-mono text-slate-500 block text-[10px] uppercase">To</span>
                    <span className="text-slate-200 break-all">{preview.to || "—"}</span>
                  </div>
                  <div className="px-3 py-2 rounded-lg" style={{ background: "rgba(255,255,255,0.03)" }}>
                    <span className="font-mono text-slate-500 block text-[10px] uppercase">Date</span>
                    <span className="text-slate-300 font-mono">{preview.date || "—"}</span>
                  </div>
                  <div className="px-3 py-2 rounded-lg" style={{ background: "rgba(255,255,255,0.03)" }}>
                    <span className="font-mono text-slate-500 block text-[10px] uppercase">Attachments</span>
                    {preview.attachments?.length ? (
                      <div className="flex flex-wrap gap-1.5 mt-0.5">
                        {preview.attachments.map((att, idx) => (
                          <span
                            key={idx}
                            className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/25"
                          >
                            <Paperclip size={10} />
                            {att.filename} ({formatBytes(att.size_bytes)})
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-slate-500 font-mono">None</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Scrollable Readable Body */}
              <div className="flex-1 min-h-[200px] max-h-[300px] overflow-y-auto rounded-xl p-4" style={{ background: "rgba(0,0,0,0.32)", border: "1px solid rgba(255,255,255,0.06)" }}>
                <pre className="whitespace-pre-wrap break-words font-sans text-xs sm:text-sm text-slate-300 leading-relaxed m-0">
                  {preview.body_text || preview.snippet || "(Empty body)"}
                </pre>
              </div>
            </>
          )}
        </div>
      </div>
    </motion.div>
  );
}
