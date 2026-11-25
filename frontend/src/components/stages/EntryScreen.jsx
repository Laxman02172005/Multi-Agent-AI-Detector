import { motion } from "framer-motion";
import { Mail, Upload, ArrowRight, Sparkles, CheckCircle2, FileText } from "lucide-react";
import { useState, useRef } from "react";
import { startGmailAuth, previewFile, previewRaw } from "../../api/client";

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  );
}

export default function EntryScreen({
  health,
  gmailConnected,
  oauthError,
  onOpenGmailInbox,
  onOpenDemoCorpus,
  onPreviewReady,
}) {
  const [dragging, setDragging] = useState(false);
  const [showPaste, setShowPaste] = useState(false);
  const [rawText, setRawText] = useState("");
  const [loadingFile, setLoadingFile] = useState(false);
  const [error, setError] = useState(oauthError || "");
  const fileInputRef = useRef(null);

  const handleFile = async (file) => {
    if (!file) return;
    setError("");
    setLoadingFile(true);
    try {
      const preview = await previewFile(file);
      onPreviewReady(preview, { type: "file", file });
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not read email file.");
    } finally {
      setLoadingFile(false);
    }
  };

  const handlePastePreview = async () => {
    const trimmed = rawText.trim();
    if (!trimmed) return;
    setError("");
    setLoadingFile(true);
    try {
      const preview = await previewRaw(trimmed);
      onPreviewReady(preview, { type: "raw", text: trimmed });
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || "Could not parse email text.");
    } finally {
      setLoadingFile(false);
    }
  };

  return (
    <motion.div
      className="w-full max-w-4xl mx-auto flex flex-col items-center justify-center py-6 space-y-10"
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
    >
      {/* Hero Header */}
      <div className="text-center space-y-3 max-w-2xl">
        <span
          className="inline-flex items-center gap-1.5 text-[11px] font-mono tracking-widest uppercase px-3 py-1 rounded-full"
          style={{
            background: "rgba(6,182,212,0.1)",
            border: "1px solid rgba(6,182,212,0.25)",
            color: "#67e8f9",
          }}
        >
          Passive Multi-Agent Engine · Zero External Lookups
        </span>
        <h1 className="text-3xl sm:text-4xl font-bold text-white tracking-tight">
          Inspect an Email Before <span className="text-cyan-400">Trusting It</span>
        </h1>
        <p className="text-sm text-slate-400">
          Choose an email source below. You will review the full message before running our 4-agent threat detector.
        </p>
      </div>

      {/* Error banner if OAuth or File failed */}
      {error && (
        <div
          className="w-full max-w-2xl px-4 py-3 rounded-xl text-xs font-mono text-red-300 text-center"
          style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)" }}
        >
          {error}
        </div>
      )}

      {/* Two Main Cards */}
      <div className="w-full grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Card 1: Connect Gmail */}
        <div
          className="glass-card p-7 flex flex-col justify-between gap-6 transition-all duration-200 hover:border-cyan-500/35"
          style={{ borderColor: gmailConnected ? "rgba(16,185,129,0.35)" : "rgba(255,255,255,0.09)" }}
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div
                className="w-12 h-12 rounded-xl flex items-center justify-center"
                style={{ background: "rgba(6,182,212,0.1)", border: "1px solid rgba(6,182,212,0.25)" }}
              >
                <Mail size={24} className="text-cyan-400" />
              </div>
              {gmailConnected && (
                <span
                  className="inline-flex items-center gap-1 text-xs font-mono px-2.5 py-1 rounded-full"
                  style={{
                    background: "rgba(16,185,129,0.12)",
                    border: "1px solid rgba(16,185,129,0.3)",
                    color: "#6ee7b7",
                  }}
                >
                  <CheckCircle2 size={12} /> Connected
                </span>
              )}
            </div>

            <div className="space-y-1.5">
              <h2 className="text-xl font-semibold text-white">Connect Gmail</h2>
              <p className="text-sm text-slate-400 leading-relaxed">
                Browse your recent Gmail inbox, preview full headers and content, and scan suspicious emails read-only.
              </p>
            </div>
          </div>

          <div className="space-y-2.5">
            {gmailConnected ? (
              <button
                onClick={onOpenGmailInbox}
                className="w-full flex items-center justify-center gap-2.5 py-3.5 px-5 rounded-xl font-semibold text-sm text-white transition-all cursor-pointer hover:brightness-110"
                style={{ background: "linear-gradient(135deg, #06b6d4, #6366f1)" }}
              >
                Open Gmail Inbox
                <ArrowRight size={16} />
              </button>
            ) : (
              <button
                onClick={startGmailAuth}
                disabled={health && health.gmail_configured === false}
                className="w-full flex items-center justify-center gap-3 py-3.5 px-5 rounded-xl font-semibold text-sm transition-all cursor-pointer hover:scale-[1.01] disabled:opacity-40 disabled:cursor-not-allowed"
                style={{ background: "#ffffff", color: "#0f172a" }}
              >
                <GoogleIcon />
                Continue with Google
              </button>
            )}
            <p className="text-[11px] font-mono text-slate-500 text-center">
              {health?.gmail_configured === false
                ? "OAuth credentials not configured on server"
                : "Read-only scope · Zero message storage"}
            </p>
          </div>
        </div>

        {/* Card 2: Upload Email File */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            const f = e.dataTransfer.files[0];
            if (f) handleFile(f);
          }}
          className="glass-card p-7 flex flex-col justify-between gap-6 transition-all duration-200"
          style={{
            borderColor: dragging ? "rgba(6,182,212,0.65)" : "rgba(255,255,255,0.09)",
            background: dragging ? "rgba(6,182,212,0.07)" : "rgba(255,255,255,0.04)",
          }}
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div
                className="w-12 h-12 rounded-xl flex items-center justify-center"
                style={{ background: "rgba(99,102,241,0.12)", border: "1px solid rgba(99,102,241,0.28)" }}
              >
                <Upload size={24} className="text-indigo-400" />
              </div>
              <button
                type="button"
                onClick={() => setShowPaste((v) => !v)}
                className="text-xs font-mono text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
              >
                {showPaste ? "Upload file instead" : "or paste raw email"}
              </button>
            </div>

            <div className="space-y-1.5">
              <h2 className="text-xl font-semibold text-white">Upload Email File</h2>
              <p className="text-sm text-slate-400 leading-relaxed">
                Drop a <span className="font-mono text-slate-300">.eml</span>,{" "}
                <span className="font-mono text-slate-300">.txt</span>, or{" "}
                <span className="font-mono text-slate-300">.mbox</span> file to inspect its full contents before scanning.
              </p>
            </div>
          </div>

          {!showPaste ? (
            <div className="space-y-2.5">
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                accept=".eml,.txt,.mbox"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleFile(f);
                  e.target.value = "";
                }}
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={loadingFile}
                className="w-full flex items-center justify-center gap-2.5 py-3.5 px-5 rounded-xl font-semibold text-sm text-slate-100 transition-all cursor-pointer hover:bg-white/10"
                style={{
                  background: "rgba(255,255,255,0.06)",
                  border: "1px dashed rgba(255,255,255,0.22)",
                }}
              >
                <Upload size={16} className="text-indigo-400" />
                {loadingFile ? "Loading email preview…" : "Choose or Drop Email File"}
              </button>
              <p className="text-[11px] font-mono text-slate-500 text-center">
                Processed locally in memory · RFC 5322 compliant
              </p>
            </div>
          ) : (
            <div className="space-y-2.5">
              <textarea
                rows={4}
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder="Paste raw RFC 822 email headers & body..."
                className="w-full rounded-xl p-3 font-mono text-xs text-slate-200 resize-none focus:outline-none focus:border-cyan-500/40"
                style={{
                  background: "rgba(0,0,0,0.3)",
                  border: "1px solid rgba(255,255,255,0.12)",
                }}
              />
              <button
                type="button"
                onClick={handlePastePreview}
                disabled={!rawText.trim() || loadingFile}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl font-semibold text-sm text-white transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                style={{ background: "linear-gradient(135deg, #06b6d4, #6366f1)" }}
              >
                <FileText size={15} />
                Preview Email
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Subtle Secondary Button for Built-in Demo Samples */}
      <div className="pt-2">
        <button
          type="button"
          onClick={onOpenDemoCorpus}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-mono text-slate-400 hover:text-cyan-300 transition-all cursor-pointer"
          style={{
            background: "rgba(255,255,255,0.03)",
            border: "1px solid rgba(255,255,255,0.08)",
          }}
        >
          <Sparkles size={13} className="text-cyan-400" />
          Try Built-in Demo Samples
        </button>
      </div>
    </motion.div>
  );
}
