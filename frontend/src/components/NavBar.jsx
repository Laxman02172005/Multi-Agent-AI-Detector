import { Shield, Wifi, WifiOff, CheckCircle2 } from "lucide-react";

export default function NavBar({ health, gmailConnected, onBrandClick }) {
  const loaded = health?.model_loaded;
  const shaVerified = health?.sha256_verified;
  const online = health?.status === "ok";

  return (
    <header
      className="relative z-20 flex items-center justify-between px-6 py-3.5 border-b"
      style={{
        borderColor: "rgba(255,255,255,0.07)",
        background: "rgba(5,8,17,0.85)",
        backdropFilter: "blur(16px)",
      }}
    >
      <button
        onClick={onBrandClick}
        className="flex items-center gap-3 text-left group cursor-pointer focus:outline-none"
        title="Return to home"
      >
        <div className="relative">
          <Shield size={26} className="text-cyan-400 transition-transform group-hover:scale-105" />
          <span
            className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2 border-[#050811]"
            style={{ background: online ? "#10B981" : "#F59E0B" }}
          />
        </div>
        <div>
          <span className="font-mono font-bold tracking-widest text-white text-sm">AEGIS</span>
          <span className="text-slate-500 font-mono text-xs tracking-widest hidden sm:inline">
            {" "}// AI PHISHING DEFENSE
          </span>
        </div>
      </button>

      <div className="flex items-center gap-2.5">
        {loaded && (
          <span
            className="hidden md:flex items-center gap-1.5 text-xs font-mono px-3 py-1 rounded-full"
            style={{
              background: "rgba(99,102,241,0.12)",
              border: "1px solid rgba(99,102,241,0.3)",
              color: "#a5b4fc",
            }}
          >
            {shaVerified && <CheckCircle2 size={12} className="text-indigo-400" />}
            {health.model_name || "meta_classifier_real_v1"}
          </span>
        )}

        {gmailConnected ? (
          <span
            className="flex items-center gap-1.5 text-xs font-mono px-3 py-1 rounded-full"
            style={{
              background: "rgba(16,185,129,0.12)",
              border: "1px solid rgba(16,185,129,0.3)",
              color: "#6ee7b7",
            }}
          >
            <Wifi size={11} />
            Gmail Connected
          </span>
        ) : (
          <span
            className="flex items-center gap-1.5 text-xs font-mono px-3 py-1 rounded-full"
            style={{
              background: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.1)",
              color: "#94a3b8",
            }}
          >
            <WifiOff size={11} />
            Offline Engine
          </span>
        )}
      </div>
    </header>
  );
}
