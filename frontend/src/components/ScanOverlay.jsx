import { motion } from "framer-motion";
import { Shield } from "lucide-react";

export default function ScanOverlay() {
  return (
    <div className="flex flex-col items-center justify-center gap-8 py-24">
      <div className="relative flex items-center justify-center">
        {/* Pulsing rings */}
        {[0, 1, 2].map((i) => (
          <motion.div
            key={i}
            className="absolute rounded-full border"
            style={{ borderColor: "rgba(6,182,212,0.3)" }}
            initial={{ scale: 0.8, opacity: 0.8 }}
            animate={{ scale: 2.5 + i * 0.5, opacity: 0 }}
            transition={{ duration: 2, delay: i * 0.6, repeat: Infinity, ease: "easeOut" }}
          />
        ))}

        {/* Inner shield */}
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
          className="w-20 h-20 rounded-full flex items-center justify-center"
          style={{ background: "rgba(6,182,212,0.08)", border: "1px solid rgba(6,182,212,0.3)" }}
        >
          <Shield size={36} className="text-cyan-400" />
        </motion.div>
      </div>

      <div className="text-center space-y-2">
        <motion.p
          className="font-mono text-cyan-400 text-sm tracking-widest"
          animate={{ opacity: [0.5, 1, 0.5] }}
          transition={{ duration: 1.4, repeat: Infinity }}
        >
          ANALYZING THREAT VECTORS…
        </motion.p>
        <p className="text-slate-500 text-xs font-mono">Multi-agent pipeline active</p>
      </div>
    </div>
  );
}
