import { motion } from "framer-motion";

function polarToXY(cx, cy, r, angle) {
  const rad = ((angle - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function arcPath(cx, cy, r, startDeg, endDeg) {
  const s = polarToXY(cx, cy, r, startDeg);
  const e = polarToXY(cx, cy, r, endDeg);
  const large = endDeg - startDeg > 180 ? 1 : 0;
  return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
}

export default function ThreatGauge({ probability, verdict }) {
  const normVerdict = (verdict || "abstain").toLowerCase();
  const color =
    normVerdict === "phishing"
      ? "#ef4444"
      : normVerdict === "legitimate"
      ? "#10b981"
      : "#f59e0b";

  const hasProb = typeof probability === "number" && !Number.isNaN(probability);
  const pct = hasProb ? Math.max(0, Math.min(1, probability)) : 0.5;
  // Gauge sweep from -90 deg (left) to +90 deg (right), avoiding zero-length arc warning
  const sweepDeg = Math.max(2, pct * 180);

  return (
    <svg viewBox="0 0 180 112" className="w-52 h-32">
      {/* Track */}
      <path
        d={arcPath(90, 92, 66, -90, 90)}
        fill="none"
        stroke="rgba(255,255,255,0.08)"
        strokeWidth="11"
        strokeLinecap="round"
      />

      {/* Filled arc */}
      {hasProb && (
        <motion.path
          d={arcPath(90, 92, 66, -90, -90 + sweepDeg)}
          fill="none"
          stroke={color}
          strokeWidth="11"
          strokeLinecap="round"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 0.75, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 8px ${color}80)` }}
        />
      )}

      {/* Value readout */}
      <text
        x="90"
        y="80"
        textAnchor="middle"
        fontFamily="JetBrains Mono, monospace"
        fontSize="24"
        fontWeight="700"
        fill={color}
      >
        {hasProb ? `${(pct * 100).toFixed(1)}%` : "N/A"}
      </text>
      <text
        x="90"
        y="102"
        textAnchor="middle"
        fontFamily="JetBrains Mono, monospace"
        fontSize="8.5"
        letterSpacing="1"
        fill="rgba(148,163,184,0.8)"
      >
        PHISHING RISK SCORE
      </text>
    </svg>
  );
}
