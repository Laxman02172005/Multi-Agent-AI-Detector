/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        obsidian: "#050811",
        "card-bg": "rgba(255,255,255,0.04)",
        cyber: {
          cyan: "#06B6D4",
          indigo: "#6366F1",
          safe: "#10B981",
          phish: "#EF4444",
          warn: "#F59E0B",
          border: "rgba(255,255,255,0.08)",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Menlo", "monospace"],
      },
      animation: {
        pulse_slow: "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        spin_slow: "spin 8s linear infinite",
        "radar-ping": "radar-ping 1.8s ease-out infinite",
      },
      keyframes: {
        "radar-ping": {
          "0%": { transform: "scale(0.9)", opacity: "0.9" },
          "70%": { transform: "scale(2.0)", opacity: "0" },
          "100%": { transform: "scale(2.0)", opacity: "0" },
        },
      },
      backdropBlur: { xl: "24px" },
    },
  },
  plugins: [],
};
