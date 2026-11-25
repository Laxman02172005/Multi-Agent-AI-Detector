export default function CyberBackground() {
  return (
    <div className="fixed inset-0 z-0 overflow-hidden pointer-events-none">
      {/* Dot grid */}
      <div className="absolute inset-0 dot-grid opacity-40" />

      {/* Radial glow — top left cyan */}
      <div
        className="absolute rounded-full"
        style={{
          width: 600,
          height: 600,
          top: -200,
          left: -150,
          background: "radial-gradient(circle, rgba(6,182,212,0.08) 0%, transparent 70%)",
        }}
      />

      {/* Radial glow — bottom right indigo */}
      <div
        className="absolute rounded-full"
        style={{
          width: 700,
          height: 700,
          bottom: -250,
          right: -200,
          background: "radial-gradient(circle, rgba(99,102,241,0.07) 0%, transparent 70%)",
        }}
      />
    </div>
  );
}
