const { useState, useEffect, useRef } = React;
const RCH = window.Recharts || {};
const Radar = RCH.Radar || (() => null);
const RadarChart = RCH.RadarChart || ((props) => <div>{props.children}</div>);
const PolarGrid = RCH.PolarGrid || (() => null);
const PolarAngleAxis = RCH.PolarAngleAxis || (() => null);
const ResponsiveContainer = RCH.ResponsiveContainer || ((props) => <div style={{ width: "100%", height: props.height || 280 }}>{props.children}</div>);
const BarChart = RCH.BarChart || ((props) => <div>{props.children}</div>);
const Bar = RCH.Bar || ((props) => <div>{props.children}</div>);
const AreaChart = RCH.AreaChart || ((props) => <div>{props.children}</div>);
const Area = RCH.Area || ((props) => <div>{props.children}</div>);
const CartesianGrid = RCH.CartesianGrid || (() => null);
const XAxis = RCH.XAxis || (() => null);
const YAxis = RCH.YAxis || (() => null);
const Tooltip = RCH.Tooltip || (() => null);
const Cell = RCH.Cell || (() => null);

const API = "";
const HAS_RECHARTS = Boolean(window.Recharts && window.Recharts.BarChart && window.Recharts.AreaChart && window.Recharts.RadarChart);
const THEMES = {
  light: {
    mode: "light",
    bg: "#efe4cd",
    card: "#f4ead8",
    blue: "#1f7a52",
    cyan: "#2e9365",
    orange: "#b88b33",
    red: "#8f4150",
    green: "#2f7f58",
    yellow: "#c6a04b",
    text: "#2c3428",
    dim: "#6d6c55",
    border: "rgba(116,103,63,0.3)",
  },
  dark: {
    mode: "dark",
    bg: "#121c17",
    card: "#1a2a22",
    blue: "#66bc90",
    cyan: "#8ad0a6",
    orange: "#d2af59",
    red: "#b66f7b",
    green: "#7cc49a",
    yellow: "#d9c178",
    text: "#e5eddc",
    dim: "#aeb69e",
    border: "rgba(171,153,101,0.35)",
  },
};
const C = { ...THEMES.light };

function applyTheme(mode) {
  Object.assign(C, THEMES[mode] || THEMES.light);
}

const riskColor = (s) => (s > 75 ? C.red : s > 55 ? C.orange : s > 35 ? C.yellow : s > 15 ? C.cyan : C.green);
const isDarkTheme = () => C.mode === "dark";
const statusColor = {
  CRITICAL: C.red,
  HIGH_RISK: C.orange,
  TRANSITIONING: C.yellow,
  PQC_READY: C.cyan,
  QUANTUM_SAFE: C.green,
  WARNING: C.yellow,
  ACCEPTABLE: C.cyan,
  SAFE: C.green,
};

const BANK_PRESETS = [
  { bank: "Punjab National Bank", domain: "pnbindia.in", region: "IN" },
  { bank: "HDFC Bank", domain: "hdfcbank.com", region: "IN" },
  { bank: "State Bank of India", domain: "sbi.co.in", region: "IN" },
  { bank: "Axis Bank", domain: "axisbank.com", region: "IN" },
  { bank: "ICICI Bank", domain: "icicibank.com", region: "IN" },
  { bank: "Kotak Mahindra Bank", domain: "kotak.com", region: "IN" },
  { bank: "Bank of Baroda", domain: "bankofbaroda.in", region: "IN" },
  { bank: "Union Bank of India", domain: "unionbankofindia.co.in", region: "IN" },
  { bank: "Canara Bank", domain: "canarabank.in", region: "IN" },
  { bank: "IndusInd Bank", domain: "indusind.com", region: "IN" },
];

const BANK_DEMO_ROWS = [
  { scan_id: "demo-1", domain: "hdfcbank.com", asset_count: 11, avg_risk: 39, safe_score: 24, risk_score: 64 },
  { scan_id: "demo-2", domain: "pnbindia.in", asset_count: 10, avg_risk: 55, safe_score: 36, risk_score: 83 },
  { scan_id: "demo-3", domain: "sbi.co.in", asset_count: 12, avg_risk: 51, safe_score: 34, risk_score: 80 },
  { scan_id: "demo-4", domain: "axisbank.com", asset_count: 10, avg_risk: 44, safe_score: 29, risk_score: 71 },
  { scan_id: "demo-5", domain: "icicibank.com", asset_count: 11, avg_risk: 43, safe_score: 28, risk_score: 69 },
  { scan_id: "demo-6", domain: "kotak.com", asset_count: 9, avg_risk: 46, safe_score: 31, risk_score: 74 },
  { scan_id: "demo-7", domain: "bankofbaroda.in", asset_count: 9, avg_risk: 52, safe_score: 35, risk_score: 81 },
  { scan_id: "demo-8", domain: "unionbankofindia.co.in", asset_count: 9, avg_risk: 50, safe_score: 33, risk_score: 78 },
  { scan_id: "demo-9", domain: "canarabank.in", asset_count: 8, avg_risk: 48, safe_score: 32, risk_score: 76 },
  { scan_id: "demo-10", domain: "indusind.com", asset_count: 8, avg_risk: 42, safe_score: 27, risk_score: 68 },
];

const BANK_REQUIREMENTS = {
  "hdfcbank.com": [
    "Harden internet-facing TLS policies and disable weak fallback ciphers.",
    "Run weekly cert-expiry and signature hygiene checks.",
    "Prioritize high-risk assets tied to customer login flows.",
  ],
  "pnbindia.in": [
    "Reduce high-risk endpoints by enforcing strict transport headers and key lifecycle controls.",
    "Patch legacy crypto dependencies in public-facing services first.",
    "Establish monthly risk-drift review against baseline scans.",
  ],
  "sbi.co.in": [
    "Focus on largest exposed asset clusters and rotate weak certificate chains.",
    "Increase scan cadence for critical banking APIs.",
    "Apply staged remediation with proof-of-fix rescans.",
  ],
  "axisbank.com": [
    "Enforce consistent cipher policy across edge gateways.",
    "Tighten auth token header protections and API hardening controls.",
    "Track risk score trend by asset class each sprint.",
  ],
};

const getBankLabel = (domain) => (BANK_PRESETS.find((b) => b.domain === domain)?.bank || domain);
const securityScore = (avgRisk) => Math.max(0, 100 - Number(avgRisk || 0));

function ParticleField() {
  const ref = useRef(null);
  useEffect(() => {
    const c = ref.current;
    const x = c.getContext("2d");
    const setSize = () => {
      c.width = innerWidth;
      c.height = innerHeight;
    };
    setSize();
    const pts = Array.from({ length: 80 }, () => ({
      x: Math.random() * c.width,
      y: Math.random() * c.height,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      r: Math.random() * 1.4 + 0.2,
    }));
    let id;
    const draw = () => {
      x.clearRect(0, 0, c.width, c.height);
      for (const p of pts) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = c.width;
        if (p.x > c.width) p.x = 0;
        if (p.y < 0) p.y = c.height;
        if (p.y > c.height) p.y = 0;
        x.beginPath();
        x.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        x.fillStyle = "rgba(132,170,208,0.6)";
        x.fill();
      }
      id = requestAnimationFrame(draw);
    };
    draw();
    addEventListener("resize", setSize);
    return () => {
      cancelAnimationFrame(id);
      removeEventListener("resize", setSize);
    };
  }, []);
  return <canvas ref={ref} style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none" }} />;
}

function Logo({ size = 46, animated = true, lockTheme = false }) {
  const gid = useRef(`g1_${Math.random().toString(36).slice(2, 9)}`);
  const dark = isDarkTheme();
  const primary = lockTheme ? (dark ? "#b9cae0" : "#5f728c") : C.blue;
  const accent = lockTheme ? (dark ? "#9fb4ce" : "#6d819d") : C.orange;
  const shellFill = lockTheme
    ? (dark ? "rgba(168,187,214,0.15)" : "rgba(116,138,166,0.14)")
    : (dark ? "rgba(122,149,184,0.16)" : "rgba(127,154,188,0.14)");
  const orbitA = lockTheme ? "rgba(120,141,168,0.34)" : "rgba(132,170,208,0.4)";
  const orbitB = lockTheme ? "rgba(102,124,151,0.28)" : "rgba(152,186,224,0.34)";
  const shadowFilter = lockTheme
    ? "none"
    : dark
      ? "drop-shadow(0 2px 7px rgba(6,12,20,0.4))"
      : "drop-shadow(0 2px 7px rgba(145,160,180,0.36))";
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      style={{
        filter: shadowFilter,
        animation: animated ? "logoBreath 4.5s ease-in-out infinite" : "none",
        transformOrigin: "50% 50%",
      }}
    >
      <defs>
        <linearGradient id={gid.current} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor={primary} />
          <stop offset="100%" stopColor={accent} />
        </linearGradient>
      </defs>
      <circle cx="32" cy="32" r="24" fill={dark ? "rgba(32,44,62,0.3)" : "rgba(233,238,246,0.66)"} />
      <path d="M32 4 L54 14 L54 36 Q54 52 32 60 Q10 52 10 36 L10 14 Z" fill={shellFill} stroke={`url(#${gid.current})`} strokeWidth="2" />
      <circle cx="32" cy="32" r="6" fill="none" stroke={primary} strokeWidth="1.5" />
      <path d="M20 28 H44 M20 36 H44" stroke={accent} strokeWidth="1.2" />
      <ellipse cx="32" cy="32" rx="16" ry="6" fill="none" stroke={orbitA} strokeWidth="1">
        {animated && !lockTheme && <animateTransform attributeName="transform" type="rotate" from="0 32 32" to="360 32 32" dur="6s" repeatCount="indefinite" />}
      </ellipse>
      <ellipse cx="32" cy="32" rx="16" ry="6" fill="none" stroke={orbitB} strokeWidth="1">
        {animated && !lockTheme && <animateTransform attributeName="transform" type="rotate" from="360 32 32" to="0 32 32" dur="4.2s" repeatCount="indefinite" />}
      </ellipse>
      <circle cx="46" cy="32" r="1.8" fill={primary}>
        {animated && <animate attributeName="opacity" values="0.3;1;0.3" dur="1.2s" repeatCount="indefinite" />}
      </circle>
      <animate attributeName="opacity" values={animated ? "0.94;1;0.94" : "1"} dur="3.2s" repeatCount="indefinite" />
      <style>{`@keyframes logoBreath{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-1px) scale(1.012)}}`}</style>
    </svg>
  );
}

function MatrixRain({ opacity = 0.42, zIndex = 0 }) {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext("2d");
    const chars = "01ABCDEFHJKMNPQRTUVWXYZ";
    let cols = 0;
    let drops = [];

    const resize = () => {
      canvas.width = innerWidth;
      canvas.height = innerHeight;
      cols = Math.floor(canvas.width / 14);
      drops = Array.from({ length: cols }, () => Math.floor(Math.random() * 20));
    };
    resize();

    let frame;
    const draw = () => {
      ctx.fillStyle = "rgba(2, 8, 14, 0.16)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.font = "12px JetBrains Mono, monospace";
      for (let i = 0; i < cols; i += 1) {
        const txt = chars[Math.floor(Math.random() * chars.length)];
        const x = i * 14;
        const y = drops[i] * 14;
        ctx.fillStyle = i % 4 === 0 ? "rgba(141,181,220,0.6)" : "rgba(132,170,208,0.45)";
        ctx.fillText(txt, x, y);
        if (y > canvas.height && Math.random() > 0.98) drops[i] = 0;
        drops[i] += 1;
      }
      frame = requestAnimationFrame(draw);
    };
    draw();
    addEventListener("resize", resize);
    return () => {
      cancelAnimationFrame(frame);
      removeEventListener("resize", resize);
    };
  }, []);
  return <canvas ref={ref} style={{ position: "absolute", inset: 0, pointerEvents: "none", zIndex, opacity }} />;
}

function FingerprintUnlock({ active, progress }) {
  const color = active ? C.cyan : C.dim;
  return (
    <div style={{ margin: "0 auto", width: 132 }}>
      <svg viewBox="0 0 120 120" width="120" height="120" style={{ filter: `drop-shadow(0 0 14px ${active ? "rgba(141,181,220,0.55)" : "rgba(132,170,208,0.2)"})` }}>
        <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(141,181,220,0.2)" strokeWidth="1.2" />
        <path d="M30 74c0-20 12-34 30-34s30 14 30 34" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" />
        <path d="M37 74c0-15 9-26 23-26s23 11 23 26" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" />
        <path d="M44 74c0-10 6-17 16-17s16 7 16 17" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" />
        <path d="M30 78c0 18 12 32 30 32s30-14 30-32" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" />
        <path d="M38 78c0 13 9 24 22 24s22-11 22-24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" />
        <path d="M46 78c0 9 6 16 14 16s14-7 14-16" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" />
        <rect x="18" y={18 + ((100 - progress) * 0.84)} width="84" height="8" rx="4" fill="rgba(141,181,220,0.35)" style={{ transition: "y 0.08s linear" }} />
      </svg>
      <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, letterSpacing: 1.5, color, textAlign: "center" }}>{active ? `FINGERPRINT VERIFY ${progress}%` : "FINGERPRINT IDLE"}</div>
    </div>
  );
}

function TrendSpark({ label, color, values }) {
  const h = 36;
  const w = 130;
  const dark = isDarkTheme();
  const max = Math.max(...values, 1);
  const gid = useRef(`trend_grad_${Math.random().toString(36).slice(2, 9)}`);
  const points = values
    .map((v, i) => {
      const x = (i / (values.length - 1 || 1)) * w;
      const y = h - (v / max) * (h - 4);
      return { x, y };
    });
  const linePath = points
    .map((p, idx) => `${idx === 0 ? "M" : "L"} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`)
    .join(" ");
  const areaPath = `${linePath} L ${w} ${h} L 0 ${h} Z`;
  return (
    <div style={{ padding: "8px 10px", borderRadius: 12, background: dark ? "linear-gradient(155deg, #142543, #0f1f39)" : "linear-gradient(155deg, #eef3fb, #e3ebf8)", border: `1px solid ${dark ? `${color}66` : `${color}33`}`, boxShadow: dark ? "inset 0 0 10px rgba(152,186,224,0.12)" : "inset 2px 2px 5px rgba(168,184,206,0.3), inset -2px -2px 5px rgba(255,255,255,0.85)" }}>
      <div style={{ fontFamily: "JetBrains Mono", color, fontSize: 10, letterSpacing: 1 }}>{label}</div>
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ marginTop: 4 }}>
        <defs>
          <linearGradient id={gid.current} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={`${color}AA`} />
            <stop offset="100%" stopColor={`${color}10`} />
          </linearGradient>
        </defs>
        <path d={areaPath} fill={`url(#${gid.current})`} />
        <path d={linePath} fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" />
      </svg>
    </div>
  );
}

function ClayBankAnalysisGraph({ selectedRow, lineUp }) {
  const dark = isDarkTheme();
  if (!selectedRow) return null;

  const selectedRisk = Number(selectedRow.avg_risk || 0);
  const selectedSecurity = Number(securityScore(selectedRisk).toFixed(1));
  const peers = (lineUp || []).filter((x) => x.domain !== selectedRow.domain);

  const average = (list, key, fallback = 0) => {
    if (!list.length) return fallback;
    const total = list.reduce((sum, item) => sum + Number(item[key] || 0), 0);
    return total / list.length;
  };

  const peerRisk = average(peers, "risk", selectedRisk);
  const peerSecurity = average(peers, "security", selectedSecurity);
  const maxAssetCount = Math.max(
    1,
    ...((lineUp || []).map((x) => Number(x.asset_count || 0))),
    Number(selectedRow.asset_count || 0),
  );
  const assetLoad = (Number(selectedRow.asset_count || 0) / maxAssetCount) * 100;
  const peerAssetLoad = (average(peers, "asset_count", Number(selectedRow.asset_count || 0)) / maxAssetCount) * 100;
  const controlStability = Math.max(0, Math.min(100, 100 - Math.abs(selectedRisk - peerRisk) * 1.35));

  const metrics = [
    { id: "security", label: "Security posture", value: selectedSecurity, peer: peerSecurity, color: C.green },
    { id: "risk", label: "Risk pressure", value: selectedRisk, peer: peerRisk, color: C.red },
    { id: "assets", label: "Asset exposure", value: assetLoad, peer: peerAssetLoad, color: C.blue },
    { id: "stability", label: "Control stability", value: controlStability, peer: 72, color: C.cyan },
  ];

  const clamp = (v) => Math.max(2, Math.min(100, Number(v || 0)));
  const selectedName = getBankLabel(selectedRow.domain);

  return (
    <Card style={{ padding: 18 }}>
      <div style={{ color: C.blue, fontFamily: "Orbitron", fontSize: 12, letterSpacing: 1.2, marginBottom: 5 }}>
        <PressureText glow={C.blue}>BANK GRAPHICAL ANALYSIS</PressureText>
      </div>
      <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, marginBottom: 11 }}>
        Claymorphic bars for {selectedName}. Vertical marker = peer baseline.
      </div>
      <div style={{ display: "grid", gap: 10 }}>
        {metrics.map((m) => (
          <div key={m.id} style={{ display: "grid", gridTemplateColumns: "130px 1fr 52px", gap: 10, alignItems: "center" }}>
            <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10 }}>{m.label}</div>
            <div
              style={{
                position: "relative",
                height: 24,
                borderRadius: 999,
                overflow: "hidden",
                background: dark ? "linear-gradient(155deg, #11233e, #0b182b)" : "linear-gradient(155deg, #dfe8f5, #f7fbff)",
                boxShadow: dark
                  ? "inset 5px 5px 12px rgba(2,8,16,0.84), inset -4px -4px 9px rgba(67,104,150,0.25)"
                  : "inset 5px 5px 11px rgba(163,180,203,0.5), inset -5px -5px 11px rgba(255,255,255,0.92)",
              }}
            >
              <div
                style={{
                  position: "absolute",
                  left: 3,
                  top: 3,
                  bottom: 3,
                  width: `${clamp(m.value)}%`,
                  borderRadius: 999,
                  background: dark ? `linear-gradient(145deg, ${m.color}, ${m.color}99)` : `linear-gradient(145deg, ${m.color}cc, ${m.color}88)`,
                  boxShadow: dark
                    ? "4px 4px 9px rgba(2,8,16,0.75), -2px -2px 7px rgba(130,176,230,0.2), inset 0 1px 0 rgba(255,255,255,0.22)"
                    : "4px 4px 9px rgba(168,184,206,0.36), -3px -3px 8px rgba(255,255,255,0.82), inset 0 1px 0 rgba(255,255,255,0.75)",
                  transition: "width 300ms ease",
                }}
              />
              <div
                style={{
                  position: "absolute",
                  left: `calc(${clamp(m.peer)}% - 1px)`,
                  top: 4,
                  bottom: 4,
                  width: 2,
                  borderRadius: 2,
                  background: dark ? "rgba(230,244,255,0.85)" : "rgba(53,80,116,0.75)",
                  boxShadow: dark ? "0 0 8px rgba(152,186,224,0.35)" : "none",
                }}
              />
            </div>
            <div style={{ textAlign: "right" }}>
              <ClayNumber value={Number(m.value).toFixed(1)} tone={m.color} size={10} minWidth={50} />
            </div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 12, display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(165px,1fr))", gap: 8 }}>
        <div style={{ borderRadius: 12, padding: "8px 10px", color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, background: dark ? "rgba(14,30,52,0.68)" : "rgba(233,238,244,0.76)", boxShadow: dark ? "inset 0 0 10px rgba(152,186,224,0.08)" : "inset 2px 2px 6px rgba(167,183,206,0.34), inset -2px -2px 6px rgba(238,243,248,0.74)" }}>
          Peer risk avg: <ClayNumber value={peerRisk.toFixed(1)} tone={C.red} size={10} minWidth={48} style={{ marginLeft: 6 }} />
        </div>
        <div style={{ borderRadius: 12, padding: "8px 10px", color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, background: dark ? "rgba(14,30,52,0.68)" : "rgba(233,238,244,0.76)", boxShadow: dark ? "inset 0 0 10px rgba(152,186,224,0.08)" : "inset 2px 2px 6px rgba(167,183,206,0.34), inset -2px -2px 6px rgba(238,243,248,0.74)" }}>
          Selected assets: <ClayNumber value={selectedRow.asset_count ?? 0} tone={C.blue} size={10} minWidth={48} style={{ marginLeft: 6 }} />
        </div>
      </div>
    </Card>
  );
}

function BlockchainMeshOverlay({ opacity = 0.22, zIndex = 1 }) {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex,
        pointerEvents: "none",
        opacity,
        background:
          "radial-gradient(circle at 12% 16%, rgba(141,181,220,0.09), transparent 35%), radial-gradient(circle at 88% 70%, rgba(185,152,112,0.08), transparent 34%), repeating-linear-gradient(0deg, rgba(132,170,208,0.07) 0px, rgba(132,170,208,0.07) 1px, transparent 1px, transparent 34px), repeating-linear-gradient(90deg, rgba(141,181,220,0.06) 0px, rgba(141,181,220,0.06) 1px, transparent 1px, transparent 34px)",
      }}
    />
  );
}

function CyanPulseVeil({ zIndex = 1 }) {
  return (
    <>
      <div
        style={{
          position: "fixed",
          inset: 0,
          zIndex,
          pointerEvents: "none",
          background:
            "radial-gradient(circle at 18% 24%, rgba(141,181,220,0.13), transparent 34%), radial-gradient(circle at 78% 70%, rgba(132,170,208,0.12), transparent 36%), radial-gradient(circle at 50% 8%, rgba(141,181,220,0.08), transparent 26%)",
          animation: "cyanPulse 8s ease-in-out infinite",
        }}
      />
      <style>{`@keyframes cyanPulse{0%,100%{opacity:.6}50%{opacity:1}}`}</style>
    </>
  );
}

function CyborgCore({ active, progress }) {
  return (
    <div style={{ position: "relative", width: 150, height: 150, display: "grid", placeItems: "center" }}>
      <div
        style={{
          position: "absolute",
          inset: 0,
          borderRadius: "50%",
          border: "1px solid rgba(141,181,220,0.35)",
          boxShadow: "0 0 24px rgba(141,181,220,0.25)",
          animation: "coreSpin 8s linear infinite",
        }}
      />
      <div
        style={{
          position: "absolute",
          width: 108,
          height: 108,
          borderRadius: "50%",
          border: "1px dashed rgba(132,170,208,0.45)",
          animation: "coreSpinRev 5s linear infinite",
        }}
      />
      <svg width="112" height="112" viewBox="0 0 112 112" style={{ filter: "drop-shadow(0 0 16px rgba(141,181,220,0.45))" }}>
        <circle cx="56" cy="56" r="42" fill="rgba(141,181,220,0.06)" stroke="rgba(141,181,220,0.55)" strokeWidth="1.5" />
        <circle cx="56" cy="56" r="26" fill="none" stroke="rgba(132,170,208,0.7)" strokeWidth="2" />
        <circle cx="56" cy="56" r="8" fill={active ? "rgba(141,181,220,0.9)" : "rgba(132,170,208,0.8)"} />
        <path d="M18 56 H94 M56 18 V94" stroke="rgba(132,170,208,0.6)" strokeWidth="1.2" />
        <rect x="16" y={16 + ((100 - progress) * 0.8)} width="80" height="6" rx="3" fill="rgba(141,181,220,0.35)" />
      </svg>
    </div>
  );
}

const LOCK_CODE_XOR = [17, 23, 31, 11, 13, 19];
const LOCK_CODE_ENC = [64, 95, 45, 59, 63, 37];
const LOCK_ACCESS_CODE = LOCK_CODE_ENC.map((n, i) => String.fromCharCode(n ^ LOCK_CODE_XOR[i])).join("");

function CursorTrail({ turbo = false }) {
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const targetRef = useRef({ x: 0, y: 0 });
  const dark = isDarkTheme();

  useEffect(() => {
    const start = { x: innerWidth * 0.5, y: innerHeight * 0.4 };
    targetRef.current = start;
    setPos(start);
  }, []);

  useEffect(() => {
    let raf = 0;
    const onMove = (e) => {
      targetRef.current = { x: e.clientX, y: e.clientY };
    };
    const onTouch = (e) => {
      const t = e.touches && e.touches[0];
      if (!t) return;
      targetRef.current = { x: t.clientX, y: t.clientY };
    };

    const tick = () => {
      const ease = turbo ? 0.5 : 0.38;
      setPos((p) => ({
        x: p.x + (targetRef.current.x - p.x) * ease,
        y: p.y + (targetRef.current.y - p.y) * ease,
      }));
      raf = requestAnimationFrame(tick);
    };

    addEventListener("mousemove", onMove);
    addEventListener("touchmove", onTouch, { passive: true });
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      removeEventListener("mousemove", onMove);
      removeEventListener("touchmove", onTouch);
    };
  }, [turbo]);

  return (
    <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 40 }}>
      <div
        style={{
          position: "absolute",
          left: pos.x - 10,
          top: pos.y - 10,
          width: 20,
          height: 20,
          borderRadius: "50%",
          border: dark ? "1px solid rgba(152,186,224,0.95)" : "1px solid rgba(79,140,255,0.85)",
          background: dark
            ? "radial-gradient(circle at 36% 30%, rgba(152,186,224,0.5), rgba(152,186,224,0.05) 65%, transparent 75%)"
            : "radial-gradient(circle at 36% 30%, rgba(79,140,255,0.45), rgba(79,140,255,0.08) 65%, transparent 75%)",
          boxShadow: dark
            ? "0 0 15px rgba(152,186,224,0.72), inset 0 0 9px rgba(152,186,224,0.32)"
            : "4px 4px 10px rgba(153,170,195,0.38), -3px -3px 8px rgba(255,255,255,0.78), 0 0 11px rgba(79,140,255,0.32)",
          transform: turbo ? "scale(1.14)" : "scale(1)",
          transition: "transform 120ms ease",
        }}
      />
      <div
        style={{
          position: "absolute",
          left: pos.x - 2.5,
          top: pos.y - 2.5,
          width: 5,
          height: 5,
          borderRadius: "50%",
          background: dark ? "rgba(152,186,224,0.95)" : "rgba(79,140,255,0.9)",
          boxShadow: dark ? "0 0 10px rgba(152,186,224,0.88)" : "0 0 7px rgba(79,140,255,0.56)",
        }}
      />
    </div>
  );
}

function LockScreen({ onUnlock, theme = "light", onThemeChange = () => {} }) {
  const [entry, setEntry] = useState("");
  const [bad, setBad] = useState(false);
  const [unlocking, setUnlocking] = useState(false);
  const [unlockProgress, setUnlockProgress] = useState(0);
  const inputRef = useRef(null);
  const dark = theme === "dark";

  useEffect(() => {
    if (!unlocking) return undefined;
    const id = setInterval(() => {
      setUnlockProgress((p) => {
        const next = Math.min(100, p + 5);
        if (next >= 100) {
          clearInterval(id);
          setTimeout(onUnlock, 140);
        }
        return next;
      });
    }, 40);
    return () => clearInterval(id);
  }, [unlocking, onUnlock]);

  const rejectEntry = () => {
    setBad(true);
    setTimeout(() => {
      setEntry("");
      setBad(false);
    }, 620);
  };

  const validate = (candidate) => {
    if (candidate === LOCK_ACCESS_CODE) {
      setUnlocking(true);
      setUnlockProgress(0);
      return;
    }
    rejectEntry();
  };

  const sanitizeEntry = (value) => String(value || "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, LOCK_ACCESS_CODE.length);

  const onEntryChange = (rawValue) => {
    if (unlocking) return;
    const next = sanitizeEntry(rawValue);
    setEntry(next);
    if (next.length === LOCK_ACCESS_CODE.length) {
      validate(next);
    }
  };

  const blockClipboard = (e) => {
    e.preventDefault();
  };

  useEffect(() => {
    if (unlocking) return;
    const id = setTimeout(() => {
      if (inputRef.current) inputRef.current.focus();
    }, 10);
    return () => clearTimeout(id);
  }, [unlocking]);

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: dark
          ? "linear-gradient(160deg, #1b251f 0%, #161f1a 56%, #121914 100%)"
          : "linear-gradient(160deg, #f4e9d2 0%, #e9dcc1 56%, #deceb0 100%)",
        display: "grid",
        placeItems: "center",
        zIndex: 9999,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          zIndex: 1,
          width: 700,
          maxWidth: "94vw",
          borderRadius: 38,
          padding: "28px 30px 24px",
          background: dark
            ? "linear-gradient(165deg, #2d3c33 0%, #27352d 62%, #212d26 100%)"
            : "linear-gradient(165deg, #f7ecd8 0%, #ecdfc4 62%, #e3d3b5 100%)",
          border: dark ? "1px solid rgba(169,154,111,0.44)" : "1px solid rgba(177,151,94,0.5)",
          boxShadow: dark
            ? "30px 30px 60px rgba(6,10,8,0.58), -20px -20px 50px rgba(67,86,73,0.3), inset 0 2px 0 rgba(205,190,145,0.17), inset 0 -4px 12px rgba(7,10,8,0.5)"
            : "30px 30px 56px rgba(186,167,126,0.42), -20px -20px 48px rgba(255,251,240,0.86), inset 0 2px 0 rgba(255,255,252,0.85), inset 0 -4px 12px rgba(188,166,120,0.35)",
          transform: bad ? "translateX(-8px)" : "none",
          transition: "transform 140ms ease",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20, gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span
              style={{
                width: 26,
                height: 26,
                borderRadius: "50%",
                background: dark ? "linear-gradient(160deg, #3d5044, #314136)" : "linear-gradient(160deg, #f5ecd8, #e7dcc2)",
                border: dark ? "1px solid rgba(169,154,111,0.44)" : "1px solid rgba(183,159,102,0.56)",
                boxShadow: dark
                  ? "5px 5px 10px rgba(10,15,12,0.58), -3px -3px 8px rgba(73,94,81,0.32), inset 0 1px 0 rgba(219,204,160,0.22)"
                  : "5px 5px 10px rgba(181,166,131,0.4), -3px -3px 8px rgba(255,255,255,0.9), inset 0 1px 0 rgba(255,255,255,0.95)",
                display: "grid",
                placeItems: "center",
              }}
            >
              <span style={{ width: 7, height: 7, borderRadius: "50%", background: dark ? "#d1ba7a" : "#b08a3b" }} />
            </span>
            <div style={{ fontFamily: "JetBrains Mono", color: dark ? "#e6e8d8" : "#6f5f3b", fontSize: 11, letterSpacing: 2, padding: "7px 16px", borderRadius: 999, background: dark ? "linear-gradient(165deg, #36473c, #2f3f35)" : "linear-gradient(165deg, #f5ebd6, #e8dcc1)", boxShadow: dark ? "inset 3px 3px 6px rgba(14,18,16,0.5), inset -3px -3px 6px rgba(73,94,81,0.26)" : "inset 3px 3px 6px rgba(188,171,132,0.32), inset -3px -3px 6px rgba(255,255,255,0.92)" }}>
              SECURE LOCK
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <button onClick={() => onThemeChange("light")} style={{ borderRadius: 999, border: theme === "light" ? "1px solid rgba(143,159,182,0.72)" : "1px solid rgba(170,182,201,0.44)", background: theme === "light" ? "linear-gradient(165deg, #ebf0f6, #dde5ef)" : "linear-gradient(165deg, #e4eaf2, #d8e0eb)", color: "#5b6f8b", padding: "5px 14px", fontFamily: "JetBrains Mono", fontSize: 10, letterSpacing: 0.8, cursor: "pointer", boxShadow: "inset 1px 1px 2px rgba(255,255,255,0.85), inset -1px -1px 2px rgba(173,185,201,0.35)" }}>Light</button>
            <button onClick={() => onThemeChange("dark")} style={{ borderRadius: 999, border: theme === "dark" ? "1px solid rgba(158,169,184,0.72)" : "1px solid rgba(126,136,151,0.42)", background: dark ? "linear-gradient(165deg, #3c4451, #333b48)" : "linear-gradient(165deg, #e4eaf2, #d8e0eb)", color: dark ? "#c3cfde" : "#72869f", padding: "5px 14px", fontFamily: "JetBrains Mono", fontSize: 10, letterSpacing: 0.8, cursor: "pointer", boxShadow: dark ? "inset 1px 1px 2px rgba(217,225,238,0.13), inset -1px -1px 2px rgba(19,24,33,0.56)" : "inset 1px 1px 2px rgba(255,255,255,0.85), inset -1px -1px 2px rgba(173,185,201,0.35)" }}>Dark</button>
          </div>
        </div>

        <div style={{ display: "grid", placeItems: "center", marginBottom: 10 }}>
          <div style={{ width: 120, height: 120, borderRadius: "50%", background: dark ? "linear-gradient(160deg, #3f4754, #343b47)" : "linear-gradient(160deg, #e2e8f1, #d4deea)", border: dark ? "1px solid rgba(145,156,172,0.42)" : "1px solid rgba(177,190,208,0.68)", display: "grid", placeItems: "center", boxShadow: dark ? "inset 8px 8px 14px rgba(15,19,27,0.52), inset -8px -8px 14px rgba(80,92,109,0.24)" : "inset 8px 8px 14px rgba(173,185,201,0.36), inset -8px -8px 14px rgba(255,255,255,0.92)" }}>
            <Logo size={64} animated={false} lockTheme />
          </div>
        </div>

        <h1 style={{ margin: "10px 0 8px", textAlign: "center", fontFamily: "Orbitron", letterSpacing: 2.8, color: dark ? "#d4deeb" : "#425974", textShadow: "none" }}>
          SECURE VAULT ACCESS
        </h1>
        <div style={{ marginBottom: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", color: dark ? "#9bb2d0" : "#6f89ad", fontFamily: "JetBrains Mono", fontSize: 10, marginBottom: 8, letterSpacing: 1.5 }}>
            <span>ACCESS KEY</span>
            <span>MASKED INPUT</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: `repeat(${LOCK_ACCESS_CODE.length}, minmax(0, 1fr))`, gap: 10 }}>
            {Array.from({ length: LOCK_ACCESS_CODE.length }).map((_, i) => (
              <div
                key={i}
                style={{
                  height: 50,
                  borderRadius: 14,
                  border: `1px solid ${bad ? "rgba(199,102,122,0.65)" : dark ? "rgba(131,153,183,0.5)" : "rgba(162,182,209,0.62)"}`,
                  background: dark ? "linear-gradient(165deg, #333e4f, #2b3544)" : "linear-gradient(165deg, #e5ebf4, #d9e2ee)",
                  boxShadow: dark
                    ? "inset 4px 4px 9px rgba(15,20,29,0.58), inset -4px -4px 9px rgba(84,101,127,0.32)"
                    : "inset 4px 4px 9px rgba(179,194,214,0.4), inset -4px -4px 9px rgba(255,255,255,0.9)",
                  display: "grid",
                  placeItems: "center",
                  fontFamily: "JetBrains Mono",
                  color: dark ? "#cfe0f8" : "#5d7ea8",
                  letterSpacing: 1.4,
                  fontWeight: 600,
                  fontSize: 18,
                }}
              >
                {i < entry.length ? "●" : ""}
              </div>
            ))}
          </div>
        </div>

        <div style={{ display: "grid", gap: 10, position: "relative" }} onClick={() => inputRef.current && inputRef.current.focus()}>
          <div
            style={{
              width: "100%",
              height: 56,
              borderRadius: 16,
              border: dark ? "1px solid rgba(132,154,183,0.5)" : "1px solid rgba(167,187,213,0.65)",
              background: dark ? "linear-gradient(165deg, #333e4f, #2a3443)" : "linear-gradient(165deg, #e6edf5, #dae3ef)",
              color: dark ? "#b7c9e1" : "#6a87ad",
              letterSpacing: 2,
              textAlign: "center",
              fontFamily: "Orbitron",
              fontWeight: 700,
              fontSize: 16,
              display: "grid",
              placeItems: "center",
              boxShadow: dark
                ? "inset 6px 6px 12px rgba(13,18,26,0.62), inset -6px -6px 12px rgba(82,99,126,0.3)"
                : "inset 6px 6px 12px rgba(179,194,214,0.42), inset -6px -6px 12px rgba(255,255,255,0.9)",
              userSelect: "none",
            }}
          >
            {entry.length ? "INPUT MASKED" : "TYPE ACCESS KEY"}
          </div>
          <input
            ref={inputRef}
            type="password"
            disabled={unlocking}
            value={entry}
            onChange={(e) => onEntryChange(e.target.value)}
            onCopy={blockClipboard}
            onCut={blockClipboard}
            onPaste={blockClipboard}
            onKeyDown={(e) => {
              if (e.key === "Enter" && entry.length === LOCK_ACCESS_CODE.length) {
                e.preventDefault();
                validate(entry);
              }
              if (e.key === "Escape") {
                e.preventDefault();
                setEntry("");
              }
            }}
            maxLength={LOCK_ACCESS_CODE.length}
            autoCapitalize="characters"
            autoCorrect="off"
            autoComplete="new-password"
            inputMode="text"
            aria-label="Access key"
            spellCheck={false}
            placeholder=""
            style={{
              position: "absolute",
              left: 0,
              top: 0,
              width: "100%",
              height: 56,
              opacity: 0.02,
              border: "none",
              outline: "none",
              background: "transparent",
              color: "transparent",
              caretColor: "transparent",
              WebkitTextSecurity: "disc",
            }}
          />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            <button
              disabled={unlocking}
              onClick={() => setEntry("")}
              style={{
                width: "100%",
                height: 50,
                borderRadius: 14,
                border: dark ? "1px solid rgba(132,154,183,0.5)" : "1px solid rgba(167,187,213,0.64)",
                background: dark ? "linear-gradient(165deg, #343f51, #2d3748)" : "linear-gradient(165deg, #e6edf5, #dae3ef)",
                color: dark ? "#c5d8f2" : "#4e6f99",
                fontFamily: "Orbitron",
                fontWeight: 700,
                letterSpacing: 1,
                fontSize: 12,
                cursor: unlocking ? "default" : "pointer",
                opacity: unlocking ? 0.55 : 1,
                boxShadow: dark
                  ? "6px 6px 12px rgba(12,16,24,0.55), -4px -4px 10px rgba(84,101,126,0.28), inset 0 1px 0 rgba(203,220,246,0.18)"
                  : "6px 6px 12px rgba(176,191,212,0.4), -4px -4px 10px rgba(255,255,255,0.9), inset 0 1px 0 rgba(255,255,255,0.9)",
              }}
            >
              CLEAR
            </button>
            <button
              disabled={unlocking || entry.length !== LOCK_ACCESS_CODE.length}
              onClick={() => validate(entry)}
              style={{
                width: "100%",
                height: 50,
                borderRadius: 14,
                border: dark ? "1px solid rgba(146,169,200,0.58)" : "1px solid rgba(153,176,207,0.68)",
                background: dark ? "linear-gradient(165deg, #3a475c, #313c4d)" : "linear-gradient(165deg, #dde6f2, #d2dcea)",
                color: dark ? "#cfe0f7" : "#5a7ca7",
                fontFamily: "Orbitron",
                fontWeight: 700,
                letterSpacing: 1,
                fontSize: 12,
                cursor: unlocking || entry.length !== LOCK_ACCESS_CODE.length ? "default" : "pointer",
                opacity: unlocking || entry.length !== LOCK_ACCESS_CODE.length ? 0.5 : 1,
                boxShadow: dark
                  ? "6px 6px 12px rgba(12,16,24,0.55), -4px -4px 10px rgba(84,101,126,0.28), inset 0 1px 0 rgba(203,220,246,0.18)"
                  : "6px 6px 12px rgba(176,191,212,0.4), -4px -4px 10px rgba(255,255,255,0.9), inset 0 1px 0 rgba(255,255,255,0.9)",
              }}
            >
              UNLOCK
            </button>
          </div>
        </div>

        <div style={{ marginTop: 12, marginBottom: 4 }}>
          <div style={{ height: 14, borderRadius: 999, background: dark ? "linear-gradient(165deg, #313c4d, #2a3443)" : "linear-gradient(165deg, #dce5f1, #d1dcea)", boxShadow: dark ? "inset 4px 4px 8px rgba(14,18,26,0.58), inset -4px -4px 8px rgba(82,99,126,0.28)" : "inset 4px 4px 8px rgba(180,195,215,0.4), inset -4px -4px 8px rgba(255,255,255,0.9)", overflow: "hidden" }}>
            <div style={{ width: `${unlockProgress}%`, height: "100%", borderRadius: 999, background: dark ? "linear-gradient(90deg, #8fa6c7, #a7bad5)" : "linear-gradient(90deg, #8cabd2, #a9c1df)", transition: "width 80ms linear" }} />
          </div>
        </div>

        <div
          style={{
            marginTop: 6,
            textAlign: "center",
            fontFamily: "JetBrains Mono",
            color: bad ? (dark ? "#d6a1ad" : "#b36c7b") : (dark ? "#a8bdd9" : "#6685ad"),
            fontSize: 11,
            letterSpacing: 1.6,
            minHeight: 16,
          }}
        >
          {unlocking
            ? "Access granted. Opening Quanthunt dashboard..."
            : bad
              ? "Invalid access key"
              : "Type the access key and press unlock"}
        </div>
      </div>
    </div>
  );
}
function PressureText({ children, style = {}, glow = C.cyan }) {
  const [hovered, setHovered] = useState(false);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const dark = isDarkTheme();
  const onMove = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - (r.left + r.width / 2)) / r.width) * 4;
    const y = ((e.clientY - (r.top + r.height / 2)) / r.height) * 4;
    setOffset({ x, y });
  };
  return (
    <span
      onMouseEnter={() => setHovered(true)}
      onMouseMove={onMove}
      onMouseLeave={() => {
        setHovered(false);
        setOffset({ x: 0, y: 0 });
      }}
      style={{
        display: "inline-block",
        transform: `translate(${offset.x}px, ${offset.y}px) scale(${hovered ? 1.03 : 1})`,
        transition: "transform 120ms ease, text-shadow 120ms ease",
        textShadow: hovered
          ? (dark ? "0 1px 0 rgba(223,231,242,0.2)" : "0 1px 0 rgba(255,255,255,0.76)")
          : "none",
        ...style,
      }}
    >
      {children}
    </span>
  );
}

function ClayNumber({ value, tone = C.blue, size = 12, minWidth = 48, style = {} }) {
  const dark = isDarkTheme();
  const pad = size >= 18 ? "6px 12px" : "4px 9px";
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        minWidth,
        padding: pad,
        borderRadius: 999,
        border: `1px solid ${dark ? `${tone}88` : `${tone}66`}`,
        background: dark
          ? `linear-gradient(145deg, rgba(13,28,50,0.94), ${tone}20)`
          : `linear-gradient(145deg, #f8fbff, ${tone}20)`,
        boxShadow: dark
          ? "4px 4px 10px rgba(2,8,16,0.8), -3px -3px 8px rgba(112,158,207,0.16), inset 0 1px 0 rgba(255,255,255,0.2)"
          : "4px 4px 10px rgba(170,186,208,0.36), -3px -3px 8px rgba(255,255,255,0.9), inset 0 1px 0 rgba(255,255,255,0.86)",
        color: dark ? "#e7f6ff" : "#27446f",
        fontFamily: "Orbitron",
        fontSize: size,
        fontWeight: 700,
        letterSpacing: 0.8,
        textShadow: dark ? `0 0 10px ${tone}44` : "none",
        ...style,
      }}
    >
      {value}
    </span>
  );
}

function ClayMetric({ label, value, tone = C.blue, size = 18, style = {} }) {
  return (
    <div style={style}>
      <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, marginBottom: 6 }}>{label}</div>
      <ClayNumber value={value} tone={tone} size={size} minWidth={size >= 18 ? 76 : 56} />
    </div>
  );
}

function Card({ children, style = {} }) {
  const [hover, setHover] = useState(false);
  const dark = isDarkTheme();
  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        background: dark ? "linear-gradient(160deg, #15243f 0%, #111d34 100%)" : "linear-gradient(160deg, #ebeff4 0%, #e1e6ed 100%)",
        border: `1px solid ${hover ? (dark ? "rgba(144,166,198,0.45)" : "rgba(112,136,166,0.35)") : C.border}`,
        borderRadius: 20,
        boxShadow: hover
          ? dark
            ? "0 20px 36px rgba(4,9,18,0.64), inset 0 1px 0 rgba(165,188,215,0.2), inset 0 -1px 0 rgba(6,17,31,0.6)"
            : "14px 14px 26px rgba(164,180,203,0.43), -10px -10px 24px rgba(239,243,248,0.72), inset 0 1px 0 rgba(241,245,248,0.8), inset 0 -1px 0 rgba(180,196,217,0.45)"
          : dark
            ? "0 14px 28px rgba(3,8,16,0.58), inset 0 1px 0 rgba(144,166,194,0.14), inset 0 -1px 0 rgba(6,17,31,0.56)"
            : "9px 9px 19px rgba(168,184,206,0.4), -8px -8px 18px rgba(239,243,248,0.72), inset 0 1px 0 rgba(241,245,248,0.8), inset 0 -1px 0 rgba(183,198,219,0.4)",
        transform: hover ? "translateY(-1px)" : "translateY(0)",
        transition: "all 180ms ease",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

const Btn = ({ children, onClick, disabled }) => {
  const dark = isDarkTheme();
  return (
    <button onClick={onClick} disabled={disabled} style={{ borderRadius: 12, border: dark ? "1px solid rgba(128,155,186,0.44)" : "1px solid rgba(104,131,166,0.3)", padding: "10px 16px", background: dark ? "linear-gradient(155deg, #233754, #1b2e49)" : "linear-gradient(155deg, #e4e9ef, #d6dde6)", color: dark ? "#d3e1f2" : "#2f4f79", fontFamily: "Orbitron", cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.45 : 1, boxShadow: dark ? "0 12px 24px rgba(5,10,18,0.42), inset 0 1px 0 rgba(177,196,221,0.2)" : "6px 6px 12px rgba(170,186,208,0.42), -5px -5px 12px rgba(238,243,248,0.72)" }}>
      <PressureText glow={dark ? C.cyan : C.blue} style={{ pointerEvents: "none" }}>{children}</PressureText>
    </button>
  );
};

const Badge = ({ status }) => (
  <span style={{ padding: "4px 10px", borderRadius: 8, border: `1px solid ${(statusColor[status] || C.dim)}55`, color: statusColor[status] || C.dim, fontSize: 10, fontFamily: "JetBrains Mono", letterSpacing: 1 }}>
    {status}
  </span>
);

function OpsStrip() {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 1200);
    return () => clearInterval(id);
  }, []);

  const ai = Math.max(35, Math.min(95, Math.round(64 + Math.sin(tick * 0.9) * 16)));
  const chain = Math.max(90, Math.min(100, Math.round(96 + Math.sin(tick * 0.5) * 2)));
  const bot = Math.max(20, Math.min(90, Math.round(42 + Math.cos(tick * 0.8) * 20)));

  const trendA = [44, 50, 53, 56, 60, 63, ai];
  const trendB = [96, 97, 95, 98, 97, 99, chain];
  const trendC = [58, 52, 49, 46, 44, 43, bot];

  return (
    <Card style={{ padding: 14, marginBottom: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <div style={{ fontFamily: "Orbitron", color: C.cyan, letterSpacing: 1.8, fontSize: 12 }}>
          <PressureText glow={C.blue}>QUANTHUNT OVERVIEW</PressureText>
        </div>
        <div style={{ fontFamily: "JetBrains Mono", color: C.dim, fontSize: 10, letterSpacing: 1.1 }}>
          LIVE RISK SNAPSHOT
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 10 }}>
        <TrendSpark label={`Risk Trend ${ai}%`} color={C.blue} values={trendA} />
        <TrendSpark label={`Security Trend ${chain}%`} color={C.green} values={trendB} />
        <TrendSpark label={`Exposure Trend ${bot}%`} color={C.orange} values={trendC} />
      </div>
    </Card>
  );
}

function CyberIntelPanel() {
  const [rows, setRows] = useState([]);
  useEffect(() => {
    const load = () =>
      fetch(`${API}/api/leaderboard`)
        .then((r) => r.json())
        .then((d) => setRows(d || []))
        .catch(() => setRows([]));
    load();
    const id = setInterval(load, 20000);
    return () => clearInterval(id);
  }, []);

  const normalized = rows.map((r) => Number(r.avg_score ?? r.average_hndl_risk ?? 0));
  const avg = normalized.length ? (normalized.reduce((a, b) => a + b, 0) / normalized.length).toFixed(1) : "-";
  const highest = rows[0];
  const secure = [...rows].sort((a, b) => Number(a.avg_score ?? 0) - Number(b.avg_score ?? 0))[0];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: 10, marginBottom: 14 }}>
      <Card style={{ padding: 14 }}>
        <ClayMetric label="PORTFOLIO AVG RISK" value={avg} tone={C.cyan} size={20} />
      </Card>
      <Card style={{ padding: 14 }}>
        <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10 }}>TOP RISK NODE</div>
        <div style={{ color: C.red, fontFamily: "Orbitron", fontSize: 14, marginTop: 6 }}>
          <PressureText glow={C.red}>{highest?.domain || "N/A"}</PressureText>
        </div>
      </Card>
      <Card style={{ padding: 14 }}>
        <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10 }}>MOST SECURE NODE</div>
        <div style={{ color: C.green, fontFamily: "Orbitron", fontSize: 14, marginTop: 6 }}>
          <PressureText glow={C.green}>{secure?.domain || "N/A"}</PressureText>
        </div>
      </Card>
    </div>
  );
}

function ScanOverlay({ domain, progress }) {
  const dark = isDarkTheme();
  const pct = Number(progress || 0);
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 45, pointerEvents: "none" }}>
      <div
        style={{
          position: "absolute",
          inset: 0,
          background: dark ? "rgba(6,15,28,0.62)" : "rgba(233,240,250,0.55)",
          backdropFilter: "blur(4px)",
        }}
      />
      <div
        style={{
          position: "absolute",
          left: "50%",
          top: "50%",
          transform: "translate(-50%, -50%)",
          width: 360,
          maxWidth: "88vw",
          borderRadius: 18,
          background: dark ? "linear-gradient(155deg, #14263f, #0f1f35)" : "linear-gradient(155deg, #e4e9ef, #d7dee6)",
          border: dark ? "1px solid rgba(107,178,240,0.36)" : "1px solid rgba(97,126,164,0.28)",
          boxShadow: dark
            ? "12px 12px 28px rgba(2,8,16,0.62), -10px -10px 22px rgba(24,48,80,0.5), inset 0 1px 0 rgba(168,218,255,0.18)"
            : "12px 12px 24px rgba(163,180,204,0.38), -10px -10px 22px rgba(255,255,255,0.9)",
          padding: 16,
        }}
      >
        <div style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: dark ? "#b8d2f4" : C.dim, marginBottom: 8 }}>
          Scanning target: {domain || "unknown"}
        </div>
        <div style={{ height: 10, borderRadius: 999, background: dark ? "#1a2b43" : "#d9e4f3", boxShadow: dark ? "inset 2px 2px 6px rgba(2,9,16,0.75), inset -2px -2px 6px rgba(59,88,126,0.3)" : "inset 2px 2px 6px rgba(161,178,202,0.4), inset -2px -2px 6px rgba(255,255,255,0.9)", overflow: "hidden" }}>
          <div style={{ width: `${pct}%`, height: "100%", borderRadius: 999, background: dark ? "linear-gradient(90deg, #7f9dc2, #9ab2d2)" : "linear-gradient(90deg, #698fbe, #8eacd0)", boxShadow: "none", transition: "width 180ms ease" }} />
        </div>
        <div style={{ marginTop: 7, textAlign: "right" }}>
          <ClayNumber value={`${pct}%`} tone={dark ? C.cyan : C.blue} size={10} minWidth={56} />
        </div>
      </div>
    </div>
  );
}

function ScannerTab() {
  const [domain, setDomain] = useState(BANK_PRESETS[0].domain);
  const [scanId, setScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [polling, setPolling] = useState(false);
  const [batch, setBatch] = useState("");
  const [formula, setFormula] = useState(null);
  const logRef = useRef(null);

  const statusScore = (status) => ({ CRITICAL: 100, WARNING: 50, ACCEPTABLE: 20, SAFE: 0 }[String(status || "").toUpperCase()] ?? 50);

  const computeHndlBreakdown = (list) => {
    const cat = {
      key_exchange: { score: 0, count: 0 },
      authentication: { score: 0, count: 0 },
      tls_version: { score: 0, count: 0 },
      certificate: { score: 0, count: 0 },
      symmetric: { score: 0, count: 0 },
    };
    (list || []).forEach((f) => {
      if (!cat[f.category]) return;
      cat[f.category].score += statusScore(f.status);
      cat[f.category].count += 1;
    });
    const avg = (k) => (cat[k].count ? (cat[k].score / cat[k].count) : 0);
    const raw = {
      key_exchange: avg("key_exchange"),
      authentication: avg("authentication"),
      tls_version: avg("tls_version"),
      certificate: avg("certificate"),
      symmetric: avg("symmetric"),
    };
    const weighted = {
      key_exchange: raw.key_exchange * 0.45,
      authentication: raw.authentication * 0.25,
      tls_version: raw.tls_version * 0.15,
      certificate: raw.certificate * 0.10,
      symmetric: raw.symmetric * 0.05,
    };
    return {
      raw,
      weighted,
      total: Number((weighted.key_exchange + weighted.authentication + weighted.tls_version + weighted.certificate + weighted.symmetric).toFixed(2)),
    };
  };

  const downloadArtifact = async (path, fallbackName) => {
    const r = await fetch(`${API}${path}`);
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      const detail = typeof err?.detail === "string" ? err.detail : "File unavailable right now.";
      alert(detail);
      return;
    }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const cd = r.headers.get("Content-Disposition") || "";
    const filename = /filename=([^;]+)/i.test(cd) ? cd.match(/filename=([^;]+)/i)[1].replace(/"/g, "") : fallbackName;
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const loadScanDetail = async (id) => {
    const detailResp = await fetch(`${API}/api/scan/${id}`);
    if (!detailResp.ok) return null;
    const detail = await detailResp.json();
    setScanData(detail);
    return detail;
  };

  const startScan = async () => {
    const target = domain.trim();
    if (!target) return;
    const r = await fetch(`${API}/api/scan`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: target, deep_scan: true }) });
    if (!r.ok) return alert("Scan failed to start");
    const d = await r.json();
    setScanId(d.scan_id);
    setFormula(null);

    // Reused completed scans are shown instantly instead of launching a new run.
    if (d.reused && d.status === "completed") {
      const detail = await loadScanDetail(d.scan_id);
      if (!detail) alert("Previous scan found, but details could not be loaded.");
      setPolling(false);
      return;
    }

    if (d.reused && (d.status === "queued" || d.status === "running")) {
      await loadScanDetail(d.scan_id);
    } else {
      setScanData(null);
    }
    setPolling(true);
  };

  useEffect(() => {
    if (!polling || !scanId) return;
    const id = setInterval(async () => {
      const r = await fetch(`${API}/api/scan/${scanId}`);
      if (!r.ok) return;
      const d = await r.json();
      setScanData(d);
      if (d.scan?.status === "completed" || d.scan?.status === "failed") setPolling(false);
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 1500);
    return () => clearInterval(id);
  }, [polling, scanId]);

  useEffect(() => {
    if (!scanData?.scan?.scan_id || scanData?.scan?.status !== "completed") return;
    let alive = true;
    fetch(`${API}/api/scan/${scanData.scan.scan_id}/findings`)
      .then((r) => (r.ok ? r.json() : { findings: [] }))
      .then((d) => {
        if (!alive) return;
        setFormula(computeHndlBreakdown(d.findings || []));
      })
      .catch(() => {
        if (alive) setFormula(null);
      });
    return () => {
      alive = false;
    };
  }, [scanData?.scan?.scan_id, scanData?.scan?.status]);

  const launchBatch = async () => {
    const domains = batch.split("\n").map((x) => x.trim()).filter(Boolean);
    if (!domains.length) return;
    const r = await fetch(`${API}/api/scan/batch`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domains }) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) {
      const detail = typeof d?.detail === "string" ? d.detail : d?.detail?.message || "Batch scan failed.";
      alert(detail);
      return;
    }
    const scheduled = Number(d?.scheduled ?? 0);
    const reused = Number(d?.reused ?? 0);
    alert(`Batch processed: ${scheduled} scheduled, ${reused} reused`);
  };

  return (
    <div style={{ display: "grid", gap: 18 }}>
      {polling && <ScanOverlay domain={scanData?.scan?.domain || domain} progress={scanData?.scan?.progress || 0} />}
      <Card style={{ padding: 24 }}>
        <h3 style={{ fontFamily: "Orbitron", color: C.cyan, marginTop: 0 }}><PressureText glow={C.cyan}>? DOMAIN SCANNER</PressureText></h3>
        <div style={{ display: "flex", gap: 10 }}>
          <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="pnbindia.in" style={{ flex: 1, borderRadius: 12, border: `1px solid ${C.border}`, background: "rgba(132,170,208,0.06)", color: C.text, padding: "12px 14px", fontFamily: "JetBrains Mono" }} />
          <Btn onClick={startScan} disabled={!domain.trim() || polling}>{polling ? "SCANNING..." : "SCAN"}</Btn>
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 7, marginTop: 10 }}>
          {BANK_PRESETS.map((b) => (
            <button
              key={b.domain}
              onClick={() => setDomain(b.domain)}
              style={{
                borderRadius: 10,
                border: `1px solid ${C.border}`,
                background: isDarkTheme() ? "rgba(18,40,70,0.85)" : "rgba(255,255,255,0.56)",
                color: C.dim,
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                padding: "5px 8px",
                cursor: "pointer",
              }}
            >
              {b.bank}
            </button>
          ))}
        </div>
        <div style={{ marginTop: 10, color: C.dim, fontFamily: "JetBrains Mono", fontSize: 12 }}>
          STATUS: <span style={{ color: C.cyan }}>{scanData?.scan?.status || "idle"}</span> ·{" "}
          <ClayNumber value={`${scanData?.scan?.progress || 0}%`} tone={isDarkTheme() ? C.cyan : C.blue} size={10} minWidth={56} />
        </div>
        {scanData?.chain_blocks?.length > 0 && (
          <div style={{ marginTop: 8, color: C.dim, fontFamily: "JetBrains Mono", fontSize: 11 }}>
            Audit block #{scanData.chain_blocks[scanData.chain_blocks.length - 1].block_index} anchored (hash-chain prefix: {String(scanData.chain_blocks[scanData.chain_blocks.length - 1].block_hash || "").slice(0, 12)}...)
          </div>
        )}
        {scanData?.scan?.scan_id && scanData?.scan?.status === "completed" && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12 }}>
            <Btn onClick={() => downloadArtifact(`/api/scan/${scanData.scan.scan_id}/report.pdf`, `quanthunt-report-${scanData.scan.scan_id}.pdf`)}>
              DOWNLOAD REPORT
            </Btn>
            <Btn onClick={() => downloadArtifact(`/api/scan/${scanData.scan.scan_id}/certificate.pdf`, `quanthunt-certificate-${scanData.scan.scan_id}.pdf`)}>
              QUANTUM READINESS CERTIFICATE
            </Btn>
          </div>
        )}
      </Card>

      {formula && (
        <Card style={{ padding: 18 }}>
          <div style={{ fontFamily: "Orbitron", color: C.blue, marginBottom: 8 }}>
            <PressureText glow={C.blue}>HNDL Formula Breakdown (Live)</PressureText>
          </div>
          <div style={{ display: "grid", gap: 8 }}>
            {[
              { key: "key_exchange", label: "Key Exchange", weight: 45 },
              { key: "authentication", label: "Auth", weight: 25 },
              { key: "tls_version", label: "TLS Version", weight: 15 },
              { key: "certificate", label: "Certificate", weight: 10 },
              { key: "symmetric", label: "Symmetric", weight: 5 },
            ].map((row) => (
              <div key={row.key} style={{ display: "grid", gridTemplateColumns: "160px 1fr 130px", gap: 8, alignItems: "center" }}>
                <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 11 }}>
                  {row.label} ({row.weight}%)
                </div>
                <div style={{ color: C.text, fontFamily: "JetBrains Mono", fontSize: 11 }}>
                  {formula.raw[row.key].toFixed(2)} x {(row.weight / 100).toFixed(2)}
                </div>
                <div style={{ textAlign: "right" }}>
                  <ClayNumber value={formula.weighted[row.key].toFixed(2)} tone={C.blue} size={10} minWidth={70} />
                </div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 10, color: C.dim, fontFamily: "JetBrains Mono", fontSize: 11 }}>
            Final HNDL Score:
            <ClayNumber value={formula.total.toFixed(2)} tone={riskColor(formula.total)} size={11} minWidth={76} style={{ marginLeft: 8 }} />
          </div>
        </Card>
      )}

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "12px 16px", borderBottom: `1px solid ${C.border}`, fontFamily: "JetBrains Mono", fontSize: 12, color: C.dim }}>TERMINAL LOG</div>
        <div ref={logRef} style={{ maxHeight: 260, overflowY: "auto", padding: 16, fontFamily: "JetBrains Mono", fontSize: 12, lineHeight: 1.6 }}>
          {(scanData?.logs || []).map((l, i) => <div key={i} style={{ color: l.message?.includes("ERROR") ? C.red : C.text }}>{l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : "--"} {l.message}</div>)}
        </div>
      </Card>

      <Card style={{ padding: 24 }}>
        <h3 style={{ fontFamily: "Orbitron", color: C.orange, marginTop: 0 }}><PressureText glow={C.orange}>? BATCH SCAN</PressureText></h3>
        <textarea value={batch} onChange={(e) => setBatch(e.target.value)} rows={6} placeholder={BANK_PRESETS.map((b) => b.domain).join("\n")} style={{ width: "100%", boxSizing: "border-box", borderRadius: 12, border: `1px solid rgba(185,152,112,0.35)`, background: "rgba(185,152,112,0.08)", color: C.text, padding: 12, fontFamily: "JetBrains Mono" }} />
        <Btn onClick={launchBatch}>LAUNCH BATCH</Btn>
      </Card>
    </div>
  );
}

function AssetMapTab() {
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [selected, setSelected] = useState(null);
  useEffect(() => { fetch(`${API}/api/scans`).then((r) => r.json()).then((d) => setScans((d || []).filter((x) => x.status === "completed"))); }, []);
  const load = async (s) => {
    setSelected(s.scan_id);
    const r = await fetch(`${API}/api/scan/${s.scan_id}`);
    const d = await r.json();
    setAssets(d.assets || []);
  };
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Card style={{ padding: 18 }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>{scans.map((s) => <button key={s.scan_id} onClick={() => load(s)} style={{ borderRadius: 10, padding: "8px 12px", border: `1px solid ${selected === s.scan_id ? C.cyan : C.border}`, background: selected === s.scan_id ? "rgba(141,181,220,0.15)" : "transparent", color: selected === s.scan_id ? C.cyan : C.dim, cursor: "pointer", fontFamily: "JetBrains Mono" }}>{s.domain}</button>)}</div>
      </Card>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))", gap: 14 }}>
        {assets.map((a) => <Card key={a.id} style={{ padding: 16 }}><div style={{ display: "flex", justifyContent: "space-between" }}><div><div style={{ color: C.text, fontFamily: "JetBrains Mono", fontSize: 12 }}>{a.hostname}</div><div style={{ color: C.dim, fontSize: 10 }}>{a.asset_type}</div></div><ClayNumber value={Number(a.risk_score || 0).toFixed(0)} tone={riskColor(a.risk_score)} size={16} minWidth={62} /></div><div style={{ marginTop: 10 }}><Badge status={a.label} /></div></Card>)}
      </div>
    </div>
  );
}

function CryptoTab() {
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [radar, setRadar] = useState([]);
  useEffect(() => { fetch(`${API}/api/scans`).then((r) => r.json()).then((d) => setScans((d || []).filter((x) => x.status === "completed"))); }, []);
  const load = async (scanId) => {
    const r = await fetch(`${API}/api/scan/${scanId}/findings`);
    const d = await r.json();
    const list = d.findings || [];
    setFindings(list);
    const cat = { key_exchange: 0, authentication: 0, symmetric: 0, certificate: 0 };
    const cnt = { key_exchange: 0, authentication: 0, symmetric: 0, certificate: 0 };
    list.forEach((f) => {
      if (cat[f.category] !== undefined) {
        cat[f.category] += ({ CRITICAL: 0, WARNING: 50, ACCEPTABLE: 80, SAFE: 100 }[f.status] || 0);
        cnt[f.category] += 1;
      }
    });
    setRadar([
      { axis: "Key Exchange", value: cnt.key_exchange ? cat.key_exchange / cnt.key_exchange : 0 },
      { axis: "Auth", value: cnt.authentication ? cat.authentication / cnt.authentication : 0 },
      { axis: "Symmetric", value: cnt.symmetric ? cat.symmetric / cnt.symmetric : 0 },
      { axis: "Certificate", value: cnt.certificate ? cat.certificate / cnt.certificate : 0 },
      { axis: "Protocol", value: 40 },
      { axis: "Hash", value: 35 },
    ]);
  };
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Card style={{ padding: 18 }}><div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>{scans.map((s) => <button key={s.scan_id} onClick={() => load(s.scan_id)} style={{ borderRadius: 10, padding: "8px 12px", border: `1px solid ${C.border}`, background: "transparent", color: C.dim, cursor: "pointer", fontFamily: "JetBrains Mono" }}>{s.domain}</button>)}</div></Card>
      {radar.length > 0 && (
        <Card style={{ padding: 20 }}>
          {HAS_RECHARTS ? (
            <ResponsiveContainer width="100%" height={280}>
              <RadarChart data={radar}>
                <PolarGrid stroke={C.border} />
                <PolarAngleAxis dataKey="axis" tick={{ fill: C.dim, fontSize: 10 }} />
                <Radar dataKey="value" stroke={C.cyan} fill={C.cyan} fillOpacity={0.15} />
              </RadarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ display: "grid", gap: 8 }}>
              {radar.map((r) => (
                <div key={r.axis} style={{ display: "grid", gridTemplateColumns: "130px 1fr 45px", gap: 8, alignItems: "center" }}>
                  <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 11 }}>{r.axis}</div>
                  <div style={{ height: 8, borderRadius: 999, background: isDarkTheme() ? "#10233f" : "#dce7f5" }}>
                    <div style={{ width: `${Math.max(1, r.value)}%`, height: "100%", borderRadius: 999, background: C.cyan }} />
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <ClayNumber value={r.value.toFixed(0)} tone={C.cyan} size={10} minWidth={48} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}
      <Card style={{ padding: 0, overflowX: "auto" }}>
        <table style={{ width: "100%", minWidth: 980, borderCollapse: "collapse", fontFamily: "JetBrains Mono", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Category</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Algorithm</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Primitive</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>OID</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Classical Level</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Key State</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>CERT-IN Map</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                <td style={{ padding: 10, color: C.dim }}>{f.category}</td>
                <td style={{ padding: 10, color: C.text }}>{f.algorithm_name || f.algorithm}</td>
                <td style={{ padding: 10, color: C.text }}>{f.primitive || "-"}</td>
                <td style={{ padding: 10, color: C.dim }}>{f.oid || "-"}</td>
                <td style={{ padding: 10, color: C.text }}>{f.classical_security_level || "-"}</td>
                <td style={{ padding: 10, color: C.text }}>{f.key_state || "-"}</td>
                <td style={{ padding: 10, color: C.dim }}>{f.cert_in_profile || "-"}</td>
                <td style={{ padding: 10 }}><Badge status={f.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function CBOMTab() {
  const [scans, setScans] = useState([]);
  const [cbom, setCbom] = useState(null);
  useEffect(() => { fetch(`${API}/api/scans`).then((r) => r.json()).then((d) => setScans((d || []).filter((x) => x.status === "completed"))); }, []);
  const load = async (id) => {
    const r = await fetch(`${API}/api/scan/${id}/cbom`);
    if (!r.ok) return setCbom(null);
    setCbom(await r.json());
  };
  const cbomText = (cbom ? JSON.stringify(cbom) : "").toUpperCase();
  const fipsRows = [
    {
      standard: "FIPS 203",
      algorithm: "ML-KEM (Kyber)",
      matched: /ML-KEM|MLKEM|KYBER|FIPS 203/.test(cbomText),
      requirement: "PQC Key Encapsulation",
    },
    {
      standard: "FIPS 204",
      algorithm: "ML-DSA (Dilithium)",
      matched: /ML-DSA|MLDSA|DILITHIUM|FIPS 204/.test(cbomText),
      requirement: "PQC Digital Signatures",
    },
    {
      standard: "FIPS 205",
      algorithm: "SLH-DSA (SPHINCS+)",
      matched: /SLH-DSA|SLHDSA|SPHINCS|FIPS 205/.test(cbomText),
      requirement: "Stateless Hash Signatures",
    },
  ];
  return (
    <div style={{ display: "grid", gap: 14 }}>
      <Card style={{ padding: 16 }}><div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>{scans.map((s) => <button key={s.scan_id} onClick={() => load(s.scan_id)} style={{ borderRadius: 10, padding: "8px 12px", border: `1px solid ${C.border}`, background: "transparent", color: C.dim, cursor: "pointer", fontFamily: "JetBrains Mono" }}>{s.domain}</button>)}</div></Card>
      <Card style={{ padding: 16 }}>
        <div style={{ fontFamily: "Orbitron", color: C.blue, marginBottom: 8 }}>
          <PressureText glow={C.blue}>NIST PQC Compliance Mapping</PressureText>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "JetBrains Mono", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              <th style={{ textAlign: "left", padding: "8px 6px", color: C.dim }}>Standard</th>
              <th style={{ textAlign: "left", padding: "8px 6px", color: C.dim }}>Algorithm Family</th>
              <th style={{ textAlign: "left", padding: "8px 6px", color: C.dim }}>Requirement</th>
              <th style={{ textAlign: "left", padding: "8px 6px", color: C.dim }}>Observed in CBOM</th>
            </tr>
          </thead>
          <tbody>
            {fipsRows.map((r) => (
              <tr key={r.standard} style={{ borderBottom: `1px solid ${C.border}` }}>
                <td style={{ padding: "8px 6px", color: C.text }}>{r.standard}</td>
                <td style={{ padding: "8px 6px", color: C.text }}>{r.algorithm}</td>
                <td style={{ padding: "8px 6px", color: C.dim }}>{r.requirement}</td>
                <td style={{ padding: "8px 6px" }}>
                  <Badge status={r.matched ? "SAFE" : "WARNING"} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Card style={{ padding: 16 }}><pre style={{ margin: 0, whiteSpace: "pre-wrap", color: C.text, fontFamily: "JetBrains Mono", fontSize: 12 }}>{cbom ? JSON.stringify(cbom, null, 2) : "Select a completed scan to view CBOM."}</pre></Card>
    </div>
  );
}

function RoadmapTab() {
  const [scans, setScans] = useState([]);
  const [recs, setRecs] = useState([]);
  useEffect(() => { fetch(`${API}/api/scans`).then((r) => r.json()).then((d) => setScans((d || []).filter((x) => x.status === "completed"))); }, []);
  const load = async (id) => {
    const r = await fetch(`${API}/api/scan/${id}/findings`);
    const d = await r.json();
    setRecs(d.recommendations || []);
  };
  return (
    <div style={{ display: "grid", gap: 14 }}>
      <Card style={{ padding: 16 }}><div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>{scans.map((s) => <button key={s.scan_id} onClick={() => load(s.scan_id)} style={{ borderRadius: 10, padding: "8px 12px", border: `1px solid ${C.border}`, background: "transparent", color: C.dim, cursor: "pointer", fontFamily: "JetBrains Mono" }}>{s.domain}</button>)}</div></Card>
      {["Phase 1", "Phase 2", "Phase 3", "Phase 4"].map((phase) => {
        const list = recs.filter((r) => r.phase === phase);
        if (!list.length) return null;
        return <Card key={phase} style={{ padding: 18 }}><h4 style={{ marginTop: 0, fontFamily: "Orbitron", color: C.cyan }}>{phase}</h4>{list.map((r) => <div key={r.id} style={{ color: C.text, marginBottom: 8, fontSize: 13 }}>? {r.text}</div>)}</Card>;
      })}
    </div>
  );
}

function LeaderboardTab() {
  const [rows, setRows] = useState([]);
  const [assetRows, setAssetRows] = useState([]);
  const [assetLoading, setAssetLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/leaderboard`)
      .then((r) => r.json())
      .then((d) => setRows(d || []))
      .catch(() => setRows([]));
  }, []);

  useEffect(() => {
    let alive = true;
    const loadAssetRows = async () => {
      setAssetLoading(true);
      try {
        const scansResp = await fetch(`${API}/api/scans`);
        const scansRaw = scansResp.ok ? await scansResp.json() : [];
        const completed = (scansRaw || []).filter((x) => x.status === "completed");
        const seen = new Set();
        const latestPerDomain = [];
        for (const scan of completed) {
          const key = String(scan.domain || "").toLowerCase();
          if (!key || seen.has(key)) continue;
          seen.add(key);
          latestPerDomain.push(scan);
          if (latestPerDomain.length >= 20) break;
        }
        const detailRows = await Promise.all(
          latestPerDomain.map(async (scan) => {
            try {
              const r = await fetch(`${API}/api/scan/${scan.scan_id}`);
              if (!r.ok) return null;
              const data = await r.json();
              const assets = data.assets || [];
              const scores = assets
                .map((a) => Number(a.risk_score ?? 0))
                .filter((n) => Number.isFinite(n));
              if (!scores.length) return null;
              return {
                scan_id: scan.scan_id,
                domain: data.scan?.domain || scan.domain,
                asset_count: scores.length,
                avg_risk: Number((scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(2)),
                safe_score: Number(Math.min(...scores).toFixed(2)),
                risk_score: Number(Math.max(...scores).toFixed(2)),
              };
            } catch {
              return null;
            }
          }),
        );
        if (!alive) return;
        setAssetRows(detailRows.filter(Boolean));
      } catch {
        if (alive) setAssetRows([]);
      } finally {
        if (alive) setAssetLoading(false);
      }
    };
    loadAssetRows();
    return () => {
      alive = false;
    };
  }, []);

  const normalized = rows
    .map((r) => ({ ...r, avg_score: Number(r.avg_score ?? r.average_hndl_risk ?? 0) }))
    .sort((a, b) => b.avg_score - a.avg_score);
  const highestRisk = normalized[0] || null;
  const mostSecure = [...normalized].sort((a, b) => a.avg_score - b.avg_score)[0] || null;
  const fallbackAssetRows = normalized.map((r) => ({
    scan_id: r.scan_id,
    domain: r.domain,
    asset_count: Number(r.asset_count || 0),
    avg_risk: Number(r.avg_score || 0),
    safe_score: Math.max(0, Number(r.avg_score || 0) - 12),
    risk_score: Math.min(100, Number(r.avg_score || 0) + 12),
  }));
  const effectiveAssetRows = (assetRows.length ? assetRows : fallbackAssetRows.length ? fallbackAssetRows : BANK_DEMO_ROWS).filter((r) => Number.isFinite(r.avg_risk));
  const riskiestFirst = [...effectiveAssetRows].sort((a, b) => b.avg_risk - a.avg_risk).slice(0, 10);
  const safestToRiskiest = [...effectiveAssetRows]
    .sort((a, b) => a.avg_risk - b.avg_risk)
    .slice(0, 10)
    .map((r, i) => ({ ...r, rank: `#${i + 1}` }));
  const analysisTarget = riskiestFirst[0];
  const predictionText = analysisTarget
    ? `If ${analysisTarget.domain} keeps current control coverage, risk may move to ${Math.min(100, analysisTarget.avg_risk + 6).toFixed(1)} in 90 days due to exposed endpoints and crypto drift.`
    : "No prediction available until bank data is present.";
  const solutionList = analysisTarget
    ? [
      `Prioritize top 10 high-risk assets under ${analysisTarget.domain} and patch TLS/cipher weaknesses.`,
      "Enforce certificate/key rotation policy and monitor weak-signature detections weekly.",
      "Run monthly scan batch for all bank domains and compare risk deltas against baseline.",
    ]
    : ["Run at least one completed bank scan to generate solution recommendations."];

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 12 }}>
        <Card style={{ padding: 16 }}>
          <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, marginBottom: 6 }}>HIGHEST RISK WEBSITE</div>
          <div style={{ fontFamily: "Orbitron", color: C.red, fontSize: 16 }}>
            <PressureText glow={C.red}>{highestRisk?.domain || "N/A"}</PressureText>
          </div>
          <div style={{ marginTop: 6 }}>Score: <ClayNumber value={highestRisk?.avg_score ?? "-"} tone={C.red} size={10} minWidth={56} style={{ marginLeft: 6 }} /></div>
        </Card>
        <Card style={{ padding: 16 }}>
          <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, marginBottom: 6 }}>MOST SECURE WEBSITE</div>
          <div style={{ fontFamily: "Orbitron", color: C.green, fontSize: 16 }}>
            <PressureText glow={C.green}>{mostSecure?.domain || "N/A"}</PressureText>
          </div>
          <div style={{ marginTop: 6 }}>Score: <ClayNumber value={mostSecure?.avg_score ?? "-"} tone={C.green} size={10} minWidth={56} style={{ marginLeft: 6 }} /></div>
        </Card>
      </div>

      <Card style={{ padding: 18 }}>
        <div style={{ marginBottom: 8, color: C.blue, fontFamily: "Orbitron", fontSize: 12, letterSpacing: 1.2 }}>
          <PressureText glow={C.blue}>ASSET RISK LADDER (SAFEST TO RISKIEST)</PressureText>
        </div>
        {!HAS_RECHARTS && (
          <div style={{ marginBottom: 8, color: C.dim, fontFamily: "JetBrains Mono", fontSize: 11 }}>
            Recharts unavailable; using built-in fallback visualization.
          </div>
        )}
        {safestToRiskiest.length > 0 && HAS_RECHARTS ? (
          <ResponsiveContainer width="100%" height={290}>
            <BarChart data={safestToRiskiest} layout="vertical" margin={{ top: 4, right: 12, left: 30, bottom: 2 }}>
              <CartesianGrid stroke="rgba(98,118,154,0.12)" strokeDasharray="3 3" />
              <XAxis type="number" domain={[0, 100]} tick={{ fill: C.dim, fontSize: 10 }} />
              <YAxis type="category" dataKey="domain" width={140} tick={{ fill: C.dim, fontSize: 10 }} />
              <Tooltip
                contentStyle={{
                  background: "#e2e8ef",
                  border: "1px solid rgba(98,118,154,0.2)",
                  borderRadius: 10,
                  color: C.text,
                }}
              />
              <Bar dataKey="avg_risk" radius={[8, 8, 8, 8]}>
                {safestToRiskiest.map((r, i) => <Cell key={i} fill={riskColor(r.avg_risk)} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : safestToRiskiest.length > 0 ? (
          <div style={{ display: "grid", gap: 8 }}>
            {safestToRiskiest.map((r) => (
              <div key={r.scan_id} style={{ display: "grid", gridTemplateColumns: "150px 1fr 48px", gap: 8, alignItems: "center" }}>
                <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 11 }}>{r.domain}</div>
                <div style={{ height: 10, borderRadius: 999, background: isDarkTheme() ? "#10233f" : "#dce7f5", overflow: "hidden" }}>
                  <div style={{ width: `${Math.max(1, r.avg_risk)}%`, height: "100%", borderRadius: 999, background: riskColor(r.avg_risk), boxShadow: isDarkTheme() ? `0 0 10px ${riskColor(r.avg_risk)}99` : "none" }} />
                </div>
                <div style={{ textAlign: "right" }}>
                  <ClayNumber value={r.avg_risk.toFixed(1)} tone={riskColor(r.avg_risk)} size={10} minWidth={52} />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 12 }}>No completed scan asset data yet.</div>
        )}
      </Card>

      <Card style={{ padding: 18 }}>
        <div style={{ marginBottom: 8, color: C.blue, fontFamily: "Orbitron", fontSize: 12, letterSpacing: 1.2 }}>
          <PressureText glow={C.blue}>SAFE VS RISK SPREAD BY SITE</PressureText>
        </div>
        {safestToRiskiest.length > 0 && HAS_RECHARTS ? (
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={safestToRiskiest} margin={{ top: 8, right: 12, left: 2, bottom: 0 }}>
              <defs>
                <linearGradient id="safeAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.green} stopOpacity={0.42} />
                  <stop offset="100%" stopColor={C.green} stopOpacity={0.03} />
                </linearGradient>
                <linearGradient id="riskMidAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.yellow} stopOpacity={0.34} />
                  <stop offset="100%" stopColor={C.yellow} stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="riskHighAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.red} stopOpacity={0.28} />
                  <stop offset="100%" stopColor={C.red} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(98,118,154,0.12)" strokeDasharray="3 3" />
              <XAxis dataKey="domain" tick={{ fill: C.dim, fontSize: 10 }} />
              <YAxis domain={[0, 100]} tick={{ fill: C.dim, fontSize: 10 }} />
              <Tooltip
                contentStyle={{
                  background: "#e2e8ef",
                  border: "1px solid rgba(98,118,154,0.2)",
                  borderRadius: 10,
                  color: C.text,
                }}
              />
              <Area type="monotone" dataKey="safe_score" stroke={C.green} fill="url(#safeAreaGrad)" strokeWidth={2.4} />
              <Area type="monotone" dataKey="avg_risk" stroke={C.yellow} fill="url(#riskMidAreaGrad)" strokeWidth={2.2} />
              <Area type="monotone" dataKey="risk_score" stroke={C.red} fill="url(#riskHighAreaGrad)" strokeWidth={2.2} />
            </AreaChart>
          </ResponsiveContainer>
        ) : safestToRiskiest.length > 0 ? (
          <div style={{ display: "grid", gap: 8 }}>
            {safestToRiskiest.map((r) => (
              <div key={r.scan_id} style={{ color: C.text, fontFamily: "JetBrains Mono", fontSize: 11 }}>
                {r.domain}: safe {r.safe_score.toFixed(1)} | avg {r.avg_risk.toFixed(1)} | risk {r.risk_score.toFixed(1)}
              </div>
            ))}
          </div>
        ) : (
          <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 12 }}>Waiting for risk spread data.</div>
        )}
      </Card>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "10px 12px", fontFamily: "JetBrains Mono", color: C.dim, borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
          SITE ASSET RISK TABLE {assetLoading ? "(loading backend data)" : ""}
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "JetBrains Mono", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Domain</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Assets</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Safest</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Avg</th>
              <th style={{ textAlign: "left", padding: 10, color: C.dim }}>Riskiest</th>
            </tr>
          </thead>
          <tbody>
            {riskiestFirst.map((r) => (
              <tr key={r.scan_id}>
                <td style={{ padding: 10, color: C.text }}>{r.domain}</td>
                <td style={{ padding: 10 }}><ClayNumber value={r.asset_count} tone={C.blue} size={10} minWidth={50} /></td>
                <td style={{ padding: 10 }}><ClayNumber value={r.safe_score.toFixed(1)} tone={C.green} size={10} minWidth={56} /></td>
                <td style={{ padding: 10 }}><ClayNumber value={r.avg_risk.toFixed(1)} tone={riskColor(r.avg_risk)} size={10} minWidth={56} /></td>
                <td style={{ padding: 10 }}><ClayNumber value={r.risk_score.toFixed(1)} tone={C.red} size={10} minWidth={56} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card style={{ padding: 18 }}>
        {HAS_RECHARTS ? (
          <ResponsiveContainer width="100%" height={230}>
            <AreaChart data={(normalized.length ? normalized : BANK_DEMO_ROWS.map((x) => ({ domain: x.domain, avg_score: x.avg_risk }))).slice(0, 10)} margin={{ top: 8, right: 12, left: 2, bottom: 0 }}>
              <defs>
                <linearGradient id="avgRiskAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.blue} stopOpacity={0.42} />
                  <stop offset="100%" stopColor={C.blue} stopOpacity={0.03} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(98,118,154,0.12)" strokeDasharray="3 3" />
              <XAxis dataKey="domain" tick={{ fill: C.dim, fontSize: 10 }} />
              <YAxis domain={[0, 100]} tick={{ fill: C.dim, fontSize: 10 }} />
              <Tooltip
                contentStyle={{
                  background: "#e2e8ef",
                  border: "1px solid rgba(98,118,154,0.2)",
                  borderRadius: 10,
                  color: C.text,
                }}
              />
              <Area type="monotone" dataKey="avg_score" stroke={C.blue} strokeWidth={2.5} fill="url(#avgRiskAreaGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 12 }}>
            Recharts unavailable; risk trend line fallback active.
          </div>
        )}
      </Card>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 12 }}>
        <Card style={{ padding: 16 }}>
          <div style={{ fontFamily: "Orbitron", color: C.blue, marginBottom: 8 }}>Analysis</div>
          <div style={{ color: C.text, fontFamily: "JetBrains Mono", fontSize: 12, lineHeight: 1.6 }}>
            {analysisTarget
              ? `${analysisTarget.domain} is currently the highest-risk bank target with avg risk ${analysisTarget.avg_risk.toFixed(1)} over ${analysisTarget.asset_count} assets.`
              : "Run a bank scan to generate analysis."}
          </div>
        </Card>
        <Card style={{ padding: 16 }}>
          <div style={{ fontFamily: "Orbitron", color: C.blue, marginBottom: 8 }}>Prediction</div>
          <div style={{ color: C.text, fontFamily: "JetBrains Mono", fontSize: 12, lineHeight: 1.6 }}>
            {predictionText}
          </div>
        </Card>
        <Card style={{ padding: 16 }}>
          <div style={{ fontFamily: "Orbitron", color: C.blue, marginBottom: 8 }}>Solutions</div>
          <div style={{ color: C.text, fontFamily: "JetBrains Mono", fontSize: 12, lineHeight: 1.6 }}>
            {solutionList.map((s, i) => <div key={i}>- {s}</div>)}
          </div>
        </Card>
      </div>
    </div>
  );
}

function BankSignalLabTab() {
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState("");

  useEffect(() => {
    fetch(`${API}/api/leaderboard`)
      .then((r) => r.json())
      .then((d) => {
        const normalized = (d || [])
          .map((x) => ({
            domain: String(x.domain || "").toLowerCase(),
            avg_risk: Number(x.avg_score ?? x.average_hndl_risk ?? 0),
            asset_count: Number(x.asset_count || 0),
          }))
          .filter((x) => BANK_PRESETS.some((b) => b.domain === x.domain));
        setRows(normalized.length ? normalized : BANK_DEMO_ROWS);
      })
      .catch(() => setRows(BANK_DEMO_ROWS));
  }, []);

  const available = rows.length ? rows : BANK_DEMO_ROWS;
  useEffect(() => {
    if (!selected && available.length) setSelected(available[0].domain);
  }, [selected, available]);

  const selectedRow = available.find((r) => r.domain === selected) || null;
  const lineUp = [...available]
    .sort((a, b) => securityScore(b.avg_risk) - securityScore(a.avg_risk))
    .map((r, i) => ({
      bank: getBankLabel(r.domain),
      domain: r.domain,
      security: Number(securityScore(r.avg_risk).toFixed(2)),
      risk: Number(r.avg_risk.toFixed ? r.avg_risk.toFixed(2) : Number(r.avg_risk || 0).toFixed(2)),
      asset_count: Number(r.asset_count || 0),
      rank: i + 1,
    }));
  const recs = selectedRow ? (BANK_REQUIREMENTS[selectedRow.domain] || [
    "Patch highest-risk exposed assets first.",
    "Rotate weak cert/signature chains and enforce TLS baseline.",
    "Track weekly risk movement and verify mitigation closure.",
  ]) : [];

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <Card style={{ padding: 16 }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center" }}>
          <div style={{ color: C.blue, fontFamily: "Orbitron", fontSize: 13, letterSpacing: 1.1 }}>
            <PressureText glow={C.blue}>BANK INSIGHT STUDIO</PressureText>
          </div>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 11 }}>Select bank</span>
            <select
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              style={{
                borderRadius: 10,
                border: `1px solid ${C.border}`,
                background: isDarkTheme() ? "rgba(13,28,49,0.84)" : "rgba(255,255,255,0.68)",
                color: C.text,
                padding: "8px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 11,
              }}
            >
              {available.map((r) => (
                <option key={r.domain} value={r.domain}>
                  {getBankLabel(r.domain)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(250px,1fr))", gap: 12 }}>
        <Card style={{ padding: 16 }}>
          <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, marginBottom: 6 }}>Selected Bank</div>
          <div style={{ color: C.text, fontFamily: "Orbitron", fontSize: 16 }}>{selectedRow ? getBankLabel(selectedRow.domain) : "N/A"}</div>
          <div style={{ marginTop: 8, fontFamily: "JetBrains Mono", fontSize: 12 }}>
            Risk Score: <ClayNumber value={selectedRow ? Number(selectedRow.avg_risk).toFixed(1) : "-"} tone={riskColor(selectedRow?.avg_risk ?? 0)} size={10} minWidth={56} style={{ marginLeft: 6 }} />
          </div>
          <div style={{ marginTop: 4, fontFamily: "JetBrains Mono", fontSize: 12 }}>
            Security Score: <ClayNumber value={selectedRow ? securityScore(selectedRow.avg_risk).toFixed(1) : "-"} tone={C.green} size={10} minWidth={56} style={{ marginLeft: 6 }} />
          </div>
          <div style={{ marginTop: 4, color: C.dim, fontFamily: "JetBrains Mono", fontSize: 11 }}>
            Assets considered: <ClayNumber value={selectedRow?.asset_count ?? "-"} tone={C.blue} size={10} minWidth={52} style={{ marginLeft: 6 }} />
          </div>
        </Card>
        <Card style={{ padding: 16 }}>
          <div style={{ color: C.blue, fontFamily: "Orbitron", fontSize: 12, marginBottom: 8 }}>Required Actions ({selectedRow ? getBankLabel(selectedRow.domain) : "Bank"})</div>
          <div style={{ color: C.text, fontFamily: "JetBrains Mono", fontSize: 12, lineHeight: 1.6 }}>
            {recs.map((r, i) => <div key={i}>- {r}</div>)}
          </div>
        </Card>
      </div>

      <ClayBankAnalysisGraph selectedRow={selectedRow} lineUp={lineUp} />

      <Card style={{ padding: 16 }}>
        <div style={{ color: C.blue, fontFamily: "Orbitron", fontSize: 12, marginBottom: 8 }}>
          Security Line-up Across Major Indian Banks
        </div>
        {HAS_RECHARTS ? (
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={lineUp} margin={{ top: 8, right: 12, left: 2, bottom: 0 }}>
              <defs>
                <linearGradient id="bankSecArea" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.green} stopOpacity={0.4} />
                  <stop offset="100%" stopColor={C.green} stopOpacity={0.03} />
                </linearGradient>
                <linearGradient id="bankRiskArea" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.red} stopOpacity={0.32} />
                  <stop offset="100%" stopColor={C.red} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(98,118,154,0.12)" strokeDasharray="3 3" />
              <XAxis dataKey="bank" tick={{ fill: C.dim, fontSize: 10 }} />
              <YAxis domain={[0, 100]} tick={{ fill: C.dim, fontSize: 10 }} />
              <Tooltip
                contentStyle={{
                  background: isDarkTheme() ? "rgba(14,30,53,0.95)" : "#e2e8ef",
                  border: `1px solid ${C.border}`,
                  borderRadius: 10,
                  color: C.text,
                }}
              />
              <Area type="monotone" dataKey="security" stroke={C.green} strokeWidth={2.4} fill="url(#bankSecArea)" />
              <Area type="monotone" dataKey="risk" stroke={C.red} strokeWidth={2.2} fill="url(#bankRiskArea)" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div style={{ display: "grid", gap: 8 }}>
            {lineUp.map((r) => (
              <div key={r.domain} style={{ display: "grid", gridTemplateColumns: "170px 1fr 48px", gap: 8, alignItems: "center" }}>
                <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 11 }}>{r.bank}</div>
                <div style={{ height: 10, borderRadius: 999, background: isDarkTheme() ? "#10233f" : "#dce7f5", overflow: "hidden" }}>
                  <div style={{ width: `${Math.max(1, r.security)}%`, height: "100%", borderRadius: 999, background: C.green }} />
                </div>
                <div style={{ textAlign: "right" }}>
                  <ClayNumber value={r.security.toFixed(1)} tone={C.green} size={10} minWidth={52} />
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function OmegaGPTFloating({ theme = "light" }) {
  const dark = theme === "dark";
  const [open, setOpen] = useState(false);
  const [fabPressed, setFabPressed] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "Quanthunt assistant is ready. Ask: safety ranking, riskiest bank, analysis, prediction, solutions, PQC limits, or demo script. Offline fallback is always available.",
    },
  ]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [context, setContext] = useState("");
  const [contextSource, setContextSource] = useState("backend");
  const [sourceMode, setSourceMode] = useState("auto");
  const [focusMode, setFocusMode] = useState("general");
  const [showPrompts, setShowPrompts] = useState(false);
  const chatRef = useRef(null);

  useEffect(() => {
    fetch(`${API}/api/leaderboard`)
      .then((r) => r.json())
      .then((d) => {
        const rows = (d || []).slice(0, 10);
        if (rows.length) {
          const ctx = rows
            .map((x, i) => `${i + 1}. ${x.domain} score=${x.avg_score} assets=${x.asset_count}`)
            .join("\n");
          setContext(`Source=backend\n${ctx}`);
          setContextSource("backend");
          return;
        }
        const fallback = BANK_DEMO_ROWS.map((x, i) => `${i + 1}. ${x.domain} score=${x.avg_risk} assets=${x.asset_count}`).join("\n");
        setContext(`Source=demo-bank-baseline\n${fallback}`);
        setContextSource("demo");
      })
      .catch(() => {
        const fallback = BANK_DEMO_ROWS.map((x, i) => `${i + 1}. ${x.domain} score=${x.avg_risk} assets=${x.asset_count}`).join("\n");
        setContext(`Source=demo-bank-baseline\n${fallback}`);
        setContextSource("demo");
      });
  }, []);

  useEffect(() => {
    const el = chatRef.current;
    if (!el) return;
    el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [messages, sending, open]);

  const toggleOpen = () => {
    setFabPressed(true);
    setTimeout(() => setFabPressed(false), 180);
    setOpen((v) => !v);
  };

  const sendMessage = async (preset) => {
    const msg = (preset ?? input).trim();
    if (!msg || sending) return;
    setMessages((m) => [...m, { role: "user", text: msg }]);
    setInput("");
    setSending(true);
    try {
      let outbound = msg;
      if (focusMode !== "general" && !outbound.toLowerCase().includes(focusMode)) {
        outbound = `${outbound}\nfocus:${focusMode}`;
      }
      const r = await fetch(`${API}/api/omegagpt/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: outbound, context, mode: sourceMode, focus: focusMode }),
      });
      const d = await r.json();
      if (!r.ok) {
        const err = d?.detail ? (typeof d.detail === "string" ? d.detail : JSON.stringify(d.detail)) : "Request failed.";
        setMessages((m) => [...m, { role: "assistant", text: `Assistant API error (${r.status}): ${err}` }]);
      } else {
        const source = d?.source ? `\n\n[source: ${d.source}]` : "";
        const offline = d?.offline_mode ? "\n[offline mode active]" : "";
        const reason = d?.offline_reason ? `\n[offline reason: ${d.offline_reason}]` : "";
        const text = d?.reply || d?.message || JSON.stringify(d);
        setMessages((m) => [...m, { role: "assistant", text: `${text || "No response."}${source}${offline}${reason}` }]);
      }
    } catch {
      setMessages((m) => [...m, { role: "assistant", text: "Assistant request failed." }]);
    } finally {
      setSending(false);
    }
  };

  const quick = [
    "best bank in terms of safety",
    "which bank is riskiest and why",
    "give analysis",
    "give prediction for next 90 days",
    "give solution plan",
    "top 3 risky banks",
    "top 3 safest banks",
    "pqc detection limits",
    "explain chain block meaning",
    "certificate criteria",
    "testing coverage",
    "frontend polish checklist",
    "demo script for judges",
    "cors stance for production",
    "known limitations",
  ];
  const featuredQuick = quick.slice(0, 4);

  return (
    <>
      <button
        onClick={toggleOpen}
        title="Open Assistant"
        style={{
          position: "fixed",
          right: 24,
          bottom: 24,
          zIndex: 30,
          width: 66,
          height: 66,
          borderRadius: "50%",
          border: dark ? "1px solid rgba(141,162,189,0.52)" : "1px solid rgba(99,127,161,0.32)",
          background: dark ? "linear-gradient(160deg, #223754, #1a2c46)" : "linear-gradient(160deg, #eef3fb, #d8e4f4)",
          boxShadow: dark ? "0 18px 30px rgba(6,10,16,0.54), inset 0 1px 0 rgba(177,197,221,0.18)" : "8px 8px 18px rgba(168,184,206,0.42), -8px -8px 18px rgba(255,255,255,0.92)",
          cursor: "pointer",
          display: "grid",
          placeItems: "center",
          transform: fabPressed ? "scale(0.92)" : open ? "scale(1.04) translateY(-2px)" : "scale(1)",
          transition: "transform 180ms ease, box-shadow 240ms ease",
        }}
      >
        <div style={{ transform: "scale(0.92)" }}>
          <Logo size={34} animated={false} />
        </div>
      </button>

      <div
        className="omega-panel"
        style={{
          position: "fixed",
          right: 24,
          bottom: 102,
          width: "min(468px, calc(100vw - 28px))",
          maxHeight: "76vh",
          zIndex: 30,
          borderRadius: 20,
          overflow: "hidden",
          border: dark ? "1px solid rgba(158,182,212,0.44)" : "1px solid rgba(118,142,173,0.34)",
          background: dark
            ? "linear-gradient(158deg, rgba(28,45,69,0.8), rgba(18,31,50,0.82))"
            : "linear-gradient(158deg, rgba(235,242,251,0.84), rgba(222,233,246,0.82))",
          backdropFilter: "blur(14px) saturate(130%)",
          boxShadow: open
              ? dark
                ? "0 26px 42px rgba(5,10,18,0.66), 0 8px 22px rgba(10,28,49,0.38), inset 0 1px 0 rgba(195,214,235,0.28), inset 0 -1px 0 rgba(8,18,30,0.45)"
              : "16px 20px 34px rgba(162,178,201,0.42), -12px -12px 24px rgba(255,255,255,0.88), inset 0 1px 0 rgba(255,255,255,0.7), inset 0 -1px 0 rgba(150,173,202,0.26)"
            : "0 0 0 rgba(0,0,0,0)",
          display: "grid",
          gridTemplateRows: "auto auto auto 1fr auto",
          opacity: open ? 1 : 0,
          transform: open ? "translateY(0) scale(1)" : "translateY(26px) scale(0.95)",
          transformOrigin: "bottom right",
          transition: "opacity 240ms ease, transform 320ms cubic-bezier(0.22, 1, 0.36, 1), box-shadow 280ms ease",
          pointerEvents: open ? "auto" : "none",
        }}
      >
        <div
          className="omega-liquid omega-liquid-a"
          style={{
            position: "absolute",
            inset: "-12% -28% auto auto",
            width: 220,
            height: 220,
            borderRadius: "52% 48% 58% 42%",
            background: dark ? "radial-gradient(circle at 30% 30%, rgba(177,212,245,0.2), rgba(76,114,157,0.06) 64%, transparent 72%)" : "radial-gradient(circle at 30% 30%, rgba(198,221,245,0.44), rgba(120,158,199,0.14) 64%, transparent 72%)",
            filter: "blur(2px)",
            pointerEvents: "none",
            zIndex: 0,
          }}
        />
        <div
          className="omega-liquid omega-liquid-b"
          style={{
            position: "absolute",
            inset: "auto auto -18% -22%",
            width: 210,
            height: 210,
            borderRadius: "46% 54% 42% 58%",
            background: dark ? "radial-gradient(circle at 30% 30%, rgba(146,188,230,0.14), rgba(78,116,155,0.04) 66%, transparent 74%)" : "radial-gradient(circle at 30% 30%, rgba(188,213,241,0.34), rgba(113,150,190,0.1) 66%, transparent 74%)",
            filter: "blur(3px)",
            pointerEvents: "none",
            zIndex: 0,
          }}
        />
        <div
          style={{
            position: "relative",
            zIndex: 1,
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "12px 14px",
            borderBottom: dark ? "1px solid rgba(162,181,204,0.22)" : "1px solid rgba(110,132,162,0.2)",
            background: dark ? "linear-gradient(180deg, rgba(31,49,73,0.74), rgba(23,39,61,0.54))" : "linear-gradient(180deg, rgba(244,249,255,0.75), rgba(231,239,249,0.55))",
            boxShadow: dark ? "inset 0 1px 0 rgba(201,219,238,0.18)" : "inset 0 1px 0 rgba(255,255,255,0.7)",
          }}
        >
          <Logo size={22} animated={false} />
          <div style={{ fontFamily: "Orbitron", color: dark ? "#d9e4f2" : "#2f4f7b", fontSize: 12, letterSpacing: 1.4 }}>
            <PressureText glow={dark ? C.cyan : C.blue}>QUANTHUNT ASSISTANT</PressureText>
          </div>
          <div style={{ marginLeft: "auto", color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, padding: "4px 9px", borderRadius: 999, border: dark ? "1px solid rgba(149,173,202,0.34)" : "1px solid rgba(112,138,170,0.3)", background: dark ? "rgba(32,50,74,0.52)" : "rgba(240,246,253,0.64)" }}>
            context: {contextSource}
          </div>
        </div>

        <div
          className="omega-controls"
          style={{
            position: "relative",
            zIndex: 1,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 10,
            padding: "10px 12px",
            borderBottom: dark ? "1px solid rgba(148,168,191,0.16)" : "1px solid rgba(92,126,168,0.16)",
          }}
        >
          <div
            style={{
              borderRadius: 14,
              padding: "8px 10px",
              border: dark ? "1px solid rgba(142,166,196,0.28)" : "1px solid rgba(102,131,166,0.24)",
              background: dark ? "linear-gradient(165deg, rgba(34,52,76,0.7), rgba(26,43,67,0.56))" : "linear-gradient(165deg, rgba(242,248,255,0.75), rgba(230,239,249,0.6))",
              boxShadow: dark ? "inset 0 1px 0 rgba(194,214,237,0.12), 5px 7px 14px rgba(7,14,24,0.25)" : "inset 0 1px 0 rgba(255,255,255,0.68), 5px 6px 12px rgba(169,185,207,0.28)",
            }}
          >
            <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, marginBottom: 6, letterSpacing: 0.8 }}>Source</div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {["auto", "offline"].map((m) => (
                <button
                  key={m}
                  onClick={() => setSourceMode(m)}
                  className="omega-pill"
                  style={{
                    borderRadius: 999,
                    border: m === sourceMode ? (dark ? "1px solid rgba(164,196,232,0.7)" : "1px solid rgba(95,129,171,0.62)") : (dark ? "1px solid rgba(136,159,188,0.38)" : "1px solid rgba(110,137,170,0.34)"),
                    background: m === sourceMode ? (dark ? "linear-gradient(160deg, rgba(79,112,151,0.5), rgba(48,79,116,0.34))" : "linear-gradient(160deg, rgba(195,218,243,0.86), rgba(169,196,227,0.56))") : (dark ? "linear-gradient(160deg, rgba(38,57,84,0.68), rgba(28,46,70,0.56))" : "linear-gradient(160deg, rgba(238,246,255,0.74), rgba(223,235,248,0.56))"),
                    color: m === sourceMode ? (dark ? "#d9ebff" : "#244f82") : C.dim,
                    padding: "4px 10px",
                    fontFamily: "JetBrains Mono",
                    fontSize: 10,
                    cursor: "pointer",
                    boxShadow: dark ? "inset 0 1px 0 rgba(198,217,241,0.14), 2px 3px 8px rgba(7,12,20,0.22)" : "inset 0 1px 0 rgba(255,255,255,0.8), 2px 3px 8px rgba(175,190,210,0.34)",
                  }}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>

          <div
            style={{
              borderRadius: 14,
              padding: "8px 10px",
              border: dark ? "1px solid rgba(142,166,196,0.28)" : "1px solid rgba(102,131,166,0.24)",
              background: dark ? "linear-gradient(165deg, rgba(34,52,76,0.7), rgba(26,43,67,0.56))" : "linear-gradient(165deg, rgba(242,248,255,0.75), rgba(230,239,249,0.6))",
              boxShadow: dark ? "inset 0 1px 0 rgba(194,214,237,0.12), 5px 7px 14px rgba(7,14,24,0.25)" : "inset 0 1px 0 rgba(255,255,255,0.68), 5px 6px 12px rgba(169,185,207,0.28)",
            }}
          >
            <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, marginBottom: 6, letterSpacing: 0.8 }}>Focus</div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {["general", "analysis", "prediction", "solutions"].map((m) => (
                <button
                  key={m}
                  onClick={() => setFocusMode(m)}
                  className="omega-pill"
                  style={{
                    borderRadius: 999,
                    border: m === focusMode ? (dark ? "1px solid rgba(164,196,232,0.7)" : "1px solid rgba(95,129,171,0.62)") : (dark ? "1px solid rgba(136,159,188,0.38)" : "1px solid rgba(110,137,170,0.34)"),
                    background: m === focusMode ? (dark ? "linear-gradient(160deg, rgba(79,112,151,0.5), rgba(48,79,116,0.34))" : "linear-gradient(160deg, rgba(195,218,243,0.86), rgba(169,196,227,0.56))") : (dark ? "linear-gradient(160deg, rgba(38,57,84,0.68), rgba(28,46,70,0.56))" : "linear-gradient(160deg, rgba(238,246,255,0.74), rgba(223,235,248,0.56))"),
                    color: m === focusMode ? (dark ? "#d9ebff" : "#244f82") : C.dim,
                    padding: "4px 10px",
                    fontFamily: "JetBrains Mono",
                    fontSize: 10,
                    cursor: "pointer",
                    boxShadow: dark ? "inset 0 1px 0 rgba(198,217,241,0.14), 2px 3px 8px rgba(7,12,20,0.22)" : "inset 0 1px 0 rgba(255,255,255,0.8), 2px 3px 8px rgba(175,190,210,0.34)",
                  }}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div
          style={{
            position: "relative",
            zIndex: 1,
            display: "grid",
            gap: 8,
            padding: "10px 12px",
            borderBottom: dark ? "1px solid rgba(146,165,188,0.18)" : "1px solid rgba(87,122,169,0.16)",
            background: dark ? "linear-gradient(180deg, rgba(24,40,63,0.52), rgba(23,38,61,0.28))" : "linear-gradient(180deg, rgba(241,247,255,0.58), rgba(230,239,249,0.24))",
          }}
        >
          <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
            {featuredQuick.map((q) => (
              <button
                key={q}
                onClick={() => sendMessage(q)}
                className="omega-chip"
                style={{
                  borderRadius: 11,
                  border: dark ? "1px solid rgba(144,166,193,0.36)" : "1px solid rgba(98,128,164,0.32)",
                  background: dark ? "linear-gradient(160deg, rgba(41,60,86,0.8), rgba(31,49,73,0.58))" : "linear-gradient(160deg, rgba(237,246,255,0.86), rgba(221,234,249,0.62))",
                  color: dark ? "#d5e4f6" : "#2d5487",
                  padding: "6px 10px",
                  fontSize: 10,
                  fontFamily: "JetBrains Mono",
                  cursor: "pointer",
                  boxShadow: dark ? "inset 0 1px 0 rgba(191,213,239,0.14), 4px 6px 12px rgba(8,14,25,0.24)" : "inset 0 1px 0 rgba(255,255,255,0.86), 4px 6px 11px rgba(173,189,210,0.28)",
                }}
              >
                {q}
              </button>
            ))}
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
            <div style={{ color: C.dim, fontFamily: "JetBrains Mono", fontSize: 10, letterSpacing: 0.7 }}>
              Prompt Library ({quick.length})
            </div>
            <button
              onClick={() => setShowPrompts((v) => !v)}
              className="omega-toggle"
              style={{
                borderRadius: 999,
                border: dark ? "1px solid rgba(144,166,193,0.38)" : "1px solid rgba(96,127,166,0.34)",
                background: dark ? "linear-gradient(160deg, rgba(37,56,83,0.86), rgba(29,47,71,0.62))" : "linear-gradient(160deg, rgba(238,246,255,0.86), rgba(223,235,248,0.64))",
                color: dark ? "#cfe0f4" : "#2c5487",
                padding: "4px 12px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                cursor: "pointer",
                boxShadow: dark ? "inset 0 1px 0 rgba(194,217,242,0.14), 3px 5px 10px rgba(9,15,24,0.24)" : "inset 0 1px 0 rgba(255,255,255,0.82), 3px 5px 10px rgba(169,186,207,0.28)",
              }}
            >
              {showPrompts ? "Hide Prompts" : "Show Prompts"}
            </button>
          </div>
          {showPrompts && (
            <div className="omega-prompt-grid">
              {quick.map((q) => (
                <button
                  key={q}
                  onClick={() => sendMessage(q)}
                  className="omega-chip omega-chip-full"
                  style={{
                    borderRadius: 12,
                    border: dark ? "1px solid rgba(144,166,193,0.34)" : "1px solid rgba(98,128,164,0.3)",
                    background: dark ? "linear-gradient(160deg, rgba(40,59,84,0.76), rgba(30,48,72,0.55))" : "linear-gradient(160deg, rgba(237,246,255,0.82), rgba(221,234,249,0.58))",
                    color: dark ? "#d5e4f6" : "#305686",
                    padding: "7px 10px",
                    fontSize: 10,
                    textAlign: "left",
                    fontFamily: "JetBrains Mono",
                    cursor: "pointer",
                    boxShadow: dark ? "inset 0 1px 0 rgba(191,213,239,0.12), 4px 6px 12px rgba(8,14,25,0.2)" : "inset 0 1px 0 rgba(255,255,255,0.82), 4px 6px 12px rgba(173,189,210,0.24)",
                  }}
                >
                  {q}
                </button>
              ))}
            </div>
          )}
        </div>

        <div
          ref={chatRef}
          style={{
            position: "relative",
            zIndex: 1,
            overflowY: "auto",
            padding: 12,
            display: "grid",
            gap: 10,
            background: dark ? "linear-gradient(180deg, rgba(24,40,63,0.34), rgba(18,30,49,0.2))" : "linear-gradient(180deg, rgba(245,250,255,0.42), rgba(229,238,248,0.24))",
          }}
        >
          {messages.map((m, i) => (
            <div key={i} style={{ justifySelf: m.role === "user" ? "end" : "start", maxWidth: "88%", animation: "omegaMsgIn 200ms ease" }}>
              <div
                style={{
                  padding: "9px 11px",
                  borderRadius: 12,
                  border: `1px solid ${m.role === "user" ? (dark ? "rgba(158,187,220,0.48)" : "rgba(98,128,166,0.34)") : dark ? "rgba(136,166,200,0.32)" : "rgba(100,124,158,0.24)"}`,
                  background: m.role === "user"
                    ? (dark ? "linear-gradient(160deg, rgba(52,75,105,0.86), rgba(38,61,90,0.58))" : "linear-gradient(160deg, rgba(205,223,243,0.58), rgba(171,194,222,0.28))")
                    : (dark ? "linear-gradient(160deg, rgba(35,55,80,0.78), rgba(24,40,63,0.56))" : "linear-gradient(160deg, rgba(248,252,255,0.74), rgba(230,239,249,0.52))"),
                  color: C.text,
                  fontFamily: "JetBrains Mono",
                  fontSize: 12,
                  lineHeight: 1.55,
                  whiteSpace: "pre-wrap",
                  boxShadow: dark ? "inset 0 1px 0 rgba(198,220,244,0.12), 5px 8px 15px rgba(8,13,22,0.25)" : "inset 0 1px 0 rgba(255,255,255,0.82), 5px 8px 15px rgba(170,188,210,0.26)",
                }}
              >
                {m.text}
              </div>
            </div>
          ))}
          {sending && <div style={{ color: dark ? "#c7d8ec" : "#3d628f", fontFamily: "JetBrains Mono", fontSize: 12, animation: "omegaThinking 900ms ease-in-out infinite" }}>Thinking...</div>}
        </div>

        <div
          style={{
            position: "relative",
            zIndex: 1,
            display: "flex",
            gap: 8,
            borderTop: dark ? "1px solid rgba(146,166,190,0.24)" : "1px solid rgba(104,131,163,0.22)",
            padding: 12,
            background: dark ? "linear-gradient(180deg, rgba(24,39,60,0.62), rgba(20,34,54,0.72))" : "linear-gradient(180deg, rgba(239,246,255,0.64), rgba(228,237,248,0.78))",
            boxShadow: dark ? "inset 0 1px 0 rgba(188,210,236,0.14)" : "inset 0 1px 0 rgba(255,255,255,0.76)",
          }}
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
              }
            }}
            placeholder="Ask safety, PQC limits, testing, or demo script..."
            style={{
              flex: 1,
              borderRadius: 14,
              border: dark ? "1px solid rgba(149,174,205,0.4)" : "1px solid rgba(103,134,171,0.34)",
              background: dark ? "linear-gradient(160deg, rgba(22,38,59,0.86), rgba(17,32,52,0.74))" : "linear-gradient(160deg, rgba(249,253,255,0.78), rgba(231,240,250,0.66))",
              color: C.text,
              padding: "10px 12px",
              fontFamily: "JetBrains Mono",
              boxShadow: dark ? "inset 0 1px 0 rgba(181,206,236,0.12), inset 0 -1px 0 rgba(8,17,28,0.42)" : "inset 0 1px 0 rgba(255,255,255,0.9), inset 0 -1px 0 rgba(167,186,208,0.26)",
            }}
          />
          <Btn onClick={() => sendMessage()} disabled={sending || !input.trim()}>
            SEND
          </Btn>
        </div>
      </div>

      <style>{`
        @keyframes omegaMsgIn {
          from { opacity: .1; transform: translateY(8px) scale(.98); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }
        @keyframes omegaThinking {
          0%,100% { opacity: .45; }
          50% { opacity: 1; }
        }
        @keyframes omegaLiquidDriftA {
          0% { transform: translate3d(0, 0, 0) scale(1); border-radius: 52% 48% 58% 42%; }
          50% { transform: translate3d(-6px, 6px, 0) scale(1.04); border-radius: 45% 55% 51% 49%; }
          100% { transform: translate3d(0, 0, 0) scale(1); border-radius: 52% 48% 58% 42%; }
        }
        @keyframes omegaLiquidDriftB {
          0% { transform: translate3d(0, 0, 0) scale(1); border-radius: 46% 54% 42% 58%; }
          50% { transform: translate3d(8px, -6px, 0) scale(1.05); border-radius: 52% 48% 56% 44%; }
          100% { transform: translate3d(0, 0, 0) scale(1); border-radius: 46% 54% 42% 58%; }
        }
        .omega-liquid-a { animation: omegaLiquidDriftA 8.5s ease-in-out infinite; }
        .omega-liquid-b { animation: omegaLiquidDriftB 10.5s ease-in-out infinite; }
        .omega-chip, .omega-pill, .omega-toggle { transition: transform 180ms ease, filter 180ms ease, box-shadow 220ms ease; }
        .omega-chip:hover, .omega-pill:hover, .omega-toggle:hover { transform: translateY(-1px); filter: saturate(1.06); }
        .omega-prompt-grid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 8px;
          max-height: 178px;
          overflow-y: auto;
          padding-right: 2px;
        }
        @media (max-width: 560px) {
          .omega-controls { grid-template-columns: 1fr !important; }
          .omega-prompt-grid { grid-template-columns: 1fr; }
        }
      `}</style>
    </>
  );
}

function DocsTab() {
  return (
    <Card style={{ padding: 22 }}>
      <h3 style={{ marginTop: 0, color: C.cyan, fontFamily: "Orbitron" }}><PressureText glow={C.cyan}>Architecture Docs</PressureText></h3>
      <pre style={{ margin: 0, color: C.text, whiteSpace: "pre-wrap", fontFamily: "JetBrains Mono", fontSize: 12, lineHeight: 1.7 }}>
        HNDL Score = key_exchange(45%) + auth(25%) + tls(15%) + cert(10%) + symmetric(5%)
        {"\n"}Standards: NIST FIPS 203/204/205, CycloneDX 1.6
        {"\n"}Pipeline: Discovery -> TLS/API scan -> heuristic PQC signal classify -> CBOM -> Roadmap
        {"\n"}Audit Integrity: Tamper-evident hash-chain blocks (non-consensus, non-crypto-currency).
        {"\n"}Bank Focus: India major-bank presets for risk benchmarking.
        {"\n"}Reference Basis: RBI-style cyber controls + TLS/PQC hardening guidance.
      </pre>
    </Card>
  );
}

const TABS = [
  ["scanner", "SCANNER"],
  ["banklab", "BANK INSIGHT STUDIO"],
  ["assets", "ASSET MAP"],
  ["crypto", "CRYPTO"],
  ["cbom", "CBOM"],
  ["roadmap", "ROADMAP"],
  ["leaderboard", "BANK INTEL"],
  ["docs", "ARCHITECTURE"],
];

const TAB_VISUALS = {
  scanner: {
    chip: "SCAN",
    darkGlass: "linear-gradient(150deg, rgba(18,60,102,0.6), rgba(10,38,73,0.54))",
    lightGlass: "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(204,216,232,0.62))",
    accentDark: "rgba(80,206,255,0.84)",
    accentLight: "rgba(74,124,221,0.76)",
  },
  banklab: {
    chip: "LAB",
    darkGlass: "linear-gradient(150deg, rgba(21,72,97,0.62), rgba(13,42,58,0.56))",
    lightGlass: "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(196,223,224,0.64))",
    accentDark: "rgba(70,242,216,0.84)",
    accentLight: "rgba(66,174,182,0.72)",
  },
  assets: {
    chip: "MAP",
    darkGlass: "linear-gradient(150deg, rgba(24,60,92,0.62), rgba(16,36,58,0.56))",
    lightGlass: "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(201,214,234,0.64))",
    accentDark: "rgba(99,182,255,0.82)",
    accentLight: "rgba(86,143,228,0.72)",
  },
  crypto: {
    chip: "CRY",
    darkGlass: "linear-gradient(150deg, rgba(56,54,95,0.62), rgba(26,24,58,0.56))",
    lightGlass: "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(214,208,235,0.64))",
    accentDark: "rgba(170,153,255,0.82)",
    accentLight: "rgba(122,108,228,0.72)",
  },
  cbom: {
    chip: "BOM",
    darkGlass: "linear-gradient(150deg, rgba(41,70,94,0.62), rgba(15,36,53,0.56))",
    lightGlass: "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(198,218,232,0.64))",
    accentDark: "rgba(112,205,255,0.84)",
    accentLight: "rgba(88,149,228,0.72)",
  },
  roadmap: {
    chip: "PLAN",
    darkGlass: "linear-gradient(150deg, rgba(61,73,96,0.62), rgba(30,37,53,0.58))",
    lightGlass: "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(212,218,228,0.66))",
    accentDark: "rgba(170,199,255,0.82)",
    accentLight: "rgba(101,132,183,0.72)",
  },
  leaderboard: {
    chip: "INTEL",
    darkGlass: "linear-gradient(150deg, rgba(29,78,84,0.62), rgba(13,45,54,0.58))",
    lightGlass: "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(196,221,218,0.64))",
    accentDark: "rgba(82,234,210,0.84)",
    accentLight: "rgba(72,183,171,0.72)",
  },
  docs: {
    chip: "DOC",
    darkGlass: "linear-gradient(150deg, rgba(65,72,84,0.62), rgba(28,33,41,0.58))",
    lightGlass: "linear-gradient(150deg, rgba(238,242,247,0.78), rgba(210,216,224,0.66))",
    accentDark: "rgba(189,207,233,0.82)",
    accentLight: "rgba(128,148,177,0.72)",
  },
};

const getTabLabel = (id) => TABS.find(([tid]) => tid === id)?.[1] || id;

function App() {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("quanthunt_theme") || "light";
    } catch {
      return "light";
    }
  });
  const [unlocked, setUnlocked] = useState(false);
  const [tab, setTab] = useState("scanner");
  const [prevTab, setPrevTab] = useState("scanner");
  const [tabFxTick, setTabFxTick] = useState(0);
  const [isNarrow, setIsNarrow] = useState(() => (typeof window !== "undefined" ? window.innerWidth < 980 : false));
  const [clock, setClock] = useState(new Date());

  const switchTab = (id) => {
    if (id === tab) return;
    setPrevTab(tab);
    setTab(id);
    setTabFxTick((v) => v + 1);
  };

  const handleLogout = () => {
    setUnlocked(false);
    setTab("scanner");
    setPrevTab("scanner");
    setTabFxTick(0);
  };

  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const onResize = () => setIsNarrow(innerWidth < 980);
    addEventListener("resize", onResize);
    onResize();
    return () => removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem("quanthunt_theme", theme);
    } catch {
      // ignore storage failures
    }
  }, [theme]);

  applyTheme(theme);

  if (!unlocked) return <LockScreen onUnlock={() => setUnlocked(true)} theme={theme} onThemeChange={setTheme} />;
  return (
    <div style={{ minHeight: "100vh", background: theme === "dark" ? "linear-gradient(155deg, #132019 0%, #101a14 56%, #0c1410 100%)" : "linear-gradient(160deg, #f2e7d2 0%, #e7dac0 52%, #dbcaa8 100%)", color: C.text, fontFamily: "Outfit", overflow: isNarrow ? "visible" : "hidden" }}>
      <div style={{ display: "grid", gridTemplateColumns: isNarrow ? "1fr" : "260px 1fr", minHeight: "100vh", position: "relative", zIndex: 2 }}>
        <aside
          style={{
            position: isNarrow ? "relative" : "sticky",
            top: 0,
            alignSelf: "start",
            height: isNarrow ? "auto" : "100vh",
            padding: 14,
            borderRight: isNarrow ? "none" : (theme === "dark" ? "1px solid rgba(174,158,110,0.44)" : "1px solid rgba(186,161,101,0.48)"),
            borderBottom: isNarrow ? (theme === "dark" ? "1px solid rgba(174,158,110,0.38)" : "1px solid rgba(186,161,101,0.42)") : "none",
            borderRadius: isNarrow ? "0 0 26px 26px" : "0 34px 34px 0",
            background: theme === "dark"
              ? "linear-gradient(165deg, rgba(35,60,46,0.9), rgba(28,49,38,0.86) 52%, rgba(22,39,30,0.84) 100%)"
              : "linear-gradient(165deg, rgba(245,235,214,0.93), rgba(236,223,195,0.89) 52%, rgba(228,209,171,0.85) 100%)",
            backgroundSize: "100% 100%",
            backdropFilter: "blur(38px) saturate(1.12) contrast(1.02)",
            WebkitBackdropFilter: "blur(38px) saturate(1.12) contrast(1.02)",
            boxShadow: theme === "dark"
              ? "26px 0 44px rgba(5,10,8,0.58), inset 0 2px 0 rgba(215,199,153,0.18), inset -2px 0 0 rgba(121,138,112,0.26), inset 10px 0 22px rgba(7,12,9,0.44), inset 0 -8px 18px rgba(4,8,6,0.3)"
              : "24px 0 42px rgba(178,156,106,0.36), inset 0 2px 0 rgba(255,250,238,0.88), inset -2px 0 0 rgba(205,179,120,0.34), inset 10px 0 20px rgba(219,198,152,0.3), inset 0 -8px 18px rgba(184,162,114,0.2)",
            display: "grid",
            gridTemplateRows: "auto auto 1fr auto",
            gap: 12,
            overflow: "hidden",
            transition: "box-shadow 320ms ease, border-color 280ms ease, backdrop-filter 340ms ease",
            animation: "none",
            isolation: "isolate",
          }}
        >
          <div style={{ position: "relative", zIndex: 1, display: "flex", alignItems: "center", gap: 10 }}>
            <Logo size={28} animated={false} />
            <div>
              <div style={{ fontFamily: "Orbitron", letterSpacing: 2, color: theme === "dark" ? "#f0e4bf" : "#5c4a23", fontWeight: 800, textShadow: theme === "dark" ? "0 1px 0 rgba(247,234,188,0.16)" : "0 1px 0 rgba(255,255,255,0.72)" }}>
                QUANTHUNT
              </div>
              <div style={{ color: theme === "dark" ? "#bfd0bd" : "#7a6840", fontFamily: "JetBrains Mono", fontSize: 10 }}>Bank cyber risk intelligence</div>
            </div>
          </div>

          <div style={{ position: "relative", zIndex: 1, display: "flex", alignItems: "center", gap: 8 }}>
            <button onClick={() => setTheme("light")} style={{ borderRadius: 999, border: theme === "light" ? "1px solid rgba(179,156,96,0.68)" : "1px solid rgba(179,156,96,0.38)", background: theme === "light" ? "rgba(193,166,99,0.22)" : "transparent", color: theme === "light" ? "#5d4a24" : (theme === "dark" ? "#ccb477" : "#7a6840"), padding: "4px 10px", fontFamily: "JetBrains Mono", fontSize: 10, cursor: "pointer" }}>Light</button>
            <button onClick={() => setTheme("dark")} style={{ borderRadius: 999, border: theme === "dark" ? "1px solid rgba(199,175,111,0.72)" : "1px solid rgba(179,156,96,0.38)", background: theme === "dark" ? "rgba(201,177,113,0.18)" : "transparent", color: theme === "dark" ? "#f1dfb6" : "#7a6840", boxShadow: theme === "dark" ? "inset 0 1px 0 rgba(250,234,191,0.18)" : "none", padding: "4px 10px", fontFamily: "JetBrains Mono", fontSize: 10, cursor: "pointer" }}>Dark</button>
            <button
              onClick={handleLogout}
              style={{
                marginLeft: 4,
                borderRadius: 999,
                border: theme === "dark" ? "1px solid rgba(194,169,106,0.74)" : "1px solid rgba(178,150,84,0.62)",
                background: theme === "dark" ? "rgba(191,162,94,0.22)" : "rgba(194,164,94,0.18)",
                color: theme === "dark" ? "#f1dfb6" : "#5f4a1f",
                padding: "4px 10px",
                fontFamily: "JetBrains Mono",
                fontSize: 10,
                cursor: "pointer",
              }}
            >
              Logout
            </button>
            <div style={{ marginLeft: "auto", color: theme === "dark" ? "#c6d5c4" : "#78663d", fontFamily: "JetBrains Mono", fontSize: 11 }}>{clock.toLocaleTimeString()}</div>
          </div>

          <div style={{ position: "relative", zIndex: 1, display: "grid", gap: 8 }}>
            {TABS.map(([id, label]) => {
              const active = tab === id;
              const visual = TAB_VISUALS[id] || TAB_VISUALS.scanner;
              return (
                <button
                  key={id}
                  onClick={() => switchTab(id)}
                  style={{
                    position: "relative",
                    overflow: "hidden",
                    borderRadius: 14,
                    border: active
                      ? (theme === "dark" ? "1px solid rgba(161,175,168,0.54)" : "1px solid rgba(149,169,152,0.62)")
                      : (theme === "dark" ? "1px solid rgba(112,126,121,0.26)" : "1px solid rgba(162,179,168,0.3)"),
                    background: active
                      ? (theme === "dark"
                        ? "linear-gradient(162deg, rgba(74,86,80,0.74), rgba(58,69,64,0.7) 60%, rgba(50,60,56,0.66) 100%)"
                        : "linear-gradient(162deg, rgba(236,244,236,0.9), rgba(221,233,222,0.82) 60%, rgba(208,222,209,0.76) 100%)")
                      : (theme === "dark"
                        ? "linear-gradient(160deg, rgba(46,56,53,0.64), rgba(41,50,48,0.56))"
                        : "linear-gradient(160deg, rgba(224,236,226,0.7), rgba(211,228,215,0.6))"),
                    color: active ? (theme === "dark" ? "#e4ece6" : "#3f5d4b") : (theme === "dark" ? "#a8bbb1" : "#65806e"),
                    backdropFilter: "blur(18px) saturate(1.08)",
                    WebkitBackdropFilter: "blur(18px) saturate(1.08)",
                    boxShadow: active
                      ? (theme === "dark"
                        ? "0 10px 24px rgba(8,13,12,0.54), inset 0 1px 0 rgba(215,225,219,0.18), inset 0 -2px 7px rgba(8,13,12,0.42)"
                        : "9px 9px 16px rgba(166,182,171,0.32), -7px -7px 14px rgba(247,252,248,0.78), inset 0 1px 0 rgba(255,255,255,0.86), inset 0 -2px 6px rgba(179,198,184,0.3)")
                      : (theme === "dark"
                        ? "inset 0 1px 0 rgba(136,153,145,0.16)"
                        : "inset 0 1px 0 rgba(248,252,248,0.74)"),
                    padding: "10px 12px",
                    textAlign: "left",
                    cursor: "pointer",
                    transform: active ? "translateX(2px)" : "translateX(0)",
                    transition: "all 280ms cubic-bezier(0.22, 1, 0.36, 1)",
                  }}
                >
                  {active && (
                    <span
                      style={{
                        position: "absolute",
                        inset: 1,
                        borderRadius: 13,
                        background: theme === "dark"
                          ? "linear-gradient(170deg, rgba(255,255,255,0.12), rgba(255,255,255,0.02) 36%, transparent 58%)"
                          : "linear-gradient(170deg, rgba(238,243,248,0.72), rgba(238,243,248,0.24) 40%, transparent 62%)",
                        pointerEvents: "none",
                      }}
                    />
                  )}
                  <div style={{ position: "relative", zIndex: 2, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                    <span
                      style={{
                        fontFamily: "Orbitron",
                        fontSize: 11,
                        letterSpacing: active ? 1.15 : 0.8,
                        fontWeight: active ? 700 : 600,
                        textShadow: active && theme === "dark" ? "0 1px 0 rgba(230,236,232,0.2)" : "none",
                      }}
                    >
                      {label}
                    </span>
                    {active ? (
                      <span
                        style={{
                          minWidth: 46,
                          borderRadius: 999,
                          padding: "2px 8px",
                          textAlign: "center",
                          fontFamily: "JetBrains Mono",
                          fontSize: 9,
                          letterSpacing: 1,
                          border: theme === "dark" ? "1px solid rgba(171,184,176,0.56)" : "1px solid rgba(139,160,143,0.56)",
                          background: theme === "dark" ? "rgba(152,166,158,0.18)" : "rgba(165,189,169,0.2)",
                          color: theme === "dark" ? "#dce7df" : "#43614f",
                        }}
                      >
                        {visual.chip}
                      </span>
                    ) : (
                      <span
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: "50%",
                          background: theme === "dark" ? "rgba(153,168,160,0.5)" : "rgba(150,172,155,0.55)",
                        }}
                      />
                    )}
                  </div>
                </button>
              );
            })}
          </div>

          <div style={{ position: "relative", zIndex: 1, borderRadius: 14, padding: "8px 10px", background: theme === "dark" ? "linear-gradient(165deg, rgba(44,55,51,0.74), rgba(37,47,43,0.64))" : "linear-gradient(165deg, rgba(228,240,230,0.74), rgba(214,228,216,0.64))", border: theme === "dark" ? "1px solid rgba(130,147,137,0.34)" : "1px solid rgba(149,173,153,0.36)", boxShadow: theme === "dark" ? "inset 0 0 12px rgba(124,142,132,0.1)" : "inset 2px 2px 7px rgba(167,189,172,0.26), inset -2px -2px 7px rgba(248,255,249,0.86)" }}>
            <div style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: theme === "dark" ? "#a9bdb2" : "#66806f", letterSpacing: 1.1, marginBottom: 2 }}>TAB TRANSITION</div>
            <div style={{ fontFamily: "Orbitron", fontSize: 10, letterSpacing: 0.8, color: theme === "dark" ? "#dce8e0" : "#446553" }}>
              {getTabLabel(prevTab)} -> {getTabLabel(tab)}
            </div>
          </div>

          <Card style={{ position: "relative", zIndex: 1, padding: 10, background: theme === "dark" ? "linear-gradient(162deg, rgba(43,54,50,0.9), rgba(36,45,42,0.88))" : "linear-gradient(162deg, rgba(231,243,233,0.92), rgba(214,230,218,0.88))", border: theme === "dark" ? "1px solid rgba(129,145,136,0.3)" : "1px solid rgba(151,176,156,0.36)" }}>
            <div style={{ color: theme === "dark" ? "#a9bdb2" : "#66806f", fontFamily: "JetBrains Mono", fontSize: 10, marginBottom: 6 }}>Bank Presets</div>
            <div style={{ display: "grid", gap: 4 }}>
              {BANK_PRESETS.slice(0, isNarrow ? 5 : 8).map((b) => (
                <div key={b.domain} style={{ color: theme === "dark" ? "#dce8e0" : "#496755", fontFamily: "JetBrains Mono", fontSize: 10 }}>
                  {b.bank}
                </div>
              ))}
            </div>
          </Card>
        </aside>

        <main
          className="qh-main-scroll"
          style={{
            padding: isNarrow ? 14 : 20,
            margin: isNarrow ? 0 : "12px 14px 12px 10px",
            borderRadius: isNarrow ? 20 : 30,
            border: theme === "dark" ? "1px solid rgba(170,152,102,0.34)" : "1px solid rgba(180,157,103,0.44)",
            background: theme === "dark"
              ? "linear-gradient(160deg, rgba(20,34,28,0.9) 0%, rgba(16,28,23,0.88) 58%, rgba(13,22,18,0.9) 100%)"
              : "linear-gradient(160deg, rgba(244,235,216,0.94) 0%, rgba(235,224,200,0.92) 58%, rgba(226,211,182,0.92) 100%)",
            boxShadow: theme === "dark"
              ? "24px 24px 48px rgba(5,10,8,0.62), -16px -16px 36px rgba(28,50,40,0.36), inset 0 2px 0 rgba(216,197,147,0.16), inset 0 -3px 10px rgba(6,12,9,0.5)"
              : "24px 24px 44px rgba(188,164,109,0.42), -16px -16px 34px rgba(255,249,236,0.8), inset 0 2px 0 rgba(255,253,246,0.82), inset 0 -3px 9px rgba(196,171,114,0.4)",
            position: "relative",
            height: isNarrow ? "auto" : "calc(100vh - 24px)",
            overflowY: isNarrow ? "visible" : "auto",
            overflowX: "hidden",
            scrollBehavior: "smooth",
            paddingRight: isNarrow ? 0 : 8,
            backdropFilter: "blur(24px) saturate(1.28)",
            WebkitBackdropFilter: "blur(24px) saturate(1.28)",
          }}
        >
          <div
            style={{
              position: "absolute",
              inset: 0,
              pointerEvents: "none",
              background: theme === "dark"
                ? "linear-gradient(140deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02) 42%, transparent 68%)"
                : "linear-gradient(140deg, rgba(255,255,255,0.58), rgba(255,255,255,0.18) 42%, transparent 68%)",
            }}
          />
          {tabFxTick > 0 && (
            <div
              key={tabFxTick}
              style={{
                position: "absolute",
                inset: 10,
                borderRadius: 22,
                pointerEvents: "none",
                background: theme === "dark"
                  ? "linear-gradient(120deg, rgba(210,220,235,0.14), rgba(210,220,235,0.02) 38%, transparent 60%)"
                  : "linear-gradient(120deg, rgba(236,241,246,0.5), rgba(236,241,246,0.16) 36%, transparent 62%)",
                border: theme === "dark" ? "1px solid rgba(160,177,201,0.26)" : "1px solid rgba(171,188,212,0.34)",
                backdropFilter: "blur(10px)",
                WebkitBackdropFilter: "blur(10px)",
                animation: "tabGlassShift 520ms ease-out forwards",
                zIndex: 0,
              }}
            />
          )}
          <div style={{ maxWidth: 1350, margin: "0 auto", position: "relative", zIndex: 1, paddingBottom: 14 }}>
            <div key={tab} style={{ animation: "mainPanelIn 360ms cubic-bezier(0.22, 1, 0.36, 1)" }}>
              <OpsStrip />
              <CyberIntelPanel />
              {tab === "scanner" && <ScannerTab />}
              {tab === "banklab" && <BankSignalLabTab />}
              {tab === "assets" && <AssetMapTab />}
              {tab === "crypto" && <CryptoTab />}
              {tab === "cbom" && <CBOMTab />}
              {tab === "roadmap" && <RoadmapTab />}
              {tab === "leaderboard" && <LeaderboardTab />}
              {tab === "docs" && <DocsTab />}
            </div>
          </div>
          <style>{`@keyframes tabGlassShift{0%{opacity:.84;transform:scale(1.03)}100%{opacity:0;transform:scale(1)}}@keyframes mainPanelIn{0%{opacity:.22;transform:translateY(14px)}100%{opacity:1;transform:translateY(0)}}.qh-main-scroll{scrollbar-width:thin;scrollbar-color:rgba(140,162,190,0.6) transparent}.qh-main-scroll::-webkit-scrollbar{width:10px}.qh-main-scroll::-webkit-scrollbar-track{background:transparent}.qh-main-scroll::-webkit-scrollbar-thumb{border-radius:999px;background:linear-gradient(180deg,rgba(156,176,205,0.75),rgba(132,154,184,0.55));border:2px solid transparent;background-clip:padding-box}`}</style>
        </main>
      </div>
      <OmegaGPTFloating theme={theme} />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);



