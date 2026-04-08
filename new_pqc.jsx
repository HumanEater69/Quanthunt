
const { useState, useEffect, useMemo } = React;

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1"]);
const sanitizeApiBase = (value) => String(value || "").trim().replace(/\/+$/, "");
const resolveApiBase = () => {
  try {
    const queryApi = sanitizeApiBase(new URLSearchParams(window.location.search).get("api"));
    if (queryApi) return queryApi;
  } catch {
    // Ignore query parsing failures and fall back to local defaults.
  }
  if (window.location.protocol === "file:") return "http://127.0.0.1:8000";
  if (LOCAL_HOSTS.has(window.location.hostname)) {
    return window.location.port === "8000" ? "" : `http://${window.location.hostname}:8000`;
  }
  try {
    const savedApi = sanitizeApiBase(window.localStorage.getItem("qh_api_base"));
    if (savedApi) return savedApi;
  } catch {
    // Ignore storage access failures.
  }
  return "";
};

let API = resolveApiBase();

const HYBRID_PQC_PROFILES = [
  {
    domain: "google.com",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
  {
    domain: "cloudflare.com",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
  {
    domain: "amazon.com",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
  {
    domain: "apple.com",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
  {
    domain: "quantumai.google",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519MLKEM", "X25519KYBER"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
];

const HYBRID_REFERENCE_DOMAINS = ["google.com", "cloudflare.com", "amazon.com", "apple.com", "quantumai.google"];

const PROFILE_CONFIG = {
  pass: { label: "PASS", payloadBytes: 9600, cryptoMs: 7, hrrRttFactor: 0, lossMultiplier: 0.9 },
  hybrid: { label: "HYBRID", payloadBytes: 16800, cryptoMs: 10, hrrRttFactor: 0.25, lossMultiplier: 1.0 },
  fail: { label: "FAIL", payloadBytes: 24200, cryptoMs: 15, hrrRttFactor: 1.0, lossMultiplier: 1.35 },
};

const fmtMs = (value) => `${Number(value || 0).toFixed(2)} ms`;
const fmtPct = (value) => `${Number(value || 0).toFixed(2)}%`;

function PQCLatencyTab({ scanModel = "general" }) {
  const [profile, setProfile] = useState("hybrid");
  const [domain, setDomain] = useState("google.com");
  const [rttMs, setRttMs] = useState(72);
  const [lossPct, setLossPct] = useState(1.2);
  const [endpointCategory, setEndpointCategory] = useState("Core Web");
  const [currentCipherSuite, setCurrentCipherSuite] = useState("TLS_AES_128_GCM_SHA256");
  const [baselineTtfbMs, setBaselineTtfbMs] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [remote, setRemote] = useState(null);
  const [error, setError] = useState("");
  const [theme, setTheme] = useState(() => window.localStorage.getItem("quanthunt_theme") || "light");

  useEffect(() => {
    const handleStorage = () => setTheme(window.localStorage.getItem("quanthunt_theme") || "light");
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, []);

  const isDark = theme === "dark";
  const paneBg = isDark
    ? "linear-gradient(145deg, rgba(16,32,48,0.72), rgba(8,16,28,0.88))"
    : "linear-gradient(145deg, rgba(240,246,252,0.82), rgba(220,230,240,0.9))";
  const paneBorder = isDark ? "rgba(100,140,200,0.32)" : "rgba(180,200,220,0.5)";
  const textMain = isDark ? "#E2E8F0" : "#2D3748";
  const textMuted = isDark ? "#A0AEC0" : "#4A5568";
  const accent = isDark ? "#4FD1C5" : "#3182CE";
  const danger = isDark ? "#FC8181" : "#E53E3E";
  const success = isDark ? "#68D391" : "#2F855A";

  const cleanedDomain = String(domain || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .split(":")[0]
    .replace(/\/+$/, "");

  const activeProfileConfig = PROFILE_CONFIG[profile] || PROFILE_CONFIG.hybrid;
  const payloadBytes = activeProfileConfig.payloadBytes;
  const nSeg = Math.max(1, Math.ceil(payloadBytes / 1460));
  const flights = nSeg <= 10 ? 0 : Math.ceil(Math.log2(nSeg / 10 + 1));
  const tCrypto = activeProfileConfig.cryptoMs;
  const tProp = rttMs * (2 + flights);
  const hrr = rttMs * activeProfileConfig.hrrRttFactor;
  const loss = Math.max(0, Math.min(0.6, (lossPct / 100) * activeProfileConfig.lossMultiplier));
  const pSuccess = Math.pow(1 - loss, nSeg);
  const rto = Math.max(200, 3 * rttMs);
  const tLoss = pSuccess > 0 ? ((1 - pSuccess) / pSuccess) * rto : 0;
  const localTtfb = tCrypto + tProp + hrr + tLoss;

  const sim = remote || {
    system_config: {
      constants: { mss_bytes: 1460, tcp_initial_window: 10, min_rto_ms: 200, packet_loss_rate: loss, hybrid_overhead_mean: 1.054 },
      payload_profiles: { pass_bytes: 9600, hybrid_bytes: 16800, fail_bytes: 24200 },
    },
    live_app_inputs: {
      target_domain: cleanedDomain,
      endpoint_category: endpointCategory,
      current_cipher_suite: currentCipherSuite,
      measured_rtt_ms: rttMs,
      baseline_ttfb_ms: baselineTtfbMs === "" ? localTtfb : Number(baselineTtfbMs),
      estimated_packet_loss_pct: lossPct,
    },
    calculated_simulation_output: {
      connection_status: "Awaiting Scan",
      pass_metrics: { tcp_segments_required: 7, extra_tcp_flights: 0, expected_hrr_ms: 0, expected_packet_loss_penalty_ms: 0, total_handshake_ttfb_ms: 0 },
      hybrid_metrics: { tcp_segments_required: nSeg, extra_tcp_flights: flights, expected_hrr_ms: hrr, expected_packet_loss_penalty_ms: tLoss, total_handshake_ttfb_ms: localTtfb },
      fail_metrics: { tcp_segments_required: 17, extra_tcp_flights: 1, expected_hrr_ms: rttMs, expected_packet_loss_penalty_ms: tLoss * 1.35, total_handshake_ttfb_ms: localTtfb * 1.35 },
      selected_profile_metrics: { profile, tcp_segments_required: nSeg, extra_tcp_flights: flights, expected_hrr_ms: hrr, expected_packet_loss_penalty_ms: tLoss, total_handshake_ttfb_ms: localTtfb, latency_degradation_percentage: 0 },
      proof_panel: {
        baseline_rtt: { label: "Baseline RTT (ms)", value_ms: rttMs, formula: "Current ping = measured_rtt_ms" },
        tcp_segments_required: { label: "TCP Segments Required", value: nSeg, formula: `ceil(S_TLS/MSS) = ceil(${payloadBytes}/1460)` },
        extra_tcp_flights: { label: "Extra TCP Flights", value: flights, formula: nSeg > 10 ? `N_seg(${nSeg}) > iw(10)` : `N_seg(${nSeg}) <= iw(10)` },
        latency_degradation: { label: "Latency Degradation %", value_pct: 0, formula: "((selected_ttfb_ms - baseline_ttfb_ms) / baseline_ttfb_ms) x 100" },
      },
    },
    headline_metrics: {
      absolute_latency_delta_ms: 0,
      latency_degradation_percentage: 0,
      risk_categorization: { label: activeProfileConfig.label, state: profile, thresholds_ms: { pass_lt: 140, hybrid_range: "140-280", fail_gt: 280 }, basis_total_ttfb_ms: localTtfb },
    },
    domain: cleanedDomain,
    profile,
    profile_display: activeProfileConfig.label,
    baseline_profile: "hybrid_overhead_mean",
    loss_rate: loss,
    mss: 1460,
    iw: 10,
    min_rto: 200,
    live_profile: { status: "skipped", rtt_ms: null, classical_tls_ms: null, error: null },
    pass: { total_latency_ms: 0 },
    hybrid: { total_latency_ms: localTtfb },
    fail: { total_latency_ms: localTtfb * 1.35 },
    selected: { segments: nSeg, extra_flights: flights, t_loss_ms: tLoss, total_latency_ms: localTtfb, payload_size: payloadBytes, p_success: pSuccess },
  };

  const selected = sim.calculated_simulation_output.selected_profile_metrics || sim.selected;
  const proof = sim.calculated_simulation_output.proof_panel || {};
  const metrics = sim.calculated_simulation_output;
  const hybridDomList = useMemo(
    () =>
      HYBRID_REFERENCE_DOMAINS.map((d) => ({
        domain: d,
        label: d === "google.com" ? "Google hybrid reference" : d === "quantumai.google" ? "Google adjacent" : "Hybrid reference",
      })),
    [],
  );
const { useState, useEffect, useMemo } = React;

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1"]);
const sanitizeApiBase = (value) => String(value || "").trim().replace(/\/+$/, "");
const resolveApiBase = () => {
  try {
    const queryApi = sanitizeApiBase(new URLSearchParams(window.location.search).get("api"));
    if (queryApi) return queryApi;
  } catch {
    // Ignore query parsing failures and fall back to local defaults.
  }
  if (window.location.protocol === "file:") return "http://127.0.0.1:8000";
  if (LOCAL_HOSTS.has(window.location.hostname)) {
    return window.location.port === "8000" ? "" : `http://${window.location.hostname}:8000`;
  }
  try {
    const savedApi = sanitizeApiBase(window.localStorage.getItem("qh_api_base"));
    if (savedApi) return savedApi;
  } catch {
    // Ignore storage access failures.
  }
  return "";
};

let API = resolveApiBase();

const HYBRID_PQC_PROFILES = [
  {
    domain: "google.com",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
  {
    domain: "cloudflare.com",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
  {
    domain: "amazon.com",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
  {
    domain: "apple.com",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "X25519KYBER512DRAFT00"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
  {
    domain: "quantumai.google",
    tls_version: "TLSv1.3",
    key_exchange_groups: ["X25519MLKEM", "X25519KYBER"],
    kem: ["KYBER", "ML-KEM"],
    group_ids: ["0xfe30", "0xfe31", "0x11ec"],
  },
];

const HYBRID_REFERENCE_DOMAINS = ["google.com", "cloudflare.com", "amazon.com", "apple.com", "quantumai.google"];

const PROFILE_CONFIG = {
  pass: { label: "PASS", payloadBytes: 9600, cryptoMs: 7, hrrRttFactor: 0, lossMultiplier: 0.9 },
  hybrid: { label: "HYBRID", payloadBytes: 16800, cryptoMs: 10, hrrRttFactor: 0.25, lossMultiplier: 1 },
  fail: { label: "FAIL", payloadBytes: 24200, cryptoMs: 15, hrrRttFactor: 1, lossMultiplier: 1.35 },
};

const fmtMs = (value) => `${Number(value || 0).toFixed(2)} ms`;
const fmtPct = (value) => `${Number(value || 0).toFixed(2)}%`;

function PQCLatencyTab({ scanModel = "general" }) {
  const [profile, setProfile] = useState("hybrid");
  const [domain, setDomain] = useState("google.com");
  const [rttMs, setRttMs] = useState(72);
  const [lossPct, setLossPct] = useState(1.2);
  const [endpointCategory, setEndpointCategory] = useState("Core Web");
  const [currentCipherSuite, setCurrentCipherSuite] = useState("TLS_AES_128_GCM_SHA256");
  const [baselineTtfbMs, setBaselineTtfbMs] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [remote, setRemote] = useState(null);
  const [error, setError] = useState("");
  const [theme, setTheme] = useState(() => window.localStorage.getItem("quanthunt_theme") || "light");

  useEffect(() => {
    const handleStorage = () => setTheme(window.localStorage.getItem("quanthunt_theme") || "light");
    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, []);

  const cleanedDomain = String(domain || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .split(":")[0]
    .replace(/\/+$/, "");

  const activeProfileConfig = PROFILE_CONFIG[profile] || PROFILE_CONFIG.hybrid;
  const payloadBytes = activeProfileConfig.payloadBytes;
  const nSeg = Math.max(1, Math.ceil(payloadBytes / 1460));
  const flights = nSeg <= 10 ? 0 : Math.ceil(Math.log2(nSeg / 10 + 1));
  const tCrypto = activeProfileConfig.cryptoMs;
  const tProp = rttMs * (2 + flights);
  const hrr = rttMs * activeProfileConfig.hrrRttFactor;
  const loss = Math.max(0, Math.min(0.6, (lossPct / 100) * activeProfileConfig.lossMultiplier));
  const pSuccess = Math.pow(1 - loss, nSeg);
  const rto = Math.max(200, 3 * rttMs);
  const tLoss = pSuccess > 0 ? ((1 - pSuccess) / pSuccess) * rto : 0;
  const localTtfb = tCrypto + tProp + hrr + tLoss;

  const sim = remote || {
    system_config: {
      constants: { mss_bytes: 1460, tcp_initial_window: 10, min_rto_ms: 200, packet_loss_rate: loss, hybrid_overhead_mean: 1.054 },
      payload_profiles: { pass_bytes: 9600, hybrid_bytes: 16800, fail_bytes: 24200 },
    },
    live_app_inputs: {
      target_domain: cleanedDomain,
      endpoint_category: endpointCategory,
      current_cipher_suite: currentCipherSuite,
      measured_rtt_ms: rttMs,
      baseline_ttfb_ms: baselineTtfbMs === "" ? localTtfb : Number(baselineTtfbMs),
      estimated_packet_loss_pct: lossPct,
    },
    calculated_simulation_output: {
      connection_status: "Awaiting Scan",
      pass_metrics: { tcp_segments_required: 7, extra_tcp_flights: 0, expected_hrr_ms: 0, expected_packet_loss_penalty_ms: 0, total_handshake_ttfb_ms: 0 },
      hybrid_metrics: { tcp_segments_required: nSeg, extra_tcp_flights: flights, expected_hrr_ms: hrr, expected_packet_loss_penalty_ms: tLoss, total_handshake_ttfb_ms: localTtfb },
      fail_metrics: { tcp_segments_required: 17, extra_tcp_flights: 1, expected_hrr_ms: rttMs, expected_packet_loss_penalty_ms: tLoss * 1.35, total_handshake_ttfb_ms: localTtfb * 1.35 },
      selected_profile_metrics: { profile, tcp_segments_required: nSeg, extra_tcp_flights: flights, expected_hrr_ms: hrr, expected_packet_loss_penalty_ms: tLoss, total_handshake_ttfb_ms: localTtfb, latency_degradation_percentage: 0 },
      proof_panel: {
        baseline_rtt: { label: "Baseline RTT (ms)", value_ms: rttMs, formula: "Current ping = measured_rtt_ms" },
        tcp_segments_required: { label: "TCP Segments Required", value: nSeg, formula: `ceil(S_TLS/MSS) = ceil(${payloadBytes}/1460)` },
        extra_tcp_flights: { label: "Extra TCP Flights", value: flights, formula: nSeg > 10 ? `N_seg(${nSeg}) > iw(10)` : `N_seg(${nSeg}) <= iw(10)` },
        latency_degradation: { label: "Latency Degradation %", value_pct: 0, formula: "((selected_ttfb_ms - baseline_ttfb_ms) / baseline_ttfb_ms) x 100" },
      },
    },
    headline_metrics: {
      absolute_latency_delta_ms: 0,
      latency_degradation_percentage: 0,
      risk_categorization: { label: activeProfileConfig.label, state: profile, thresholds_ms: { pass_lt: 140, hybrid_range: "140-280", fail_gt: 280 }, basis_total_ttfb_ms: localTtfb },
    },
    domain: cleanedDomain,
    profile,
    profile_display: activeProfileConfig.label,
    baseline_profile: "hybrid_overhead_mean",
    loss_rate: loss,
    mss: 1460,
    iw: 10,
    min_rto: 200,
    live_profile: { status: "skipped", rtt_ms: null, classical_tls_ms: null, error: null },
    pass: { total_latency_ms: 0 },
    hybrid: { total_latency_ms: localTtfb },
    fail: { total_latency_ms: localTtfb * 1.35 },
    selected: { segments: nSeg, extra_flights: flights, t_loss_ms: tLoss, total_latency_ms: localTtfb, payload_size: payloadBytes, p_success: pSuccess },
  };

  const selected = sim.calculated_simulation_output.selected_profile_metrics || sim.selected;
  const proof = sim.calculated_simulation_output.proof_panel || {};
  const metrics = sim.calculated_simulation_output;
  const rootClass = `proto-root ${theme === "dark" ? "proto-theme-dark" : "proto-theme-light"}`;
  const hybridSignals = ["TLSv1.3", "X25519KYBER", "X25519MLKEM", "X25519KYBER768DRAFT00", "X25519MLKEM768", "0xfe30", "0xfe31", "0x11ec"];
  const hybridDomList = useMemo(
    () =>
      HYBRID_REFERENCE_DOMAINS.map((d) => ({
        domain: d,
        label: d === "google.com" ? "Google hybrid reference" : d === "quantumai.google" ? "Google adjacent" : "Hybrid reference",
      })),
    [],
  );

  const runSimulation = async (nextProfile = profile) => {
    setProfile(nextProfile);
    setIsScanning(true);
    setError("");
    try {
      const payload = {
        domain: cleanedDomain || undefined,
        rtt_ms: cleanedDomain ? undefined : rttMs,
        baseline_ttfb_ms: baselineTtfbMs === "" ? undefined : Number(baselineTtfbMs),
        loss_rate: Number(lossPct) / 100,
        profile: nextProfile,
        endpoint_category: endpointCategory,
        current_cipher_suite: currentCipherSuite,
      };
      const resp = await fetch(`${API}/api/pqc/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) {
        throw new Error(await resp.text());
      }
      setRemote(await resp.json());
    } catch (err) {
      setRemote(null);
      setError(String(err?.message || err || "Simulation failed."));
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className={rootClass}>
      <div className="proto-backdrop" />
      <div className="proto-shell">
        <section className="proto-card proto-card--hero">
          <div className="proto-header-row">
            <div>
              <div className="proto-kicker">Cyber Safe Prototype</div>
              <h1 className="proto-title">PQC latency simulator with Google hybrid crypto detail</h1>
              <p className="proto-copy">
                This prototype keeps the live simulation path and the latest hybrid-domain data: Google reference domains, hybrid PQC markers, and the current payload-driven TLS timing model.
              </p>
            </div>
            <div className="proto-meta">
              <div className="proto-meta__label">scan model</div>
              <div className="proto-meta__value">{scanModel}</div>
              <div className="proto-meta__label">profile {profile}</div>
            </div>
          </div>
        </section>

        <section className="proto-grid-two">
          <div className="proto-card proto-panel">
            <div className="proto-grid-compact proto-grid-compact--two">
              <Field label="Target domain" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="google.com" />
              <Field label="Endpoint category" value={endpointCategory} onChange={(e) => setEndpointCategory(e.target.value)} as="select" options={["Core Web", "Payment Gateway", "Mobile API", "Auth Server"]} />
            </div>
            <div className="proto-grid-compact proto-grid-compact--two">
              <Field label="Cipher suite" value={currentCipherSuite} onChange={(e) => setCurrentCipherSuite(e.target.value)} placeholder="TLS_AES_128_GCM_SHA256" />
              <Field label="Baseline TTFB (ms)" value={baselineTtfbMs} onChange={(e) => setBaselineTtfbMs(e.target.value)} placeholder="auto from PASS profile" type="number" />
            </div>
            <Slider label="RTT (ms)" value={rttMs} min={20} max={250} onChange={setRttMs} />
            <Slider label="Packet loss (%)" value={lossPct} min={0} max={8} step={0.1} onChange={setLossPct} />

            <div className="proto-actions">
              <ActionButton active={profile === "pass"} tone="pass" onClick={() => runSimulation("pass")}>PASS MODEL</ActionButton>
              <ActionButton active={profile === "hybrid"} tone="hybrid" onClick={() => runSimulation("hybrid")}>HYBRID MODEL</ActionButton>
              <ActionButton active={profile === "fail"} tone="fail" onClick={() => runSimulation("fail")}>FAIL MODEL</ActionButton>
              <ActionButton active={false} tone="neutral" onClick={() => runSimulation(profile)}>{isScanning ? "SCANNING..." : "RUN LIVE SIMULATION"}</ActionButton>
            </div>

            {error ? <div className="proto-error">{error}</div> : null}
          </div>

          <div className="proto-card proto-panel proto-panel--stack">
            <div className="proto-section-title">Google hybrid crypto details</div>
            <div className="proto-copy">
              The backend hybrid matcher treats these domains as the current reference set and classifies Google signals through TLSv1.3 plus hybrid KEM markers.
            </div>
            <div className="proto-list">
              {HYBRID_PQC_PROFILES.map((item) => (
                <div key={item.domain} className="proto-domain-card">
                  <div className="proto-domain-card__head">
                    <strong>{item.domain}</strong>
                    <span className="proto-note">{item.tls_version}</span>
                  </div>
                  <div className="proto-domain-card__meta">
                    KEM: {item.kem.join(", ")} | Groups: {item.key_exchange_groups.slice(0, 3).join(", ")} | IDs: {item.group_ids.join(", ")}
                  </div>
                </div>
              ))}
            </div>
            <div className="proto-chip-list">
              {hybridSignals.map((signal) => (
                <div key={signal} className="proto-chip proto-chip--accent">{signal}</div>
              ))}
            </div>
          </div>
        </section>

        <section className="proto-grid-three">
          <Metric title="Selected profile TTFB" value={fmtMs(selected?.total_handshake_ttfb_ms ?? selected?.total_latency_ms ?? localTtfb)} toneClass={profile === "fail" ? "proto-tone--danger" : profile === "hybrid" ? "proto-tone--accent" : "proto-tone--success"} />
          <Metric title="TCP flights" value={`${selected?.extra_tcp_flights ?? flights} RTT`} toneClass="proto-tone--accent" />
          <Metric title="Loss penalty" value={fmtMs(selected?.expected_packet_loss_penalty_ms ?? tLoss)} toneClass="proto-tone--danger" />
        </section>

        <section className="proto-grid-two">
          <div className="proto-card proto-panel proto-panel--stack">
            <div className="proto-section-title">Simulation output</div>
            <div className="proto-list">
              <DetailRow label="Connection status" value={metrics.connection_status || "Awaiting Scan"} />
              <DetailRow label="Target domain" value={sim.live_app_inputs?.target_domain || ""} />
              <DetailRow label="Measured RTT" value={fmtMs(sim.live_app_inputs?.measured_rtt_ms)} />
              <DetailRow label="Baseline TTFB" value={fmtMs(sim.live_app_inputs?.baseline_ttfb_ms ?? localTtfb)} />
              <DetailRow label="Selected profile" value={sim.profile_display || profile} />
              <DetailRow label="Latency degradation" value={fmtPct(metrics.selected_profile_metrics?.latency_degradation_percentage || 0)} />
              <DetailRow label="Risk label" value={metrics.headline_metrics?.risk_categorization?.label || "PASS"} />
            </div>
            <div className="proto-list">
              <Formula label="TCP segments required" value={String(proof.tcp_segments_required?.value ?? nSeg)} formula={proof.tcp_segments_required?.formula || `ceil(${payloadBytes}/1460)`} />
              <Formula label="Extra TCP flights" value={String(proof.extra_tcp_flights?.value ?? flights)} formula={proof.extra_tcp_flights?.formula || `N_seg(${nSeg}) and iw(10)`} />
              <Formula label="Latency degradation" value={String(proof.latency_degradation?.value_pct ?? 0)} formula={proof.latency_degradation?.formula || "selected_ttfb - baseline_ttfb"} />
            </div>
          </div>

          <div className="proto-card proto-panel proto-panel--stack">
            <div className="proto-section-title">Hybrid domain map</div>
            <div className="proto-list">
              {hybridDomList.map((item) => (
                <div key={item.domain} className="proto-signal-card">
                  <div className="proto-domain-card__head">
                    <strong>{item.domain}</strong>
                    <span className="proto-note">{item.label}</span>
                  </div>
                  <div className="proto-signal-card__meta">
                    Hybridness signal: TLSv1.3 + KEM markers + named group IDs. Google remains the anchor reference in the current profile set.
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function Field({ label, value, onChange, placeholder, type = "text", as = "input", options = [] }) {
  return (
    <label className="proto-label-wrap">
      <span className="proto-label">{label}</span>
      {as === "select" ? (
        <select className="proto-select" value={value} onChange={onChange}>
          {options.map((option) => (
            <option key={option}>{option}</option>
          ))}
        </select>
      ) : (
        <input className="proto-input" type={type} value={value} onChange={onChange} placeholder={placeholder} />
      )}
    </label>
  );
}

function Slider({ label, value, min, max, step = 1, onChange }) {
  return (
    <label className="proto-label-wrap">
      <span className="proto-label">{label}</span>
      <input className="proto-range" type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} />
      <span className="proto-note">{value}</span>
    </label>
  );
}

function ActionButton({ children, active, tone, onClick }) {
  return (
    <button className={`proto-btn proto-btn--${tone} ${active ? "proto-btn--active" : ""}`} onClick={onClick}>
      {children}
    </button>
  );
}

function Metric({ title, value, toneClass }) {
  return (
    <div className="proto-metric">
      <div className="proto-metric__label">{title}</div>
      <div className={`proto-metric__value ${toneClass || ""}`}>{value}</div>
    </div>
  );
}

function DetailRow({ label, value }) {
  return (
    <div className="proto-detail">
      <div className="proto-detail__label">{label}</div>
      <div className="proto-detail__value">{String(value ?? "")}</div>
    </div>
  );
}

function Formula({ label, value, formula }) {
  return (
    <div className="proto-formula">
      <div className="proto-formula__head">
        <strong>{label}</strong>
        <span className="proto-formula__value">{value}</span>
      </div>
      <div className="proto-formula__body">{formula}</div>
    </div>
  );
}

window.PQCLatencyTab = PQCLatencyTab;
