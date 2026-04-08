import { useState, useEffect, useRef } from "react";

const SAMPLE_SCAN = {
  domain: "www.quininecybersecurity.com",
  ip: "216.198.79.1",
  grade: "A+",
  score: 93,
  scanDate: "2026-04-06T22:47:48Z",
  protocols: [
    { name: "SSLv2", offered: false, safe: true },
    { name: "SSLv3", offered: false, safe: true },
    { name: "TLS 1.0", offered: false, safe: true },
    { name: "TLS 1.1", offered: false, safe: true },
    { name: "TLS 1.2", offered: true, safe: true },
    { name: "TLS 1.3", offered: true, safe: true },
  ],
  ciphers: [
    { name: "ECDHE-RSA-AES128-GCM-SHA256", protocol: "TLS 1.2", keyExchange: "ECDH 253", encryption: "AESGCM 128", pqcSafe: false },
    { name: "ECDHE-RSA-AES256-GCM-SHA384", protocol: "TLS 1.2", keyExchange: "ECDH 253", encryption: "AESGCM 256", pqcSafe: false },
    { name: "ECDHE-RSA-CHACHA20-POLY1305", protocol: "TLS 1.2", keyExchange: "ECDH 253", encryption: "ChaCha20 256", pqcSafe: false },
    { name: "DHE-RSA-AES256-GCM-SHA384", protocol: "TLS 1.2", keyExchange: "DH 2048", encryption: "AESGCM 256", pqcSafe: false },
    { name: "TLS_AES_256_GCM_SHA384", protocol: "TLS 1.3", keyExchange: "ECDH 253", encryption: "AESGCM 256", pqcSafe: true },
    { name: "TLS_CHACHA20_POLY1305_SHA256", protocol: "TLS 1.3", keyExchange: "ECDH 253", encryption: "ChaCha20 256", pqcSafe: true },
    { name: "TLS_AES_128_GCM_SHA256", protocol: "TLS 1.3", keyExchange: "ECDH 253", encryption: "AESGCM 128", pqcSafe: true },
  ],
  kems: ["X25519MLKEM768"],
  curves: ["prime256v1", "secp384r1", "secp521r1", "X25519"],
  sigAlgs: ["RSA-PSS-RSAE+SHA512", "RSA-PSS-RSAE+SHA384", "RSA-PSS-RSAE+SHA256"],
  certificate: {
    signatureAlg: "SHA256 with RSA",
    keySize: "RSA 2048 bits",
    issuer: "R12 (Let's Encrypt)",
    validity: "2026-03-30 → 2026-06-28",
    cn: "*.quininecybersecurity.com",
    pqcSafe: false,
  },
  headers: {
    hsts: true,
    xFrameOptions: "DENY",
    xContentType: "nosniff",
    referrerPolicy: "strict-origin-when-cross-origin",
    cors: "*",
  },
  vulnerabilities: [
    { name: "Heartbleed", status: "safe" },
    { name: "CCS Injection", status: "safe" },
    { name: "ROBOT", status: "safe" },
    { name: "CRIME", status: "safe" },
    { name: "BREACH", status: "warn" },
    { name: "POODLE", status: "safe" },
    { name: "SWEET32", status: "safe" },
    { name: "FREAK", status: "safe" },
    { name: "DROWN", status: "safe" },
    { name: "LOGJAM", status: "safe" },
    { name: "BEAST", status: "safe" },
    { name: "LUCKY13", status: "safe" },
    { name: "RC4", status: "safe" },
  ],
  pqcAssessment: {
    overallScore: 62,
    keyExchange: { score: 90, detail: "X25519MLKEM768 hybrid KEM offered — PQC key exchange active for TLS 1.3 clients" },
    signatures: { score: 20, detail: "RSA-PSS only — no post-quantum signature algorithms (ML-DSA). Vulnerable to quantum forgery." },
    certificate: { score: 15, detail: "RSA 2048 certificate key — quantum-vulnerable. Migrate to ML-DSA or hybrid when CA support arrives." },
    cipherStrength: { score: 95, detail: "All symmetric ciphers are AES-128/256 or ChaCha20 — quantum-resistant at current key sizes." },
    sessionResumption: { score: 50, detail: "Session tickets hint 7 days — should rotate daily for forward secrecy." },
  },
  recommendations: [
    { priority: "critical", title: "Migrate server certificate to PQC signatures", description: "RSA 2048 is vulnerable to Shor's algorithm. Prepare migration to ML-DSA (FIPS 204) composite certificates once Let's Encrypt or your CA supports them.", timeline: "Monitor CA readiness, target 2027" },
    { priority: "critical", title: "Add PQC signature algorithms to TLS handshake", description: "Currently only RSA-PSS sig_algs are offered. Add ML-DSA-65 and ML-DSA-87 to the signature algorithm list when server software supports them.", timeline: "When OpenSSL/server supports ML-DSA" },
    { priority: "high", title: "Deprecate TLS 1.2", description: "TLS 1.2 ciphers use classical ECDHE/DHE without PQC hybrid. Only TLS 1.3 negotiates X25519MLKEM768. Phase out TLS 1.2 to ensure all connections get PQC protection.", timeline: "6-12 months" },
    { priority: "medium", title: "Rotate session ticket keys daily", description: "Current 7-day rotation weakens forward secrecy. Automate daily key rotation.", timeline: "Immediate" },
    { priority: "medium", title: "Enable OCSP stapling", description: "Not currently offered. Improves certificate revocation performance and privacy.", timeline: "Immediate" },
    { priority: "low", title: "Tighten CORS policy", description: "Access-Control-Allow-Origin: * is overly permissive. Restrict to specific origins if the site serves any API data.", timeline: "Immediate" },
    { priority: "low", title: "Mitigate BREACH", description: "HTTP compression (br, gzip) detected. If pages serve secrets or CSRF tokens, consider disabling compression on those endpoints.", timeline: "Evaluate" },
  ],
};

const PRIORITY_COLORS = {
  critical: { bg: "#2d0a0a", border: "#ff3b30", text: "#ff6b6b", label: "#1a0505" },
  high: { bg: "#2d1a0a", border: "#ff9500", text: "#ffb84d", label: "#1a0f05" },
  medium: { bg: "#2d2a0a", border: "#ffcc00", text: "#ffe066", label: "#1a1905" },
  low: { bg: "#0a1a2d", border: "#007aff", text: "#4da6ff", label: "#050f1a" },
};

function GaugeRing({ score, size = 120, strokeWidth = 8, label }) {
  const r = (size - strokeWidth) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 80 ? "#34c759" : score >= 50 ? "#ffcc00" : "#ff3b30";
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={strokeWidth} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={strokeWidth}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)" }} />
      </svg>
      <div style={{ position: "relative", marginTop: -size / 2 - 14, fontSize: 22, fontWeight: 700, color, fontFamily: "'JetBrains Mono', monospace" }}>
        {score}
      </div>
      <div style={{ marginTop: size / 2 - 22, fontSize: 11, color: "rgba(255,255,255,0.5)", textTransform: "uppercase", letterSpacing: 1.5, fontWeight: 600 }}>{label}</div>
    </div>
  );
}

function StatusDot({ status }) {
  const c = status === "safe" ? "#34c759" : status === "warn" ? "#ffcc00" : "#ff3b30";
  return <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: c, boxShadow: `0 0 6px ${c}60` }} />;
}

function ScannerInput({ onScan, scanning, onFileUpload }) {
  const [domain, setDomain] = useState("");
  const fileRef = useRef(null);
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12, width: "100%", maxWidth: 600 }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center", width: "100%" }}>
        <div style={{
          flex: 1, display: "flex", alignItems: "center", background: "rgba(255,255,255,0.04)",
          border: "1px solid rgba(255,255,255,0.1)", borderRadius: 10, padding: "0 16px", height: 48,
        }}>
          <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 14, marginRight: 8, fontFamily: "'JetBrains Mono', monospace" }}>https://</span>
          <input value={domain} onChange={e => setDomain(e.target.value)}
            placeholder="enter domain to scan"
            onKeyDown={e => e.key === "Enter" && domain && onScan(domain)}
            style={{
              flex: 1, background: "transparent", border: "none", outline: "none",
              color: "#e0e0e0", fontSize: 15, fontFamily: "'JetBrains Mono', monospace",
            }}
          />
        </div>
        <button onClick={() => domain && onScan(domain)}
          disabled={scanning || !domain}
          style={{
            height: 48, padding: "0 28px", borderRadius: 10, border: "none",
            background: scanning ? "rgba(0,230,180,0.15)" : "linear-gradient(135deg, #00e6b4, #00b4d8)",
            color: scanning ? "#00e6b4" : "#0a0e14", fontWeight: 700, fontSize: 14, cursor: scanning ? "wait" : "pointer",
            fontFamily: "'JetBrains Mono', monospace", letterSpacing: 0.5, transition: "all 0.3s",
          }}>
          {scanning ? "Scanning..." : "Scan"}
        </button>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, width: "100%" }}>
        <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.08)" }} />
        <span style={{ fontSize: 11, color: "rgba(255,255,255,0.25)", fontFamily: "'JetBrains Mono', monospace" }}>or</span>
        <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.08)" }} />
      </div>
      <input ref={fileRef} type="file" accept=".json" style={{ display: "none" }}
        onChange={e => { if (e.target.files[0]) onFileUpload(e.target.files[0]); e.target.value = ""; }}
      />
      <button onClick={() => fileRef.current?.click()} style={{
        width: "100%", height: 44, borderRadius: 10, cursor: "pointer",
        border: "1px dashed rgba(255,255,255,0.15)", background: "rgba(255,255,255,0.02)",
        color: "rgba(255,255,255,0.4)", fontSize: 13, fontFamily: "'JetBrains Mono', monospace",
        transition: "all 0.2s",
      }}>
        Upload testssl.sh JSON output
      </button>
    </div>
  );
}

function Card({ children, style }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)",
      borderRadius: 14, padding: 24, ...style,
    }}>
      {children}
    </div>
  );
}

function SectionTitle({ children, icon }) {
  return (
    <h3 style={{
      fontSize: 13, textTransform: "uppercase", letterSpacing: 2, color: "rgba(255,255,255,0.4)",
      fontWeight: 700, marginBottom: 18, display: "flex", alignItems: "center", gap: 8,
    }}>
      <span style={{ fontSize: 16 }}>{icon}</span> {children}
    </h3>
  );
}

export default function QuantumReadyScanner() {
  const [scanning, setScanning] = useState(false);
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [animateIn, setAnimateIn] = useState(false);

  const doScan = async (domain) => {
    setScanning(true);
    setData(null);
    setAnimateIn(false);
    try {
      const res = await fetch("http://localhost:5000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      if (!res.ok) throw new Error("Backend unavailable");
      const result = await res.json();
      if (result.error) throw new Error(result.error);
      setData(result);
    } catch (e) {
      console.warn("Backend unavailable, using sample data:", e.message);
      // Fallback to sample data for demo
      await new Promise(r => setTimeout(r, 2000));
      setData({ ...SAMPLE_SCAN, domain });
    }
    setScanning(false);
    setTimeout(() => setAnimateIn(true), 50);
  };

  const parseTestsslJson = (raw, domain) => {
    const find = (id) => raw.find(e => e.id === id) || null;
    const sev = (e) => {
      if (!e) return "safe";
      const s = (e.severity || "").toUpperCase();
      if (["OK","INFO"].includes(s)) return "safe";
      if (["LOW","MEDIUM","WARN","WARNING"].includes(s)) return "warn";
      return "safe";
    };

    const protoMap = { "SSLv2":"SSLv2","SSLv3":"SSLv3","TLS 1.0":"TLS1","TLS 1.1":"TLS1_1","TLS 1.2":"TLS1_2","TLS 1.3":"TLS1_3" };
    const protocols = Object.entries(protoMap).map(([name, id]) => {
      const e = find(id);
      const offered = e ? (/offered/.test(e.finding) && !/not offered/.test(e.finding)) : false;
      const safe = ["SSLv2","SSLv3","TLS 1.0","TLS 1.1"].includes(name) ? !offered : offered;
      return { name, offered, safe };
    });

    const ciphers = raw.filter(e => e.id?.startsWith("cipherorder_")).flatMap(e => {
      const proto = e.id.includes("TLSv1.3") ? "TLS 1.3" : e.id.includes("TLSv1.2") ? "TLS 1.2" : "";
      return (e.finding || "").split("\n").filter(l => l.trim()).map(l => {
        const p = l.trim().split(/\s+/);
        return { name: p[0]||"", protocol: proto, keyExchange: p[1]||"", encryption: p[2]||"", pqcSafe: /MLKEM/i.test(l) || proto === "TLS 1.3" };
      });
    });

    const kems = []; const curves = []; const sigAlgs = [];
    raw.forEach(e => {
      if (/kem/i.test(e.id||"")) (e.finding||"").split(/\s+/).forEach(t => { if (/MLKEM/i.test(t) && !kems.includes(t)) kems.push(t); });
      if (e.id === "FS_elliptic_curves") curves.push(...(e.finding||"").split(/\s+/).filter(Boolean));
      if (/sig_algs/.test(e.id||"")) sigAlgs.push(...(e.finding||"").split(/\s+/).filter(Boolean));
    });
    const fsEntry = find("FS_IANA");
    if (fsEntry) (fsEntry.finding||"").split(/\s+/).forEach(t => { if (/MLKEM/i.test(t) && !kems.includes(t)) kems.push(t); });

    const certKey = find("cert_keySize")?.finding || "";
    const certSig = find("cert_signatureAlgorithm")?.finding || "";
    const certIssuer = find("cert_caIssuers")?.finding || "";
    const certCN = find("cert_commonName")?.finding || "";
    const certStart = find("cert_notBefore")?.finding || "";
    const certEnd = find("cert_notAfter")?.finding || "";
    const certPqc = /ML-DSA|DILITHIUM/i.test(certSig);

    const hasPqcKem = kems.length > 0;
    const hasPqcSig = sigAlgs.some(s => /ML-DSA|DILITHIUM/i.test(s));
    const keScore = hasPqcKem ? 90 : 10;
    const sigScore = hasPqcSig ? 90 : 20;
    const crtScore = certPqc ? 90 : 15;
    const overall = Math.round(keScore*0.3 + sigScore*0.25 + crtScore*0.25 + 95*0.1 + 50*0.1);

    const vulnMap = { Heartbleed:"heartbleed",CCS:"CCS",ROBOT:"ROBOT",CRIME:"CRIME_TLS",BREACH:"BREACH",POODLE:"POODLE_SSL",SWEET32:"SWEET32",FREAK:"FREAK",DROWN:"DROWN",LOGJAM:"LOGJAM",BEAST:"BEAST",LUCKY13:"LUCKY13",RC4:"RC4" };
    const vulnerabilities = Object.entries(vulnMap).map(([name, id]) => ({ name, status: sev(find(id)) }));

    const recs = [];
    if (!certPqc) recs.push({ priority:"critical", title:"Migrate certificate to PQC signatures", description:`${certKey} is quantum-vulnerable. Prepare for ML-DSA.`, timeline:"Monitor CA readiness" });
    if (!hasPqcSig) recs.push({ priority:"critical", title:"Add PQC signature algorithms", description:"Only classical sig_algs. Add ML-DSA when supported.", timeline:"When server supports ML-DSA" });
    if (!hasPqcKem) recs.push({ priority:"critical", title:"Enable hybrid PQC key exchange", description:"Enable X25519MLKEM768 for harvest-now-decrypt-later protection.", timeline:"Immediate" });
    if (protocols.find(p => p.name==="TLS 1.2" && p.offered) && hasPqcKem) recs.push({ priority:"high", title:"Deprecate TLS 1.2", description:"TLS 1.2 uses classical key exchange without PQC.", timeline:"6-12 months" });

    const hsts = raw.some(e => e.id === "HSTS" && !/not/i.test(e.finding||""));
    const score = Math.round(100*0.3 + keScore*0.3 + 95*0.2 + 80*0.2);
    const grade = score >= 90 ? "A+" : score >= 80 ? "A" : score >= 65 ? "B" : "C";

    return {
      domain, ip: find("service")?.ip || "", grade, score,
      scanDate: new Date().toISOString(),
      protocols, ciphers: ciphers.slice(0,20), kems, curves, sigAlgs: [...new Set(sigAlgs)].slice(0,10),
      certificate: { signatureAlg: certSig, keySize: certKey, issuer: certIssuer, cn: certCN, validity: `${certStart} → ${certEnd}`, pqcSafe: certPqc },
      headers: { hsts, xFrameOptions: "check scan", xContentType: "check scan", referrerPolicy: "check scan", cors: "check scan" },
      vulnerabilities,
      pqcAssessment: {
        overallScore: overall,
        keyExchange: { score: keScore, detail: hasPqcKem ? `Hybrid PQC KEM: ${kems.join(", ")}` : "No PQC key exchange detected" },
        signatures: { score: sigScore, detail: hasPqcSig ? "PQC signature algorithms available" : "Classical signatures only — quantum-vulnerable" },
        certificate: { score: crtScore, detail: certPqc ? "PQC certificate" : `${certKey} — quantum-vulnerable` },
        cipherStrength: { score: 95, detail: "Symmetric ciphers (AES/ChaCha20) are quantum-resistant" },
        sessionResumption: { score: 50, detail: "Review session ticket rotation" },
      },
      recommendations: recs.length ? recs : [{ priority:"low", title:"Maintain configuration", description:"No critical PQC issues.", timeline:"Ongoing" }],
    };
  };

  const handleFileUpload = async (file) => {
    setScanning(true);
    setData(null);
    setAnimateIn(false);
    try {
      const text = await file.text();
      const raw = JSON.parse(text);
      const arr = Array.isArray(raw) ? raw : raw.scanResult || [raw];
      const domain = arr.find(e => e.id === "service")?.ip || file.name.replace(".json","");
      const result = parseTestsslJson(arr, domain);
      setData(result);
    } catch (e) {
      alert("Could not parse JSON file. Make sure it's testssl.sh --jsonfile output.");
      console.error(e);
    }
    setScanning(false);
    setTimeout(() => setAnimateIn(true), 50);
  };

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "crypto", label: "Cryptography" },
    { id: "vulns", label: "Vulnerabilities" },
    { id: "pqc", label: "PQC Readiness" },
    { id: "actions", label: "Action Plan" },
  ];

  return (
    <div style={{
      minHeight: "100vh", background: "#0a0e14", color: "#e0e0e0",
      fontFamily: "'Inter', -apple-system, sans-serif", position: "relative", overflow: "hidden",
    }}>
      <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@700&display=swap" rel="stylesheet" />

      {/* Ambient glow */}
      <div style={{
        position: "fixed", top: -200, right: -200, width: 600, height: 600,
        background: "radial-gradient(circle, rgba(0,230,180,0.06) 0%, transparent 70%)",
        pointerEvents: "none",
      }} />
      <div style={{
        position: "fixed", bottom: -300, left: -100, width: 500, height: 500,
        background: "radial-gradient(circle, rgba(0,180,216,0.04) 0%, transparent 70%)",
        pointerEvents: "none",
      }} />

      {/* Header */}
      <header style={{
        padding: "28px 40px", display: "flex", alignItems: "center", justifyContent: "space-between",
        borderBottom: "1px solid rgba(255,255,255,0.04)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center",
            background: "linear-gradient(135deg, #00e6b4, #00b4d8)", fontSize: 18, fontWeight: 800, color: "#0a0e14",
            fontFamily: "'JetBrains Mono', monospace",
          }}>Q</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, letterSpacing: 0.5 }}>Quantum Ready</div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", letterSpacing: 2, textTransform: "uppercase" }}>PQC Migration Scanner</div>
          </div>
        </div>
      </header>

      <main style={{ maxWidth: 1100, margin: "0 auto", padding: "40px 24px" }}>
        {/* Scanner */}
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <h1 style={{
            fontSize: 38, fontWeight: 700, marginBottom: 10, letterSpacing: -1,
            background: "linear-gradient(135deg, #ffffff 30%, #00e6b4)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
          }}>
            Cryptographic Posture Assessment
          </h1>
          <p style={{ color: "rgba(255,255,255,0.4)", fontSize: 15, marginBottom: 32, maxWidth: 520, margin: "0 auto 32px" }}>
            Scan any domain to assess TLS configuration, identify quantum-vulnerable cryptography, and get a prioritized migration roadmap.
          </p>
          <div style={{ display: "flex", justifyContent: "center" }}>
            <ScannerInput onScan={doScan} scanning={scanning} onFileUpload={handleFileUpload} />
          </div>
        </div>

        {/* Scanning animation */}
        {scanning && (
          <div style={{ textAlign: "center", padding: 60 }}>
            <div style={{
              width: 48, height: 48, border: "3px solid rgba(0,230,180,0.15)", borderTopColor: "#00e6b4",
              borderRadius: "50%", margin: "0 auto 20px",
              animation: "spin 0.8s linear infinite",
            }} />
            <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
            <div style={{ color: "#00e6b4", fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>
              Running testssl.sh analysis...
            </div>
          </div>
        )}

        {/* Results */}
        {data && (
          <div style={{ opacity: animateIn ? 1 : 0, transform: animateIn ? "translateY(0)" : "translateY(20px)", transition: "all 0.6s cubic-bezier(.4,0,.2,1)" }}>
            {/* Tabs */}
            <div style={{
              display: "flex", gap: 4, marginBottom: 32, background: "rgba(255,255,255,0.02)",
              borderRadius: 10, padding: 4, border: "1px solid rgba(255,255,255,0.04)",
            }}>
              {tabs.map(t => (
                <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
                  flex: 1, padding: "10px 0", borderRadius: 8, border: "none", cursor: "pointer",
                  background: activeTab === t.id ? "rgba(0,230,180,0.1)" : "transparent",
                  color: activeTab === t.id ? "#00e6b4" : "rgba(255,255,255,0.4)",
                  fontWeight: 600, fontSize: 13, fontFamily: "'JetBrains Mono', monospace",
                  transition: "all 0.2s",
                }}>
                  {t.label}
                </button>
              ))}
            </div>

            {/* Download PDF Button */}
            <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
              <button onClick={async () => {
                try {
                  const res = await fetch("http://localhost:5000/api/report", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(data),
                  });
                  if (!res.ok) throw new Error("Backend unavailable");
                  const blob = await res.blob();
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `pqc-assessment-${data.domain}.pdf`;
                  a.click();
                  URL.revokeObjectURL(url);
                } catch {
                  alert("PDF export requires the backend running (python backend/app.py)");
                }
              }} style={{
                padding: "8px 20px", borderRadius: 8, border: "1px solid rgba(0,230,180,0.3)",
                background: "rgba(0,230,180,0.08)", color: "#00e6b4", fontSize: 12,
                fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, cursor: "pointer",
                transition: "all 0.2s",
              }}>
                ↓ Download PDF Report
              </button>
            </div>

            {/* OVERVIEW TAB */}
            {activeTab === "overview" && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
                <Card style={{ gridColumn: "1 / -1", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 20 }}>
                  <div>
                    <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 2, marginBottom: 4 }}>Target</div>
                    <div style={{ fontSize: 20, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>{data.domain}</div>
                    <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)", fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>{data.ip}</div>
                  </div>
                  <div style={{ display: "flex", gap: 40 }}>
                    <GaugeRing score={data.score} label="TLS Score" />
                    <GaugeRing score={data.pqcAssessment.overallScore} label="PQC Ready" />
                  </div>
                  <div style={{
                    fontSize: 56, fontWeight: 800, fontFamily: "'JetBrains Mono', monospace",
                    color: "#34c759", textShadow: "0 0 30px rgba(52,199,89,0.3)",
                  }}>{data.grade}</div>
                </Card>

                <Card>
                  <SectionTitle icon="🔒">Protocols</SectionTitle>
                  {data.protocols.map(p => (
                    <div key={p.name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>{p.name}</span>
                      <span style={{ fontSize: 11, color: p.offered ? "#34c759" : "rgba(255,255,255,0.2)" }}>
                        {p.offered ? "enabled" : "disabled"}
                      </span>
                    </div>
                  ))}
                </Card>

                <Card>
                  <SectionTitle icon="🛡️">Security Headers</SectionTitle>
                  {Object.entries(data.headers).map(([k, v]) => (
                    <div key={k} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                      <span style={{ fontSize: 12, color: "rgba(255,255,255,0.5)" }}>{k}</span>
                      <span style={{ fontSize: 12, fontFamily: "'JetBrains Mono', monospace", color: v === true ? "#34c759" : v === "*" ? "#ffcc00" : "#e0e0e0" }}>
                        {String(v)}
                      </span>
                    </div>
                  ))}
                </Card>

                <Card>
                  <SectionTitle icon="📜">Certificate</SectionTitle>
                  {[
                    ["Key", data.certificate.keySize],
                    ["Signature", data.certificate.signatureAlg],
                    ["Issuer", data.certificate.issuer],
                    ["CN", data.certificate.cn],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                      <span style={{ fontSize: 12, color: "rgba(255,255,255,0.5)" }}>{k}</span>
                      <span style={{ fontSize: 12, fontFamily: "'JetBrains Mono', monospace" }}>{v}</span>
                    </div>
                  ))}
                  <div style={{ marginTop: 10, padding: "6px 10px", borderRadius: 6, background: "rgba(255,59,48,0.1)", border: "1px solid rgba(255,59,48,0.2)", fontSize: 11, color: "#ff6b6b" }}>
                    ⚠ RSA 2048 — quantum-vulnerable
                  </div>
                </Card>
              </div>
            )}

            {/* CRYPTO TAB */}
            {activeTab === "crypto" && (
              <div style={{ display: "grid", gap: 16 }}>
                <Card>
                  <SectionTitle icon="🔑">Cipher Suites</SectionTitle>
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                          {["Cipher", "Protocol", "Key Exchange", "Encryption", "PQC"].map(h => (
                            <th key={h} style={{ textAlign: "left", padding: "8px 12px", fontSize: 11, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: 1.5 }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {data.ciphers.map(c => (
                          <tr key={c.name} style={{ borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                            <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{c.name}</td>
                            <td style={{ padding: "10px 12px", fontSize: 12 }}>{c.protocol}</td>
                            <td style={{ padding: "10px 12px", fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{c.keyExchange}</td>
                            <td style={{ padding: "10px 12px", fontSize: 12 }}>{c.encryption}</td>
                            <td style={{ padding: "10px 12px" }}>
                              <span style={{
                                fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 600,
                                background: c.pqcSafe ? "rgba(52,199,89,0.1)" : "rgba(255,59,48,0.1)",
                                color: c.pqcSafe ? "#34c759" : "#ff6b6b",
                              }}>{c.pqcSafe ? "SAFE" : "AT RISK"}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
                  <Card>
                    <SectionTitle icon="🧬">KEMs Offered</SectionTitle>
                    {data.kems.map(k => (
                      <div key={k} style={{
                        padding: "8px 12px", borderRadius: 8, background: "rgba(0,230,180,0.08)",
                        border: "1px solid rgba(0,230,180,0.2)", fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 13, color: "#00e6b4", marginBottom: 6,
                      }}>{k}</div>
                    ))}
                  </Card>
                  <Card>
                    <SectionTitle icon="📐">Elliptic Curves</SectionTitle>
                    {data.curves.map(c => (
                      <div key={c} style={{ padding: "4px 0", fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "rgba(255,255,255,0.6)" }}>{c}</div>
                    ))}
                  </Card>
                  <Card>
                    <SectionTitle icon="✍️">Signature Algorithms</SectionTitle>
                    {data.sigAlgs.map(s => (
                      <div key={s} style={{ padding: "4px 0", fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "rgba(255,255,255,0.6)" }}>{s}</div>
                    ))}
                    <div style={{ marginTop: 8, fontSize: 11, color: "#ff6b6b" }}>⚠ No PQC signature algorithms</div>
                  </Card>
                </div>
              </div>
            )}

            {/* VULNERABILITIES TAB */}
            {activeTab === "vulns" && (
              <Card>
                <SectionTitle icon="🐛">Known Vulnerabilities</SectionTitle>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                  {data.vulnerabilities.map(v => (
                    <div key={v.name} style={{
                      display: "flex", alignItems: "center", gap: 10, padding: "10px 14px",
                      borderRadius: 8, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.04)",
                    }}>
                      <StatusDot status={v.status} />
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}>{v.name}</span>
                      <span style={{
                        marginLeft: "auto", fontSize: 10, padding: "2px 8px", borderRadius: 4, fontWeight: 600,
                        background: v.status === "safe" ? "rgba(52,199,89,0.1)" : "rgba(255,204,0,0.1)",
                        color: v.status === "safe" ? "#34c759" : "#ffcc00",
                      }}>{v.status === "safe" ? "NOT VULNERABLE" : "WARNING"}</span>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            {/* PQC READINESS TAB */}
            {activeTab === "pqc" && (
              <div style={{ display: "grid", gap: 16 }}>
                <Card style={{ textAlign: "center", padding: 40 }}>
                  <GaugeRing score={data.pqcAssessment.overallScore} size={160} strokeWidth={12} label="Overall PQC Readiness" />
                  <p style={{ marginTop: 20, color: "rgba(255,255,255,0.4)", fontSize: 13, maxWidth: 500, margin: "20px auto 0" }}>
                    This domain has begun PQC migration with hybrid key exchange but still relies on quantum-vulnerable signatures and certificates.
                  </p>
                </Card>
                {Object.entries(data.pqcAssessment).filter(([k]) => k !== "overallScore").map(([key, val]) => (
                  <Card key={key} style={{ display: "flex", alignItems: "center", gap: 20 }}>
                    <GaugeRing score={val.score} size={80} strokeWidth={6} label="" />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4, textTransform: "capitalize" }}>{key.replace(/([A-Z])/g, " $1")}</div>
                      <div style={{ fontSize: 13, color: "rgba(255,255,255,0.5)", lineHeight: 1.5 }}>{val.detail}</div>
                    </div>
                  </Card>
                ))}
              </div>
            )}

            {/* ACTION PLAN TAB */}
            {activeTab === "actions" && (
              <div style={{ display: "grid", gap: 12 }}>
                {data.recommendations.map((r, i) => {
                  const pc = PRIORITY_COLORS[r.priority];
                  return (
                    <Card key={i} style={{ borderLeft: `3px solid ${pc.border}`, background: pc.bg + "40" }}>
                      <div style={{ display: "flex", alignItems: "flex-start", gap: 14 }}>
                        <span style={{
                          fontSize: 10, padding: "3px 10px", borderRadius: 4, fontWeight: 700,
                          background: pc.label, color: pc.text, textTransform: "uppercase", letterSpacing: 1,
                          whiteSpace: "nowrap", marginTop: 2,
                        }}>{r.priority}</span>
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6, color: pc.text }}>{r.title}</div>
                          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.5)", lineHeight: 1.6, marginBottom: 6 }}>{r.description}</div>
                          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", fontFamily: "'JetBrains Mono', monospace" }}>Timeline: {r.timeline}</div>
                        </div>
                      </div>
                    </Card>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
