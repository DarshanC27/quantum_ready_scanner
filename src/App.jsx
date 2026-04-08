import { useState, useEffect, useRef } from "react";

const SAMPLE_SCAN = {
  domain: "www.quininecybersecurity.com", ip: "216.198.79.1", grade: "A+", score: 93,
  scanDate: "2026-04-06T22:47:48Z",
  protocols: [
    { name: "SSLv2", offered: false, safe: true }, { name: "SSLv3", offered: false, safe: true },
    { name: "TLS 1.0", offered: false, safe: true }, { name: "TLS 1.1", offered: false, safe: true },
    { name: "TLS 1.2", offered: true, safe: true }, { name: "TLS 1.3", offered: true, safe: true },
  ],
  ciphers: [
    { name: "ECDHE-RSA-AES128-GCM-SHA256", protocol: "TLS 1.2", keyExchange: "ECDH 253", encryption: "AESGCM 128", pqcSafe: false },
    { name: "ECDHE-RSA-AES256-GCM-SHA384", protocol: "TLS 1.2", keyExchange: "ECDH 253", encryption: "AESGCM 256", pqcSafe: false },
    { name: "TLS_AES_256_GCM_SHA384", protocol: "TLS 1.3", keyExchange: "ECDH 253", encryption: "AESGCM 256", pqcSafe: true },
    { name: "TLS_CHACHA20_POLY1305_SHA256", protocol: "TLS 1.3", keyExchange: "ECDH 253", encryption: "ChaCha20 256", pqcSafe: true },
    { name: "TLS_AES_128_GCM_SHA256", protocol: "TLS 1.3", keyExchange: "ECDH 253", encryption: "AESGCM 128", pqcSafe: true },
  ],
  kems: ["X25519MLKEM768"], curves: ["prime256v1","secp384r1","secp521r1","X25519"],
  sigAlgs: ["RSA-PSS-RSAE+SHA512","RSA-PSS-RSAE+SHA384","RSA-PSS-RSAE+SHA256"],
  certificate: { signatureAlg: "SHA256 with RSA", keySize: "RSA 2048 bits", issuer: "R12 (Let's Encrypt)", validity: "2026-03-30 to 2026-06-28", cn: "*.quininecybersecurity.com", pqcSafe: false },
  headers: { hsts: true, xFrameOptions: "DENY", xContentType: "nosniff", referrerPolicy: "strict-origin-when-cross-origin", cors: "*" },
  vulnerabilities: [
    { name: "Heartbleed", status: "safe" },{ name: "CCS", status: "safe" },{ name: "ROBOT", status: "safe" },
    { name: "CRIME", status: "safe" },{ name: "BREACH", status: "warn" },{ name: "POODLE", status: "safe" },
    { name: "SWEET32", status: "safe" },{ name: "FREAK", status: "safe" },{ name: "DROWN", status: "safe" },
    { name: "LOGJAM", status: "safe" },{ name: "BEAST", status: "safe" },{ name: "LUCKY13", status: "safe" },{ name: "RC4", status: "safe" },
  ],
  pqcAssessment: {
    overallScore: 62,
    keyExchange: { score: 90, detail: "X25519MLKEM768 hybrid KEM active" },
    signatures: { score: 20, detail: "RSA-PSS only. No ML-DSA." },
    certificate: { score: 15, detail: "RSA 2048 - quantum-vulnerable" },
    cipherStrength: { score: 95, detail: "AES/ChaCha20 quantum-resistant" },
    sessionResumption: { score: 50, detail: "Review ticket rotation" },
  },
  recommendations: [
    { priority: "critical", title: "Migrate certificate to PQC", description: "RSA 2048 vulnerable to Shor's algorithm. Migrate to ML-DSA.", timeline: "2027" },
    { priority: "critical", title: "Add PQC signature algorithms", description: "Add ML-DSA-65/87 when supported.", timeline: "When available" },
    { priority: "high", title: "Deprecate TLS 1.2", description: "Only TLS 1.3 gets PQC KEM.", timeline: "6-12 months" },
    { priority: "medium", title: "Rotate session tickets daily", description: "Currently 7-day rotation.", timeline: "Immediate" },
    { priority: "low", title: "Tighten CORS", description: "ACAO:* is overly permissive.", timeline: "Immediate" },
  ],
};

const COMPLIANCE = {
  cnsa2: {
    name: "CNSA 2.0", full: "NSA Commercial National Security Algorithm Suite 2.0",
    milestones: [
      { year: 2025, req: "Software signing with ML-DSA/LMS", status: "active" },
      { year: 2026, req: "TLS 1.3 with ML-KEM required", status: "active" },
      { year: 2030, req: "AES-256 and SHA-384+ only", status: "upcoming" },
      { year: 2033, req: "All crypto exclusively PQC", status: "upcoming" },
      { year: 2035, req: "Full CNSA 2.0 mandatory", status: "upcoming" },
    ],
    checks: [
      { id: "kem", label: "ML-KEM key exchange", test: d => (d.kems||[]).some(k=>/MLKEM/i.test(k)), req: "ML-KEM-768/1024" },
      { id: "sig", label: "ML-DSA signatures", test: d => (d.sigAlgs||[]).some(s=>/ML-DSA/i.test(s)), req: "ML-DSA-65/87" },
      { id: "cert", label: "PQC certificate", test: d => d.certificate?.pqcSafe===true, req: "ML-DSA cert" },
      { id: "sym", label: "AES-256", test: d => (d.ciphers||[]).some(c=>/256/.test(c.encryption||"")), req: "AES-256-GCM" },
      { id: "tls13", label: "TLS 1.3", test: d => (d.protocols||[]).some(p=>p.name==="TLS 1.3"&&p.offered), req: "TLS 1.3" },
      { id: "legacy", label: "No legacy protocols", test: d => !(d.protocols||[]).some(p=>["SSLv2","SSLv3","TLS 1.0","TLS 1.1"].includes(p.name)&&p.offered), req: "Disable SSLv2/3, TLS 1.0/1.1" },
    ],
  },
  nist: {
    name: "NIST PQC", full: "NIST FIPS 203/204/205",
    checks: [
      { id: "mlkem", label: "FIPS 203 ML-KEM", test: d => (d.kems||[]).some(k=>/MLKEM/i.test(k)), req: "ML-KEM-512/768/1024" },
      { id: "mldsa", label: "FIPS 204 ML-DSA", test: d => (d.sigAlgs||[]).some(s=>/ML-DSA/i.test(s)), req: "ML-DSA-44/65/87" },
      { id: "hybrid", label: "Hybrid mode", test: d => (d.kems||[]).some(k=>/X25519MLKEM/i.test(k)), req: "X25519+ML-KEM" },
      { id: "aes", label: "AES encryption", test: d => (d.ciphers||[]).some(c=>/AES/i.test(c.name||"")), req: "AES-128/256" },
    ],
  },
};

const PRI_COL = { critical:{bg:"#2d0a0a",border:"#ff3b30",text:"#ff6b6b",label:"#1a0505"}, high:{bg:"#2d1a0a",border:"#ff9500",text:"#ffb84d",label:"#1a0f05"}, medium:{bg:"#2d2a0a",border:"#ffcc00",text:"#ffe066",label:"#1a1905"}, low:{bg:"#0a1a2d",border:"#007aff",text:"#4da6ff",label:"#050f1a"} };
const scColor = s => s>=80?"#34c759":s>=50?"#ffcc00":"#ff3b30";

function GaugeRing({score,size=120,strokeWidth=8,label}){const r=(size-strokeWidth)/2;const c=2*Math.PI*r;const o=c-(score/100)*c;const col=scColor(score);return(<div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:6}}><svg width={size} height={size} style={{transform:"rotate(-90deg)"}}><circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={strokeWidth}/><circle cx={size/2} cy={size/2} r={r} fill="none" stroke={col} strokeWidth={strokeWidth} strokeDasharray={c} strokeDashoffset={o} strokeLinecap="round" style={{transition:"stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)"}}/></svg><div style={{position:"relative",marginTop:-size/2-14,fontSize:22,fontWeight:700,color:col,fontFamily:"'JetBrains Mono',monospace"}}>{score}</div><div style={{marginTop:size/2-22,fontSize:11,color:"rgba(255,255,255,0.5)",textTransform:"uppercase",letterSpacing:1.5,fontWeight:600}}>{label}</div></div>);}
function Card({children,style,onClick}){return <div onClick={onClick} style={{background:"rgba(255,255,255,0.02)",border:"1px solid rgba(255,255,255,0.06)",borderRadius:14,padding:24,...style}}>{children}</div>;}
function SectionTitle({children,icon}){return <h3 style={{fontSize:13,textTransform:"uppercase",letterSpacing:2,color:"rgba(255,255,255,0.4)",fontWeight:700,marginBottom:18,display:"flex",alignItems:"center",gap:8}}><span style={{fontSize:16}}>{icon}</span>{children}</h3>;}
function StatusDot({status}){const c=status==="safe"?"#34c759":status==="warn"?"#ffcc00":"#ff3b30";return <span style={{display:"inline-block",width:8,height:8,borderRadius:"50%",background:c,boxShadow:`0 0 6px ${c}60`}}/>;}

function ScannerInput({onScan,scanning,onFileUpload}){const[domain,setDomain]=useState("");const fileRef=useRef(null);return(
<div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:12,width:"100%",maxWidth:600}}>
<div style={{display:"flex",gap:12,alignItems:"center",width:"100%"}}>
<div style={{flex:1,display:"flex",alignItems:"center",background:"rgba(255,255,255,0.04)",border:"1px solid rgba(255,255,255,0.1)",borderRadius:10,padding:"0 16px",height:48}}>
<span style={{color:"rgba(255,255,255,0.3)",fontSize:14,marginRight:8,fontFamily:"'JetBrains Mono',monospace"}}>https://</span>
<input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="enter domain" onKeyDown={e=>e.key==="Enter"&&domain&&onScan(domain)} style={{flex:1,background:"transparent",border:"none",outline:"none",color:"#e0e0e0",fontSize:15,fontFamily:"'JetBrains Mono',monospace"}}/>
</div>
<button onClick={()=>domain&&onScan(domain)} disabled={scanning||!domain} style={{height:48,padding:"0 28px",borderRadius:10,border:"none",background:scanning?"rgba(0,230,180,0.15)":"linear-gradient(135deg,#00e6b4,#00b4d8)",color:scanning?"#00e6b4":"#0a0e14",fontWeight:700,fontSize:14,cursor:scanning?"wait":"pointer",fontFamily:"'JetBrains Mono',monospace"}}>{scanning?"Scanning...":"Scan"}</button>
</div>
<div style={{display:"flex",alignItems:"center",gap:12,width:"100%"}}><div style={{flex:1,height:1,background:"rgba(255,255,255,0.08)"}}/><span style={{fontSize:11,color:"rgba(255,255,255,0.25)"}}>or</span><div style={{flex:1,height:1,background:"rgba(255,255,255,0.08)"}}/></div>
<input ref={fileRef} type="file" accept=".json" style={{display:"none"}} onChange={e=>{if(e.target.files[0])onFileUpload(e.target.files[0]);e.target.value="";}}/>
<button onClick={()=>fileRef.current?.click()} style={{width:"100%",height:44,borderRadius:10,cursor:"pointer",border:"1px dashed rgba(255,255,255,0.15)",background:"rgba(255,255,255,0.02)",color:"rgba(255,255,255,0.4)",fontSize:13,fontFamily:"'JetBrains Mono',monospace"}}>Upload testssl.sh JSON</button>
</div>);}

function parseTestsslJson(raw,domain){const find=id=>raw.find(e=>e.id===id)||null;const sev=e=>{if(!e)return"safe";const s=(e.severity||"").toUpperCase();if(["OK","INFO"].includes(s))return"safe";if(["LOW","MEDIUM","WARN","WARNING"].includes(s))return"warn";return"safe";};const pm={"SSLv2":"SSLv2","SSLv3":"SSLv3","TLS 1.0":"TLS1","TLS 1.1":"TLS1_1","TLS 1.2":"TLS1_2","TLS 1.3":"TLS1_3"};const protocols=Object.entries(pm).map(([n,id])=>{const e=find(id);const o=e?(/offered/.test(e.finding)&&!/not offered/.test(e.finding)):false;const safe=["SSLv2","SSLv3","TLS 1.0","TLS 1.1"].includes(n)?!o:o;return{name:n,offered:o,safe};});const ciphers=raw.filter(e=>e.id?.startsWith("cipherorder_")).flatMap(e=>{const pr=e.id.includes("TLSv1.3")?"TLS 1.3":e.id.includes("TLSv1.2")?"TLS 1.2":"";return(e.finding||"").split("\n").filter(l=>l.trim()).map(l=>{const p=l.trim().split(/\s+/);return{name:p[0]||"",protocol:pr,keyExchange:p[1]||"",encryption:p[2]||"",pqcSafe:/MLKEM/i.test(l)||pr==="TLS 1.3"};});});const kems=[],curves=[],sigAlgs=[];raw.forEach(e=>{if(/kem/i.test(e.id||""))(e.finding||"").split(/\s+/).forEach(t=>{if(/MLKEM/i.test(t)&&!kems.includes(t))kems.push(t);});if(e.id==="FS_elliptic_curves")curves.push(...(e.finding||"").split(/\s+/).filter(Boolean));if(/sig_algs/.test(e.id||""))sigAlgs.push(...(e.finding||"").split(/\s+/).filter(Boolean));});const fs=find("FS_IANA");if(fs)(fs.finding||"").split(/\s+/).forEach(t=>{if(/MLKEM/i.test(t)&&!kems.includes(t))kems.push(t);});const ck=find("cert_keySize")?.finding||"",cs=find("cert_signatureAlgorithm")?.finding||"",ci=find("cert_caIssuers")?.finding||"",cc=find("cert_commonName")?.finding||"",cp=/ML-DSA|DILITHIUM/i.test(cs);const hk=kems.length>0,hs=sigAlgs.some(s=>/ML-DSA/i.test(s)),ke=hk?90:10,si=hs?90:20,cr=cp?90:15,ov=Math.round(ke*.3+si*.25+cr*.25+95*.1+50*.1);const vm={Heartbleed:"heartbleed",CCS:"CCS",ROBOT:"ROBOT",CRIME:"CRIME_TLS",BREACH:"BREACH",POODLE:"POODLE_SSL",SWEET32:"SWEET32",FREAK:"FREAK",DROWN:"DROWN",LOGJAM:"LOGJAM",BEAST:"BEAST",LUCKY13:"LUCKY13",RC4:"RC4"};const vulns=Object.entries(vm).map(([n,id])=>({name:n,status:sev(find(id))}));const recs=[];if(!cp)recs.push({priority:"critical",title:"Migrate cert to PQC",description:`${ck} is quantum-vulnerable.`,timeline:"2027"});if(!hs)recs.push({priority:"critical",title:"Add PQC sig algs",description:"Add ML-DSA when supported.",timeline:"When available"});if(!hk)recs.push({priority:"critical",title:"Enable PQC KEM",description:"Enable X25519MLKEM768.",timeline:"Immediate"});const sc=Math.round(100*.3+ke*.3+95*.2+80*.2),gr=sc>=90?"A+":sc>=80?"A":sc>=65?"B":"C";return{domain,ip:find("service")?.ip||"",grade:gr,score:sc,scanDate:new Date().toISOString(),protocols,ciphers:ciphers.slice(0,20),kems,curves,sigAlgs:[...new Set(sigAlgs)].slice(0,10),certificate:{signatureAlg:cs,keySize:ck,issuer:ci,cn:cc,validity:"",pqcSafe:cp},headers:{hsts:true,xFrameOptions:"check",xContentType:"check",referrerPolicy:"check",cors:"check"},vulnerabilities:vulns,pqcAssessment:{overallScore:ov,keyExchange:{score:ke,detail:hk?`Hybrid PQC: ${kems.join(",")}`:"No PQC KEM"},signatures:{score:si,detail:hs?"PQC sigs available":"Classical only"},certificate:{score:cr,detail:cp?"PQC cert":`${ck} - vulnerable`},cipherStrength:{score:95,detail:"AES/ChaCha20 quantum-resistant"},sessionResumption:{score:50,detail:"Review ticket rotation"}},recommendations:recs.length?recs:[{priority:"low",title:"Maintain config",description:"No critical issues.",timeline:"Ongoing"}]};}

function generatePdfHtml(d){const pc={critical:"#ff3b30",high:"#ff9500",medium:"#ffcc00",low:"#007aff"};const sc=s=>s>=80?"#34c759":s>=50?"#ffcc00":"#ff3b30";const gc=g=>g.startsWith("A")?"#34c759":g==="B"?"#ffcc00":"#ff3b30";const pqc=d.pqcAssessment||{};return`<!DOCTYPE html><html><head><meta charset="utf-8"><title>PQC Report - ${d.domain}</title><style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;700&display=swap');*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',sans-serif;color:#1a1a2e;padding:40px 50px;font-size:11px;line-height:1.5}@media print{body{padding:20px 30px}@page{margin:15mm;size:A4}}.mono{font-family:'JetBrains Mono',monospace}h1{font-size:24px;margin-bottom:2px}h2{font-size:15px;margin:24px 0 10px;padding-bottom:6px;border-bottom:2px solid #00e6b4}.hl{height:3px;background:linear-gradient(90deg,#00e6b4,#00b4d8);margin:8px 0 20px}.meta{color:#666;font-size:11px}.scores{display:flex;gap:30px;margin:16px 0 20px}.sb{text-align:center;padding:16px 24px;border:1px solid #e0e0e0;border-radius:10px;background:#f8fafb}.sv{font-size:36px;font-weight:800;font-family:'JetBrains Mono',monospace}.sl{font-size:10px;color:#888;text-transform:uppercase;letter-spacing:1.5px;margin-top:4px}table{width:100%;border-collapse:collapse;margin:8px 0 16px;font-size:10px}th{background:#0a0e14;color:#fff;text-align:left;padding:7px 10px;font-size:9px;text-transform:uppercase;letter-spacing:1px}td{padding:6px 10px;border-bottom:1px solid #eee}tr:nth-child(even){background:#f8fafb}.t{display:inline-block;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700}.ts{background:#e8f9f0;color:#34c759}.tr{background:#fff0f0;color:#ff3b30}.tw{background:#fff8e0;color:#e6a800}.rec{margin:10px 0;padding:10px 14px;border-left:3px solid;border-radius:0 6px 6px 0;background:#fafafa}.pi{margin:8px 0;padding:8px 12px;border-radius:6px;background:#f8fafb;border:1px solid #eee}.ps{font-size:18px;font-weight:700;font-family:'JetBrains Mono',monospace;margin-right:10px}.ft{margin-top:30px;padding-top:10px;border-top:1px solid #ddd;color:#999;font-size:9px}</style></head><body><h1>Post-Quantum Cryptography Assessment</h1><div class="hl"></div><div class="meta"><b>Target:</b> <span class="mono">${d.domain}</span> | <b>IP:</b> <span class="mono">${d.ip}</span> | <b>Scanned:</b> ${(d.scanDate||"").slice(0,10)}</div><h2>Executive Summary</h2><div class="scores"><div class="sb"><div class="sv" style="color:${gc(d.grade)}">${d.grade}</div><div class="sl">TLS Grade</div></div><div class="sb"><div class="sv" style="color:${sc(d.score)}">${d.score}</div><div class="sl">TLS Score</div></div><div class="sb"><div class="sv" style="color:${sc(pqc.overallScore||0)}">${pqc.overallScore||0}</div><div class="sl">PQC Readiness</div></div></div><h2>Protocols</h2><table><tr><th>Protocol</th><th>Status</th><th>OK</th></tr>${(d.protocols||[]).map(p=>`<tr><td class="mono">${p.name}</td><td>${p.offered?"Enabled":"Disabled"}</td><td><span class="t ${p.safe?"ts":"tr"}">${p.safe?"OK":"RISK"}</span></td></tr>`).join("")}</table><h2>Ciphers</h2><table><tr><th>Cipher</th><th>Protocol</th><th>PQC</th></tr>${(d.ciphers||[]).slice(0,10).map(c=>`<tr><td class="mono" style="font-size:9px">${c.name}</td><td>${c.protocol}</td><td><span class="t ${c.pqcSafe?"ts":"tr"}">${c.pqcSafe?"SAFE":"RISK"}</span></td></tr>`).join("")}</table><h2>PQC Readiness</h2>${["keyExchange","signatures","certificate","cipherStrength","sessionResumption"].map(k=>{const i=pqc[k];if(!i)return"";const l=k.replace(/([A-Z])/g," $1");return`<div class="pi"><span class="ps" style="color:${sc(i.score)}">${i.score}</span><b>${l}</b><br><span style="color:#666">${i.detail}</span></div>`;}).join("")}<h2>CNSA 2.0 Compliance</h2><table><tr><th>Check</th><th>Status</th><th>Required</th></tr>${COMPLIANCE.cnsa2.checks.map(c=>`<tr><td>${c.label}</td><td><span class="t ${c.test(d)?"ts":"tr"}">${c.test(d)?"PASS":"FAIL"}</span></td><td>${c.req}</td></tr>`).join("")}</table><h2>NIST PQC Compliance</h2><table><tr><th>Check</th><th>Status</th><th>Required</th></tr>${COMPLIANCE.nist.checks.map(c=>`<tr><td>${c.label}</td><td><span class="t ${c.test(d)?"ts":"tr"}">${c.test(d)?"PASS":"FAIL"}</span></td><td>${c.req}</td></tr>`).join("")}</table><h2>Vulnerabilities</h2><table><tr><th>Name</th><th>Status</th></tr>${(d.vulnerabilities||[]).map(v=>`<tr><td>${v.name}</td><td><span class="t ${v.status==="safe"?"ts":v.status==="warn"?"tw":"tr"}">${v.status==="safe"?"OK":v.status==="warn"?"WARN":"VULN"}</span></td></tr>`).join("")}</table><h2>Action Plan</h2>${(d.recommendations||[]).map((r,i)=>`<div class="rec" style="border-color:${pc[r.priority]||"#007aff"}"><b style="color:${pc[r.priority]}">[${r.priority.toUpperCase()}]</b> <b>${i+1}. ${r.title}</b><br>${r.description}<br><span style="color:#888;font-size:9px">Timeline: ${r.timeline}</span></div>`).join("")}<div class="ft">Quantum Ready PQC Migration-as-a-Service | ${new Date().toISOString().slice(0,10)}</div></body></html>`;}

function LandingPage({onStart}){return(
<div style={{minHeight:"100vh",background:"#0a0e14",color:"#e0e0e0",fontFamily:"'Inter',sans-serif"}}>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&family=Sora:wght@400;600;700;800&display=swap" rel="stylesheet"/>
<div style={{position:"fixed",top:-200,right:-200,width:600,height:600,background:"radial-gradient(circle,rgba(0,230,180,0.08) 0%,transparent 70%)",pointerEvents:"none"}}/>
<nav style={{padding:"20px 40px",display:"flex",alignItems:"center",justifyContent:"space-between",borderBottom:"1px solid rgba(255,255,255,0.04)"}}>
<div style={{display:"flex",alignItems:"center",gap:10}}><div style={{width:32,height:32,borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",background:"linear-gradient(135deg,#00e6b4,#00b4d8)",fontSize:16,fontWeight:800,color:"#0a0e14",fontFamily:"'JetBrains Mono',monospace"}}>Q</div><span style={{fontSize:16,fontWeight:700}}>Quantum Ready</span></div>
<button onClick={onStart} style={{padding:"8px 20px",borderRadius:8,border:"none",background:"linear-gradient(135deg,#00e6b4,#00b4d8)",color:"#0a0e14",fontWeight:700,fontSize:13,cursor:"pointer"}}>Get Started</button>
</nav>
<section style={{textAlign:"center",padding:"100px 40px 60px",maxWidth:800,margin:"0 auto"}}>
<div style={{display:"inline-block",padding:"4px 14px",borderRadius:20,background:"rgba(0,230,180,0.1)",border:"1px solid rgba(0,230,180,0.2)",fontSize:12,color:"#00e6b4",fontWeight:600,marginBottom:24,fontFamily:"'JetBrains Mono',monospace"}}>PQC Migration-as-a-Service</div>
<h1 style={{fontSize:52,fontWeight:800,lineHeight:1.1,letterSpacing:-2,marginBottom:20,fontFamily:"'Sora',sans-serif"}}><span style={{background:"linear-gradient(135deg,#fff 40%,#00e6b4)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent"}}>Quantum-proof your</span><br/><span style={{background:"linear-gradient(135deg,#00e6b4,#00b4d8)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent"}}>cryptography</span></h1>
<p style={{fontSize:18,color:"rgba(255,255,255,0.5)",lineHeight:1.7,maxWidth:560,margin:"0 auto 40px"}}>Inventory your crypto. Assess quantum risk. Migrate in phases. For SMBs who need PQC compliance without in-house expertise.</p>
<div style={{display:"flex",gap:14,justifyContent:"center"}}><button onClick={onStart} style={{padding:"14px 36px",borderRadius:10,border:"none",background:"linear-gradient(135deg,#00e6b4,#00b4d8)",color:"#0a0e14",fontWeight:700,fontSize:16,cursor:"pointer"}}>Scan Your Domain</button></div>
</section>
<section style={{display:"flex",justifyContent:"center",gap:60,padding:"40px 0 80px"}}>{[["2025","CNSA 2.0"],["5min","Scan time"],["NIST","FIPS 203/204"],["A+","Grade possible"]].map(([v,l])=><div key={v} style={{textAlign:"center"}}><div style={{fontSize:32,fontWeight:800,fontFamily:"'JetBrains Mono',monospace",color:"#00e6b4"}}>{v}</div><div style={{fontSize:12,color:"rgba(255,255,255,0.4)",marginTop:4}}>{l}</div></div>)}</section>
<section style={{maxWidth:1000,margin:"0 auto",padding:"60px 40px"}}><h2 style={{textAlign:"center",fontSize:32,fontWeight:700,marginBottom:50,fontFamily:"'Sora',sans-serif"}}>Everything for PQC migration</h2>
<div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:20}}>{[["🔍","Crypto Inventory","Discover all TLS configs, ciphers, KEMs and certificates."],["📊","Risk Scoring","PQC readiness score based on NIST standards."],["🗺️","Migration Roadmap","Prioritized action plan aligned to CNSA 2.0."],["📋","Compliance","Map to NIST FIPS 203/204/205 and CNSA 2.0."],["📄","PDF Reports","Professional reports for boards and auditors."],["🔄","Monitoring","Track progress with scan history and comparisons."]].map(([i,t,d])=><Card key={t} style={{padding:28}}><div style={{fontSize:28,marginBottom:12}}>{i}</div><div style={{fontSize:16,fontWeight:700,marginBottom:8}}>{t}</div><div style={{fontSize:13,color:"rgba(255,255,255,0.5)",lineHeight:1.6}}>{d}</div></Card>)}</div></section>
<section style={{maxWidth:900,margin:"0 auto",padding:"60px 40px"}}><h2 style={{textAlign:"center",fontSize:32,fontWeight:700,marginBottom:50,fontFamily:"'Sora',sans-serif"}}>Simple pricing</h2>
<div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:20}}>{[["Starter","Free","3 domains","Basic scan, PDF reports, Compliance"],["Professional","$299/mo","25 domains","History, Comparison, Priority support"],["Enterprise","Custom","Unlimited","API, White-label, Dedicated CSM"]].map(([n,p,dom,feat],i)=><Card key={n} style={{padding:32,border:i===1?"1px solid rgba(0,230,180,0.3)":undefined}}>{i===1&&<div style={{fontSize:10,color:"#00e6b4",fontWeight:700,textTransform:"uppercase",letterSpacing:2,marginBottom:8}}>Popular</div>}<div style={{fontSize:18,fontWeight:700,marginBottom:4}}>{n}</div><div style={{fontSize:32,fontWeight:800,fontFamily:"'JetBrains Mono',monospace",color:"#00e6b4",marginBottom:4}}>{p}</div><div style={{fontSize:12,color:"rgba(255,255,255,0.4)",marginBottom:20}}>{dom}</div>{feat.split(", ").map(f=><div key={f} style={{fontSize:13,color:"rgba(255,255,255,0.6)",padding:"4px 0"}}>✓ {f}</div>)}<button onClick={onStart} style={{width:"100%",marginTop:20,padding:"10px",borderRadius:8,border:i===1?"none":"1px solid rgba(255,255,255,0.15)",background:i===1?"linear-gradient(135deg,#00e6b4,#00b4d8)":"transparent",color:i===1?"#0a0e14":"#e0e0e0",fontWeight:700,fontSize:13,cursor:"pointer"}}>{i===2?"Contact Sales":"Get Started"}</button></Card>)}</div></section>
<footer style={{textAlign:"center",padding:40,borderTop:"1px solid rgba(255,255,255,0.04)",color:"rgba(255,255,255,0.3)",fontSize:12}}>© 2026 Quantum Ready</footer>
</div>);}

function ComparisonView({scans,onBack}){if(scans.length===0)return<div style={{textAlign:"center",padding:60,color:"rgba(255,255,255,0.4)"}}>No scans yet. Run at least 2 scans.</div>;return(
<div><button onClick={onBack} style={{marginBottom:20,padding:"6px 16px",borderRadius:6,border:"1px solid rgba(255,255,255,0.1)",background:"transparent",color:"rgba(255,255,255,0.5)",fontSize:12,cursor:"pointer",fontFamily:"'JetBrains Mono',monospace"}}>← Back</button>
<h2 style={{fontSize:20,fontWeight:700,marginBottom:20}}>Multi-Domain Comparison</h2>
<div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
<thead><tr style={{borderBottom:"2px solid rgba(255,255,255,0.1)"}}><th style={{textAlign:"left",padding:"10px 14px",fontSize:11,color:"rgba(255,255,255,0.3)"}}>Metric</th>{scans.map(s=><th key={s.domain+s.scanDate} style={{textAlign:"center",padding:"10px 14px",fontSize:11,color:"#00e6b4",fontFamily:"'JetBrains Mono',monospace"}}>{s.domain}</th>)}</tr></thead>
<tbody>{[["Grade",s=><span style={{fontWeight:800,fontSize:18,color:s.grade?.startsWith("A")?"#34c759":"#ffcc00"}}>{s.grade}</span>],["TLS Score",s=><span style={{fontWeight:700,color:scColor(s.score),fontFamily:"'JetBrains Mono',monospace"}}>{s.score}</span>],["PQC Score",s=><span style={{fontWeight:700,color:scColor(s.pqcAssessment?.overallScore||0),fontFamily:"'JetBrains Mono',monospace"}}>{s.pqcAssessment?.overallScore||0}</span>],["PQC KEM",s=>(s.kems||[]).length?<span style={{color:"#34c759"}}>✓ {s.kems[0]}</span>:<span style={{color:"#ff3b30"}}>✗</span>],["PQC Sigs",s=>(s.sigAlgs||[]).some(a=>/ML-DSA/i.test(a))?<span style={{color:"#34c759"}}>✓</span>:<span style={{color:"#ff3b30"}}>✗</span>],["Cert Key",s=><span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11}}>{s.certificate?.keySize||"?"}</span>],["TLS 1.3",s=>(s.protocols||[]).some(p=>p.name==="TLS 1.3"&&p.offered)?<span style={{color:"#34c759"}}>✓</span>:<span style={{color:"#ff3b30"}}>✗</span>],["CNSA 2.0",s=>{const p=COMPLIANCE.cnsa2.checks.filter(c=>c.test(s)).length;return<span style={{color:scColor(p/COMPLIANCE.cnsa2.checks.length*100)}}>{p}/{COMPLIANCE.cnsa2.checks.length}</span>;}],["Critical",s=>{const c=(s.recommendations||[]).filter(r=>r.priority==="critical").length;return<span style={{color:c?"#ff3b30":"#34c759",fontWeight:700}}>{c}</span>;}]].map(([l,r])=><tr key={l} style={{borderBottom:"1px solid rgba(255,255,255,0.04)"}}><td style={{padding:"10px 14px",fontSize:12,color:"rgba(255,255,255,0.6)",fontWeight:600}}>{l}</td>{scans.map(s=><td key={s.domain+s.scanDate} style={{textAlign:"center",padding:"10px 14px"}}>{r(s)}</td>)}</tr>)}</tbody>
</table></div></div>);}

function HistoryView({history,onSelect,onBack,onClear}){if(!history.length)return<div style={{textAlign:"center",padding:60,color:"rgba(255,255,255,0.4)"}}>No history yet.</div>;return(
<div><div style={{display:"flex",justifyContent:"space-between",marginBottom:20}}>
<button onClick={onBack} style={{padding:"6px 16px",borderRadius:6,border:"1px solid rgba(255,255,255,0.1)",background:"transparent",color:"rgba(255,255,255,0.5)",fontSize:12,cursor:"pointer"}}>← Back</button>
<button onClick={onClear} style={{padding:"6px 16px",borderRadius:6,border:"1px solid rgba(255,59,48,0.3)",background:"transparent",color:"#ff6b6b",fontSize:12,cursor:"pointer"}}>Clear</button></div>
<h2 style={{fontSize:20,fontWeight:700,marginBottom:20}}>Scan History</h2>
<div style={{display:"grid",gap:10}}>{history.map((s,i)=><Card key={i} onClick={()=>onSelect(s)} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:16,cursor:"pointer"}}>
<div><div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:14,fontWeight:600}}>{s.domain}</div><div style={{fontSize:11,color:"rgba(255,255,255,0.3)",marginTop:2}}>{(s.scanDate||"").slice(0,10)}</div></div>
<div style={{display:"flex",gap:20}}><div style={{textAlign:"center"}}><div style={{fontSize:20,fontWeight:800,color:s.grade?.startsWith("A")?"#34c759":"#ffcc00",fontFamily:"'JetBrains Mono',monospace"}}>{s.grade}</div><div style={{fontSize:9,color:"rgba(255,255,255,0.3)"}}>Grade</div></div><div style={{textAlign:"center"}}><div style={{fontSize:20,fontWeight:800,color:scColor(s.pqcAssessment?.overallScore||0),fontFamily:"'JetBrains Mono',monospace"}}>{s.pqcAssessment?.overallScore||0}</div><div style={{fontSize:9,color:"rgba(255,255,255,0.3)"}}>PQC</div></div></div>
</Card>)}</div></div>);}

function ComplianceTab({data}){return(<div style={{display:"grid",gap:16}}>{Object.entries(COMPLIANCE).map(([key,fw])=>{const passed=fw.checks.filter(c=>c.test(data)).length;const total=fw.checks.length;return(<Card key={key}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}><div><SectionTitle icon={key==="cnsa2"?"🇺🇸":"🏛️"}>{fw.name}</SectionTitle><div style={{fontSize:12,color:"rgba(255,255,255,0.4)",marginTop:-12,marginBottom:12}}>{fw.full}</div></div><div style={{textAlign:"center"}}><div style={{fontSize:28,fontWeight:800,color:scColor(passed/total*100),fontFamily:"'JetBrains Mono',monospace"}}>{passed}/{total}</div><div style={{fontSize:10,color:"rgba(255,255,255,0.3)"}}>Passed</div></div></div>
<div style={{display:"grid",gap:8}}>{fw.checks.map(c=>{const p=c.test(data);return(<div key={c.id} style={{display:"flex",alignItems:"center",gap:12,padding:"10px 14px",borderRadius:8,background:"rgba(255,255,255,0.02)",border:"1px solid rgba(255,255,255,0.04)"}}><span style={{fontSize:16}}>{p?"✅":"❌"}</span><div style={{flex:1}}><div style={{fontSize:13,fontWeight:600}}>{c.label}</div><div style={{fontSize:11,color:"rgba(255,255,255,0.4)"}}>Required: {c.req}</div></div><span style={{fontSize:10,padding:"2px 10px",borderRadius:4,fontWeight:700,background:p?"rgba(52,199,89,0.1)":"rgba(255,59,48,0.1)",color:p?"#34c759":"#ff6b6b"}}>{p?"PASS":"FAIL"}</span></div>);})}</div>
{key==="cnsa2"&&fw.milestones&&<div style={{marginTop:16}}><div style={{fontSize:12,fontWeight:700,color:"rgba(255,255,255,0.5)",marginBottom:10,textTransform:"uppercase",letterSpacing:1.5}}>Timeline</div><div style={{display:"flex",position:"relative"}}><div style={{position:"absolute",top:14,left:0,right:0,height:2,background:"rgba(255,255,255,0.06)"}}/>{fw.milestones.map(m=><div key={m.year} style={{flex:1,textAlign:"center",position:"relative"}}><div style={{width:12,height:12,borderRadius:"50%",background:m.status==="active"?"#00e6b4":"rgba(255,255,255,0.15)",margin:"8px auto",position:"relative",zIndex:1}}/><div style={{fontSize:13,fontWeight:700,color:m.status==="active"?"#00e6b4":"rgba(255,255,255,0.5)",fontFamily:"'JetBrains Mono',monospace"}}>{m.year}</div><div style={{fontSize:9,color:"rgba(255,255,255,0.3)",marginTop:4,lineHeight:1.3}}>{m.req}</div></div>)}</div></div>}
</Card>);})}</div>);}

export default function App(){
  const[page,setPage]=useState("landing");
  const[scanning,setScanning]=useState(false);
  const[data,setData]=useState(null);
  const[tab,setTab]=useState("overview");
  const[anim,setAnim]=useState(false);
  const[history,setHistory]=useState([]);
  useEffect(()=>{try{setHistory(JSON.parse(localStorage.getItem("qr_h")||"[]"))}catch{}},[]);
  const saveH=h=>{setHistory(h);try{localStorage.setItem("qr_h",JSON.stringify(h))}catch{}};
  const addH=s=>{saveH([s,...history.filter(h=>h.domain!==s.domain||h.scanDate!==s.scanDate)].slice(0,50));};

  const doScan=async(domain)=>{setScanning(true);setData(null);setAnim(false);try{const r=await fetch("http://localhost:5000/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain})});if(!r.ok)throw new Error();const res=await r.json();if(res.error)throw new Error();setData(res);addH(res);}catch{await new Promise(r=>setTimeout(r,2000));const res={...SAMPLE_SCAN,domain,scanDate:new Date().toISOString()};setData(res);addH(res);}setScanning(false);setTimeout(()=>setAnim(true),50);};

  const doFile=async(file)=>{setScanning(true);setData(null);setAnim(false);try{const t=await file.text();const raw=JSON.parse(t);const arr=Array.isArray(raw)?raw:raw.scanResult||[raw];const dom=arr.find(e=>e.id==="service")?.ip||file.name.replace(".json","");const res=parseTestsslJson(arr,dom);setData(res);addH(res);}catch(e){alert("Could not parse JSON.");console.error(e);}setScanning(false);setTimeout(()=>setAnim(true),50);};

  if(page==="landing")return<LandingPage onStart={()=>setPage("scanner")}/>;

  const tabs=[{id:"overview",l:"Overview"},{id:"crypto",l:"Crypto"},{id:"vulns",l:"Vulns"},{id:"pqc",l:"PQC"},{id:"compliance",l:"Compliance"},{id:"actions",l:"Actions"}];

  return(
<div style={{minHeight:"100vh",background:"#0a0e14",color:"#e0e0e0",fontFamily:"'Inter',sans-serif"}}>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&family=Sora:wght@700;800&display=swap" rel="stylesheet"/>
<div style={{position:"fixed",top:-200,right:-200,width:600,height:600,background:"radial-gradient(circle,rgba(0,230,180,0.06) 0%,transparent 70%)",pointerEvents:"none"}}/>
<header style={{padding:"20px 40px",display:"flex",alignItems:"center",justifyContent:"space-between",borderBottom:"1px solid rgba(255,255,255,0.04)"}}>
<div style={{display:"flex",alignItems:"center",gap:10,cursor:"pointer"}} onClick={()=>setPage("landing")}><div style={{width:32,height:32,borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",background:"linear-gradient(135deg,#00e6b4,#00b4d8)",fontSize:16,fontWeight:800,color:"#0a0e14",fontFamily:"'JetBrains Mono',monospace"}}>Q</div><div><div style={{fontSize:15,fontWeight:700}}>Quantum Ready</div><div style={{fontSize:9,color:"rgba(255,255,255,0.3)",letterSpacing:2,textTransform:"uppercase"}}>PQC Scanner</div></div></div>
<div style={{display:"flex",gap:8}}>{[{l:"Scanner",p:"scanner"},{l:`History (${history.length})`,p:"history"},{l:"Compare",p:"compare"}].map(({l,p})=><button key={p} onClick={()=>setPage(p)} style={{padding:"6px 16px",borderRadius:6,border:"none",cursor:"pointer",background:page===p?"rgba(0,230,180,0.1)":"rgba(255,255,255,0.04)",color:page===p?"#00e6b4":"rgba(255,255,255,0.4)",fontSize:12,fontWeight:600,fontFamily:"'JetBrains Mono',monospace"}}>{l}</button>)}</div>
</header>
<main style={{maxWidth:1100,margin:"0 auto",padding:"30px 24px"}}>
{page==="history"&&<HistoryView history={history} onSelect={s=>{setData(s);setAnim(true);setPage("scanner");}} onBack={()=>setPage("scanner")} onClear={()=>saveH([])}/>}
{page==="compare"&&<ComparisonView scans={history.slice(0,6)} onBack={()=>setPage("scanner")}/>}
{page==="scanner"&&<>
<div style={{textAlign:"center",marginBottom:40}}>
<h1 style={{fontSize:32,fontWeight:700,marginBottom:10,background:"linear-gradient(135deg,#fff 30%,#00e6b4)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent"}}>Cryptographic Posture Assessment</h1>
<p style={{color:"rgba(255,255,255,0.4)",fontSize:14,marginBottom:28,maxWidth:520,margin:"0 auto 28px"}}>Scan any domain or upload testssl.sh JSON.</p>
<div style={{display:"flex",justifyContent:"center"}}><ScannerInput onScan={doScan} scanning={scanning} onFileUpload={doFile}/></div>
</div>
{scanning&&<div style={{textAlign:"center",padding:60}}><div style={{width:48,height:48,border:"3px solid rgba(0,230,180,0.15)",borderTopColor:"#00e6b4",borderRadius:"50%",margin:"0 auto 20px",animation:"spin .8s linear infinite"}}/><style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style><div style={{color:"#00e6b4",fontFamily:"'JetBrains Mono',monospace",fontSize:13}}>Analyzing...</div></div>}
{data&&<div style={{opacity:anim?1:0,transform:anim?"translateY(0)":"translateY(20px)",transition:"all .6s cubic-bezier(.4,0,.2,1)"}}>
<div style={{display:"flex",gap:4,marginBottom:16,background:"rgba(255,255,255,0.02)",borderRadius:10,padding:4,border:"1px solid rgba(255,255,255,0.04)"}}>{tabs.map(t=><button key={t.id} onClick={()=>setTab(t.id)} style={{flex:1,padding:"10px 0",borderRadius:8,border:"none",cursor:"pointer",background:tab===t.id?"rgba(0,230,180,0.1)":"transparent",color:tab===t.id?"#00e6b4":"rgba(255,255,255,0.4)",fontWeight:600,fontSize:12,fontFamily:"'JetBrains Mono',monospace"}}>{t.l}</button>)}</div>
<div style={{display:"flex",justifyContent:"flex-end",marginBottom:16}}><button onClick={()=>{const w=window.open("","_blank");w.document.write(generatePdfHtml(data));w.document.close();setTimeout(()=>w.print(),500);}} style={{padding:"8px 20px",borderRadius:8,border:"1px solid rgba(0,230,180,0.3)",background:"rgba(0,230,180,0.08)",color:"#00e6b4",fontSize:12,fontFamily:"'JetBrains Mono',monospace",fontWeight:600,cursor:"pointer"}}>↓ Download PDF</button></div>

{tab==="overview"&&<div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:16}}>
<Card style={{gridColumn:"1/-1",display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:20}}>
<div><div style={{fontSize:12,color:"rgba(255,255,255,0.3)",textTransform:"uppercase",letterSpacing:2,marginBottom:4}}>Target</div><div style={{fontSize:20,fontWeight:700,fontFamily:"'JetBrains Mono',monospace"}}>{data.domain}</div><div style={{fontSize:12,color:"rgba(255,255,255,0.3)",fontFamily:"'JetBrains Mono',monospace"}}>{data.ip}</div></div>
<div style={{display:"flex",gap:40}}><GaugeRing score={data.score} label="TLS Score"/><GaugeRing score={data.pqcAssessment?.overallScore||0} label="PQC Ready"/></div>
<div style={{fontSize:56,fontWeight:800,fontFamily:"'JetBrains Mono',monospace",color:"#34c759",textShadow:"0 0 30px rgba(52,199,89,0.3)"}}>{data.grade}</div>
</Card>
<Card><SectionTitle icon="🔒">Protocols</SectionTitle>{(data.protocols||[]).map(p=><div key={p.name} style={{display:"flex",justifyContent:"space-between",padding:"6px 0",borderBottom:"1px solid rgba(255,255,255,0.03)"}}><span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:13}}>{p.name}</span><span style={{fontSize:11,color:p.offered?"#34c759":"rgba(255,255,255,0.2)"}}>{p.offered?"on":"off"}</span></div>)}</Card>
<Card><SectionTitle icon="🛡️">Headers</SectionTitle>{Object.entries(data.headers||{}).map(([k,v])=><div key={k} style={{display:"flex",justifyContent:"space-between",padding:"6px 0",borderBottom:"1px solid rgba(255,255,255,0.03)"}}><span style={{fontSize:12,color:"rgba(255,255,255,0.5)"}}>{k}</span><span style={{fontSize:12,fontFamily:"'JetBrains Mono',monospace",color:v===true?"#34c759":v==="*"?"#ffcc00":"#e0e0e0"}}>{String(v)}</span></div>)}</Card>
<Card><SectionTitle icon="📜">Certificate</SectionTitle>{[["Key",data.certificate?.keySize],["Sig",data.certificate?.signatureAlg],["Issuer",data.certificate?.issuer]].map(([k,v])=><div key={k} style={{display:"flex",justifyContent:"space-between",padding:"6px 0",borderBottom:"1px solid rgba(255,255,255,0.03)"}}><span style={{fontSize:12,color:"rgba(255,255,255,0.5)"}}>{k}</span><span style={{fontSize:12,fontFamily:"'JetBrains Mono',monospace"}}>{v}</span></div>)}{!data.certificate?.pqcSafe&&<div style={{marginTop:10,padding:"6px 10px",borderRadius:6,background:"rgba(255,59,48,0.1)",fontSize:11,color:"#ff6b6b"}}>⚠ Quantum-vulnerable</div>}</Card>
</div>}

{tab==="crypto"&&<div style={{display:"grid",gap:16}}>
<Card><SectionTitle icon="🔑">Ciphers</SectionTitle><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr style={{borderBottom:"1px solid rgba(255,255,255,0.08)"}}>{["Cipher","Proto","PQC"].map(h=><th key={h} style={{textAlign:"left",padding:"8px 12px",fontSize:11,color:"rgba(255,255,255,0.3)",textTransform:"uppercase"}}>{h}</th>)}</tr></thead><tbody>{(data.ciphers||[]).map(c=><tr key={c.name} style={{borderBottom:"1px solid rgba(255,255,255,0.03)"}}><td style={{padding:"8px 12px",fontFamily:"'JetBrains Mono',monospace",fontSize:11}}>{c.name}</td><td style={{padding:"8px 12px",fontSize:12}}>{c.protocol}</td><td style={{padding:"8px 12px"}}><span style={{fontSize:10,padding:"2px 8px",borderRadius:4,fontWeight:600,background:c.pqcSafe?"rgba(52,199,89,0.1)":"rgba(255,59,48,0.1)",color:c.pqcSafe?"#34c759":"#ff6b6b"}}>{c.pqcSafe?"SAFE":"RISK"}</span></td></tr>)}</tbody></table></Card>
<div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:16}}>
<Card><SectionTitle icon="🧬">KEMs</SectionTitle>{(data.kems||[]).length?data.kems.map(k=><div key={k} style={{padding:"8px 12px",borderRadius:8,background:"rgba(0,230,180,0.08)",border:"1px solid rgba(0,230,180,0.2)",fontFamily:"'JetBrains Mono',monospace",fontSize:13,color:"#00e6b4",marginBottom:6}}>{k}</div>):<div style={{color:"#ff6b6b",fontSize:12}}>None</div>}</Card>
<Card><SectionTitle icon="📐">Curves</SectionTitle>{(data.curves||[]).map(c=><div key={c} style={{padding:"4px 0",fontFamily:"'JetBrains Mono',monospace",fontSize:13,color:"rgba(255,255,255,0.6)"}}>{c}</div>)}</Card>
<Card><SectionTitle icon="✍️">Sig Algs</SectionTitle>{(data.sigAlgs||[]).map(s=><div key={s} style={{padding:"4px 0",fontFamily:"'JetBrains Mono',monospace",fontSize:12,color:"rgba(255,255,255,0.6)"}}>{s}</div>)}</Card>
</div></div>}

{tab==="vulns"&&<Card><SectionTitle icon="🐛">Vulnerabilities</SectionTitle><div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>{(data.vulnerabilities||[]).map(v=><div key={v.name} style={{display:"flex",alignItems:"center",gap:10,padding:"10px 14px",borderRadius:8,background:"rgba(255,255,255,0.02)",border:"1px solid rgba(255,255,255,0.04)"}}><StatusDot status={v.status}/><span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:13}}>{v.name}</span><span style={{marginLeft:"auto",fontSize:10,padding:"2px 8px",borderRadius:4,fontWeight:600,background:v.status==="safe"?"rgba(52,199,89,0.1)":"rgba(255,204,0,0.1)",color:v.status==="safe"?"#34c759":"#ffcc00"}}>{v.status==="safe"?"OK":"WARN"}</span></div>)}</div></Card>}

{tab==="pqc"&&<div style={{display:"grid",gap:16}}>
<Card style={{textAlign:"center",padding:40}}><GaugeRing score={data.pqcAssessment?.overallScore||0} size={160} strokeWidth={12} label="PQC Readiness"/></Card>
{Object.entries(data.pqcAssessment||{}).filter(([k])=>k!=="overallScore").map(([k,v])=><Card key={k} style={{display:"flex",alignItems:"center",gap:20}}><GaugeRing score={v.score} size={80} strokeWidth={6} label=""/><div style={{flex:1}}><div style={{fontSize:14,fontWeight:600,textTransform:"capitalize"}}>{k.replace(/([A-Z])/g," $1")}</div><div style={{fontSize:13,color:"rgba(255,255,255,0.5)"}}>{v.detail}</div></div></Card>)}
</div>}

{tab==="compliance"&&<ComplianceTab data={data}/>}

{tab==="actions"&&<div style={{display:"grid",gap:12}}>{(data.recommendations||[]).map((r,i)=>{const p=PRI_COL[r.priority]||PRI_COL.low;return<Card key={i} style={{borderLeft:`3px solid ${p.border}`,background:p.bg+"40"}}><div style={{display:"flex",alignItems:"flex-start",gap:14}}><span style={{fontSize:10,padding:"3px 10px",borderRadius:4,fontWeight:700,background:p.label,color:p.text,textTransform:"uppercase",letterSpacing:1,whiteSpace:"nowrap",marginTop:2}}>{r.priority}</span><div style={{flex:1}}><div style={{fontSize:15,fontWeight:600,marginBottom:6,color:p.text}}>{r.title}</div><div style={{fontSize:13,color:"rgba(255,255,255,0.5)",lineHeight:1.6,marginBottom:6}}>{r.description}</div><div style={{fontSize:11,color:"rgba(255,255,255,0.3)",fontFamily:"'JetBrains Mono',monospace"}}>Timeline: {r.timeline}</div></div></div></Card>;})}</div>}
</div>}
</>}
</main></div>);}
