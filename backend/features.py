"""
Quantum Ready — Extended API Endpoints
- AI-powered analysis (Claude API)
- Certificate discovery via Certificate Transparency
- Cryptographic Bill of Materials (CBOM) generation
"""

import json
import requests
from datetime import datetime, timezone


def ai_analyze(scan_data: dict, api_key: str = None) -> dict:
    """Use Claude API to generate plain-English PQC risk analysis."""
    if not api_key:
        return _fallback_analysis(scan_data)

    prompt = f"""You are a PQC (Post-Quantum Cryptography) security analyst. Analyze this TLS scan result and provide:

1. EXECUTIVE SUMMARY (2-3 sentences for a non-technical CISO)
2. TOP 3 RISKS ranked by urgency
3. IMMEDIATE ACTIONS the IT team should take this week
4. 90-DAY ROADMAP for PQC migration
5. COMPLIANCE GAPS against CNSA 2.0 and NIST FIPS 203/204/205

Scan data:
- Domain: {scan_data.get('domain')}
- TLS Grade: {scan_data.get('grade')}
- PQC Score: {scan_data.get('pqcAssessment', {}).get('overallScore', 'N/A')}/100
- KEMs offered: {scan_data.get('kems', [])}
- Signature algorithms: {scan_data.get('sigAlgs', [])}
- Certificate: {scan_data.get('certificate', {}).get('keySize', 'unknown')} / {scan_data.get('certificate', {}).get('signatureAlg', 'unknown')}
- Protocols: {', '.join(p['name'] for p in scan_data.get('protocols', []) if p.get('offered'))}
- Vulnerabilities with warnings: {[v['name'] for v in scan_data.get('vulnerabilities', []) if v.get('status') != 'safe']}
- Recommendations: {json.dumps(scan_data.get('recommendations', []))}

Be specific, actionable, and reference actual standards. Format as JSON with keys: executive_summary, top_risks (array), immediate_actions (array), roadmap_90day (array of objects with week and action), compliance_gaps (array).
Respond ONLY with valid JSON, no markdown."""

    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1500,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        text = data["content"][0]["text"]
        # Clean any markdown fences
        text = text.strip().removeprefix("```json").removesuffix("```").strip()
        return json.loads(text)
    except Exception as e:
        print(f"AI analysis error: {e}")
        return _fallback_analysis(scan_data)


def _fallback_analysis(scan_data: dict) -> dict:
    """Generate analysis without AI when API key not available."""
    pqc = scan_data.get("pqcAssessment", {})
    score = pqc.get("overallScore", 0)
    has_kem = len(scan_data.get("kems", [])) > 0
    has_pqc_sig = any("ML-DSA" in s for s in scan_data.get("sigAlgs", []))
    cert_key = scan_data.get("certificate", {}).get("keySize", "")

    risks = []
    actions = []

    if not has_pqc_sig:
        risks.append({
            "risk": "No post-quantum signature algorithms",
            "severity": "critical",
            "detail": "Server only offers classical signatures (RSA/ECDSA). Vulnerable to quantum forgery attacks."
        })
        actions.append("Monitor OpenSSL releases for ML-DSA support and plan upgrade")

    if "RSA" in cert_key:
        risks.append({
            "risk": f"Quantum-vulnerable certificate ({cert_key})",
            "severity": "critical",
            "detail": "RSA certificates will be broken by Shor's algorithm. No quantum-safe CAs widely available yet."
        })
        actions.append("Prepare certificate migration plan for when CAs support ML-DSA")

    if not has_kem:
        risks.append({
            "risk": "No post-quantum key exchange",
            "severity": "critical",
            "detail": "Vulnerable to harvest-now-decrypt-later attacks. Adversaries can record traffic today and decrypt when quantum computers arrive."
        })
        actions.append("Enable X25519MLKEM768 hybrid key exchange immediately")
    else:
        actions.append("PQC key exchange is active — verify all clients negotiate it")

    return {
        "executive_summary": f"This domain scores {score}/100 for PQC readiness. {'Hybrid PQC key exchange is active, which is ahead of most organizations.' if has_kem else 'No PQC protections are in place — this domain is fully vulnerable to quantum attacks.'} Certificate and signature algorithms still use classical cryptography that will need migration.",
        "top_risks": risks[:3],
        "immediate_actions": actions,
        "roadmap_90day": [
            {"week": "1-2", "action": "Complete cryptographic inventory of all services"},
            {"week": "3-4", "action": "Enable TLS 1.3 with hybrid PQC key exchange on all servers"},
            {"week": "5-8", "action": "Test PQC cipher suites in staging environment"},
            {"week": "9-12", "action": "Deploy PQC configurations to production, generate CBOM for compliance"},
        ],
        "compliance_gaps": [
            gap for gap in [
                None if has_kem else "CNSA 2.0: ML-KEM key exchange not available",
                None if has_pqc_sig else "CNSA 2.0: ML-DSA signatures not available",
                "NIST FIPS 204: No ML-DSA certificate support (CA dependency)",
            ] if gap
        ],
    }


def discover_certificates(domain: str) -> list:
    """Discover all certificates for a domain using Certificate Transparency logs."""
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "QuantumReady/1.0"}
        )
        resp.raise_for_status()
        entries = resp.json()
    except Exception as e:
        print(f"crt.sh error: {e}")
        return []

    # Deduplicate by serial number
    seen = set()
    certs = []
    for entry in entries:
        serial = entry.get("serial_number", "")
        if serial in seen:
            continue
        seen.add(serial)

        not_after = entry.get("not_after", "")
        not_before = entry.get("not_before", "")
        issuer = entry.get("issuer_name", "")
        cn = entry.get("common_name", "")
        san = entry.get("name_value", "")

        # Determine if expired
        is_expired = False
        try:
            expiry = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
            is_expired = expiry < datetime.now()
            days_remaining = (expiry - datetime.now()).days
        except:
            days_remaining = None

        certs.append({
            "commonName": cn,
            "san": san.split("\n") if san else [],
            "issuer": issuer,
            "notBefore": not_before,
            "notAfter": not_after,
            "serialNumber": serial,
            "isExpired": is_expired,
            "daysRemaining": days_remaining,
            "pqcSafe": False,  # No CT-logged certs use PQC yet
        })

    # Sort by expiry (most recent first), limit to 50
    certs.sort(key=lambda c: c.get("notAfter", ""), reverse=True)
    return certs[:50]


def generate_cbom(scan_data: dict, certs: list = None) -> dict:
    """Generate a Cryptographic Bill of Materials (CBOM)."""
    domain = scan_data.get("domain", "unknown")
    now = datetime.now(timezone.utc).isoformat()

    # Collect all crypto assets
    assets = []

    # TLS protocols
    for p in scan_data.get("protocols", []):
        if p.get("offered"):
            assets.append({
                "type": "protocol",
                "name": p["name"],
                "status": "active",
                "pqcSafe": p["name"] == "TLS 1.3",
                "location": f"TLS endpoint {domain}",
                "recommendation": "Maintain" if p["name"] == "TLS 1.3" else "Deprecate — use TLS 1.3 only",
            })

    # Cipher suites
    for c in scan_data.get("ciphers", []):
        assets.append({
            "type": "cipher_suite",
            "name": c.get("name", ""),
            "protocol": c.get("protocol", ""),
            "keyExchange": c.get("keyExchange", ""),
            "encryption": c.get("encryption", ""),
            "status": "active",
            "pqcSafe": c.get("pqcSafe", False),
            "location": f"TLS endpoint {domain}",
            "recommendation": "Maintain" if c.get("pqcSafe") else "Migrate to PQC-safe suite",
        })

    # Key exchange mechanisms
    for k in scan_data.get("kems", []):
        assets.append({
            "type": "kem",
            "name": k,
            "status": "active",
            "pqcSafe": "MLKEM" in k.upper(),
            "location": f"TLS 1.3 endpoint {domain}",
            "recommendation": "Maintain — hybrid PQC active",
        })

    # Signature algorithms
    for s in scan_data.get("sigAlgs", []):
        is_pqc = "ML-DSA" in s.upper() or "DILITHIUM" in s.upper()
        assets.append({
            "type": "signature_algorithm",
            "name": s,
            "status": "active",
            "pqcSafe": is_pqc,
            "location": f"TLS handshake {domain}",
            "recommendation": "Maintain" if is_pqc else "Add ML-DSA when supported",
        })

    # Certificate
    cert = scan_data.get("certificate", {})
    if cert:
        assets.append({
            "type": "certificate",
            "name": f"{cert.get('cn', domain)} ({cert.get('keySize', 'unknown')})",
            "algorithm": cert.get("signatureAlg", ""),
            "keySize": cert.get("keySize", ""),
            "issuer": cert.get("issuer", ""),
            "status": "active",
            "pqcSafe": cert.get("pqcSafe", False),
            "location": f"Server certificate {domain}",
            "recommendation": "Migrate to ML-DSA certificate when CA support available",
        })

    # Elliptic curves
    for curve in scan_data.get("curves", []):
        assets.append({
            "type": "elliptic_curve",
            "name": curve,
            "status": "active",
            "pqcSafe": False,  # All classical EC curves are quantum-vulnerable for key agreement
            "location": f"TLS key exchange {domain}",
            "recommendation": "Supplement with ML-KEM hybrid",
        })

    # Summary stats
    total = len(assets)
    pqc_safe = sum(1 for a in assets if a.get("pqcSafe"))
    at_risk = total - pqc_safe

    return {
        "version": "1.0",
        "generatedAt": now,
        "domain": domain,
        "summary": {
            "totalAssets": total,
            "pqcSafe": pqc_safe,
            "atRisk": at_risk,
            "readinessPercent": round(pqc_safe / total * 100) if total > 0 else 0,
        },
        "assets": assets,
        "complianceMapping": {
            "CNSA_2_0": {
                "status": "partial" if pqc_safe > 0 else "non_compliant",
                "gaps": [a["name"] for a in assets if not a.get("pqcSafe")],
            },
            "NIST_FIPS_203": {
                "status": "compliant" if any(a["type"] == "kem" and a.get("pqcSafe") for a in assets) else "non_compliant",
            },
            "NIST_FIPS_204": {
                "status": "compliant" if any("ML-DSA" in a.get("name", "").upper() for a in assets) else "non_compliant",
            },
        },
    }


def generate_remediation_playbook(scan_data: dict, server_type: str = "nginx") -> dict:
    """Generate server-specific PQC remediation config."""
    playbooks = {
        "nginx": {
            "name": "Nginx",
            "description": "PQC-enabled TLS configuration for Nginx",
            "prerequisites": [
                "Nginx 1.25.0+ compiled with OpenSSL 3.5+",
                "Or use BoringSSL with ML-KEM support",
            ],
            "config": """# /etc/nginx/conf.d/ssl-pqc.conf
# Quantum Ready — PQC TLS Configuration for Nginx

ssl_protocols TLSv1.3;  # TLS 1.3 only — required for PQC KEM
ssl_prefer_server_ciphers off;  # Let TLS 1.3 handle cipher negotiation

# PQC-safe cipher suites (TLS 1.3)
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;

# Enable hybrid PQC key exchange (requires OpenSSL 3.5+)
ssl_conf_command Groups X25519MLKEM768:X25519:secp384r1;

# HSTS — force HTTPS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Security headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;

# Session tickets — rotate daily for forward secrecy
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;  # Disable until key rotation is automated
""",
            "verification": [
                "sudo nginx -t",
                "sudo systemctl reload nginx",
                "testssl.sh --jsonfile post-fix.json https://yourdomain.com",
                "Compare pre and post scan results in Quantum Ready dashboard",
            ],
        },
        "apache": {
            "name": "Apache",
            "description": "PQC-enabled TLS configuration for Apache",
            "prerequisites": [
                "Apache 2.4.58+ with OpenSSL 3.5+",
                "mod_ssl enabled",
            ],
            "config": """# /etc/apache2/conf-available/ssl-pqc.conf
# Quantum Ready — PQC TLS Configuration for Apache

SSLProtocol -all +TLSv1.3
SSLOpenSSLConfCmd Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:secp384r1

SSLHonorCipherOrder off
SSLSessionTickets off

SSLUseStapling On
SSLStaplingCache shmcb:/tmp/ssl_stapling(128000)

Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
""",
            "verification": [
                "sudo apachectl configtest",
                "sudo systemctl reload apache2",
                "testssl.sh --jsonfile post-fix.json https://yourdomain.com",
            ],
        },
        "aws_alb": {
            "name": "AWS ALB",
            "description": "PQC-enabled security policy for AWS Application Load Balancer",
            "prerequisites": [
                "AWS CLI configured",
                "ALB with HTTPS listener",
            ],
            "config": """# AWS CLI — Set PQC-compatible security policy
# As of 2026, use the latest TLS 1.3 policy with PQC support

aws elbv2 modify-listener \\
  --listener-arn arn:aws:elasticloadbalancing:REGION:ACCOUNT:listener/app/ALB_NAME/ID/ID \\
  --ssl-policy ELBSecurityPolicy-TLS13-1-3-2023-12

# Terraform equivalent:
# resource "aws_lb_listener" "https" {
#   ssl_policy = "ELBSecurityPolicy-TLS13-1-3-2023-12"
# }

# CloudFormation:
# Type: AWS::ElasticLoadBalancingV2::Listener
# Properties:
#   SslPolicy: ELBSecurityPolicy-TLS13-1-3-2023-12
""",
            "verification": [
                "aws elbv2 describe-listeners --listener-arns <ARN>",
                "testssl.sh --jsonfile post-fix.json https://yourdomain.com",
            ],
        },
    }

    return playbooks.get(server_type, playbooks["nginx"])
