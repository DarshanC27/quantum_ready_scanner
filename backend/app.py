"""
Quantum Ready — PQC Migration Scanner Backend
Runs testssl.sh against a target domain, parses results, and returns a PQC readiness report.
"""

import json
import os
import re
import subprocess
import tempfile
import uuid
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Path to testssl.sh — update this to your local clone
TESTSSL_PATH = os.environ.get("TESTSSL_PATH", os.path.expanduser("~/testssl.sh/testssl.sh"))


def run_testssl(domain: str) -> dict:
    """Run testssl.sh with JSON output and return parsed results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        json_file = os.path.join(tmpdir, f"{uuid.uuid4().hex}.json")
        cmd = [
            "bash", TESTSSL_PATH,
            "--jsonfile", json_file,
            "--warnings", "off",
            "--color", "0",
            f"https://{domain}"
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
        except subprocess.TimeoutExpired:
            raise Exception("Scan timed out after 5 minutes")
        except FileNotFoundError:
            raise Exception(f"testssl.sh not found at {TESTSSL_PATH}. Set TESTSSL_PATH env var.")

        if not os.path.exists(json_file):
            raise Exception(f"testssl.sh did not produce output. stderr: {result.stderr[:500]}")

        with open(json_file, "r") as f:
            raw = json.load(f)

    return raw


def parse_testssl_json(raw: list, domain: str) -> dict:
    """Parse testssl.sh JSON output into structured PQC assessment."""

    def find(test_id: str) -> dict | None:
        for entry in raw:
            if entry.get("id") == test_id:
                return entry
        return None

    def find_all(id_prefix: str) -> list:
        return [e for e in raw if e.get("id", "").startswith(id_prefix)]

    def severity(entry):
        if entry is None:
            return "unknown"
        s = entry.get("severity", "").upper()
        if s in ("OK", "INFO"):
            return "safe"
        if s in ("LOW", "MEDIUM", "WARN", "WARNING"):
            return "warn"
        if s in ("HIGH", "CRITICAL", "NOT OK"):
            return "fail"
        return "safe"

    # --- IP ---
    ip_entry = find("service")
    ip = ""
    if ip_entry:
        ip = ip_entry.get("ip", "")

    # --- Protocols ---
    protocol_ids = {
        "SSLv2": "SSLv2",
        "SSLv3": "SSLv3",
        "TLS 1.0": "TLS1",
        "TLS 1.1": "TLS1_1",
        "TLS 1.2": "TLS1_2",
        "TLS 1.3": "TLS1_3",
    }
    protocols = []
    for display_name, test_id in protocol_ids.items():
        entry = find(test_id)
        offered = False
        if entry:
            finding = entry.get("finding", "").lower()
            offered = "offered" in finding and "not offered" not in finding
        is_safe = True
        if display_name in ("SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"):
            is_safe = not offered
        else:
            is_safe = offered
        protocols.append({"name": display_name, "offered": offered, "safe": is_safe})

    # --- Ciphers ---
    cipher_entries = find_all("cipher_x")
    ciphers = []
    for c in cipher_entries:
        finding = c.get("finding", "")
        # Parse cipher info from finding
        parts = finding.split()
        name = parts[0] if parts else finding
        protocol = ""
        key_exchange = ""
        encryption = ""

        # Determine PQC safety
        pqc_safe = "TLS 1.3" in c.get("finding", "") or "MLKEM" in finding.upper()

        ciphers.append({
            "name": name,
            "protocol": protocol,
            "keyExchange": key_exchange,
            "encryption": encryption,
            "pqcSafe": pqc_safe,
        })

    # If no individual cipher entries, build from cipher category findings
    if not ciphers:
        for entry in raw:
            eid = entry.get("id", "")
            if eid.startswith("cipherorder_"):
                finding = entry.get("finding", "")
                protocol = "TLS 1.3" if "TLSv1.3" in eid else "TLS 1.2" if "TLSv1.2" in eid else ""
                for line in finding.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 1:
                        cipher_name = parts[0]
                        kx = parts[1] if len(parts) > 1 else ""
                        enc = parts[2] if len(parts) > 2 else ""
                        pqc_safe = "MLKEM" in line.upper() or protocol == "TLS 1.3"
                        ciphers.append({
                            "name": cipher_name,
                            "protocol": protocol,
                            "keyExchange": kx,
                            "encryption": enc,
                            "pqcSafe": pqc_safe,
                        })

    # --- KEMs ---
    kems = []
    kem_entry = find("FS_IANA")
    if kem_entry:
        finding = kem_entry.get("finding", "")
        if "MLKEM" in finding.upper() or "X25519MLKEM" in finding.upper():
            for token in finding.split():
                if "MLKEM" in token.upper():
                    kems.append(token)
    # Also check KEMs offered field
    for entry in raw:
        if "kem" in entry.get("id", "").lower():
            finding = entry.get("finding", "")
            for token in finding.split():
                if "MLKEM" in token.upper() and token not in kems:
                    kems.append(token)

    # --- Curves ---
    curves = []
    curve_entry = find("FS_elliptic_curves")
    if curve_entry:
        curves = [c.strip() for c in curve_entry.get("finding", "").split() if c.strip()]

    # --- Signature algorithms ---
    sig_algs = []
    for entry in raw:
        if "sig_algs" in entry.get("id", ""):
            sig_algs.extend([s.strip() for s in entry.get("finding", "").split() if s.strip()])

    # --- Certificate ---
    cert_key_size = ""
    cert_sig_alg = ""
    cert_issuer = ""
    cert_cn = ""
    cert_validity = ""

    key_entry = find("cert_keySize")
    if key_entry:
        cert_key_size = key_entry.get("finding", "")

    sig_entry = find("cert_signatureAlgorithm")
    if sig_entry:
        cert_sig_alg = sig_entry.get("finding", "")

    issuer_entry = find("cert_caIssuers")
    if issuer_entry:
        cert_issuer = issuer_entry.get("finding", "")

    cn_entry = find("cert_commonName")
    if cn_entry:
        cert_cn = cn_entry.get("finding", "")

    start_entry = find("cert_notBefore")
    end_entry = find("cert_notAfter")
    if start_entry and end_entry:
        cert_validity = f"{start_entry.get('finding', '')} → {end_entry.get('finding', '')}"

    cert_pqc_safe = "ML-DSA" in cert_sig_alg.upper() or "DILITHIUM" in cert_sig_alg.upper()

    certificate = {
        "signatureAlg": cert_sig_alg,
        "keySize": cert_key_size,
        "issuer": cert_issuer,
        "validity": cert_validity,
        "cn": cert_cn,
        "pqcSafe": cert_pqc_safe,
    }

    # --- Security Headers ---
    hsts = False
    x_frame = ""
    x_content_type = ""
    referrer = ""
    cors = ""

    for entry in raw:
        eid = entry.get("id", "")
        finding = entry.get("finding", "")
        if eid == "HSTS":
            hsts = "not" not in finding.lower()
        elif eid == "X-Frame-Options":
            x_frame = finding
        elif eid == "X-Content-Type-Options":
            x_content_type = finding
        elif eid == "Referrer-Policy":
            referrer = finding
        elif "access-control" in eid.lower():
            cors = finding

    headers = {
        "hsts": hsts,
        "xFrameOptions": x_frame or "not set",
        "xContentType": x_content_type or "not set",
        "referrerPolicy": referrer or "not set",
        "cors": cors or "not set",
    }

    # --- Vulnerabilities ---
    vuln_ids = {
        "Heartbleed": "heartbleed",
        "CCS Injection": "CCS",
        "ROBOT": "ROBOT",
        "CRIME": "CRIME_TLS",
        "BREACH": "BREACH",
        "POODLE": "POODLE_SSL",
        "SWEET32": "SWEET32",
        "FREAK": "FREAK",
        "DROWN": "DROWN",
        "LOGJAM": "LOGJAM",
        "BEAST": "BEAST",
        "LUCKY13": "LUCKY13",
        "RC4": "RC4",
    }
    vulnerabilities = []
    for display_name, test_id in vuln_ids.items():
        entry = find(test_id)
        status = severity(entry)
        vulnerabilities.append({"name": display_name, "status": status})

    # --- PQC Assessment ---
    has_pqc_kem = len(kems) > 0
    has_pqc_sig = any("ML-DSA" in s.upper() or "DILITHIUM" in s.upper() for s in sig_algs)
    has_pqc_cert = cert_pqc_safe
    all_aead = True  # Assume if we got this far, symmetric is fine

    ke_score = 90 if has_pqc_kem else 10
    sig_score = 90 if has_pqc_sig else 20
    cert_score = 90 if has_pqc_cert else 15
    cipher_score = 95 if all_aead else 60
    session_score = 50  # Default conservative

    overall = int(ke_score * 0.3 + sig_score * 0.25 + cert_score * 0.25 + cipher_score * 0.1 + session_score * 0.1)

    pqc_assessment = {
        "overallScore": overall,
        "keyExchange": {
            "score": ke_score,
            "detail": f"{'Hybrid PQC KEM detected: ' + ', '.join(kems) if has_pqc_kem else 'No PQC key exchange mechanisms detected — vulnerable to harvest-now-decrypt-later attacks.'}",
        },
        "signatures": {
            "score": sig_score,
            "detail": f"{'PQC signature algorithms available' if has_pqc_sig else 'Only classical signature algorithms (RSA/ECDSA) — vulnerable to quantum forgery.'}",
        },
        "certificate": {
            "score": cert_score,
            "detail": f"{'PQC certificate detected' if has_pqc_cert else f'{cert_key_size} certificate — quantum-vulnerable. Migrate when CA support arrives.'}",
        },
        "cipherStrength": {
            "score": cipher_score,
            "detail": "Symmetric ciphers (AES/ChaCha20) are quantum-resistant at current key sizes.",
        },
        "sessionResumption": {
            "score": session_score,
            "detail": "Review session ticket rotation frequency for forward secrecy.",
        },
    }

    # --- Recommendations ---
    recommendations = []

    if not has_pqc_cert:
        recommendations.append({
            "priority": "critical",
            "title": "Migrate server certificate to PQC signatures",
            "description": f"Current {cert_key_size} key is vulnerable to Shor's algorithm. Prepare migration to ML-DSA (FIPS 204) composite certificates.",
            "timeline": "Monitor CA readiness, target 2027",
        })

    if not has_pqc_sig:
        recommendations.append({
            "priority": "critical",
            "title": "Add PQC signature algorithms to TLS handshake",
            "description": "Only classical sig_algs offered. Add ML-DSA-65/ML-DSA-87 when server software supports them.",
            "timeline": "When OpenSSL/server supports ML-DSA",
        })

    if not has_pqc_kem:
        recommendations.append({
            "priority": "critical",
            "title": "Enable hybrid PQC key exchange",
            "description": "No PQC KEM detected. Enable X25519MLKEM768 to protect against harvest-now-decrypt-later attacks.",
            "timeline": "Immediate — supported in modern TLS libraries",
        })

    # Check TLS 1.2 still offered
    tls12_offered = any(p["name"] == "TLS 1.2" and p["offered"] for p in protocols)
    if tls12_offered and has_pqc_kem:
        recommendations.append({
            "priority": "high",
            "title": "Deprecate TLS 1.2",
            "description": "TLS 1.2 uses classical key exchange without PQC hybrid. Phase it out to ensure all connections get PQC protection.",
            "timeline": "6-12 months",
        })

    if not hsts:
        recommendations.append({
            "priority": "medium",
            "title": "Enable HSTS",
            "description": "HTTP Strict Transport Security not detected. Enable to prevent downgrade attacks.",
            "timeline": "Immediate",
        })

    breach = next((v for v in vulnerabilities if v["name"] == "BREACH" and v["status"] == "warn"), None)
    if breach:
        recommendations.append({
            "priority": "low",
            "title": "Mitigate BREACH",
            "description": "HTTP compression detected. Disable on endpoints serving secrets or CSRF tokens.",
            "timeline": "Evaluate",
        })

    if not recommendations:
        recommendations.append({
            "priority": "low",
            "title": "Maintain current configuration",
            "description": "No critical PQC issues found. Continue monitoring for new standards and CA support.",
            "timeline": "Ongoing",
        })

    # --- Grade ---
    score = 0
    proto_score = 100
    for p in protocols:
        if not p["safe"]:
            proto_score -= 20
    score = int(proto_score * 0.3 + ke_score * 0.3 + cipher_score * 0.2 + 80 * 0.2)

    grade = "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "F"

    return {
        "domain": domain,
        "ip": ip,
        "grade": grade,
        "score": score,
        "scanDate": datetime.utcnow().isoformat() + "Z",
        "protocols": protocols,
        "ciphers": ciphers[:20],  # Limit to top 20
        "kems": kems,
        "curves": curves,
        "sigAlgs": list(set(sig_algs))[:10],
        "certificate": certificate,
        "headers": headers,
        "vulnerabilities": vulnerabilities,
        "pqcAssessment": pqc_assessment,
        "recommendations": recommendations,
    }


@app.route("/api/scan", methods=["POST"])
def scan():
    """Run a testssl.sh scan and return PQC assessment."""
    data = request.get_json()
    domain = data.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "domain is required"}), 400

    # Basic domain validation
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$", domain):
        return jsonify({"error": "Invalid domain"}), 400

    try:
        raw = run_testssl(domain)
        result = parse_testssl_json(raw, domain)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health", methods=["GET"])
def health():
    """Health check."""
    testssl_exists = os.path.exists(TESTSSL_PATH)
    return jsonify({
        "status": "ok",
        "testssl_path": TESTSSL_PATH,
        "testssl_installed": testssl_exists,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
