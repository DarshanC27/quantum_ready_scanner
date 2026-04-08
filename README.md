# Quantum Ready — PQC Migration Scanner

Assess the post-quantum cryptographic readiness of any domain. Built for SMBs migrating to PQC-safe TLS configurations.

![Quantum Ready Screenshot](https://img.shields.io/badge/PQC-Scanner-00e6b4?style=for-the-badge)

## What It Does

- Parses **testssl.sh** scan output and visualizes TLS configuration
- Scores **PQC readiness** across key exchange, signatures, certificates, and cipher strength
- Flags quantum-vulnerable cryptography (RSA, classical ECDHE/DHE)
- Generates a **prioritized action plan** with migration timelines

## Quick Start

### Frontend only (demo mode)
```bash
git clone https://github.com/DarshanC27/quantum_ready_scanner.git
cd quantum_ready_scanner
npm install
npm run dev
```

### Full stack (live scanning)
```bash
# Terminal 1 — Backend
cd backend
pip install -r requirements.txt
git clone https://github.com/drwetter/testssl.sh.git ~/testssl.sh
python app.py

# Terminal 2 — Frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

The frontend calls the backend at `localhost:5000`. If the backend is unavailable, it falls back to sample data.

## Configuration

Set the path to testssl.sh via environment variable:
```bash
export TESTSSL_PATH=~/testssl.sh/testssl.sh
python backend/app.py
```

## Tech Stack

- **React 18** + **Vite**
- Zero external UI dependencies — pure CSS

## Project Structure

```
quantum-ready-scanner/
├── index.html
├── package.json
├── vite.config.js
├── src/
│   ├── main.jsx
│   └── App.jsx              # Scanner dashboard
└── backend/
    ├── app.py                # Flask API — runs testssl.sh
    └── requirements.txt
```

## Roadmap

- [ ] Backend API (Python/Flask) to run testssl.sh scans live
- [ ] PDF report export
- [ ] Historical scan comparison
- [ ] Bulk domain scanning
- [ ] CI/CD integration for continuous monitoring

## License

MIT
