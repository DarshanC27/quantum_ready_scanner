# Quantum Ready — PQC Migration Scanner

Assess the post-quantum cryptographic readiness of any domain. Built for SMBs migrating to PQC-safe TLS configurations.

![Quantum Ready Screenshot](https://img.shields.io/badge/PQC-Scanner-00e6b4?style=for-the-badge)

## What It Does

- Parses **testssl.sh** scan output and visualizes TLS configuration
- Scores **PQC readiness** across key exchange, signatures, certificates, and cipher strength
- Flags quantum-vulnerable cryptography (RSA, classical ECDHE/DHE)
- Generates a **prioritized action plan** with migration timelines

## Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/quantum-ready-scanner.git
cd quantum-ready-scanner

# Install dependencies
npm install

# Start dev server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Running a Real Scan

1. Install [testssl.sh](https://github.com/drwetter/testssl.sh):
   ```bash
   git clone https://github.com/drwetter/testssl.sh.git
   ```

2. Run a scan with JSON output:
   ```bash
   ./testssl.sh --jsonfile results.json https://your-target.com
   ```

3. The dashboard currently uses sample data. To connect live scans, add a backend API that runs testssl.sh and returns parsed JSON (backend integration coming soon).

## Tech Stack

- **React 18** + **Vite**
- Zero external UI dependencies — pure CSS

## Project Structure

```
quantum-ready-scanner/
├── index.html
├── package.json
├── vite.config.js
└── src/
    ├── main.jsx
    └── App.jsx          # Scanner dashboard component
```

## Roadmap

- [ ] Backend API (Python/Flask) to run testssl.sh scans live
- [ ] PDF report export
- [ ] Historical scan comparison
- [ ] Bulk domain scanning
- [ ] CI/CD integration for continuous monitoring

## License

MIT
