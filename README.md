# VirusScan Security 🛡️
### AI-Assisted Android APK Malware Detection & Forensic Security Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![Gemini](https://img.shields.io/badge/Google-Gemini_AI-orange.svg)](https://ai.google.dev/)
[![Status](https://img.shields.io/badge/Build-Hackathon_Ready-green.svg)]()

**VirusScan Security** is an end-to-end, automated Android APK security analysis platform. It empowers security analysts, mobile developers, and privacy-conscious users to audit unknown `.apk` packages before installation, providing a transparent malware risk score, granular evidence breakdowns, and AI-generated threat explanations.

---

## 🎨 Design System & Color Palette

Built using a custom **Warm Ivory** modern aesthetic:

| Element | Color Name | Hex Code | Purpose |
|---|---|---|---|
| **Main Background** | Warm Ivory | `#F7F5F0` | Clean, easy-on-the-eyes app backdrop |
| **Navbar / Cards** | Pure White | `#FFFFFF` | High-contrast elevated surfaces |
| **Main Text** | Deep Charcoal | `#17202A` | Legible, sharp typography |
| **Primary Accent** | Coral Red | `#E4573D` | Key interactive buttons & highlights |
| **Secondary Accent** | Slate Blue | `#52677A` | Sub-actions and secondary UI elements |
| **Safe / Verified** | Forest Green | `#16805C` | Passing security checks & safe verdicts |
| **Suspicious** | Amber | `#C98200` | Warning thresholds & medium indicators |
| **Critical / Malicious**| Deep Red | `#C9362B` | Flagged threats & critical hazards |
| **Secondary Text** | Cool Gray | `#667085` | Subtitles, metadata, timestamps |
| **Borders** | Light Gray | `#D9DDE3` | Subtle structural division |
| **Hover Background** | Soft Gray | `#F2F3F5` | Interactive hover states & table rows |

---

## 🚀 Key Modules & Capabilities

### 1. 🔍 APK Malware Scanner (`/scanner`)
- **Evidence-first scoring**: sensitive permissions are contextualized instead of treating every dangerous permission as malware.
- **Cross-signal corroboration**: permission combinations, API families, intents, network signals, resources and signing evidence are scored independently and correlated.
- **Byte-level DEX inspection**: API family detection works directly on DEX bytes and deduplicates repeated matches.
- **Network validation**: validates extracted URLs/IPs, separates known benign infrastructure, and identifies stronger phishing/network patterns.
- **Calibrated confidence**: confidence depends on evidence breadth and strength, not simply on a high/low score.
- **AI as a bounded second opinion**: Gemini contributes up to 25% of the final score and is down-weighted further when it strongly disagrees with deterministic evidence.
- **Explainable results**: the UI exposes why a score was produced and how many independent evidence categories support it.
- **Real-Time Static Decompilation**: Extracts package metadata, activities, exported services, and receivers.
- **Permission Matrix**: Audits sensitive permissions (`READ_SMS`, `CAMERA`, `ACCESS_FINE_LOCATION`) and detects toxic permission combinations.
- **Network Forensic Parser**: Identifies hardcoded external URLs, suspect domains, and raw IP addresses.
- **Animated Progress Steps**: Visual step-by-step progress tracking from manifest extraction to AI threat synthesis.
- **Hackathon Quick Demo Mode**: Instant inspection of real-world banking trojan / spyware sample without requiring a local APK file.

### 2. 🌐 URL & Network Analyzer (`/url-analyzer`)
- Inspects web destinations, phishing domains, and direct-download `.apk` links.
- Evaluates protocol security, port anomalies, domain level depth, and sensitive credential-harvesting keywords.
- Powered with quick test presets (e.g. raw IP endpoints, free TLDs, safe platforms).

### 3. ⚡ Behavior Sandbox (`/behavior`)
- Reconstructs probable application execution sequence without risky dynamic execution.
- Visual lifecycle timeline with risk-coded status indicators (Autostart on boot, SMS interception, dynamic code loading).

### 4. 📜 Certificate Inspector (`/certificate`)
- Parses x509 cryptographic signing data from `META-INF/`.
- Verifies SHA-256 fingerprint, signature algorithm strength, validity timeframes, and flags debug certificates.

### 5. 🛡️ Device Protection Center (`/protection`)
- Aggregated personal defense hygiene score calculated from historical scans.
- Actionable hardening guidelines for Android endpoints.

### 6. ℹ️ About & 💬 Contact (`/about` & `/contact`)
- Transparent documentation of the multi-tier detection architecture.
- Real-time contact and feedback submission stored in SQLite database.

---

## 🏗 Architecture & Scoring Pipeline

```
[ Uploaded APK / URL ]
          │
          ▼
   [ Validation ] ────── (Corrupt / Non-APK rejected)
          │
          ▼
 [ Static Decompilation ] ──── (Androguard + Zipfile + Cryptography)
          ├── Manifest Extraction (Permissions, Components, Intents)
          ├── Bytecode Extraction (API calls, DexClassLoader, Shell strings)
          └── Certificate Audit (x509, SHA-256 fingerprint, Debug key)
          │
          ▼
[ Heuristic Scoring Engine ] ── (Deterministic 0-100 score + severity flags)
          │
          ▼
[ Google Gemini AI Synthesis ] ── (Contextual threat evaluation & plain-English summary)
          │
          ▼
 [ Combined Risk Score ] ──── (75% Static Evidence + 25% Gemini AI)
                                  │
                                  └─ If AI strongly disagrees, AI influence is reduced to 10%
          │
          ▼
 [ Comprehensive Dashboard & Report ]
```

---

## 🛠️ Quickstart & Installation

### Prerequisites
- Python 3.10+
- Modern Web Browser (Chrome, Edge, Firefox, Safari)

### 1. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 2. Configure Environment (Optional)
Set your Google Gemini API key in `.env`:
```env
GEMINI_API_KEY=your_actual_gemini_api_key_here
MAX_APK_SIZE_MB=50
```
*(Note: If no API key is set, the system automatically falls back to static heuristic scoring seamlessly!)*

### 3. Start the Server
```bash
python backend/app.py
```
Open **[http://localhost:5000](http://localhost:5000)** in your browser.

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check & dependency availability status |
| `POST` | `/api/analyze/apk` | Upload & full multi-tier APK static analysis |
| `POST` | `/api/analyze/url` | URL structure, domain & phishing analysis |
| `POST` | `/api/analyze/certificate` | Extract and audit signing certificate |
| `POST` | `/api/analyze/behavior` | Reconstruct static behavioral sequence |
| `GET` | `/api/analyze/demo` | Return precomputed demo APK dataset |
| `GET` | `/api/history` | Retrieve recent security scan logs |
| `GET` | `/api/stats` | Aggregate dashboard threat metrics |
| `POST` | `/api/contact` | Submit inquiry / bug bounty message |

---

## 🔒 Security & Privacy Notice
Uploaded APK files are temporarily written to an isolated directory, parsed in read-only memory, and immediately unlinked/deleted from disk upon scan completion. No uploaded binaries are stored permanently.
