# 🛡️ SentinelX AI — Product Walkthrough & Engineering Specification

> **Tagline:** *"Protecting Every Click, Every Download, Every Payment."*

SentinelX AI is a full-stack, production-quality cybersecurity assistant designed to evaluate digital artifacts—**Files**, **Messages**, and **Links**—through deterministic security rules, bounded static parsers, live threat intelligence lookups, and an explanatory AI layer.

---

## 🏛️ System Architecture

SentinelX is built on the fundamental principle that **the AI model is NOT the security engine**.

```text
                             USER SUBMISSION
                                    │
                 ┌──────────────────┼──────────────────┐
                 ↓                  ↓                  ↓
          📁 FILE GUARDIAN   💬 MESSAGE SCAM     🔗 LINK ANALYZER
                 │                  │                  │
                 ↓                  ↓                  ↓
          Magic Bytes &       Natural Entity       URL Syntax &
          Static Parsers     Extraction & Rules  Brand Typo Heuristics
                 │                  │                  │
                 └──────────────────┼──────────────────┘
                                    ↓
                        THREAT INTELLIGENCE FEEDS
                      (VirusTotal / Google Safe Browsing)
                                    ↓
                       GLOBAL DETERMINISTIC RISK ENGINE
                        • Severity Weights: Critical (+40), High (+25), Med (+15), Low (+5)
                        • Category Diminishing Returns (100% / 40% / 15%)
                        • Score Bounds: 0 – 100
                        • Safe (0-29) | Suspicious (30-69) | Dangerous (70-100)
                                    │
                                    ↓
                       ┌────────────┴────────────┐
                       ↓                         ↓
               DETERMINISTIC VERDICT     TECHNICAL EVIDENCE
                                                 │
                                                 ↓
                                           AI EXPLANATION
                                        (OpenAI / Structured JSON)
                                                 │
                                                 ↓
                                         FINAL UNIFIED REPORT
```

---

## 🔍 Core Security Modules

### 1. 📁 File Guardian (`/app/analyze/file` & `lib/security/file-scanner.ts`)
- **Magic Bytes & Header Parsing:** Inspects raw binary signatures to detect extension spoofing (e.g. an executable `.exe` disguised as `invoice.pdf`).
- **Cryptographic Hashes:** Calculates SHA-256, SHA-1, and MD5 hashes with 1-click clipboard copying.
- **EICAR Benchmark Support:** Recognizes the universal EICAR antivirus test signature.
- **Bounded Static Parsers:**
  - **PDF Analyzer:** Inspects `/JavaScript`, `/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFiles`, and `/URI` streams without executing code.
  - **Office Analyzer:** Safely decompresses OOXML containers (DOCX, XLSX, PPTX) to detect `vbaProject.bin` macros, remote template injections (`_rels/.rels`), and embedded OLE objects.
  - **ZIP Archive Analyzer:** Enforces compression ratio limits to detect archive bombs (ratio > 100:1), executable file inclusions, nested archives, and double-extension cloaking (`.pdf.exe`).
  - **PE Executable Analyzer:** Parses DOS MZ headers, PE section tables, calculates Shannon Entropy ($H \ge 7.2$) to detect packed code, checks Authenticode certificates, and detects dangerous Windows API imports (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`).
  - **APK Analyzer:** Analyzes AndroidManifest for high-risk capabilities (`BIND_ACCESSIBILITY_SERVICE`, `SEND_SMS`, `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`).
  - **Image Analyzer:** Validates PNG/JPG/GIF/WebP headers and checks for trailing appended data/polyglots.
- **Privacy-First Threat Intel:** Queries VirusTotal via **SHA-256 hash lookup only**. Private user files are never silently uploaded to third parties.

---

### 2. 💬 Message / Scam Analyzer (`/app/analyze/message` & `lib/security/message-analyzer.ts`)
- **Entity Extraction:** Automatically extracts URLs, emails, international phone numbers, UPI payment IDs (`pay@okhdfcbank`), crypto addresses (BTC/ETH), and monetary amounts.
- **Scam Pattern Heuristics:**
  - Banking & OTP Credential Theft ("account will be blocked", "pending KYC", "share OTP")
  - Advance-Fee Lottery Lures ("you won ₹50,000", "pay processing fee")
  - Courier / Postal Smishing ("package could not be delivered", "reschedule fee")
  - Fake Job Offers ("work from home ₹3000 daily", "like youtube videos")
  - Crypto & High-Yield Investment Scams ("guaranteed 2x returns")
  - Psychological Urgency & Threat Language
- **Extracted URL Handoff:** Detected links feature an instant `[Analyze in Link Analyzer 🔗]` button.
- **Linguistic AI-Writing Patterns:** Probabilistic linguistic estimate with mandatory disclaimer: *"Linguistic pattern analysis is probabilistic and does not prove AI authorship."*

---

### 3. 🔗 Link Analyzer (`/app/analyze/link` & `lib/security/url-analyzer.ts`)
- **URL Syntax & Structure:** Protocol analysis (HTTPS transport encryption check), raw IP hostnames, Punycode/homograph attacks (`xn--`), non-standard ports, and credential harvesting paths (`/login`, `/verify`, `/kyc`).
- **Config-Driven Brand Typosquatting:** Evaluates domains against protected brands (PayPal, Apple, Google, Microsoft, Amazon, Netflix, SBI, HDFC, Chase, Binance) using Levenshtein edit distance and keyword affinity.
- **Vendor Telemetry:** Integrates with VirusTotal and Google Safe Browsing APIs with transparent `CHECKED_CLEAN`, `THREAT_DETECTED`, or `UNAVAILABLE` status badges.

---

## ⚙️ Global Deterministic Risk Engine (`lib/security/risk-engine.ts`)

| Risk Score | Classification | Action Recommended |
|---|---|---|
| **0 – 29** | 🟢 **SAFE** | No known threats detected in performed checks. |
| **30 – 69** | 🟡 **SUSPICIOUS** | Exercise caution. Anomalies or suspicious indicators present. |
| **70 – 100** | 🔴 **DANGEROUS** | High-risk threat confirmed. Do NOT interact, open, or pay. |

### Severity Weights
- `CRITICAL`: +40
- `HIGH`: +25
- `MEDIUM`: +15
- `LOW`: +5
- `MITIGATION`: -15 to -40 (e.g. verified official domain or clean certificate)
- **HTTPS Transport:** Informational only (+0 / -0; transport security != website legitimacy)

---

## 🚀 Getting Started

### 1. Prerequisites
- Node.js `v18+` or `v20+` (Tested on Node `v24`)
- npm `v9+` or `v11+`

### 2. Installation
```bash
git clone https://github.com/rudrapatel2411/SentinelX-AI.git
cd SentinelX-AI
npm install
```

### 3. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

```env
# Database (SQLite embedded file for zero-setup local dev)
DATABASE_URL="file:./dev.db"

# Optional AI Provider (Technical analysis operates fully even without AI)
OPENAI_API_KEY=""
OPENAI_MODEL="gpt-4o-mini"

# Optional Threat Intelligence APIs
VIRUSTOTAL_API_KEY=""
GOOGLE_SAFE_BROWSING_API_KEY=""

# Application URL
NEXT_PUBLIC_APP_URL="http://localhost:3000"
```

### 4. Database Setup & Seeding
```bash
# Push schema to local SQLite database
npx prisma db push

# Seed sample security benchmark records
npx -y tsx scripts/seed.ts
```

### 5. Start Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Automated Testing

SentinelX includes a complete Vitest suite covering exact risk boundary conditions, scam rule heuristics, brand lookalikes, EICAR detection, and file extension spoofing:

```bash
npm run test
```

---

## 📦 Production Build

```bash
npm run build
npm run start
```

---

## 🛡️ License
MIT License. Built for advanced cybersecurity demonstrations and telemetry research.
