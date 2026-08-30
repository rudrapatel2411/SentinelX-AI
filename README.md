# 🛡️ SentinelX AI

> **"Protecting Every Click, Every Download, Every Payment."**

SentinelX AI is a production-quality cybersecurity platform engineered to perform deterministic static analysis, live threat intelligence correlation, and AI-assisted contextualization across three distinct security modules:
- 📁 **File Guardian** (Safe static inspection of PDF, Office OOXML, ZIP archives, Windows PE executables, Android APKs, Images, and hashes)
- 💬 **Message / Scam Analyzer** (NLP entity extraction, multi-category fraud/smishing heuristics, OTP/banking theft detection, and secondary AI-writing pattern estimation)
- 🔗 **Link Analyzer** (URL syntax parsing, protocol inspection, IP host detection, brand typosquatting heuristics, Google Safe Browsing, and VirusTotal reputation lookups)

---

## 🏛️ Architecture & Security Principles

SentinelX is **NOT** an AI wrapper. The system adheres to strict security engineering principles:

```text
                 USER INPUT
                     │
          ┌──────────┼──────────┐
          ↓          ↓          ↓
        FILE       MESSAGE      URL
          │          │          │
          ↓          ↓          ↓
       STATIC      RULES      URL RULES
       ANALYSIS    ENGINE      ENGINE
          │          │          │
          └──────────┼──────────┘
                     ↓
              THREAT INTEL
          (VirusTotal / Safe Browsing)
                     ↓
                RISK ENGINE
                     ↓
              ┌──────┴──────┐
              ↓             ↓
           VERDICT       EVIDENCE
                            ↓
                      AI EXPLANATION
                     (OpenAI / Zod)
```

1. **Deterministic Security First:** Deterministic rules, magic byte decoders, and threat intelligence APIs compute the raw evidence and risk indicators first.
2. **Deterministic Risk Engine:** The shared Risk Engine (`lib/security/risk-engine.ts`) calculates the exact score (`0–100`) and classification (`SAFE: 0–29`, `SUSPICIOUS: 30–69`, `DANGEROUS: 70–100`). **AI cannot modify the risk score.**
3. **Category Diminishing Returns:** Correlated indicators within the same category are weighted with diminishing returns to prevent artificial score inflation.
4. **Honest Security Semantics:** Local static analysis is *bounded static and heuristic inspection identifying suspicious indicators*, not "guaranteed proof of malware".
5. **Privacy-First Threat Intel:** File scanning queries VirusTotal via **SHA-256 hash lookup only** by default. Private user files are never silently uploaded to third parties.
6. **Explicit Source Attribution:** Every indicator displays its explicit source (`VirusTotal`, `Google Safe Browsing`, `SentinelX PDF Analyzer`, `SentinelX URL Engine`, etc.).
7. **Stand-alone Operation:** If external API keys (`OPENAI_API_KEY`, `VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`) are unconfigured, SentinelX executes full local static analysis and clearly marks external sources as unavailable with zero data fabrication.

---

## 🚀 Quick Start

### 1. Installation
```bash
git clone <repo-url>
cd sentinelx-ai
npm install
```

### 2. Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Configure your environment variables as needed:
```env
# Database (Optional - session mode active when offline)
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/sentinelx?schema=public"

# AI Explanation Provider (Optional)
OPENAI_API_KEY="sk-..."
OPENAI_MODEL="gpt-4o-mini"

# Threat Intelligence APIs (Optional)
VIRUSTOTAL_API_KEY="..."
GOOGLE_SAFE_BROWSING_API_KEY="..."

# App URL
NEXT_PUBLIC_APP_URL="http://localhost:3000"
```

### 3. Database Setup (Optional Docker PostgreSQL)
Start PostgreSQL using Docker Compose:
```bash
docker compose up -d
npx prisma db push
```

### 4. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Automated Testing

Run the test suite covering the Risk Engine, Message Scam Rules, URL Brand Impersonation, and File Static Parsers:
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

## 📡 API Reference

### 1. File Guardian
- `POST /api/analyze/file`
- `multipart/form-data` with `file` field (max 50MB)

### 2. Message Analyzer
- `POST /api/analyze/message`
- Body: `{ "message": "string" }`

### 3. Link Analyzer
- `POST /api/analyze/link`
- Body: `{ "url": "https://..." }`

### 4. Analysis History & Dashboard
- `GET /api/analyses`
- `GET /api/analyses?mode=dashboard`
- `GET /api/analyses/:id`

---

## 🛡️ License
MIT License. Built for advanced cybersecurity demonstrations and telemetry research.
