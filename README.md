# Privacy Posture Analyzer

**Static auditing of Android application privacy through hybrid rule-based and AI-powered analysis.**

Privacy Posture Analyzer is an open-source web platform that audits Android APK files for privacy risks. It automatically classifies declared permissions, detects embedded third-party SDKs and trackers, evaluates GDPR compliance using the Llama 3.3 70B large language model, and generates a professional PDF report with a privacy score from 0 to 100.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Usage Guide](#usage-guide)
- [API Reference](#api-reference)
- [Running Tests](#running-tests)
- [Video Demo](#video-demo)
- [Project Structure](#project-structure)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Overview

Privacy Posture Analyzer was developed as part of the Cybersecurity and Embedded Telecommunications Systems curriculum at the National School of Applied Sciences, Cadi Ayyad University, Marrakech. The platform targets developers, security analysts, and compliance officers who need fast, interpretable, and actionable privacy audits without requiring deep reverse-engineering expertise.

The system combines three complementary analysis layers:

1. Rule-based permission classification using a curated database of 60+ Android permissions with risk weights and justification scoring.
2. SDK and tracker detection via recursive APK and DEX binary scanning against a database of 35 known tracking libraries.
3. AI-powered GDPR compliance evaluation using Llama 3.3 70B (Groq API) with sector-specific checklist generation.

---

## Features

**Permission Analysis**
- Parses binary AndroidManifest.xml without external dependencies (pure Python)
- Classifies 60+ Android permissions by protection level and impact severity
- Labels each permission as Necessary, Optional, or Excessive
- Applies a logarithmic justification score: an Excessive permission is downgraded to Optional if domain-relevant keywords are found in the APK body (threshold: 70)

**SDK and Tracker Detection**
- Recursive scan of APK archives up to 3 nesting levels (APK, XAPK, JAR, AAR)
- Detection of 35 known tracking libraries across 5 categories: Advertising, Analytics, Social, Payment, Crash Reporting
- Binary DEX scanning for obfuscated SDK class paths (ProGuard-renamed packages)
- Deduplication of detected trackers before persistence

**AI-Powered GDPR Evaluation**
- Permission classification with contextual justification (Llama 3.3 70B via Groq)
- Hybrid privacy scoring: rule-based penalties combined with AI contextual scoring
- Sector-specific GDPR compliance checklists: Health (GDPR+HIPAA), Education (GDPR+COPPA), E-commerce (GDPR+PCI-DSS), Gaming (GDPR+COPPA), General (GDPR)
- Each checklist item is mapped to a real GDPR article with PASS / FAIL / REVIEW status

**Privacy Score**
- Composite score from 0 to 100 using the formula:
  `score = 0.5 * sdk_privacy + 0.3 * perm_score + 0.2 * gdpr_score`
- Letter grade from A (90-100) to F (below 40)

**PDF Report Generation**
- Professional A4 report generated with ReportLab and streamed directly from memory
- Sections: executive summary, score gauge, permission breakdown, tracker risk matrix, GDPR findings, compliance checklist

**Audit History**
- Persistent history of all past analyses stored in SQLite
- Each audit can be revisited, re-downloaded as PDF, or permanently deleted

---

## Architecture

The platform follows a layered architecture:

```
Client Layer       HTML5 SPA (drag-and-drop upload, results dashboard)
      |
API Layer          FastAPI REST (11 endpoints, Swagger at /docs, ReDoc at /redoc)
      |
Business Layer     permissions.py | trackers.py | ai_classifier.py | report.py
      |                                               |
Data Layer         SQLAlchemy ORM / SQLite        Groq Cloud API (Llama 3.3 70B)
```

---

## Requirements

- Python 3.12 or higher
- pip
- A valid Groq API key (free tier available at https://console.groq.com)
- Operating system: Windows, macOS, or Linux

---

## Installation

**Step 1 — Clone the repository**

```bash
git clone https://github.com/El-ouarzazi-aya/privacy_posture_analyzer.git
cd privacy_posture_analyzer
```

**Step 2 — Create and activate a virtual environment (recommended)**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

**Step 3 — Install dependencies**

```bash
cd backend
pip install fastapi==0.111.0 \
            uvicorn[standard]==0.29.0 \
            sqlalchemy==2.0.49 \
            python-multipart==0.0.9 \
            groq \
            python-dotenv \
            reportlab \
            pytest
```

---

## Configuration

Create a `.env` file inside the `backend/` directory:

```bash
# backend/.env
GROQ_API_KEY=your_groq_api_key_here
```

To obtain a Groq API key:
1. Go to https://console.groq.com
2. Create a free account
3. Navigate to API Keys and generate a new key
4. Paste it into the `.env` file

**Important:** Never commit your `.env` file to version control. Add it to `.gitignore`:

```
.env
*.db
uploads/
__pycache__/
.pytest_cache/
*.pyc
```

---

## Running the Application

From the `backend/` directory, start the development server:

```bash
uvicorn main:app --reload
```

For a specific host and port:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Once running, the following URLs are available:

| URL | Description |
|-----|-------------|
| http://localhost:8000/app | Web interface (main entry point) |
| http://localhost:8000 | Health check endpoint |
| http://localhost:8000/docs | Swagger interactive API documentation |
| http://localhost:8000/redoc | ReDoc API documentation |

---

## Usage Guide

**Analyzing an APK**

1. Open http://localhost:8000/app in your browser.
2. Drag and drop an APK file onto the upload area, or click to browse and select one.
3. Click Analyze. The platform runs five sequential steps shown in real time:
   - Step 1: Unpack APK and read binary manifest
   - Step 2: Classify permissions and compute risk labels
   - Step 3: Scan for embedded SDKs and score tracker risk
   - Step 4: Classify app category and generate GDPR checklist
   - Step 5: Compose the full forensic report
4. The results dashboard displays:
   - Global privacy score (0-100) and letter grade
   - Score breakdown by component (SDK privacy, permissions, GDPR)
   - List of detected SDKs ranked by risk score
   - Full permission list with Necessary / Optional / Excessive labels
5. Click **Download PDF Report** to download the full professional report.

**Viewing Audit History**

- Navigate to the History tab or visit http://localhost:8000/history.
- All past analyses are listed with their package name, score, and date.
- Click on any entry to retrieve the full report.
- Click the delete button to permanently remove an audit and its stored APK.

**Using the API Directly**

You can also interact with the platform via HTTP. Example workflow using curl:

```bash
# 1. Upload an APK
curl -X POST http://localhost:8000/upload \
     -F "file=@/path/to/your/app.apk"
# Returns: { "app_id": "your_app", "apk_size_mb": 4.2, ... }

# 2. Run tracker detection
curl -X POST http://localhost:8000/analyze/trackers/your_app

# 3. Run permission analysis
curl -X POST http://localhost:8000/analyze/permissions/your_app

# 4. Run AI GDPR analysis
curl -X POST http://localhost:8000/analyze/ai/your_app

# 5. Get the full JSON report
curl http://localhost:8000/report/your_app

# 6. Download the PDF report
curl http://localhost:8000/report/your_app/pdf -o report.pdf

# 7. List all past audits
curl http://localhost:8000/history

# 8. Delete an audit
curl -X DELETE http://localhost:8000/audit/your_app
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| GET | `/app` | Serves the web SPA |
| POST | `/upload` | Upload an APK file |
| POST | `/analyze/permissions/{app_id}` | Run permission analysis |
| POST | `/analyze/trackers/{app_id}` | Run SDK/tracker detection |
| POST | `/analyze/ai/{app_id}` | Run AI GDPR evaluation |
| GET | `/report/{app_id}` | Get full JSON report |
| GET | `/report/{app_id}/pdf` | Download PDF report |
| GET | `/report/{app_id}/ai-details` | Get enriched AI analysis details |
| GET | `/history` | List all past audits |
| DELETE | `/audit/{app_id}` | Delete audit and associated APK |

Full interactive documentation is available at http://localhost:8000/docs once the server is running.

---

## Running Tests

The project includes 27 unit tests across three test files.

```bash
# From the backend/ directory

# Run all tests
pytest tests/ modules/tests/ -v

# Permission tests only (no network required, fast)
pytest tests/test_permissions.py -v

# Tracker tests only (no network required, uses mocks)
pytest modules/tests/test_trackers.py -v

# AI engine tests (requires a valid GROQ_API_KEY, makes real API calls)
pytest tests/test_ai_engine.py -v
```

| Test file | Tests | Network calls |
|-----------|-------|---------------|
| `tests/test_ai_engine.py` | 12 | Yes (Groq API) |
| `tests/test_permissions.py` | 10 | No |
| `modules/tests/test_trackers.py` | 5 | No |

Note: AI engine tests consume Groq API tokens. Run them selectively during development.

---

## Video Demo

A walkthrough of the full analysis workflow — APK upload, real-time analysis pipeline, results dashboard, and PDF report download — is available below.

https://github.com/user-attachments/assets/4f8e9490-18d4-4d6d-9072-a457e90fdc3e

---

## Project Structure

```
privacy_posture_analyzer/
|
+-- Privacy_Posture_Analyzer.html     # Standalone frontend SPA
+-- README.md
|
+-- backend/
    +-- main.py                       # FastAPI application — all endpoints
    +-- database.py                   # SQLite connection and SessionLocal
    +-- models.py                     # ORM models: Audit, Tracker
    +-- requirements.txt
    +-- .env                          # API keys (DO NOT commit)
    +-- uploads/                      # Stored APK files
    |
    +-- modules/
    |   +-- __init__.py
    |   +-- permissions.py            # Binary AXML parser, permission classifier
    |   +-- trackers.py               # Recursive APK/DEX scanner
    |   +-- report.py                 # PDF report generator (ReportLab)
    |   +-- ai_classifier.py          # AI orchestration entry point
    |   +-- classifier.py             # Groq permission classification
    |   +-- scorer.py                 # Hybrid privacy score computation
    |   +-- checklist.py              # GDPR checklist generator
    |   +-- prompt_engine.py          # Centralized prompt templates
    |   +-- tests/
    |       +-- test_trackers.py
    |
    +-- tests/
        +-- test_ai_engine.py         # 12 AI engine tests (Groq API)
        +-- test_permissions.py       # 10 permission tests (no network)
```

---

## Known Limitations

The following issues are known and should be addressed before any production deployment:

| Severity | Issue | Location |
|----------|-------|----------|
| Critical | `requirements.txt` is incomplete (groq, python-dotenv, reportlab missing) | `requirements.txt` |
| Critical | No authentication on the API — all endpoints are publicly accessible | `main.py` |
| High | Permission score is hardcoded to 80 instead of being computed dynamically | `main.py:168` |
| High | Real permissions are not passed to the AI engine (2 defaults used instead) | `main.py:132` |
| High | No file size limit on APK uploads | `main.py:58` |
| Medium | CORS is open to all origins (`allow_origins=["*"]`) | `main.py:29` |
| Medium | Database session management does not use the FastAPI `Depends()` + `yield` pattern | `main.py:45` |
| Medium | No pagination on the `/history` endpoint | `main.py:261` |
| Low | No structured logging | Throughout |

---

## License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2025 Aya El Ouarzazi, Laila Elamiri, Sara Alaoui Sossi, Vanessa Ella Mugisha

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

*Cadi Ayyad University — National School of Applied Sciences, Marrakech, Morocco*



