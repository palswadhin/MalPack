# MalPack User Manual

Welcome to MalPack! MalPack is a VS Code extension designed to automatically detect and intercept malicious PyPI packages before you install them.

## Features

### 1. Manual Scanning (PyPI or Local)
You can manually scan any Python package by running the `MalPack: Secure Install` command.
- Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`).
- Type `MalPack: Secure Install` and hit Enter.
- **Source Selection**: First, choose between **PyPI Package** or **Local Directory**. Then provide the names or select the folder/file from your disk.
- **Method Selection**: After picking the source, select your preferred detection method (Semgrep, Rule Based, or LLM).
- **Instant Result**: The scan starts immediately after method selection.
- **Multi-Package Scanning**: When scanning PyPI packages, you can enter multiple names separated by a space. Each scan opens its own dedicated result panel.

### 2. Auto-Scanning `requirements.txt`
MalPack automatically protects your projects by scanning your dependencies.
- **On Project Load**: When you open a folder in VS Code, MalPack automatically looks for a `requirements.txt` file and begins scanning any unchecked Python packages in the background.
- **On Save**: Whenever you add a new package to your `requirements.txt` and save the file, MalPack instantly scans the new additions.
- **Status Annotations**: To avoid redundant scanning and to let you know a package is safe, MalPack automatically appends a comment to the line in `requirements.txt` after it finishes scanning (e.g., `requests == 2.31.0  # MalPack: SAFE` or `malicious-pkg  # MalPack: DANGER`).

### 3. Finding Navigation & Inspection
When a package is flagged as malicious, MalPack highlights the exact lines of code with red boxes in the editor.
- **In-Code Navigation**: Use `<< prev` and `next >>` links above any finding to move through issues.
- **Cross-File Flow**: Navigation automatically jumps between files. If you are at the end of a file, `next >>` opens the next file's first finding. If at the start, `<< prev` jumps to the previous file's last finding.
- **Alt Shortcuts**: Use `Alt + Right Arrow` for the next finding and `Alt + Left Arrow` for the previous one.
- **Rule-Specific Filtering**: In the "High Level Details" view, click **"See in Code →"** to filter navigation and highlights to only that specific rule type.
- **Fresh Start**: Clicking "Show in Code" opens **only the first** relevant file and jumps to the first detection, keeping your workspace clean.

### 4. Live Log Streaming
While scanning large packages, MalPack streams real-time logs to the VS Code Output Panel so you can see exactly which file is currently being analyzed.
- The logs automatically open in the `MalPack Scanner` output channel when a scan begins.

## Configuration
You can configure MalPack in your VS Code Settings (`Cmd+,` or `Ctrl+,`).
- `malpack.backendUrl`: The URL of the MalPack analysis server (defaults to the deployed Render server).
- `malpack.defaultMethod`: The default detection method used for background auto-scanning of `requirements.txt` (defaults to `rule_based`).

## Detection Fallbacks & Error Handling

MalPack ensures that even if one analysis mechanism fails, you are still protected:
1. **Regex Fallback**: If a Python file is too obfuscated or has syntax errors preventing the AST (Abstract Syntax Tree) engine from parsing it, MalPack automatically falls back to raw RegEx scanning (detecting hardcoded IPs, long hex payloads, etc.).
2. **Quota Handling (API Error)**: When using the LLM/Gemini engine, if your Google Cloud free-tier quota is exhausted, MalPack will **not** silently fail. It will intercept the error and present an explicit `LLM ANALYSIS FAILED` status in the UI, directing you to wait for a quota reset or change your API key.
3. **PyPI 404 Fallback**: If you search for a package that doesn't exist, MalPack intercepts the 404 from PyPI and halts cleanly without attempting to extract non-existent data.

## Running Tests Locally (For Developers)

MalPack includes a comprehensive F1 evaluation framework for its 40+ rule-based and Semgrep detection methods.

1. **Generate the Test Dataset**:
   This script generates over 80 specific Python files (one malicious and one benign per rule).
   ```bash
   cd backend
   source venv/bin/activate
   python3 tests/test_cases_data.py
   ```
2. **Run the Evaluation**:
   This script runs the AST, Regex, and Semgrep engines against the generated dataset and outputs False Positives, False Negatives, True Positives, and True Negatives, finally calculating the F1 Accuracy Score.
   ```bash
   python3 tests/run_eval.py
   ```
