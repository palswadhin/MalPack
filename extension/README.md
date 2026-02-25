# MalPack VS Code Extension

MalPack is an innovative Visual Studio Code extension designed to automatically intercept and analyze Python packages for malicious indicators *before* you install them, protecting your environment from supply-chain attacks.

## Core Features
*   **Manual Scanning**: Run `MalPack: Secure Install` to input one or more package names and scan them instantly using your choice of Semgrep, custom Regex Rules, or Gemini AI.
*   **Auto-Scanning**: Simply leave MalPack running in the background. It watches your `requirements.txt` file and automatically scans any newly added packages or unverified packages when you open your workspace.
*   **Code-Level Diagnostics**: If a package is dangerous, MalPack highlights the exact malicious lines with red diagnostic boxes right inside your editor and explains why it was flagged.
*   **Seamless Navigation**: Use `Alt + Right Arrow` or `Alt + Left Arrow` to jump instantly between malicious findings in the file.
*   **Live Log Streaming**: Follow along in real-time as MalPack extracts and analyzes packages in the dedicated "MalPack Scanner" Output Channel.

## Getting Started
Please read the [User Manual](./USER_MANUAL.md) for detailed instructions on usage and configuration.

## Setup
By default, this extension sends analysis requests to the deployed backend on Render.
If you wish to run the backend locally:
1.  Go to VS Code Settings -> `Extensions` -> `MalPack Settings`.
2.  Change the `Backend Url` to `http://localhost:8000`.

## Publishing Updates
When you are ready to publish a new version of the extension to the Visual Studio Marketplace, follow these exact steps:

1. **Update `package.json`**: Open `extension/package.json` and bump the `"version"` field (e.g., from `"0.0.1"` to `"0.0.2"`). 
2. **Build and Package**: Open your terminal in the `extension/` directory and run:
   ```bash
   npx @vscode/vsce package --no-dependencies
   ```
   *(Note: MalPack uses `@vercel/ncc` to bundle all runtime dependencies into a single output file, making it completely cross-platform and extremely fast. We use the `--no-dependencies` flag because the `vscode:prepublish` script handles the build process automatically).*
3. **Publish to Marketplace**: With your Personal Access Token (PAT) ready, publish directly from your terminal:
   ```bash
   npx @vscode/vsce publish --no-dependencies
   ```
   If prompted to login, use the publisher ID (`swadhinpal`) and your PAT token.
