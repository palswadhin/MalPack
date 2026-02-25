import * as vscode from 'vscode';

export type DetectionMethod = 'semgrep' | 'rule_based' | 'llm' | 'classifier';

export interface ScanResult {
    packageName: string;
    verdict: 'MALICIOUS' | 'BENIGN' | 'NOT_IMPLEMENTED' | 'API_ERROR';
    totalIssues: number;
    filesScanned: number;
    detectionMethod: DetectionMethod;
    stats: {
        critical: number;
        high: number;
        warning: number;
        info: number;
    };
    summary: Array<{
        rule_id: string;
        message: string;
        severity: string;
        count: number;
    }>;
    llmSummary?: string;      // For LLM-based results
    allFindings?: any[];
    isLocal?: boolean;
    alternatives?: Array<{ name: string, reason: string }>;
}

export class MalPackWebviewProvider {
    private panel: vscode.WebviewPanel | undefined;
    private scanResult: ScanResult | undefined;
    private onShowCodeDetailsCallback: ((ruleId?: string) => void) | undefined;
    private onInstallCallback: ((install: boolean, actionStr?: string, altName?: string) => void) | undefined;

    constructor(private context: vscode.ExtensionContext) { }

    /**
     * FIRST SCREEN: Detection Method Selection
     */
    showMethodSelectionPanel(onMethodSelected: (method: DetectionMethod) => void) {
        this.panel = vscode.window.createWebviewPanel(
            'malpackMethodSelect',
            'MalPack: Select Analysis Method',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        this.panel.webview.html = this.getMethodSelectionHtml();

        this.panel.webview.onDidReceiveMessage(
            message => {
                if (message.command === 'selectMethod') {
                    onMethodSelected(message.method as DetectionMethod);
                    this.panel?.dispose();
                }
            },
            undefined,
            this.context.subscriptions
        );
    }

    /**
     * Stage 1: Show initial verdict (MALICIOUS or BENIGN)
     */
    showVerdictPanel(result: ScanResult, onNext: (ruleId?: string) => void, onInstall: (install: boolean, actionStr?: string, altName?: string) => void, onSuggest: () => void, onDispose?: () => void) {
        this.scanResult = result;
        this.onInstallCallback = onInstall;

        if (!this.panel) {
            this.panel = vscode.window.createWebviewPanel(
                'malpackVerdict',
                `MalPack Scan: ${result.packageName}`,
                vscode.ViewColumn.One,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true
                }
            );
        } else {
            this.panel.title = `MalPack Scan: ${result.packageName}`;
        }

        this.panel.webview.html = this.getVerdictHtml(result);

        this.panel.onDidDispose(() => {
            if (onDispose) { onDispose(); }
        }, null, this.context.subscriptions);

        this.panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'showDetails':
                        onNext();
                        break;
                    case 'install':
                        this.panel?.dispose();
                        onInstall(true, 'force');
                        break;
                    case 'abort':
                        this.panel?.dispose();
                        onInstall(false, message.action);
                        break;
                    case 'installAlt':
                        this.panel?.dispose();
                        onInstall(true, 'alternative', message.altName);
                        break;
                    case 'suggestAlternatives':
                        onSuggest();
                        break;
                }
            },
            undefined,
            this.context.subscriptions
        );
    }

    /**
     * Stage 1 (LLM variant): Show LLM verdict with summary text
     */
    showLlmVerdictPanel(result: ScanResult, onInstall: (install: boolean, actionStr?: string, altName?: string) => void, onSuggest: () => void, onDispose?: () => void) {
        this.scanResult = result;
        this.onInstallCallback = onInstall;

        this.panel = vscode.window.createWebviewPanel(
            'malpackLlmVerdict',
            `MalPack LLM Scan: ${result.packageName}`,
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );
        this.panel.webview.html = this.getLlmVerdictHtml(result);

        this.panel.onDidDispose(() => {
            if (onDispose) { onDispose(); }
        }, null, this.context.subscriptions);

        this.panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'install':
                        this.panel?.dispose();
                        onInstall(true, 'force');
                        break;
                    case 'abort':
                        this.panel?.dispose();
                        onInstall(false, message.action);
                        break;
                    case 'installAlt':
                        this.panel?.dispose();
                        onInstall(true, 'alternative', message.altName);
                        break;
                    case 'suggestAlternatives':
                        onSuggest();
                        break;
                }
            },
            undefined,
            this.context.subscriptions
        );
    }

    /**
     * Stage 2: Show high-level details (no file paths/line numbers)
     */
    showHighLevelDetails(onShowCode: (ruleId?: string) => void, onBack: () => void, onSuggest: () => void, onPrev?: () => void, onNext?: () => void) {
        if (!this.scanResult || !this.panel) return;

        this.onShowCodeDetailsCallback = onShowCode;
        this.panel.webview.html = this.getHighLevelDetailsHtml(this.scanResult);

        this.panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'showCode':
                        onShowCode(message.ruleId);
                        break;
                    case 'prev':
                        if (onPrev) onPrev();
                        break;
                    case 'next':
                        if (onNext) onNext();
                        break;
                    case 'back':
                        if (this.scanResult) {
                            this.showVerdictPanel(
                                this.scanResult,
                                (rId) => this.showHighLevelDetails(onShowCode, onBack, onSuggest, onPrev, onNext),
                                this.onInstallCallback!,
                                onSuggest
                            );
                        }
                        break;
                    case 'install':
                        this.panel?.dispose();
                        this.onInstallCallback?.(true, 'force');
                        break;
                    case 'abort':
                        this.panel?.dispose();
                        this.onInstallCallback?.(false, message.action);
                        break;
                    case 'installAlt':
                        this.panel?.dispose();
                        this.onInstallCallback?.(true, 'alternative', message.altName);
                        break;
                    case 'suggestAlternatives':
                        onSuggest();
                        break;
                }
            },
            undefined,
            this.context.subscriptions
        );
    }


    /** Show "Classifier Coming Soon" message */
    showClassifierComingSoon() {
        this.panel = vscode.window.createWebviewPanel(
            'malpackClassifier',
            'MalPack: Classifier Analysis',
            vscode.ViewColumn.One,
            { enableScripts: true }
        );
        this.panel.webview.html = this.getClassifierComingSoonHtml();

        this.panel.webview.onDidReceiveMessage(
            message => {
                if (message.command === 'back') {
                    this.panel?.dispose();
                }
            },
            undefined,
            this.context.subscriptions
        );
    }

    updateAlternatives(alternatives: Array<{ name: string, reason: string }>, error?: string) {
        if (this.panel) {
            this.panel.webview.postMessage({
                command: 'setAlternatives',
                alternatives: alternatives,
                error: error
            });
        }
    }

    dispose() {
        this.panel?.dispose();
    }

    // ─── HTML Generators ───────────────────────────────────────────────────────

    private getMethodSelectionHtml(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MalPack - Select Analysis Method</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--vscode-font-family);
            padding: 30px 20px;
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
        }
        .header {
            text-align: center;
            margin-bottom: 36px;
        }
        .logo { font-size: 48px; margin-bottom: 8px; }
        .title {
            font-size: 26px;
            font-weight: bold;
            color: var(--vscode-foreground);
        }
        .subtitle {
            font-size: 14px;
            color: var(--vscode-descriptionForeground);
            margin-top: 8px;
        }
        .methods-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            max-width: 680px;
            margin: 0 auto;
        }
        .method-card {
            padding: 24px 20px;
            border: 2px solid var(--vscode-panel-border, #454545);
            border-radius: 10px;
            cursor: pointer;
            transition: border-color 0.2s, background 0.2s, transform 0.1s;
            background: var(--vscode-editor-inactiveSelectionBackground);
            position: relative;
            overflow: hidden;
        }
        .method-card:hover {
            border-color: var(--vscode-button-background);
            background: var(--vscode-list-hoverBackground);
            transform: translateY(-2px);
        }
        .method-card.disabled {
            opacity: 0.45;
            cursor: not-allowed;
        }
        .method-card.disabled:hover {
            border-color: var(--vscode-panel-border, #454545);
            background: var(--vscode-editor-inactiveSelectionBackground);
            transform: none;
        }
        .method-icon { font-size: 32px; margin-bottom: 12px; }
        .method-name {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--vscode-foreground);
        }
        .method-desc {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            line-height: 1.5;
        }
        .badge {
            position: absolute;
            top: 10px; right: 10px;
            background: #ff8c00;
            color: #fff;
            font-size: 10px;
            font-weight: bold;
            padding: 3px 8px;
            border-radius: 10px;
        }
        .badge.new { background: #89d185; color: #000; }
        .badge.soon { background: #666; }
        .method-card.semgrep { border-left: 4px solid #61afef; }
        .method-card.rule_based { border-left: 4px solid #e5c07b; }
        .method-card.llm { border-left: 4px solid #c678dd; }
        .method-card.classifier { border-left: 4px solid #56b6c2; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🔍</div>
        <div class="title">MalPack Security Scanner</div>
        <div class="subtitle">Select a detection approach to analyze the package</div>
    </div>

    <div class="methods-grid">
        <div class="method-card semgrep" onclick="select('semgrep')">
            <div class="badge">Fast</div>
            <div class="method-icon">⚡</div>
            <div class="method-name">Semgrep Analysis</div>
            <div class="method-desc">Pattern-based static analysis using Semgrep YAML rules. Detects known attack patterns across Python files with high precision.</div>
        </div>

        <div class="method-card rule_based" onclick="select('rule_based')">
            <div class="badge">Detailed</div>
            <div class="method-icon">📋</div>
            <div class="method-name">Rule Based Analysis</div>
            <div class="method-desc">AST (Abstract Syntax Tree) based detection using 48+ hand-crafted rules across 8 security domains. Provides code-level findings.</div>
        </div>

        <div class="method-card llm" onclick="select('llm')">
            <div class="badge new">AI</div>
            <div class="method-icon">🤖</div>
            <div class="method-name">LLM Based Analysis</div>
            <div class="method-desc">Sends each Python file to Google Gemini AI for intelligent security analysis. Returns a high-level summary of malicious indicators.</div>
        </div>

        <div class="method-card classifier disabled" onclick="">
            <div class="badge soon">Soon</div>
            <div class="method-icon">🧠</div>
            <div class="method-name">Classifier Based Analysis</div>
            <div class="method-desc">ML classifier trained on thousands of malicious packages. Feature extraction + classification pipeline. <em>Not yet implemented.</em></div>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        function select(method) {
            vscode.postMessage({ command: 'selectMethod', method });
        }
    </script>
</body>
</html>`;
    }

    private getVerdictHtml(result: ScanResult): string {
        const isMalicious = result.verdict === 'MALICIOUS';
        const color = isMalicious ? '#f14c4c' : '#89d185';
        const icon = isMalicious ? '⚠️' : '✅';
        const verdictText = isMalicious ? 'MALICIOUS PACKAGE DETECTED' : 'PACKAGE APPEARS SAFE';
        const methodLabel = this.methodLabel(result.detectionMethod);

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MalPack Scan Result</title>
    <style>
        body { font-family: var(--vscode-font-family); padding: 20px; color: var(--vscode-foreground); background-color: var(--vscode-editor-background); }
        .container { max-width: 600px; margin: 0 auto; text-align: center; }
        .verdict-icon { font-size: 80px; margin: 20px 0; }
        .verdict-title { font-size: 28px; font-weight: bold; color: ${color}; margin: 20px 0; }
        .package-name { font-size: 20px; margin: 10px 0; color: var(--vscode-descriptionForeground); }
        .method-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; background: var(--vscode-button-background); color: var(--vscode-button-foreground); margin-bottom: 10px; }
        .stats { margin: 30px 0; padding: 20px; background-color: var(--vscode-editor-inactiveSelectionBackground); border-radius: 8px; }
        .stat-row { display: flex; justify-content: space-between; padding: 8px 0; font-size: 16px; }
        .stat-label { font-weight: 500; }
        .stat-value { font-weight: bold; }
        .critical { color: #f14c4c; }
        .high { color: #ff8c00; }
        .warning { color: #ffcc00; }
        .info { color: #75beff; }
        .buttons { margin-top: 30px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
        button { padding: 10px 24px; font-size: 14px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; }
        .btn-primary { background-color: var(--vscode-button-background); color: var(--vscode-button-foreground); }
        .btn-primary:hover { background-color: var(--vscode-button-hoverBackground); }
        .btn-danger { background-color: #f14c4c; color: white; }
        .btn-danger:hover { background-color: #d93838; }
        .btn-success { background-color: #89d185; color: black; }
        .btn-success:hover { background-color: #72b86f; }
        .btn-alt { background-color: #75beff; color: #000; margin-top: 5px; }
        .btn-alt:hover { background-color: #5a9edc; }
        .alternatives-container { margin-top: 20px; text-align: left; background: var(--vscode-editor-inactiveSelectionBackground); padding: 15px; border-radius: 6px; }
        .alt-title { font-weight: bold; margin-bottom: 10px; color: #75beff; font-size: 14px; }
        .alt-item { margin-bottom: 12px; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 8px; }
        .alt-item:last-child { border-bottom: none; }
        .alt-reason { font-size: 12px; color: var(--vscode-descriptionForeground); margin-bottom: 6px; line-height: 1.4; }
        #loading-alts { display: none; margin-top: 15px; font-style: italic; color: #75beff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="verdict-icon">${icon}</div>
        <div class="method-badge">🔍 ${methodLabel}</div>
        <div class="verdict-title">${verdictText}</div>
        <div class="package-name">${result.packageName}</div>

        <div class="stats">
            <div class="stat-row">
                <span class="stat-label">Files Scanned:</span>
                <span class="stat-value">${result.filesScanned}</span>
            </div>
            ${isMalicious ? `
            <div class="stat-row">
                <span class="stat-label">Total Issues:</span>
                <span class="stat-value">${result.totalIssues}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label critical">Critical:</span>
                <span class="stat-value critical">${result.stats.critical}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label high">High:</span>
                <span class="stat-value high">${result.stats.high}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label warning">Warnings:</span>
                <span class="stat-value warning">${result.stats.warning}</span>
            </div>
            <div class="stat-row">
                <span class="stat-label info">Info:</span>
                <span class="stat-value info">${result.stats.info}</span>
            </div>
            ` : ''}
        </div>

        <div class="buttons">
            ${isMalicious ? `
                <button class="btn-primary" onclick="showDetails()">Show Details</button>
                ${result.isLocal ? `<button class="btn-secondary" onclick="abort('close')">Close</button>` : `
                    <button class="btn-danger" onclick="install()">Forcefully Install</button>
                    <button class="btn-danger" onclick="abort('block')">Block Installation</button>
                    <button class="btn-primary" onclick="suggestAlternatives()">Suggest Alternatives</button>
                `}
            ` : `
                ${result.isLocal ? `
                    <button class="btn-success" onclick="abort('close')">Close</button>
                ` : `
                    <button class="btn-success" onclick="install()">Install Package</button>
                    <button class="btn-danger" onclick="abort('cancel')">Cancel</button>
                `}
            `}
        </div>

        <div id="loading-alts">🤖 Gemini is searching for alternatives...</div>
        <div id="alternatives-list">
            ${(isMalicious && !result.isLocal && result.alternatives && result.alternatives.length > 0) ? `
            <div class="alternatives-container">
                <div class="alt-title">⭐ Safe Alternatives</div>
                ${result.alternatives.map(alt => `
                    <div class="alt-item">
                        <div class="alt-reason">${alt.reason}</div>
                        <button class="btn-alt" onclick="installAlt('${alt.name}')">Install '${alt.name}'</button>
                    </div>
                `).join('')}
            </div>
            ` : ''}
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        function showDetails() { vscode.postMessage({ command: 'showDetails' }); }
        function install() { vscode.postMessage({ command: 'install' }); }
        function installAlt(altName) { vscode.postMessage({ command: 'installAlt', altName }); }
        function abort(action) { vscode.postMessage({ command: 'abort', action }); }
        function suggestAlternatives() { 
            document.getElementById('loading-alts').style.display = 'block';
            vscode.postMessage({ command: 'suggestAlternatives' }); 
        }

        window.addEventListener('message', event => {
            const message = event.data;
            if (message.command === 'setAlternatives') {
                document.getElementById('loading-alts').style.display = 'none';
                const list = document.getElementById('alternatives-list');
                const alts = message.alternatives;
                if (alts && alts.length > 0) {
                    let html = '<div class="alternatives-container"><div class="alt-title">⭐ Safe Alternatives</div>';
                    alts.forEach(alt => {
                        html += \`
                            <div class="alt-item">
                                <div class="alt-reason">\${alt.reason}</div>
                                <button class="btn-alt" onclick="installAlt('\${alt.name}')">Install '\${alt.name}'</button>
                            </div>
                        \`;
                    });
                    html += '</div>';
                    list.innerHTML = html;
                } else {
                    list.innerHTML = '<div style="margin-top:15px; color: #f14c4c;">' + (message.error ? '❌ ' + message.error : 'No alternatives found.') + '</div>';
                }
            }
        });
    </script>
</body>
</html>`;
    }

    private getLlmVerdictHtml(result: ScanResult): string {
        const isApiError = result.verdict === 'API_ERROR';
        const isMalicious = result.verdict === 'MALICIOUS';
        const color = isApiError ? '#ff8c00' : (isMalicious ? '#f14c4c' : '#89d185');
        const icon = isApiError ? '❌' : (isMalicious ? '⚠️' : '✅');
        const verdictText = isApiError ? 'LLM ANALYSIS FAILED' : (isMalicious ? 'MALICIOUS PACKAGE DETECTED' : 'PACKAGE APPEARS SAFE');
        const summaryText = result.llmSummary || 'No summary available.';

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MalPack LLM Scan Result</title>
    <style>
        body { font-family: var(--vscode-font-family); padding: 20px; color: var(--vscode-foreground); background-color: var(--vscode-editor-background); }
        .container { max-width: 680px; margin: 0 auto; text-align: center; }
        .verdict-icon { font-size: 80px; margin: 20px 0; }
        .verdict-title { font-size: 28px; font-weight: bold; color: ${color}; margin: 20px 0; }
        .package-name { font-size: 20px; margin: 10px 0; color: var(--vscode-descriptionForeground); }
        .method-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; background: #c678dd; color: #fff; margin-bottom: 10px; }
        .stats { margin: 20px 0; padding: 20px; background-color: var(--vscode-editor-inactiveSelectionBackground); border-radius: 8px; }
        .stat-row { display: flex; justify-content: space-between; padding: 8px 0; font-size: 16px; }
        .stat-label { font-weight: 500; }
        .stat-value { font-weight: bold; }
        .summary-box {
            margin: 20px 0;
            padding: 20px;
            text-align: left;
            border-left: 4px solid ${color};
            background: var(--vscode-editor-inactiveSelectionBackground);
            border-radius: 4px;
            font-size: 14px;
            line-height: 1.7;
            color: var(--vscode-foreground);
        }
        .summary-title { font-weight: bold; margin-bottom: 8px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--vscode-descriptionForeground); }
        .note { font-size: 12px; color: var(--vscode-descriptionForeground); margin: 10px 0; font-style: italic; }
        .buttons { margin-top: 24px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
        button { padding: 10px 24px; font-size: 14px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; }
        .btn-primary { background-color: var(--vscode-button-background); color: var(--vscode-button-foreground); }
        .btn-primary:hover { background-color: var(--vscode-button-hoverBackground); }
        .btn-danger { background-color: #f14c4c; color: white; }
        .btn-danger:hover { background-color: #d93838; }
        .btn-success { background-color: #89d185; color: black; }
        .btn-success:hover { background-color: #72b86f; }
        .btn-alt { background-color: #75beff; color: #000; margin-top: 5px; }
        .btn-alt:hover { background-color: #5a9edc; }
        .alternatives-container { margin-top: 20px; text-align: left; background: var(--vscode-editor-inactiveSelectionBackground); padding: 15px; border-radius: 6px; }
        .alt-title { font-weight: bold; margin-bottom: 10px; color: #75beff; font-size: 14px; }
        .alt-item { margin-bottom: 12px; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 8px; }
        .alt-item:last-child { border-bottom: none; }
        .alt-reason { font-size: 12px; color: var(--vscode-descriptionForeground); margin-bottom: 6px; line-height: 1.4; }
        #loading-alts { display: none; margin-top: 15px; font-style: italic; color: #75beff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="verdict-icon">${icon}</div>
        <div class="method-badge">🤖 Gemini AI Analysis</div>
        <div class="verdict-title">${verdictText}</div>
        <div class="package-name">${result.packageName}</div>

        <div class="stats">
            <div class="stat-row">
                <span class="stat-label">Files Analyzed:</span>
                <span class="stat-value">${result.filesScanned}</span>
            </div>
        </div>

        <div class="summary-box">
            <div class="summary-title">🤖 AI Analysis Summary</div>
            ${summaryText}
        </div>
        <div class="note">Note: LLM analysis provides a high-level summary only. No code-level details are available.</div>

        <div class="buttons">
            ${isApiError ? `
                <button class="btn-secondary" onclick="abort('cancel')">Close</button>
            ` : isMalicious ? `
                ${result.isLocal ? `<button class="btn-secondary" onclick="abort('close')">Close</button>` : `
                    <button class="btn-danger" onclick="install()">Forcefully Install</button>
                    <button class="btn-danger" onclick="abort('block')">Block Installation</button>
                    <button class="btn-primary" onclick="suggestAlternatives()">Suggest Alternatives</button>
                `}
            ` : `
                ${result.isLocal ? `
                    <button class="btn-success" onclick="abort('close')">Close</button>
                ` : `
                    <button class="btn-success" onclick="install()">Install Package</button>
                    <button class="btn-danger" onclick="abort('cancel')">Cancel</button>
                `}
            `}
        </div>

        <div id="loading-alts">🤖 Gemini is searching for alternatives...</div>
        <div id="alternatives-list">
            ${(isMalicious && !result.isLocal && result.alternatives && result.alternatives.length > 0) ? `
            <div class="alternatives-container">
                <div class="alt-title">⭐ Safe Alternatives</div>
                ${result.alternatives.map(alt => `
                    <div class="alt-item">
                        <div class="alt-reason">${alt.reason}</div>
                        <button class="btn-alt" onclick="installAlt('${alt.name}')">Install '${alt.name}'</button>
                    </div>
                `).join('')}
            </div>
            ` : ''}
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        function install() { vscode.postMessage({ command: 'install' }); }
        function installAlt(altName) { vscode.postMessage({ command: 'installAlt', altName }); }
        function abort(action) { vscode.postMessage({ command: 'abort', action }); }
        function suggestAlternatives() { 
            document.getElementById('loading-alts').style.display = 'block';
            vscode.postMessage({ command: 'suggestAlternatives' }); 
        }

        window.addEventListener('message', event => {
            const message = event.data;
            if (message.command === 'setAlternatives') {
                document.getElementById('loading-alts').style.display = 'none';
                const list = document.getElementById('alternatives-list');
                const alts = message.alternatives;
                if (alts && alts.length > 0) {
                    let html = '<div class="alternatives-container"><div class="alt-title">⭐ Safe Alternatives</div>';
                    alts.forEach(alt => {
                        html += \`
                            <div class="alt-item">
                                <div class="alt-reason">\${alt.reason}</div>
                                <button class="btn-alt" onclick="installAlt('\${alt.name}')">Install '\${alt.name}'</button>
                            </div>
                        \`;
                    });
                    html += '</div>';
                    list.innerHTML = html;
                } else {
                    list.innerHTML = '<div style="margin-top:15px; color: #f14c4c;">' + (message.error ? '❌ ' + message.error : 'No alternatives found.') + '</div>';
                }
            }
        });
    </script>
</body>
</html>`;
    }

    private getHighLevelDetailsHtml(result: ScanResult): string {
        const summaryHtml = result.summary.map(item => {
            let severityClass = item.severity.toLowerCase();
            return `
                <div class="issue-item ${severityClass}">
                    <div class="issue-header">
                        <span class="severity-badge ${severityClass}">${item.severity}</span>
                        <span class="issue-count">${item.count} occurrence${item.count > 1 ? 's' : ''}</span>
                    </div>
                    <div class="issue-message">${item.message}</div>
                    <div class="issue-rule">${item.rule_id}</div>
                    <div style="margin-top: 10px; text-align: right;">
                        <button class="btn-micro" onclick="showCode('${item.rule_id}')">See in Code →</button>
                    </div>
                </div>
            `;
        }).join('');

        const methodLabel = this.methodLabel(result.detectionMethod);

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MalPack - Issue Details</title>
    <style>
        body { font-family: var(--vscode-font-family); padding: 20px; color: var(--vscode-foreground); background-color: var(--vscode-editor-background); }
        .header { text-align: center; margin-bottom: 30px; }
        .title { font-size: 24px; font-weight: bold; color: #f14c4c; }
        .subtitle { font-size: 16px; color: var(--vscode-descriptionForeground); margin-top: 10px; }
        .method-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; background: var(--vscode-button-background); color: var(--vscode-button-foreground); margin-top: 8px; }
        .container { max-width: 800px; margin: 0 auto; }
        .issue-item { margin: 15px 0; padding: 15px; border-left: 4px solid; background-color: var(--vscode-editor-inactiveSelectionBackground); border-radius: 4px; }
        .issue-item.critical { border-left-color: #f14c4c; }
        .issue-item.high { border-left-color: #ff8c00; }
        .issue-item.warning { border-left-color: #ffcc00; }
        .issue-item.info { border-left-color: #75beff; }
        .issue-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
        .severity-badge { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .severity-badge.critical { background-color: #f14c4c; color: white; }
        .severity-badge.high { background-color: #ff8c00; color: white; }
        .severity-badge.warning { background-color: #ffcc00; color: black; }
        .severity-badge.info { background-color: #75beff; color: black; }
        .issue-count { color: var(--vscode-descriptionForeground); font-size: 14px; }
        .issue-message { font-size: 14px; margin: 8px 0; font-weight: 500; }
        .issue-rule { font-size: 12px; color: var(--vscode-descriptionForeground); font-family: monospace; }
        .buttons { margin-top: 30px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
        button { padding: 10px 24px; font-size: 14px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; }
        .btn-primary { background-color: var(--vscode-button-background); color: var(--vscode-button-foreground); }
        .btn-primary:hover { background-color: var(--vscode-button-hoverBackground); }
        .btn-secondary { background-color: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); }
        .btn-danger { background-color: #f14c4c; color: white; }
        .btn-danger:hover { background-color: #d93838; }
        .btn-alt { background-color: #75beff; color: #000; margin-top: 5px; }
        .btn-alt:hover { background-color: #5a9edc; }
        .btn-micro { padding: 4px 10px; font-size: 11px; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground); border-radius: 3px; }

        .btn-micro:hover { background: var(--vscode-button-hoverBackground); color: var(--vscode-button-foreground); }
        .note { text-align: center; margin: 20px 0; padding: 15px; background-color: var(--vscode-textBlockQuote-background); border-left: 4px solid var(--vscode-textBlockQuote-border); font-size: 13px; color: var(--vscode-descriptionForeground); }
        .alternatives-container { margin-top: 20px; text-align: left; background: var(--vscode-editor-inactiveSelectionBackground); padding: 15px; border-radius: 6px; }
        .alt-title { font-weight: bold; margin-bottom: 10px; color: #75beff; font-size: 14px; }
        .alt-item { margin-bottom: 12px; border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 8px; }
        .alt-item:last-child { border-bottom: none; }
        .alt-reason { font-size: 12px; color: var(--vscode-descriptionForeground); margin-bottom: 6px; line-height: 1.4; }
        #loading-alts { display: none; margin-top: 15px; font-style: italic; color: #75beff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">⚠️ Security Issues Detected</div>
            <div class="subtitle">${result.packageName} - ${result.totalIssues} issue${result.totalIssues > 1 ? 's' : ''} found</div>
            <div class="method-badge">🔍 ${methodLabel}</div>
        </div>

        <div class="note">
            The following issues were detected. Click "See in Code" to inspect. 
            Use the <b>&lt;&lt; prev</b> and <b>next &gt;&gt;</b> buttons appearing directly 
            above the code in the editor to navigate between issues!
        </div>

        ${summaryHtml}

        <div class="buttons">
            <button class="btn-primary" onclick="showCode()">Show all in Code</button>
            <div style="width: 100%; height: 10px;"></div> <!-- spacer -->
            <button class="btn-secondary" onclick="back()">Back</button>
            ${result.isLocal ? '' : `
                <button class="btn-danger" onclick="install()">Forcefully Install</button>
                <button class="btn-danger" onclick="abort('block')">Block Installation</button>
                <button class="btn-primary" onclick="suggestAlternatives()">Suggest Alternatives</button>
            `}
        </div>

        <div id="loading-alts">🤖 Gemini is searching for alternatives...</div>
        <div id="alternatives-list">
            ${(result.verdict === 'MALICIOUS' && !result.isLocal && result.alternatives && result.alternatives.length > 0) ? `
            <div class="alternatives-container">
                <div class="alt-title">⭐ Safe Alternatives</div>
                ${result.alternatives.map(alt => `
                    <div class="alt-item">
                        <div class="alt-reason">${alt.reason}</div>
                        <button class="btn-alt" onclick="installAlt('${alt.name}')">Install '${alt.name}'</button>
                    </div>
                `).join('')}
            </div>
            ` : ''}
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        function showCode(ruleId) { vscode.postMessage({ command: 'showCode', ruleId }); }
        function back() { vscode.postMessage({ command: 'back' }); }
        function install() { vscode.postMessage({ command: 'install' }); }
        function installAlt(altName) { vscode.postMessage({ command: 'installAlt', altName }); }
        function abort(action) { vscode.postMessage({ command: 'abort', action }); }
        function suggestAlternatives() { 
            document.getElementById('loading-alts').style.display = 'block';
            vscode.postMessage({ command: 'suggestAlternatives' }); 
        }

        window.addEventListener('message', event => {
            const message = event.data;
            if (message.command === 'setAlternatives') {
                document.getElementById('loading-alts').style.display = 'none';
                const list = document.getElementById('alternatives-list');
                const alts = message.alternatives;
                if (alts && alts.length > 0) {
                    let html = '<div class="alternatives-container"><div class="alt-title">⭐ Safe Alternatives</div>';
                    alts.forEach(alt => {
                        html += \`
                            <div class="alt-item">
                                <div class="alt-reason">\${alt.reason}</div>
                                <button class="btn-alt" onclick="installAlt('\${alt.name}')">Install '\${alt.name}'</button>
                            </div>
                        \`;
                    });
                    html += '</div>';
                    list.innerHTML = html;
                } else {
                    list.innerHTML = '<div style="margin-top:15px; color: #f14c4c;">' + (message.error ? '❌ ' + message.error : 'No alternatives found.') + '</div>';
                }
            }
        });
    </script>
</body>
</html>`;
    }

    private getClassifierComingSoonHtml(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MalPack - Classifier</title>
    <style>
        body { font-family: var(--vscode-font-family); padding: 40px 20px; color: var(--vscode-foreground); background: var(--vscode-editor-background); text-align: center; }
        .icon { font-size: 80px; margin: 20px 0; }
        .title { font-size: 26px; font-weight: bold; margin: 16px 0; }
        .subtitle { font-size: 14px; color: var(--vscode-descriptionForeground); max-width: 480px; margin: 0 auto 30px; line-height: 1.6; }
        button { padding: 10px 24px; font-size: 14px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
        button:hover { background: var(--vscode-button-hoverBackground); }
    </style>
</head>
<body>
    <div class="icon">🧠</div>
    <div class="title">Classifier Analysis — Coming Soon</div>
    <div class="subtitle">
        A machine learning classifier trained on thousands of malicious and benign packages is under development.
        It will use feature extraction and a classification pipeline to detect malicious patterns automatically.
        Please use another detection method for now.
    </div>
    <button onclick="back()">← Back to Method Selection</button>

    <script>
        const vscode = acquireVsCodeApi();
        function back() { vscode.postMessage({ command: 'back' }); }
    </script>
</body>
</html>`;
    }

    private methodLabel(method: DetectionMethod): string {
        switch (method) {
            case 'semgrep': return 'Semgrep Analysis';
            case 'rule_based': return 'Rule Based Analysis';
            case 'llm': return 'LLM Based Analysis';
            case 'classifier': return 'Classifier Based Analysis';
            default: return method;
        }
    }
}
