import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as cp from 'child_process';
import axios from 'axios';
import * as util from 'util';
import * as os from 'os';
import { MalPackWebviewProvider, DetectionMethod, ScanResult } from './webviewProvider';
import { MalPackSidebarProvider } from './SidebarProvider';

axios.defaults.headers.common['User-Agent'] = 'MalPack-VSCode-Extension/1.0.0';

const exec = util.promisify(cp.exec);

/**
 * Lightweight concurrency limiter to replace p-limit and avoid ESM/CJS issues.
 */
function createLimit(concurrency: number) {
    const queue: { fn: () => Promise<any>, resolve: (v: any) => void, reject: (e: any) => void }[] = [];
    let activeCount = 0;

    const next = () => {
        if (queue.length === 0 || activeCount >= concurrency) return;
        activeCount++;
        const item = queue.shift()!;
        item.fn().then(item.resolve).catch(item.reject).finally(() => {
            activeCount--;
            next();
        });
    };

    return (fn: () => Promise<any>) => new Promise((resolve, reject) => {
        queue.push({ fn, resolve, reject });
        next();
    });
}

function getApiUrl(): string {
    const config = vscode.workspace.getConfiguration('malpack');

    let baseUrl = config.get<string>('backendUrl', 'https://malpack-backend1.onrender.com');
    if (baseUrl.endsWith('/')) { baseUrl = baseUrl.slice(0, -1); }
    return `${baseUrl}/api/v1`;
}

interface Finding {
    line: number;
    col_offset: number;
    end_col_offset: number;
    message: string;
    severity: string;
    rule_id: string;
}

interface FileFindings {
    file: string;
    status: string;
    findings: Finding[];
    stats: { total: number; critical: number; high: number; warning: number; info: number; };
}


// Stores findings: packageName -> filePath -> Finding[]
let findingsMap: Map<string, Map<string, Finding[]>> = new Map();
let currentPackage: string | undefined; // Tracks which package the user is currently navigating
let currentRuleFilter: string | undefined; // Tracks active rule filter for navigation
let currentScanDir: string = '';
let cleanupCompleted: boolean = false;
let codeLensProvider: MalPackCodeLensProvider;

const redBoxDecorationType = vscode.window.createTextEditorDecorationType({
    borderWidth: '2px',
    borderStyle: 'solid',
    borderColor: '#f14c4c',
    backgroundColor: 'rgba(255, 76, 76, 0.15)',
    isWholeLine: false
});

function performCleanup(scanDir: string, pkgName?: string) {
    if (scanDir && fs.existsSync(scanDir)) {
        try {
            fs.rmSync(scanDir, { recursive: true, force: true });
            if (pkgName) { findingsMap.delete(pkgName); }
            outputChannel.appendLine(`[MalPack] Cleaned up temporary files for ${pkgName || scanDir}`);
        } catch (err: any) {
            console.error(`Cleanup failed: ${err.message}`);
        }
    }
}

function methodDisplayName(method: DetectionMethod): string {
    const names: Record<DetectionMethod, string> = {
        semgrep: 'Semgrep', rule_based: 'Rule Based', llm: 'LLM/AI', classifier: 'Classifier'
    };
    return names[method] || method;
}

function cleanApiError(msg: string): string {
    if (msg.includes('RESOURCE_EXHAUSTED') || msg.toLowerCase().includes('quota')) {
        return 'Gemini API quota exceeded. Please wait for reset or use a different API key.';
    }
    if (msg.includes('404') && msg.toLowerCase().includes('not found')) {
        return 'Gemini model not found. The model may have been deprecated.';
    }
    if (msg.includes('PERMISSION_DENIED') || msg.includes('403')) {
        return 'Gemini API key is invalid or lacks permissions.';
    }
    if (msg.includes('UNAUTHENTICATED') || msg.includes('401')) {
        return 'Gemini API key is invalid. Please check your GEMINI_API_KEY.';
    }
    return msg.length > 120 ? msg.substring(0, 120) + '...' : msg;
}

let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("MalPack Scanner");
    context.subscriptions.push(outputChannel);

    const sidebarProvider = new MalPackSidebarProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            MalPackSidebarProvider.viewType,
            sidebarProvider
        )
    );

    console.log('MalPack extension is now active!');
    vscode.window.showInformationMessage('MalPack Extension Activated!');
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('malpack');
    context.subscriptions.push(diagnosticCollection);

    // Re-assert global PIP_CONSTRAINT if there's an existing blocked package collection
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
        const rootPath = vscode.workspace.workspaceFolders[0].uri.fsPath;
        const globalConstraintsFile = path.join(rootPath, '.malpack_pip_constraints.txt');
        if (fs.existsSync(globalConstraintsFile)) {
            context.environmentVariableCollection.replace('PIP_CONSTRAINT', globalConstraintsFile);
        }
    }

    vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor) { applyDecorations(editor); }
    }, null, context.subscriptions);

    // Auto-scan requirements.txt on save
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (path.basename(document.uri.fsPath) === 'requirements.txt') {
            await autoScanRequirementsTxt(document, context);
        }
    }));

    // Auto-scan requirements.txt on load (workspace open)
    setTimeout(async () => {
        const uris = await vscode.workspace.findFiles('requirements.txt', '**/node_modules/**', 10);
        for (const uri of uris) {
            try {
                const doc = await vscode.workspace.openTextDocument(uri);
                await autoScanRequirementsTxt(doc, context);
            } catch (err) {
                console.error(`Failed to auto-scan ${uri.fsPath}`, err);
            }
        }
    }, 2000); // Small delay to let VS Code settle

    context.subscriptions.push(vscode.commands.registerCommand('malpack.prevFinding', () => navigateFinding('prev')));
    context.subscriptions.push(vscode.commands.registerCommand('malpack.nextFinding', () => navigateFinding('next')));

    codeLensProvider = new MalPackCodeLensProvider();
    context.subscriptions.push(vscode.languages.registerCodeLensProvider({ language: 'python', scheme: 'file' }, codeLensProvider));
    context.subscriptions.push(vscode.languages.registerCodeLensProvider({ language: 'javascript', scheme: 'file' }, codeLensProvider));
    context.subscriptions.push(vscode.languages.registerCodeLensProvider({ language: 'json', scheme: 'file' }, codeLensProvider));

    let disposable = vscode.commands.registerCommand('malpack.install', async () => {
        const webviewProvider = new MalPackWebviewProvider(context);

        // Choice: PyPI or Local
        const choice = await vscode.window.showQuickPick(['PyPI Package', 'Local Directory'], {
            placeHolder: 'Select what to scan'
        });
        if (!choice) return;

        let method: DetectionMethod | undefined;
        const apiUrl = getApiUrl();

        if (choice === 'PyPI Package') {
            const pkgNamesInput = await vscode.window.showInputBox({
                prompt: `Enter packages to scan (space separated)`,
                placeHolder: "requests urllib3 numpy"
            });
            if (!pkgNamesInput) { return; }

            const packages = pkgNamesInput.split(' ').map(p => p.trim()).filter(p => p.length > 0);
            if (packages.length === 0) { return; }

            // Then pick method
            await new Promise<void>(resolve => {
                webviewProvider.showMethodSelectionPanel((m: DetectionMethod) => {
                    method = m;
                    resolve();
                });
            });
            if (!method) return;

            if (method === 'classifier') {
                webviewProvider.showClassifierComingSoon();
                return;
            }

            for (const pkgName of packages) {
                scanPackage(pkgName, method, apiUrl, diagnosticCollection, context);
            }
            vscode.window.showInformationMessage("MalPack: Analyzing packages in background...");
        } else {
            const folderUri = await vscode.window.showOpenDialog({
                canSelectFiles: true,
                canSelectFolders: true,
                canSelectMany: false,
                openLabel: 'Select Folder/File to Scan'
            });
            if (!folderUri || folderUri.length === 0) return;

            const localPath = folderUri[0].fsPath;
            const folderName = path.basename(localPath);

            // Then pick method
            await new Promise<void>(resolve => {
                webviewProvider.showMethodSelectionPanel((m: DetectionMethod) => {
                    method = m;
                    resolve();
                });
            });
            if (!method) return;

            if (method === 'classifier') {
                webviewProvider.showClassifierComingSoon();
                return;
            }

            // For local, we don't have a "scanDir" to cleanup (it's user source), but we might want to scan it as is.
            // We'll pass scanDir=null to signal no extraction cleanup needed.
            scanSourceDirectory(localPath, folderName, method, apiUrl, diagnosticCollection, context, null);
            vscode.window.showInformationMessage(`MalPack: Analyzing local folder '${folderName}'...`);
        }
    });

    context.subscriptions.push(disposable);
}

async function scanPackage(pkgName: string, method: DetectionMethod, apiUrl: string, diagnosticCollection: vscode.DiagnosticCollection, context: vscode.ExtensionContext): Promise<void> {
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
        const rootPath = vscode.workspace.workspaceFolders[0].uri.fsPath;
    }

    const extractRoot = context.globalStorageUri.fsPath;
    const scanDir = path.join(extractRoot, 'malpack_analysis', pkgName);

    return vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `MalPack (${methodDisplayName(method)}): Downloading ${pkgName}...`,
        cancellable: false
    }, async (progress) => {
        try {
            if (fs.existsSync(scanDir)) { fs.rmSync(scanDir, { recursive: true, force: true }); }
            fs.mkdirSync(scanDir, { recursive: true });

            const downloadDir = path.join(scanDir, 'download');
            fs.mkdirSync(downloadDir, { recursive: true });
            const extractDir = path.join(scanDir, 'source');
            fs.mkdirSync(extractDir, { recursive: true });

            let res;
            try {
                res = await axios.get(`https://pypi.org/pypi/${pkgName}/json`);
            } catch (e: any) {
                if (e.response && e.response.status === 404) {
                    throw new Error(`Package '${pkgName}' not found on PyPI.`);
                }
                throw e;
            }
            const releases = res.data.urls;
            if (!releases || releases.length === 0) {
                throw new Error(`No downloadable files found for ${pkgName} on PyPI.`);
            }

            let target = releases.find((r: any) => r.url.endsWith('.whl'));
            if (!target) target = releases.find((r: any) => r.url.endsWith('.tar.gz') || r.url.endsWith('.zip'));
            if (!target) throw new Error(`No suitable archive found for ${pkgName} on PyPI.`);

            const archivePath = path.join(downloadDir, target.filename);
            const writer = fs.createWriteStream(archivePath);
            const downloadStream = await axios.get(target.url, { responseType: 'stream' });
            downloadStream.data.pipe(writer);

            await new Promise((resolve, reject) => {
                writer.on('finish', resolve);
                writer.on('error', reject);
            });

            if (archivePath.endsWith('.whl') || archivePath.endsWith('.zip')) {
                const AdmZip = require('adm-zip');
                const zip = new AdmZip(archivePath);
                zip.extractAllTo(extractDir, true);
            } else if (archivePath.endsWith('.tar.gz')) {
                const tar = require('tar');
                await tar.x({ file: archivePath, cwd: extractDir });
            } else {
                throw new Error("Unsupported archive format.");
            }

            await scanSourceDirectory(extractDir, pkgName, method, apiUrl, diagnosticCollection, context, scanDir);
        } catch (err: any) {
            performCleanup(scanDir, pkgName);
            vscode.window.showErrorMessage(`MalPack Error: ${err.message}`);
        }
    });
}

async function scanSourceDirectory(sourceDir: string, pkgName: string, method: DetectionMethod, apiUrl: string, diagnosticCollection: vscode.DiagnosticCollection, context: vscode.ExtensionContext, cleanupDir: string | null): Promise<void> {
    const webviewProvider = new MalPackWebviewProvider(context);
    return vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `MalPack (${methodDisplayName(method)}): Scanning ${pkgName}...`,
        cancellable: false
    }, async (progress) => {
        try {
            outputChannel.clear();
            outputChannel.show(true);
            outputChannel.appendLine(`[MalPack] Starting analysis of '${pkgName}' using ${methodDisplayName(method)} method...`);

            // LLM flow
            if (method === 'llm') {
                progress.report({ message: "Collecting Python files for AI analysis..." });

                const pyFiles: string[] = [];
                function collectPyFiles(dir: string) {
                    for (const entry of fs.readdirSync(dir)) {
                        const full = path.join(dir, entry);
                        if (fs.statSync(full).isDirectory()) {
                            collectPyFiles(full);
                        } else if (entry.endsWith('.py')) {
                            pyFiles.push(full);
                        }
                    }
                }
                collectPyFiles(sourceDir);

                let maliciousFilesCount = 0;
                let filesAnalyzed = 0;
                let errorCount = 0;
                let firstErrorMsg = '';
                let allIndicators: string[] = [];
                const maliciousFilesDetail: any[] = [];

                const limit = createLimit(10);
                const tasks = pyFiles.map((full, i) => limit(async () => {
                    const relPath = full.replace(sourceDir, '').substring(1);
                    progress.report({ message: `Analyzing: ${relPath} [${i + 1}/${pyFiles.length}]` });
                    outputChannel.appendLine(`[LLM SCAN] Analyzing: ${relPath}`);

                    try {
                        const contentBuffer = fs.readFileSync(full, 'utf-8');
                        const res = await axios.post(`${apiUrl}/llm_file_check`, {
                            file_path: relPath,
                            content: Buffer.from(contentBuffer).toString('base64'),
                            is_base64: true
                        });

                        const fileResult = res.data;
                        if (fileResult.summary && fileResult.summary.includes("Skipped")) {
                            return;
                        }

                        filesAnalyzed++;

                        // Track API errors (quota exhaustion, key missing, etc.)
                        if (fileResult.error) {
                            errorCount++;
                            if (!firstErrorMsg && fileResult.summary) {
                                firstErrorMsg = fileResult.summary;
                            }
                            outputChannel.appendLine(`[LLM SCAN] ❌ API Error for ${relPath}: ${fileResult.summary}`);
                            return;
                        }

                        if (fileResult.is_malicious) {
                            maliciousFilesCount++;
                            allIndicators = allIndicators.concat(fileResult.indicators || []);
                            maliciousFilesDetail.push({
                                file: relPath,
                                summary: fileResult.summary
                            });
                            outputChannel.appendLine(`[LLM SCAN] ⚠️ Malicious indicators found in ${relPath}: ${fileResult.summary}`);
                        }
                    } catch (err: any) {
                        outputChannel.appendLine(`[LLM SCAN] ❌ Error analyzing ${relPath}: ${err.message}`);
                    }
                }));

                await Promise.all(tasks);

                // Determine verdict: if ALL files errored, show API error
                const allErrored = filesAnalyzed > 0 && errorCount === filesAnalyzed;
                const isMalicious = maliciousFilesCount > 0;
                let verdict: ScanResult['verdict'];
                let overallSummary: string;

                if (allErrored) {
                    verdict = 'API_ERROR';
                    // Extract a clean error message
                    let cleanError = firstErrorMsg.replace('Analysis failed: ', '');
                    // Check if it's a quota error
                    if (cleanError.includes('RESOURCE_EXHAUSTED') || cleanError.includes('quota')) {
                        overallSummary = `⚠️ Gemini API quota exhausted!\n\nAll ${filesAnalyzed} file(s) failed to analyze.\n\nError: Your free-tier quota for Gemini API has been exceeded (limit: 0 requests remaining).\n\nTo fix this:\n• Wait for your daily quota to reset\n• Use an API key from a different Google Cloud project\n• Enable billing on your Google Cloud project for higher limits`;
                    } else if (cleanError.includes('not configured')) {
                        overallSummary = `⚠️ Gemini API key not configured!\n\nThe GEMINI_API_KEY environment variable is not set on the backend server.\n\nPlease set it in your Render dashboard under Environment Variables.`;
                    } else {
                        overallSummary = `⚠️ LLM Analysis Failed\n\nAll ${filesAnalyzed} file(s) failed with errors.\n\nError: ${cleanError}`;
                    }
                } else if (isMalicious) {
                    verdict = 'MALICIOUS';
                    const uniqueIndicators = [...new Set(allIndicators)];
                    overallSummary = `Package '${pkgName}' contains malicious indicators in ${maliciousFilesCount} out of ${filesAnalyzed} analyzed file(s).\\n\\nKey findings: ${uniqueIndicators.slice(0, 5).join('; ')}\\n\\nFiles affected:\\n` + maliciousFilesDetail.map(d => `- ${d.file}: ${d.summary}`).join('\\n');
                    if (errorCount > 0) {
                        overallSummary += `\\n\\n⚠️ Note: ${errorCount} file(s) could not be analyzed due to API errors.`;
                    }
                } else {
                    verdict = 'BENIGN';
                    overallSummary = `Package '${pkgName}' appears safe. Analyzed ${filesAnalyzed - errorCount} Python file(s) with no malicious indicators detected.`;
                    if (errorCount > 0) {
                        overallSummary += `\n\n⚠️ Note: ${errorCount} file(s) could not be analyzed due to API errors. Results may be incomplete.`;
                    }
                }

                webviewProvider.showLlmVerdictPanel(
                    {
                        packageName: pkgName,
                        verdict: verdict,
                        totalIssues: maliciousFilesCount,
                        filesScanned: filesAnalyzed,
                        detectionMethod: 'llm',
                        stats: { critical: 0, high: 0, warning: 0, info: 0 },
                        summary: [],
                        llmSummary: overallSummary,
                        isLocal: cleanupDir === null,
                        alternatives: []
                    },
                    async (install: boolean, actionStr?: string, altName?: string) => {
                        await processInstallDecision(pkgName, install, actionStr, altName, cleanupDir || '', context);
                    },
                    async () => {
                        try {
                            const altRes = await axios.post(`${apiUrl}/suggest_alternatives`, { package_name: pkgName }, { timeout: 15000 });
                            if (altRes.data.success) {
                                webviewProvider.updateAlternatives(altRes.data.alternatives);
                            } else {
                                webviewProvider.updateAlternatives([], cleanApiError(altRes.data.error || 'Failed to fetch alternatives'));
                            }
                        } catch (e: any) {
                            outputChannel.appendLine(`[MalPack] Error calling suggest_alternatives API: ${e.message}`);
                            webviewProvider.updateAlternatives([], cleanApiError(`Request failed: ${e.message}`));
                        }
                    },
                    () => {
                        if (cleanupDir) performCleanup(cleanupDir, pkgName);
                        showFeedbackPopup(pkgName);
                    }
                );
                return;
            }

            // Semgrep / Rule-based flow
            progress.report({ message: "Scanning for malicious patterns..." });
            const allFileResults: FileFindings[] = [];
            const checkEndpoint = method === 'semgrep'
                ? `${apiUrl}/semgrep_check/check`
                : `${apiUrl}/rule_based_check/check`;

            const ruleLimit = createLimit(10);
            const allFiles: string[] = [];
            function collectAllFiles(dir: string) {
                for (const file of fs.readdirSync(dir)) {
                    const filePath = path.join(dir, file);
                    if (fs.statSync(filePath).isDirectory()) {
                        collectAllFiles(filePath);
                    } else if (file.endsWith('.py') || file.endsWith('.json') || file.endsWith('.js')) {
                        allFiles.push(filePath);
                    }
                }
            }
            collectAllFiles(sourceDir);

            const ruleTasks = allFiles.map((filePath, i) => ruleLimit(async () => {
                const file = path.basename(filePath);
                progress.report({ message: `Scanning ${file} [${i + 1}/${allFiles.length}]...` });
                outputChannel.appendLine(`[SCAN] Analyzing: ${file}`);
                try {
                    const content = fs.readFileSync(filePath, 'utf-8');
                    const res = await axios.post(checkEndpoint, {
                        file_path: filePath.replace(sourceDir, '').substring(1),
                        content: Buffer.from(content).toString('base64'),
                        is_base64: true
                    });
                    allFileResults.push(res.data);

                    const findings: Finding[] = res.data.findings || [];
                    if (res.data.status === "DANGER" || findings.length > 0) {
                        if (!findingsMap.has(pkgName)) { findingsMap.set(pkgName, new Map()); }
                        findingsMap.get(pkgName)!.set(filePath, findings);

                        const diagnostics = findings.map(f => {
                            const line = Math.max(0, f.line - 1);
                            const col = Math.max(0, f.col_offset);
                            const endCol = Math.max(col + 1, f.end_col_offset || col + 10);

                            const range = new vscode.Range(
                                new vscode.Position(line, col),
                                new vscode.Position(line, endCol)
                            );
                            const sv = f.severity === 'CRITICAL' || f.severity === 'HIGH'
                                ? vscode.DiagnosticSeverity.Error
                                : f.severity === 'WARNING'
                                    ? vscode.DiagnosticSeverity.Warning
                                    : vscode.DiagnosticSeverity.Information;
                            return new vscode.Diagnostic(range, `[${f.rule_id}] ${f.message}`, sv);
                        });
                        diagnosticCollection.set(vscode.Uri.file(filePath), diagnostics);
                    }
                } catch (scanErr: any) {
                    let errorMsg = scanErr.message;
                    if (scanErr.response) {
                        errorMsg = `Status ${scanErr.response.status} - ${scanErr.response.statusText}`;
                    }
                    outputChannel.appendLine(`[ERROR] Failed to scan ${file}: ${errorMsg}`);
                    allFileResults.push({
                        file: filePath.replace(sourceDir, '').substring(1),
                        status: "SAFE",
                        findings: [],
                        stats: { total: 0, critical: 0, high: 0, warning: 0, info: 0 }
                    });
                }
            }));

            await Promise.all(ruleTasks);
            if (codeLensProvider) codeLensProvider.refresh();

            outputChannel.appendLine(`[MalPack] Analysis complete! Preparing results...`);
            progress.report({ message: "Analyzing results..." });
            const summaryRes = await axios.post(`${apiUrl}/scan/summary`, { findings_data: allFileResults });
            const summary = summaryRes.data;

            webviewProvider.showVerdictPanel(
                {
                    packageName: pkgName,
                    verdict: summary.verdict,
                    totalIssues: summary.total_issues,
                    filesScanned: summary.files_scanned,
                    detectionMethod: method,
                    stats: summary.stats,
                    summary: summary.summary,
                    allFindings: allFileResults,
                    isLocal: cleanupDir === null,
                    alternatives: []
                },
                (ruleId) => {
                    webviewProvider.showHighLevelDetails(
                        async (rId) => {
                            await showCodeLevelDetails(pkgName, diagnosticCollection, rId || ruleId);
                        },
                        () => { },
                        async () => {
                            try {
                                const altRes = await axios.post(`${apiUrl}/suggest_alternatives`, { package_name: pkgName }, { timeout: 15000 });
                                if (altRes.data.success) {
                                    webviewProvider.updateAlternatives(altRes.data.alternatives);
                                } else {
                                    webviewProvider.updateAlternatives([], cleanApiError(altRes.data.error || 'Failed to fetch alternatives'));
                                }
                            } catch (e: any) {
                                outputChannel.appendLine(`[MalPack] Error calling suggest_alternatives API: ${e.message}`);
                                webviewProvider.updateAlternatives([], cleanApiError(`Request failed: ${e.message}`));
                            }
                        },
                        () => navigateFinding('prev'),
                        () => navigateFinding('next')
                    );
                },
                async (install: boolean, actionStr?: string, altName?: string) => {
                    await processInstallDecision(pkgName, install, actionStr, altName, cleanupDir || '', context);
                },
                async () => {
                    try {
                        const altRes = await axios.post(`${apiUrl}/suggest_alternatives`, { package_name: pkgName }, { timeout: 15000 });
                        if (altRes.data.success) {
                            webviewProvider.updateAlternatives(altRes.data.alternatives);
                        } else {
                            webviewProvider.updateAlternatives([], cleanApiError(altRes.data.error || 'Failed to fetch alternatives'));
                        }
                    } catch (e: any) {
                        outputChannel.appendLine(`[MalPack] Error calling suggest_alternatives API: ${e.message}`);
                        webviewProvider.updateAlternatives([], cleanApiError(`Request failed: ${e.message}`));
                    }
                },
                () => {
                    if (cleanupDir) performCleanup(cleanupDir, pkgName);
                    showFeedbackPopup(pkgName);
                }
            );
            return;

        } catch (err: any) {
            if (cleanupDir) performCleanup(cleanupDir, pkgName);
            vscode.window.showErrorMessage(`MalPack Error parsing '${pkgName}': ${err.message}`);
        }
    });
}

async function showCodeLevelDetails(pkgName: string, diagnosticCollection: vscode.DiagnosticCollection, ruleIdLimit?: string) {
    const pkgFindings = findingsMap.get(pkgName);
    if (!pkgFindings) return;

    currentPackage = pkgName;
    currentRuleFilter = ruleIdLimit;

    // Open ONLY the first file where issues appear
    const files = Array.from(pkgFindings.keys()).sort();
    for (const filePath of files) {
        const findings = pkgFindings.get(filePath)!;
        const filtered = ruleIdLimit ? findings.filter(f => f.rule_id === ruleIdLimit) : findings;
        if (filtered.length > 0) {
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
            const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One, true); // true = preserveFocus
            applyDecorations(editor);

            // Jump to the VERY FIRST detection as a fresh start
            const first = filtered.sort((a, b) => a.line - b.line)[0];
            const pos = new vscode.Position(first.line - 1, first.col_offset);
            editor.selection = new vscode.Selection(pos, pos);
            editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
            break; // Stop after opening the first matching file
        }
    }

    if (codeLensProvider) codeLensProvider.refresh();
}

async function processInstallDecision(pkgName: string, install: boolean, actionStr: string | undefined, altName: string | undefined, scanDir: string, context: vscode.ExtensionContext) {
    if (!scanDir) return; // If local, we don't install anything.

    try {
        if (install) {
            let term = vscode.window.activeTerminal;
            if (!term) term = vscode.window.createTerminal("MalPack Install");
            term.show();

            if (actionStr === 'force') {
                term.sendText(`pip install ${pkgName}`);
            } else if (actionStr === 'alternative' && altName) {
                term.sendText(`pip install ${altName}`);
                vscode.window.showInformationMessage(`MalPack: Safely installing alternative package: ${altName}`);
            } else {
                term.sendText(`pip install ${pkgName}`);
            }
        } else {
            if (actionStr === 'block') {
                await blockInstallation(pkgName, context);
            } else {
                vscode.window.showInformationMessage(`Installation of ${pkgName} cancelled.`);
            }
        }
    } finally {
        performCleanup(scanDir, pkgName);
    }
}

async function getVenvPath(): Promise<string | undefined> {
    // 1. Try Python extension API (most reliable if ms-python is installed)
    try {
        const pythonExtension = vscode.extensions.getExtension('ms-python.python');
        if (pythonExtension) {
            if (!pythonExtension.isActive) { await pythonExtension.activate(); }
            const api = pythonExtension.exports;
            const activeEnv = await api.environments.getActiveEnvironmentPath();
            if (activeEnv && activeEnv.path) {
                // If path points to python executable, get the parent directory (the venv root)
                const p = activeEnv.path;
                if (p.includes('bin') || p.includes('Scripts')) {
                    return path.dirname(path.dirname(p));
                }
                return path.dirname(p);
            }
        }
    } catch (e) {
        outputChannel.appendLine(`[MalPack] Python API detection failed: ${e}`);
    }

    // 2. Try process.env.VIRTUAL_ENV
    if (process.env.VIRTUAL_ENV) { return process.env.VIRTUAL_ENV; }

    // 3. Try workspace configuration (python.defaultInterpreterPath)
    const config = vscode.workspace.getConfiguration('python');
    const interpreterPath = config.get<string>('defaultInterpreterPath');
    if (interpreterPath && interpreterPath !== 'python') {
        if (interpreterPath.includes('bin') || interpreterPath.includes('Scripts')) {
            return path.dirname(path.dirname(interpreterPath));
        }
    }

    // 4. Heuristic: Look for common venv folders in workspace root
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
        const root = vscode.workspace.workspaceFolders[0].uri.fsPath;
        const commonNames = ['.venv', 'venv', 'env', '.env'];
        for (const name of commonNames) {
            const fullPath = path.join(root, name);
            if (fs.existsSync(path.join(fullPath, 'bin', 'pip')) || fs.existsSync(path.join(fullPath, 'Scripts', 'pip.exe'))) {
                return fullPath;
            }
        }
    }

    return undefined;
}

async function blockInstallation(pkgName: string, context: vscode.ExtensionContext) {
    vscode.window.showInformationMessage(`MalPack: Blocking installation of '${pkgName}'. It cannot be installed in the future within this environment.`);

    // 1. Write to .malpack_blocked in workspace root (for extension-level blocking)
    if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
        const rootPath = vscode.workspace.workspaceFolders[0].uri.fsPath;
        const blockedFile = path.join(rootPath, '.malpack_blocked');

        let blockedPkgs = new Set<string>();
        if (fs.existsSync(blockedFile)) {
            const content = fs.readFileSync(blockedFile, 'utf-8');
            content.split('\n').forEach(p => { if (p.trim()) blockedPkgs.add(p.trim()); });
        }
        blockedPkgs.add(pkgName);
        fs.writeFileSync(blockedFile, Array.from(blockedPkgs).join('\n') + '\n');

        // 1b. Write constraint file at workspace root for global terminal blocking
        const globalConstraintsFile = path.join(rootPath, '.malpack_pip_constraints.txt');
        let existingGlobal = '';
        if (fs.existsSync(globalConstraintsFile)) {
            existingGlobal = fs.readFileSync(globalConstraintsFile, 'utf-8');
        }
        const constraintLine = `${pkgName}==0.0.0.malpack.blocked`;
        if (!existingGlobal.includes(constraintLine)) {
            existingGlobal += constraintLine + '\n';
            fs.writeFileSync(globalConstraintsFile, existingGlobal);
        }

        // Apply PIP_CONSTRAINT to ALL integrated VS Code terminals!
        context.environmentVariableCollection.replace('PIP_CONSTRAINT', globalConstraintsFile);
    }

    // 2. Find ALL venvs in the workspace and write a pip constraints file to block the package
    const venvs = new Set<string>();
    const activeVenv = await getVenvPath();
    if (activeVenv && fs.existsSync(activeVenv)) venvs.add(activeVenv);

    try {
        const pipUnix = await vscode.workspace.findFiles('**/{bin/pip,Scripts/pip.exe,Scripts/pip}', '**/node_modules/**', 50);
        for (const uri of pipUnix) {
            venvs.add(path.dirname(path.dirname(uri.fsPath)));
        }
    } catch (e) {
        // Ignore search errors
    }

    if (venvs.size > 0) {
        let blockedCount = 0;
        for (const venvPath of venvs) {
            if (!fs.existsSync(venvPath)) continue;
            blockedCount++;

            // Write constraint file at venv root
            const constraintsFile = path.join(venvPath, 'malpack_constraints.txt');
            let existingConstraints = '';
            if (fs.existsSync(constraintsFile)) {
                existingConstraints = fs.readFileSync(constraintsFile, 'utf-8');
            }
            const constraintLine = `${pkgName}==0.0.0.malpack.blocked`;
            if (!existingConstraints.includes(constraintLine)) {
                existingConstraints += constraintLine + '\n';
                fs.writeFileSync(constraintsFile, existingConstraints);
            }

            // Write pip.conf at the correct OS-specific location inside the venv
            const isWindows = process.platform === 'win32';
            const pipConfFile = isWindows
                ? path.join(venvPath, 'pip.ini')
                : path.join(venvPath, 'pip.conf');

            const constraintDirective = `constraints = ${constraintsFile}`;

            if (fs.existsSync(pipConfFile)) {
                const existingConf = fs.readFileSync(pipConfFile, 'utf-8');
                if (!existingConf.includes('malpack_constraints.txt')) {
                    if (existingConf.includes('[global]')) {
                        const updated = existingConf.replace('[global]', `[global]\n${constraintDirective}`);
                        fs.writeFileSync(pipConfFile, updated);
                    } else {
                        fs.appendFileSync(pipConfFile, `\n[global]\n${constraintDirective}\n`);
                    }
                }
            } else {
                fs.writeFileSync(pipConfFile, `[global]\n${constraintDirective}\n`);
            }

            // Also try to uninstall the package if it's currently installed
            try {
                const pipBin = isWindows
                    ? path.join(venvPath, 'Scripts', 'pip')
                    : path.join(venvPath, 'bin', 'pip');
                if (fs.existsSync(pipBin)) {
                    await exec(`"${pipBin}" uninstall -y ${pkgName} 2>/dev/null || true`);
                }
            } catch (e) {
            }
        }

        outputChannel.appendLine(`[MalPack] Blocked '${pkgName}' via pip constraints in ${blockedCount} venv(s) and VS Code Integrated Terminals.`);
        vscode.window.showWarningMessage(`'${pkgName}' is now BLOCKED in ${blockedCount} venv(s) and all VS Code terminals.`);
    } else {
        outputChannel.appendLine(`[MalPack] Blocked '${pkgName}' globally via VS Code Integrated Terminals.`);
        vscode.window.showWarningMessage(`'${pkgName}' is now BLOCKED in all current and future VS Code terminals.`);
    }
}

function showFeedbackPopup(pkgName: string) {
    vscode.window.showInformationMessage(
        `The analysis of ${pkgName} was correct?`,
        'Yes', 'No'
    ).then(selection => {
        if (selection === 'Yes') {
            outputChannel.appendLine(`[Feedback] User confirmed analysis of ${pkgName} was correct.`);
        } else if (selection === 'No') {
            outputChannel.appendLine(`[Feedback] User flagged analysis of ${pkgName} as INCORRECT.`);
        }
    });
}

function applyDecorations(editor: vscode.TextEditor) {
    const filePath = editor.document.uri.fsPath;
    let allFindings: Finding[] = [];

    // Aggregate findings for this file from ALL active package sessions
    for (const pkgMap of findingsMap.values()) {
        const fileFindings = pkgMap.get(filePath);
        if (fileFindings) {
            allFindings = allFindings.concat(fileFindings);
        }
    }

    if (allFindings.length === 0) {
        editor.setDecorations(redBoxDecorationType, []);
        return;
    }

    const ranges: vscode.DecorationOptions[] = allFindings.map(f => {
        const range = new vscode.Range(
            new vscode.Position(f.line - 1, f.col_offset),
            new vscode.Position(f.line - 1, Math.max(f.end_col_offset, f.col_offset + 10))
        );
        const hoverMessage = new vscode.MarkdownString();
        hoverMessage.appendMarkdown(`**⚠️ ${f.severity}**\n\n**Rule:** ${f.rule_id}\n\n**Issue:** ${f.message}`);
        return { range, hoverMessage };
    });
    editor.setDecorations(redBoxDecorationType, ranges);
}

export function deactivate() {
    performCleanup(currentScanDir);
}

// ============================================================================
// FINDING NAVIGATION LOGIC (Cross-file)
// ============================================================================

async function navigateFinding(direction: 'next' | 'prev') {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !currentPackage) { return; }

    const pkgFindings = findingsMap.get(currentPackage);
    if (!pkgFindings || pkgFindings.size === 0) { return; }

    // Convert findings to a sorted list of {file, finding}
    const allFindingsList: { file: string, f: Finding }[] = [];
    const files = Array.from(pkgFindings.keys()).sort();
    for (const file of files) {
        let findings = pkgFindings.get(file)!.sort((a, b) => a.line - b.line || a.col_offset - b.col_offset);
        if (currentRuleFilter) {
            findings = findings.filter(f => f.rule_id === currentRuleFilter);
        }
        for (const f of findings) {
            allFindingsList.push({ file, f });
        }
    }

    if (allFindingsList.length === 0) return;

    const currentFile = editor.document.uri.fsPath;
    const currentPos = editor.selection.active;

    // Find if we are currently ON a finding
    let currentIndex = allFindingsList.findIndex(item =>
        item.file === currentFile &&
        (item.f.line - 1 === currentPos.line)
    );

    if (direction === 'next') {
        if (currentIndex === -1) {
            // Find first finding AFTER current cursor
            currentIndex = allFindingsList.findIndex(item =>
                files.indexOf(item.file) > files.indexOf(currentFile) ||
                (item.file === currentFile && (item.f.line - 1 > currentPos.line))
            );
            if (currentIndex === -1) currentIndex = 0; // Wrap to start
        } else {
            currentIndex = (currentIndex + 1) % allFindingsList.length;
        }
    } else {
        if (currentIndex === -1) {
            // Find first finding BEFORE current cursor
            for (let i = allFindingsList.length - 1; i >= 0; i--) {
                const item = allFindingsList[i];
                if (files.indexOf(item.file) < files.indexOf(currentFile) ||
                    (item.file === currentFile && (item.f.line - 1 < currentPos.line))) {
                    currentIndex = i;
                    break;
                }
            }
            if (currentIndex === -1) currentIndex = allFindingsList.length - 1; // Wrap to end
        } else {
            currentIndex = (currentIndex - 1 + allFindingsList.length) % allFindingsList.length;
        }
    }

    const target = allFindingsList[currentIndex];
    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(target.file));
    const targetEditor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);

    const newPos = new vscode.Position(target.f.line - 1, target.f.col_offset);
    targetEditor.selection = new vscode.Selection(newPos, newPos);
    targetEditor.revealRange(new vscode.Range(newPos, newPos), vscode.TextEditorRevealType.InCenter);
    applyDecorations(targetEditor);
}

// ============================================================================
// AUTO-SCAN LOGIC for requirements.txt
// ============================================================================

async function autoScanRequirementsTxt(document: vscode.TextDocument, context: vscode.ExtensionContext) {
    const text = document.getText();
    const lines = text.split(/\r?\n/);
    const packagesToScan: { pkgName: string; lineIndex: number }[] = [];

    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        if (!line || line.startsWith('#')) { continue; }
        if (line.includes('# MalPack: SAFE') || line.includes('# MalPack: DANGER')) { continue; }

        const match = line.match(/^([a-zA-Z0-9_\-\.]+)/);
        if (match && match[1]) {
            const pkgName = match[1];
            packagesToScan.push({ pkgName, lineIndex: i });
        }
    }

    if (packagesToScan.length === 0) { return; }

    const method: DetectionMethod = vscode.workspace.getConfiguration('malpack').get<DetectionMethod>('defaultMethod') || 'rule_based';
    const apiUrl = getApiUrl();

    for (const { pkgName, lineIndex } of packagesToScan) {
        let verdict = 'SAFE';
        try {
            const isMalicious = await performHeadlessScan(pkgName, method, apiUrl, context);
            verdict = isMalicious ? 'DANGER' : 'SAFE';
        } catch (err) {
            console.error(`Failed to headless scan ${pkgName}`, err);
            continue;
        }

        const edit = new vscode.WorkspaceEdit();
        const lineText = document.lineAt(lineIndex).text;
        const currentLineText = document.lineAt(lineIndex).text;
        if (currentLineText === lineText) {
            const pos = new vscode.Position(lineIndex, lineText.length);
            edit.insert(document.uri, pos, ` \t# MalPack: ${verdict}`);
            await vscode.workspace.applyEdit(edit);
            await document.save();
        }
    }
}

async function performHeadlessScan(pkgName: string, method: DetectionMethod, apiUrl: string, context: vscode.ExtensionContext): Promise<boolean> {
    let isMalicious = false;
    const extractRoot = context.globalStorageUri.fsPath;
    const scanDir = path.join(extractRoot, `malpack_auto_${Date.now()}_${pkgName}`);

    outputChannel.appendLine(`[MalPack Auto-Scanner] Scanning '${pkgName}' in background...`);

    try {
        fs.mkdirSync(scanDir, { recursive: true });
        const downloadDir = path.join(scanDir, 'download');
        fs.mkdirSync(downloadDir, { recursive: true });
        const extractDir = path.join(scanDir, 'source');
        fs.mkdirSync(extractDir, { recursive: true });

        const res = await axios.get(`https://pypi.org/pypi/${pkgName}/json`);
        const releases = res.data.urls;
        if (!releases || releases.length === 0) {
            throw new Error(`No downloadable files found for ${pkgName} on PyPI.`);
        }

        let target = releases.find((r: any) => r.url.endsWith('.whl'));
        if (!target) target = releases.find((r: any) => r.url.endsWith('.tar.gz') || r.url.endsWith('.zip'));
        if (!target) throw new Error(`No suitable archive found for ${pkgName} on PyPI.`);

        const archivePath = path.join(downloadDir, target.filename);
        const writer = fs.createWriteStream(archivePath);
        const downloadStream = await axios.get(target.url, { responseType: 'stream' });
        downloadStream.data.pipe(writer);

        await new Promise((resolve, reject) => {
            writer.on('finish', resolve);
            writer.on('error', reject);
        });

        if (archivePath.endsWith('.whl') || archivePath.endsWith('.zip')) {
            const AdmZip = require('adm-zip');
            const zip = new AdmZip(archivePath);
            zip.extractAllTo(extractDir, true);
        } else if (archivePath.endsWith('.tar.gz')) {
            const tar = require('tar');
            await tar.x({ file: archivePath, cwd: extractDir });
        } else {
            throw new Error("Unsupported archive format.");
        }

        if (method === 'llm') {
            const pyFiles: Array<{ file_path: string; content: string; is_base64: boolean }> = [];
            function collect(dir: string) {
                for (const entry of fs.readdirSync(dir)) {
                    const full = path.join(dir, entry);
                    if (fs.statSync(full).isDirectory()) collect(full);
                    else if (entry.endsWith('.py')) {
                        pyFiles.push({
                            file_path: full.replace(extractDir, '').substring(1),
                            content: Buffer.from(fs.readFileSync(full, 'utf-8')).toString('base64'),
                            is_base64: true
                        });
                    }
                }
            }
            collect(extractDir);
            const llmRes = await axios.post(`${apiUrl}/llm_based_check`, { package_name: pkgName, files: pyFiles });
            isMalicious = llmRes.data.verdict === 'MALICIOUS';
        } else {
            const allFileResults: FileFindings[] = [];
            const checkEndpoint = method === 'semgrep' ? `${apiUrl}/semgrep_check/check` : `${apiUrl}/rule_based_check/check`;

            const allFiles: string[] = [];
            function collectAll(dir: string) {
                for (const file of fs.readdirSync(dir)) {
                    const filePath = path.join(dir, file);
                    if (fs.statSync(filePath).isDirectory()) collectAll(filePath);
                    else if (file.endsWith('.py') || file.endsWith('.json') || file.endsWith('.js')) {
                        allFiles.push(filePath);
                    }
                }
            }
            collectAll(extractDir);

            const headlessLimit = createLimit(10);
            const headlessTasks = allFiles.map(filePath => headlessLimit(async () => {
                try {
                    const content = fs.readFileSync(filePath, 'utf-8');
                    const res = await axios.post(checkEndpoint, {
                        file_path: filePath.replace(extractDir, '').substring(1),
                        content: Buffer.from(content).toString('base64'),
                        is_base64: true
                    });
                    allFileResults.push(res.data);
                } catch (e) {
                }
            }));
            await Promise.all(headlessTasks);

            const summaryRes = await axios.post(`${apiUrl}/scan/summary`, { findings_data: allFileResults });
            isMalicious = summaryRes.data.verdict === 'MALICIOUS';
        }

    } finally {
        if (fs.existsSync(scanDir)) {
            try { fs.rmSync(scanDir, { recursive: true, force: true }); } catch (e) { }
        }
    }

    return isMalicious;
}

// ============================================================================
// CODELENS PROVIDER for In-Code Navigation
// ============================================================================

class MalPackCodeLensProvider implements vscode.CodeLensProvider {
    private _onDidChangeCodeLenses: vscode.EventEmitter<void> = new vscode.EventEmitter<void>();
    public readonly onDidChangeCodeLenses: vscode.Event<void> = this._onDidChangeCodeLenses.event;

    constructor() { }

    public refresh() {
        this._onDidChangeCodeLenses.fire();
    }

    public provideCodeLenses(document: vscode.TextDocument, token: vscode.CancellationToken): vscode.CodeLens[] {
        const lenses: vscode.CodeLens[] = [];
        const filePath = document.uri.fsPath;

        // Find all findings for this file across all packages
        for (const pkgMap of findingsMap.values()) {
            const fileFindings = pkgMap.get(filePath);
            if (!fileFindings) continue;

            let filtered = fileFindings;
            if (currentRuleFilter) {
                filtered = fileFindings.filter(f => f.rule_id === currentRuleFilter);
            }

            // We want one set of << >> per line that has findings
            const uniqueLines = new Set(filtered.map(f => f.line));
            for (const lineNum of uniqueLines) {
                const range = new vscode.Range(lineNum - 1, 0, lineNum - 1, 0);

                lenses.push(new vscode.CodeLens(range, {
                    title: "<< prev",
                    command: "malpack.prevFinding"
                }));
                lenses.push(new vscode.CodeLens(range, {
                    title: "next >>",
                    command: "malpack.nextFinding"
                }));
            }
        }

        return lenses;
    }
}