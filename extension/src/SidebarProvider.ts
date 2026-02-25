import * as vscode from 'vscode';

export class MalPackSidebarProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'malpack.sidebarView';

    private _view?: vscode.WebviewView;

    constructor(private readonly _extensionUri: vscode.Uri) { }

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken,
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        webviewView.webview.html = this._getHtmlForWebview();

        webviewView.webview.onDidReceiveMessage(data => {
            switch (data.command) {
                case 'startScan': {
                    vscode.commands.executeCommand('malpack.install');
                    break;
                }
            }
        });
    }

    private _getHtmlForWebview() {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MalPack</title>
    <style>
        body { font-family: var(--vscode-font-family); padding: 20px; color: var(--vscode-foreground); background-color: var(--vscode-editor-background); text-align: center; }
        .logo { font-size: 64px; margin-bottom: 20px; }
        .title { font-size: 20px; font-weight: bold; margin-bottom: 15px; color: var(--vscode-foreground); }
        .description { font-size: 14px; margin-bottom: 30px; line-height: 1.5; color: var(--vscode-descriptionForeground); }
        .btn { padding: 12px 20px; background-color: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: bold; width: 100%; transition: background-color 0.2s; }
        .btn:hover { background-color: var(--vscode-button-hoverBackground); }
    </style>
</head>
<body>
    <div class="logo">🔍</div>
    <div class="title">MalPack Security</div>
    <div class="description">Analyze Python packages for malicious indicators before installing them to protect your environment.</div>
    <button class="btn" onclick="startScan()">Start New Scan</button>

    <script>
        const vscode = acquireVsCodeApi();
        function startScan() {
            vscode.postMessage({ command: 'startScan' });
        }
    </script>
</body>
</html>`;
    }
}
