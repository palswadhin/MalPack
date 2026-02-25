"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.MalPackSidebarProvider = void 0;
const vscode = __importStar(require("vscode"));
class MalPackSidebarProvider {
    constructor(_extensionUri) {
        this._extensionUri = _extensionUri;
    }
    resolveWebviewView(webviewView, context, _token) {
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
    _getHtmlForWebview() {
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
exports.MalPackSidebarProvider = MalPackSidebarProvider;
MalPackSidebarProvider.viewType = 'malpack.sidebarView';
//# sourceMappingURL=SidebarProvider.js.map