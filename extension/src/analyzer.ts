import * as vscode from 'vscode';
import axios from 'axios';

export async function scanFile(filePath: string, content: string): Promise<string[]> {
    try {
        const config = vscode.workspace.getConfiguration('malpack');
        let baseUrl = config.get<string>('backendUrl', 'https://malpack-backend1.onrender.com');
        if (baseUrl.endsWith('/')) { baseUrl = baseUrl.slice(0, -1); }
        const apiUrl = `${baseUrl}/api/v1/process/check`;

        const response = await axios.post(apiUrl, {
            file_path: filePath,
            content: Buffer.from(content).toString('base64'),
            is_base64: true
        });

        if (response.data.status === 'DANGER') {
            return response.data.violations;
        }
        return [];
    } catch (error) {
        console.error(`Failed to scan ${filePath}`, error);
        return [];
    }
}