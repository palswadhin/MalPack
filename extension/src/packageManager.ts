import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as util from 'util';
import AdmZip from 'adm-zip'; // <--- FIXED IMPORT

const exec = util.promisify(cp.exec);

export async function downloadAndExtract(pkgName: string): Promise<string> {
    const tmpDir = path.join(os.tmpdir(), 'malpack_staging', pkgName);
    
    // Clean previous
    if (fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.mkdirSync(tmpDir, { recursive: true });

    // 1. Download Wheel/Source (only download, no install)
    // We use --no-deps to only scan the specific package requested
    await exec(`pip download ${pkgName} --dest "${tmpDir}" --no-deps`);

    // 2. Find the archive
    const files = fs.readdirSync(tmpDir);
    const archive = files.find(f => f.endsWith('.whl') || f.endsWith('.zip') || f.endsWith('.tar.gz'));

    if (!archive) throw new Error("Download failed or no archive found");

    const archivePath = path.join(tmpDir, archive);
    const extractPath = path.join(tmpDir, 'extracted');

    // 3. Extract (Simple implementation for .whl/zip)
    // Note: .whl is just a zip file
    if (archive.endsWith('.whl') || archive.endsWith('.zip')) {
        const zip = new AdmZip(archivePath);
        zip.extractAllTo(extractPath, true);
    } else {
        // Fallback for tar.gz if needed (omitted for brevity)
        throw new Error("Only .whl and .zip supported for this demo");
    }

    return extractPath;
}