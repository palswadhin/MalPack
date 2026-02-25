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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.downloadAndExtract = downloadAndExtract;
const cp = __importStar(require("child_process"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const util = __importStar(require("util"));
const adm_zip_1 = __importDefault(require("adm-zip")); // <--- FIXED IMPORT
const exec = util.promisify(cp.exec);
async function downloadAndExtract(pkgName) {
    const tmpDir = path.join(os.tmpdir(), 'malpack_staging', pkgName);
    // Clean previous
    if (fs.existsSync(tmpDir))
        fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.mkdirSync(tmpDir, { recursive: true });
    // 1. Download Wheel/Source (only download, no install)
    // We use --no-deps to only scan the specific package requested
    await exec(`pip download ${pkgName} --dest "${tmpDir}" --no-deps`);
    // 2. Find the archive
    const files = fs.readdirSync(tmpDir);
    const archive = files.find(f => f.endsWith('.whl') || f.endsWith('.zip') || f.endsWith('.tar.gz'));
    if (!archive)
        throw new Error("Download failed or no archive found");
    const archivePath = path.join(tmpDir, archive);
    const extractPath = path.join(tmpDir, 'extracted');
    // 3. Extract (Simple implementation for .whl/zip)
    // Note: .whl is just a zip file
    if (archive.endsWith('.whl') || archive.endsWith('.zip')) {
        const zip = new adm_zip_1.default(archivePath);
        zip.extractAllTo(extractPath, true);
    }
    else {
        // Fallback for tar.gz if needed (omitted for brevity)
        throw new Error("Only .whl and .zip supported for this demo");
    }
    return extractPath;
}
//# sourceMappingURL=packageManager.js.map