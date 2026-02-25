import subprocess, json, tempfile, os

def run_semgrep(content: str, config_path: str):
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.py', delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    try:
        # Runs Semgrep against the temp file
        cmd = ["semgrep", "--config", config_path, "--json", tmp_path]
        res = subprocess.run(cmd, capture_output=True, text=True)
        data = json.loads(res.stdout)
        return [r['extra']['message'] for r in data.get('results', [])]
    finally:
        if os.path.exists(tmp_path): os.remove(tmp_path)