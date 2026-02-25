from fastapi import APIRouter, Body
from typing import List, Dict, Any
import ast
import os
import glob
import importlib

# Engines
from app.engine.ast_engine import run_ast_scan
from app.engine.regex_engine import run_regex_scan

# Dynamic Rule Loading
def load_ast_rules(directory: str):
    """
    Dynamically loads all `check` functions from python files in the directory.
    """
    rules = []
    base_path = "app/engine/rules/" + directory
    
    # Assuming standard structure relative to app root
    # We need to list files in `backend/app/engine/rules/{directory}`
    # but import them as `app.engine.rules.{directory}.{filename}`
    
    # Resolve absolute path for listing
    abs_path = os.path.join(os.path.dirname(__file__), "../../../engine/rules", directory)
    print(f"Loading rules from: {abs_path}")
    
    if not os.path.exists(abs_path):
        return rules

    for filename in os.listdir(abs_path):
        if filename.endswith(".py") and not filename.startswith("__"):
            module_name = filename[:-3]
            full_module_path = f"app.engine.rules.{directory}.{module_name}"
            try:
                mod = importlib.import_module(full_module_path)
                if hasattr(mod, 'check'):
                    rules.append(mod.check)
            except Exception as e:
                print(f"Error loading rule {full_module_path}: {e}")
    return rules

# Load rules once on startup (or lazy load)
# For simplicity, loading them globally here.
AST_RULES = []
categories = ['execution', 'network', 'file_ops', 'evasion', 'exfiltration', 'metadata']
for cat in categories:
    AST_RULES.extend(load_ast_rules(cat))

# Regex Patterns (Move to a separate config file in production)
REGEX_PATTERNS = [
    {
        "id": "NET-003",
        "pattern": r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
        "message": "IPv4 Address detected. Suspicious if hardcoded.",
        "severity": "INFO"
    },
    {
        "id": "EVASION-006",
        "pattern": r"(\\x[0-9a-fA-F]{2}){10,}",
        "message": "Long sequence of Hex escapes detected. Possible shellcode or obfuscation.",
        "severity": "WARNING"
    }
    # Add more robust regexes later
]

router = APIRouter()

@router.post("/check")
async def scan_package(
    file_path: str = Body(..., embed=True),
    content: str = Body(..., embed=True),
    is_base64: bool = Body(False, embed=True)
):
    import base64
    if is_base64:
        content = base64.b64decode(content).decode('utf-8')
    findings = []
    
    # 1. AST Scan (Python only)
    if file_path.endswith('.py'):
        ast_results = run_ast_scan(content, AST_RULES)
        findings.extend(ast_results)

    # 2. Regex Scan (All files)
    # Compile regexes first
    compiled_patterns = []
    import re
    for p in REGEX_PATTERNS:
        compiled_patterns.append({
            "id": p['id'],
            "pattern": re.compile(p['pattern']),
            "message": p['message'],
            "severity": p['severity']
        })
        
    regex_results = run_regex_scan(content, compiled_patterns)
    findings.extend(regex_results)

    # 3. Aggregation & Formatting
    is_danger = any(f['severity'] in ['CRITICAL', 'HIGH'] for f in findings)
    
    # Enhanced response format
    return {
        "file": file_path,
        "status": "DANGER" if is_danger else "SAFE",
        "findings": findings,  # Detailed list for tooltips/boxes
        "violations": [f"Line {f['line']}: {f['message']}" for f in findings],
        "stats": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f['severity'] == 'CRITICAL'),
            "high": sum(1 for f in findings if f['severity'] == 'HIGH'),
            "warning": sum(1 for f in findings if f['severity'] == 'WARNING'),
            "info": sum(1 for f in findings if f['severity'] == 'INFO')
        }
    }

@router.post("/summary")
async def scan_summary(
    findings_data: List[Dict[str, Any]] = Body(..., embed=True)
):
    """
    Aggregate findings from multiple files and return high-level summary
    without exposing file paths or line numbers.
    """
    all_findings = []
    file_count = 0
    
    for file_data in findings_data:
        file_count += 1
        if 'findings' in file_data:
            all_findings.extend(file_data['findings'])
    
    # Group by rule_id and severity
    grouped = {}
    for finding in all_findings:
        rule_id = finding.get('rule_id', 'UNKNOWN')
        if rule_id not in grouped:
            grouped[rule_id] = {
                'rule_id': rule_id,
                'message': finding.get('message', ''),
                'severity': finding.get('severity', 'INFO'),
                'count': 0
            }
        grouped[rule_id]['count'] += 1
    
    # Sort by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'WARNING': 2, 'INFO': 3}
    summary_list = sorted(
        grouped.values(),
        key=lambda x: (severity_order.get(x['severity'], 99), -x['count'])
    )
    
    is_malicious = any(f['severity'] in ['CRITICAL', 'HIGH'] for f in all_findings)
    
    return {
        "verdict": "MALICIOUS" if is_malicious else "BENIGN",
        "total_issues": len(all_findings),
        "files_scanned": file_count,
        "summary": summary_list,
        "stats": {
            "critical": sum(1 for f in all_findings if f['severity'] == 'CRITICAL'),
            "high": sum(1 for f in all_findings if f['severity'] == 'HIGH'),
            "warning": sum(1 for f in all_findings if f['severity'] == 'WARNING'),
            "info": sum(1 for f in all_findings if f['severity'] == 'INFO')
        }
    }
