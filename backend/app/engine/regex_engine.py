import re

def run_regex_scan(content: str, patterns: list):
    """
    Scans the content using a list of regex patterns.
    Each pattern in the list should be a dictionary with keys:
    - pattern: compiled regex object
    - message: warning message
    - id: rule id
    - severity: 'CRITICAL', 'WARNING', 'INFO'
    """
    findings = []
    lines = content.splitlines()

    for rule in patterns:
        matches = rule['pattern'].finditer(content)
        for match in matches:
            # Find line number
            start_index = match.start()
            line_no = content[:start_index].count('\n') + 1
            
            # Context snippet (e.g. the matching line)
            match_str = match.group()
            
            findings.append({
                "rule_id": rule['id'],
                "line": line_no,
                "message": rule['message'],
                "severity": rule.get('severity', 'WARNING'),
                "snippet": match_str[:100] # Truncate if too long
            })
            
    return findings
