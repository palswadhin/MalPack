import ast

def check(node, visitor):
    """
    Rule: Detect downloading of payloads/executables.
    Addresses: code_netops_download_payload, code_netops_download_executable
    """
    targets = {
        'requests.get', 'requests.post', 'urllib.request.urlretrieve',
        'urllib.request.urlopen', 'http.client.HTTPConnection', 'wget.download'
    }
    
    func_name = _get_func_name(node, visitor.aliases)
    
    if func_name and (func_name in targets or ('.' in func_name and func_name.split('.')[-1] in ['get', 'post', 'urlretrieve', 'urlopen'])):
        # Refine: Check if the URL points to an executable extension
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            url = node.args[0].value.lower()
            if any(url.endswith(ext) for ext in ['.exe', '.sh', '.elf', '.dll', '.bat', '.ps1']):
                 return {"id": "NET-001", "message": f"Suspicious File Download Detected ({url}). Potential dropper.", "severity": "CRITICAL"}
        
        # General warning for network request in setup.py context (would need context tracking)
        # For now, just a warning if it looks like a file download
        if 'urlretrieve' in func_name or 'wget' in func_name:
             return {"id": "NET-001", "message": "File Download function called. Verify if necessary.", "severity": "WARNING"}

    return None

def _get_func_name(node, alias_map):
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            if module in alias_map:
                module = alias_map[module]
            return f"{module}.{node.func.attr}"
    elif isinstance(node.func, ast.Name):
        func_id = node.func.id
        if func_id in alias_map:
            return alias_map[func_id]
        return func_id
    return None
