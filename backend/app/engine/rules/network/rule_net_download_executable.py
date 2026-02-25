import ast
import os

def check(node, visitor):
    """
    Rule ID: NETWORK_DOWNLOAD_EXECUTABLE
    Description: Detects downloading of files with executable extensions.
    Severity: CRITICAL
    """
    targets = {'urllib.request.urlretrieve', 'requests.get'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
            url_arg = None
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    url_arg = arg0.value
            
            if url_arg:
                # Check extension in URL (naive but effective)
                # Remove query params
                path = url_arg.split('?')[0]
                ext = os.path.splitext(path)[1].lower()
                if ext in {'.exe', '.sh', '.elf', '.dll', '.so', '.bat', '.ps1'}:
                    return {
                        "id": "NETWORK_DOWNLOAD_EXECUTABLE",
                        "message": f"Downloading executable file detected: {url_arg}",
                        "severity": "CRITICAL"
                    }

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
