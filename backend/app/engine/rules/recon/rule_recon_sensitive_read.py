import ast

def check(node, visitor):
    """
    Rule ID: RECON_SENSITIVE_FILE_READ
    Description: Detects reading of sensitive files (SSH keys, config files, etc.).
    Severity: CRITICAL
    """
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name == 'open':
             # Check filename
             if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    path = arg0.value
                    if _is_sensitive(path):
                        # Check mode - default is 'r'
                        is_read = True
                        if len(node.args) >= 2:
                             mode = node.args[1]
                             if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
                                 if 'w' in mode.value or 'a' in mode.value:
                                     is_read = False
                        
                        for keyword in node.keywords:
                             if keyword.arg == 'mode':
                                  if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                                      if 'w' in keyword.value.value or 'a' in keyword.value.value:
                                           is_read = False

                        if is_read:
                             return {
                                "id": "RECON_SENSITIVE_FILE_READ",
                                "message": f"Reading sensitive file detected: {path}",
                                "severity": "CRITICAL"
                            }
    return None

def _is_sensitive(path):
    sensitive_paths = {
        '/etc/passwd', '/etc/shadow', '.ssh/id_rsa', '.aws/credentials', 
        '.bash_history', 'config.json', 'secrets.yaml', '.env'
    }
    for sp in sensitive_paths:
        if isinstance(path, str) and (path.endswith(sp) or sp in path):
            return True
    return False

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
