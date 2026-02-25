import ast

def check(node, visitor):
    """
    Rule ID: FILE_WRITE_SENSITIVE_LOCATION
    Description: Detects attempts to write to sensitive system directories.
    Severity: CRITICAL
    """
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name == 'open':
            # Check filename (arg 0)
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    path = arg0.value
                    if _is_sensitive(path):
                        # Verify it is a write
                        is_write = False
                        if len(node.args) >= 2:
                             mode = node.args[1]
                             if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and ('w' in mode.value or 'a' in mode.value or '+' in mode.value):
                                 is_write = True
                        for keyword in node.keywords:
                             if keyword.arg == 'mode':
                                  if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str) and ('w' in keyword.value.value or 'a' in keyword.value.value or '+' in keyword.value.value):
                                      is_write = True
                                      
                        if is_write:
                             return {
                                "id": "FILE_WRITE_SENSITIVE_LOCATION",
                                "message": f"Writing to sensitive file location detected: {path}",
                                "severity": "CRITICAL"
                            }
                            
    return None

def _is_sensitive(path):
    sensitive_paths = {
        '/etc', '/var/run', '/var/log', '.ssh', '.bashrc', '.profile', 
        '/boot', '/proc', '/sys', '/root'
    }
    for sp in sensitive_paths:
        if isinstance(path, str) and (path.startswith(sp) or sp in path):
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
