import ast

def check(node, visitor):
    """
    Rule ID: FILE_MODIFY_STARTUP
    Description: Detects modification of startup files for persistence.
    Severity: CRITICAL
    """
    startup_files = {'.bashrc', '.bash_profile', '.zshrc', '.profile', '/etc/rc.local', 'systemd', 'init.d', 'autostart'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name == 'open':
             # Check if opening a startup file for writing
             if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    path = arg0.value
                    if any(s in path for s in startup_files):
                         # Check write mode
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
                                "id": "FILE_MODIFY_STARTUP",
                                "message": f"Persistence attempt detected: Modifying startup file {path}.",
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
