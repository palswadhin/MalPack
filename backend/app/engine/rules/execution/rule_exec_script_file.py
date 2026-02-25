import ast
import os

def check(node, visitor):
    """
    Rule ID: EXEC_SCRIPT_FILE
    Description: Detects execution of shell script files (.sh, .bat, .ps1).
    Severity: CRITICAL
    """
    exec_funcs = {'subprocess.Popen', 'subprocess.run', 'subprocess.call', 'os.system'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in exec_funcs:
            # Check args for .sh, .bat, .ps1
            cmd_str = None
            
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    cmd_str = arg0.value
                elif isinstance(arg0, ast.List) and arg0.elts:
                    # e.g. ['bash', 'script.sh']
                    for elt in arg0.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            if elt.value.lower().endswith(('.sh', '.bat', '.ps1', '.cmd')):
                                cmd_str = elt.value
                                break
            
            if cmd_str:
                ext = os.path.splitext(cmd_str)[1].lower()
                if ext in {'.sh', '.bat', '.ps1', '.cmd'}:
                    return {
                        "id": "EXEC_SCRIPT_FILE",
                        "message": f"Execution of script file detected: {cmd_str}",
                        "severity": "CRITICAL"
                    }
                    
                # Check for 'bash -c' or 'sh -c' patterns
                if 'bash' in cmd_str or 'sh' in cmd_str or 'powershell' in cmd_str:
                     return {
                        "id": "EXEC_SCRIPT_FILE",
                        "message": f"Shell invocation detected: {cmd_str}",
                        "severity": "WARNING"
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
