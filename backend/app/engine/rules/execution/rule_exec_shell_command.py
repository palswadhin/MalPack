import ast

def check(node, visitor):
    """
    Rule ID: EXEC_SHELL_COMMAND
    Description: Detects execution of shell commands.
    Severity: CRITICAL
    """
    shell_funcs = {
        'os.system', 'os.popen', 'subprocess.call', 'subprocess.check_call', 
        'subprocess.check_output', 'subprocess.run', 'subprocess.Popen',
        'commands.getoutput', 'commands.getstatusoutput'
    }
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        # Check for shell=True in subprocess
        if func_name in shell_funcs:
            shell_true = False
            
            # Check keywords for shell=True
            for keyword in node.keywords:
                if keyword.arg == 'shell':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        shell_true = True
            
            # os.system is always shell
            if func_name == 'os.system' or func_name == 'os.popen':
                shell_true = True
                
            if shell_true:
                return {
                    "id": "EXEC_SHELL_COMMAND",
                    "message": f"Shell command execution detected via {func_name}. This allows command injection.",
                    "severity": "CRITICAL"
                }
            elif func_name.startswith('subprocess'):
                 return {
                    "id": "EXEC_SHELL_COMMAND",
                    "message": f"Subprocess execution via {func_name}. Verify arguments.",
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
