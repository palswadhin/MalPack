import ast

def check(node, visitor):
    """
    Rule: Detect subprocess execution, especially with shell=True.
    Addresses: code_execution_shell_command, code_execution_hidden
    """
    alias_map = visitor.aliases
    
    # Target functions: subprocess.Popen, run, call, check_output, os.system, os.popen
    targets = {
        'subprocess.Popen', 'subprocess.run', 'subprocess.call', 'subprocess.check_output',
        'os.system', 'os.popen', 'os.spawn'
    }

    # 1. Resolve function name
    func_name = None
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            # e.g. subprocess.Popen -> module=subprocess, func=Popen
            module = node.func.value.id
            if module in alias_map:
                module = alias_map[module] # resolve alias `import subprocess as sp` -> `sp` becomes `subprocess`
            func_name = f"{module}.{node.func.attr}"
    elif isinstance(node.func, ast.Name):
        # e.g. system("ls") -> id=system
        func_id = node.func.id
        if func_id in alias_map:
            # resolve alias `from os import system` -> `system` becomes `os.system`
            func_name = alias_map[func_id]
        else:
            func_name = func_id

    if not func_name:
        return None

    # 2. Check overlap
    if func_name in targets or any(func_name.endswith(t.split('.')[-1]) for t in targets if '.' in t and func_name.startswith(t.split('.')[0])):
        # Refined check: `subprocess.anything` might be suspicious but let's stick to known executors or broad catch
        pass
    else:
        # Check if it matches exactly known dangerous aliases
        if func_name not in targets:
             return None

    msg = f"Process Execution detected via {func_name}."
    severity = "WARNING"

    # 3. Check arguments (shell=True)
    for keyword in node.keywords:
        if keyword.arg == 'shell':
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                msg = f"CRITICAL: Shell Command Execution detected via {func_name} with shell=True."
                severity = "CRITICAL"
                return {"id": "EXEC-003", "message": msg, "severity": severity}

    # If it is os.system, it is always shell execution
    if func_name == 'os.system':
        msg = f"CRITICAL: Direct Shell Command Execution via os.system."
        severity = "CRITICAL"
        return {"id": "EXEC-003", "message": msg, "severity": severity}

    return {"id": "EXEC-003", "message": msg, "severity": severity}
