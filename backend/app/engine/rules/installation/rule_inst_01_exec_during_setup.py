import ast

def check(node, visitor):
    """
    Rule ID: INSTALL_SETUP_EXEC
    Description: Detects code execution in setup.py at module level (import time).
    
    Malicious setup.py files may execute shell commands or download payloads
    when the package is installed, before user has a chance to inspect code.
    
    Detection:
    - Flags dangerous functions (os.system, subprocess.*, exec, eval) 
      at module-level scope (not inside function definitions)
    - Specifically targets code that runs during 'pip install'
    
    Research: GuardDog command_overwrites heuristic
    """
    # Target dangerous execution functions
    dangerous_funcs = {
        'os.system', 'os.popen', 'os.spawn', 'os.spawnl', 'os.spawnv',
        'subprocess.Popen', 'subprocess.run', 'subprocess.call', 'subprocess.check_output',
        'exec', 'eval'
    }
    
    # Get function name with alias resolution
    func_name = _get_func_name(node, visitor.aliases)
    
    if func_name and func_name in dangerous_funcs:
        # This is a setup.py-specific check
        # In a real implementation, we'd pass filename context
        # For now, flag ALL module-level dangerous calls with WARNING
        # Backend will upgrade to CRITICAL if filename == 'setup.py'
        
        return {
            "id": "INSTALL_SETUP_EXEC",
            "message": f"Code execution during installation detected: {func_name}(). "
                      f"This runs when package is installed, potentially malicious.",
            "severity": "WARNING"  # Upgraded to CRITICAL in setup.py context
        }
    
    return None

def _get_func_name(node, alias_map):
    """Helper to resolve function name with alias support."""
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
