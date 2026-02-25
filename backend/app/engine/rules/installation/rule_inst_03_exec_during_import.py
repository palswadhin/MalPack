import ast

def check(node, visitor):
    """
    Rule ID: INSTALL_IMPORT_EXEC
    Description: Detects malicious code in __init__.py that runs on import.
    
    Attackers place dangerous code in __init__.py so it executes when package
    is simply imported, before user calls any functions.
    
    Detection:
    - Network calls (requests.get/post, urllib)
    - File writes 
    - Subprocess execution
    - At module level (not in functions)
    
    Note: Filename filtering happens in backend scanner
    """
    dangerous_imports_patterns = {
        # Network operations
        'requests.get', 'requests.post', 'requests.put',
        'urllib.request.urlopen', 'urllib.request.urlretrieve', 
        'urllib.request.Request',
        'http.client.HTTPConnection', 'http.client.HTTPSConnection',
        
        # Process execution
        'subprocess.Popen', 'subprocess.run', 'subprocess.call',
        'os.system', 'os.popen',
        
        # File operations (when at import time, suspicious)
        'open',  # Will check context
    }
    
    func_name = _get_func_name(node, visitor.aliases)
    
    if func_name in dangerous_imports_patterns:
        # Special handling for 'open' - only flag if writing
        if func_name == 'open':
            # Check if mode argument suggests writing
            if _is_write_mode(node):
                return {
                    "id": "INSTALL_IMPORT_EXEC",
                    "message": f"File write operation in __init__.py: {func_name}(). "
                              f"Executes on package import.",
                    "severity": "WARNING"
                }
            return None  # Reading is ok
        
        # Network/subprocess in __init__.py is highly suspicious
        severity = "CRITICAL" if func_name.startswith(('requests', 'urllib', 'subprocess', 'os.system')) else "WARNING"
        
        return {
            "id": "INSTALL_IMPORT_EXEC",
            "message": f"Suspicious operation in package import: {func_name}(). "
                      f"This executes automatically when package is imported.",
            "severity": severity
        }
    
    return None

def _get_func_name(node, alias_map):
    """Helper to resolve function name."""
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

def _is_write_mode(node):
    """Check if open() call has write mode."""
    # Check keyword arguments
    for keyword in node.keywords:
        if keyword.arg == 'mode':
            if isinstance(keyword.value, ast.Constant):
                mode = keyword.value.value
                if isinstance(mode, str) and ('w' in mode or 'a' in mode):
                    return True
    
    # Check positional argument (second arg is mode)
    if len(node.args) >= 2:
        mode_arg = node.args[1]
        if isinstance(mode_arg, ast.Constant):
            mode = mode_arg.value
            if isinstance(mode, str) and ('w' in mode or 'a' in mode):
                return True
    
    return False
