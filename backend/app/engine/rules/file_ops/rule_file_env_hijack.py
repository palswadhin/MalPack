import ast

def check(node, visitor):
    """
    Rule ID: FILE_ENV_PATH_HIJACK
    Description: Detects modification of the PATH environment variable.
    Severity: CRITICAL
    """
    
    # Needs to check Assign nodes, but engine only checks Call nodes.
    # However, can detect os.putenv('PATH', ...)
    # Or os.environ['PATH'] = ... (Assign node) -> not supported by current engine visitor loop.
    
    # We will check 'os.environ.update', 'os.putenv'
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name == 'os.putenv':
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str) and arg0.value == 'PATH':
                     return {
                        "id": "FILE_ENV_PATH_HIJACK",
                        "message": "PATH environment variable modification detected (os.putenv).",
                        "severity": "CRITICAL"
                    }
                    
        if func_name == 'os.environ.update':
            # Check keywords or dict arg
             return {
                "id": "FILE_ENV_PATH_HIJACK",
                "message": "Environment variable modification detected (os.environ.update). Check if PATH is modified.",
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
