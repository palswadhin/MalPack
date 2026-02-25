import ast

def check(node, visitor):
    """
    Rule ID: NETWORK_REVERSE_SHELL
    Description: Detects pattern of connecting a socket to a subprocess (reverse shell).
    Severity: CRITICAL
    """
    # Detects: subprocess.call(["/bin/sh", "-i"], stdin=s.fileno(), ...)
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name == 'subprocess.call' or func_name == 'subprocess.Popen':
            # Check for redirecting stdin/stdout/stderr to a file descriptor
            # Usually looks like stdin=s.fileno()
            
            suspicious_args = False
            for keyword in node.keywords:
                if keyword.arg in {'stdin', 'stdout', 'stderr'}:
                    # Check if value is a call to .fileno()
                    if isinstance(keyword.value, ast.Call):
                         if isinstance(keyword.value.func, ast.Attribute) and keyword.value.func.attr == 'fileno':
                             suspicious_args = True
            
            if suspicious_args:
                return {
                    "id": "NETWORK_REVERSE_SHELL",
                    "message": "Reverse shell pattern detected: subprocess with socket file descriptor.",
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
