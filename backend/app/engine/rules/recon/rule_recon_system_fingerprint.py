import ast

def check(node, visitor):
    """
    Rule ID: RECON_SYSTEM_FINGERPRINT
    Description: Detects attempts to fingerprint the system (platform checks).
    Severity: INFO
    """
    targets = {'platform.system', 'platform.release', 'platform.version', 'sys.platform', 'os.uname'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
             return {
                "id": "RECON_SYSTEM_FINGERPRINT",
                "message": f"System fingerprinting detected via {func_name}. Malware checks environment before execution.",
                "severity": "INFO"
            }
            
    # sys.platform access (Attribute)
    # Require Assign or If check usually. 
    # Current engine is Call only.
    
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
