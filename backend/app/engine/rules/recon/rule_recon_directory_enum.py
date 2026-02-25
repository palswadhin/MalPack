import ast

def check(node, visitor):
    """
    Rule ID: RECON_DIRECTORY_ENUM
    Description: Detects directory enumeration/listing.
    Severity: WARNING
    """
    targets = {'os.listdir', 'os.walk', 'glob.glob', 'pathlib.Path.iterdir', 'pathlib.Path.glob'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
             return {
                "id": "RECON_DIRECTORY_ENUM",
                "message": f"Directory enumeration detected via {func_name}. Malware often scans for interesting files.",
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
