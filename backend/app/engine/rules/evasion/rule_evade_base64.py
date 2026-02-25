import ast

def check(node, visitor):
    """
    Rule ID: EVADE_BASE64_DECODE
    Description: Detects Base64 decoding, often used to hide payloads.
    Severity: WARNING
    """
    targets = {'base64.b64decode', 'base64.urlsafe_b64decode', 'binascii.a2b_base64'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
            return {
                "id": "EVADE_BASE64_DECODE",
                "message": f"Base64 decoding detected via {func_name}. Check decoded content.",
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
