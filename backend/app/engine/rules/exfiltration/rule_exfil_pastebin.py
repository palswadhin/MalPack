import ast

def check(node, visitor):
    """
    Rule ID: EXFIL_PASTEBIN_UPLOAD
    Description: Detects uploads to Pastebin or similar services.
    Severity: WARNING
    """
    
    if isinstance(node, ast.Call):
        # Look for pastebin URLs in network calls
         func_name = _get_func_name(node, visitor.aliases)
         
         # If it's a network call
         if func_name and ('requests' in func_name or 'urllib' in func_name or 'http' in func_name):
             for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if 'pastebin.com' in arg.value or 'hastebin.com' in arg.value:
                         return {
                            "id": "EXFIL_PASTEBIN_UPLOAD",
                            "message": "Connection to Pastebin/Hastebin detected. Possible exfiltration or payload download.",
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
