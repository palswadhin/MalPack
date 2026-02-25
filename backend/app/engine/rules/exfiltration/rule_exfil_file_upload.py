import ast

def check(node, visitor):
    """
    Rule ID: EXFIL_FILE_UPLOAD
    Description: Detects file uploads, often used to exfiltrate data.
    Severity: WARNING
    """
    targets = {'requests.post', 'requests.put'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
            # Check for 'files' argument in requests
            for keyword in node.keywords:
                if keyword.arg == 'files':
                    return {
                        "id": "EXFIL_FILE_UPLOAD",
                        "message": "File upload detected (requests.post/put with files=...). Possible exfiltration.",
                        "severity": "WARNING"
                    }
            
            # Check for 'data' argument if it looks variable based (not constant string)
            # This is weaker signal but worth checking if name suggests sensitive data
            # Hard to do with simple AST
            
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
