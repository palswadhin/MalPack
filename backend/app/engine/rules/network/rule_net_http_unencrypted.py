import ast

def check(node, visitor):
    """
    Rule ID: NETWORK_HTTP_UNENCRYPTED
    Description: Detects use of unencrypted HTTP protocol.
    Severity: WARNING
    """
    
    if isinstance(node, ast.Call):
        # Scan string arguments for http://
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if 'http://' in arg.value:
                     return {
                        "id": "NETWORK_HTTP_UNENCRYPTED",
                        "message": "Unencrypted HTTP URL detected. Use HTTPS.",
                        "severity": "WARNING"
                    }
                    
        for keyword in node.keywords:
             if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                if 'http://' in keyword.value.value:
                     return {
                        "id": "NETWORK_HTTP_UNENCRYPTED",
                        "message": "Unencrypted HTTP URL detected. Use HTTPS.",
                        "severity": "WARNING"
                    }
                    
        func_name = _get_func_name(node, visitor.aliases)
        if func_name == 'http.client.HTTPConnection':
             return {
                "id": "NETWORK_HTTP_UNENCRYPTED",
                "message": "Unencrypted HTTPConnection usage detected.",
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
