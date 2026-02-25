import ast

def check(node, visitor):
    """
    Rule ID: NETWORK_SSL_DISABLED
    Description: Detects disabling of SSL verification (verify=False).
    Severity: WARNING
    """
    targets = {'requests.get', 'requests.post', 'requests.put', 'requests.patch', 'requests.delete', 'requests.request'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
            for keyword in node.keywords:
                if keyword.arg == 'verify':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                        return {
                            "id": "NETWORK_SSL_DISABLED",
                            "message": "SSL verification disabled (verify=False). Vulnerable to MITM.",
                            "severity": "WARNING"
                        }
                        
        # Check ssl context creation
        if func_name == 'ssl.create_default_context':
             for keyword in node.keywords:
                if keyword.arg == 'check_hostname':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                         return {
                            "id": "NETWORK_SSL_DISABLED",
                            "message": "SSL hostname check disabled.",
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
