import ast

def check(node, visitor):
    """
    Rule ID: NETWORK_DNS_TUNNELING
    Description: Detects potential DNS tunneling (data exfiltration via DNS).
    Severity: WARNING
    """
    targets = {'socket.gethostbyname', 'socket.getaddrinfo', 'dns.resolver.query'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
            # Check if argument looks like a variable rather than a string literal
            # Loop + variable hostname lookup = possible tunneling/scanning
            
            if node.args:
                arg0 = node.args[0]
                if not isinstance(arg0, ast.Constant):
                     return {
                        "id": "NETWORK_DNS_TUNNELING",
                        "message": f"Potential DNS tunneling/scanning: Dynamic hostname lookup via {func_name}.",
                        "severity": "INFO" # High false positive rate likely, so INFO
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
