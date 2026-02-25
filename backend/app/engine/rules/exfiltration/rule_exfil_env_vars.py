import ast

def check(node, visitor):
    """
    Rule ID: EXFIL_ENV_CREDENTIALS
    Description: Detects sending environment variables (potentially credentials) over network.
    Severity: CRITICAL
    """
    net_targets = {
        'requests.get', 'requests.post', 'requests.put', 
        'urllib.request.urlopen', 'http.client.HTTPConnection.request'
    }
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in net_targets:
            # Check if arguments involve os.environ
            
            # Helper to recursively check for os.environ
            if _has_environ_access(node):
                 return {
                    "id": "EXFIL_ENV_CREDENTIALS",
                    "message": f"Environment variable exfiltration detected via {func_name}. Sending env vars over network.",
                    "severity": "CRITICAL"
                }

    return None

def _has_environ_access(node):
    """Recursively check for os.environ or os.getenv usage in AST node."""
    if isinstance(node, ast.Name) and node.id == 'environ': # ambiguous but suspicious
        return True
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id == 'os' and node.attr == 'environ':
            return True
        if node.attr == 'environ':
             return True
             
    if isinstance(node, ast.Call):
        # check os.getenv
        if isinstance(node.func, ast.Attribute):
             if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os' and node.func.attr == 'getenv':
                 return True
        
        # Recurse into args
        for arg in node.args:
            if _has_environ_access(arg):
                return True
        for k in node.keywords:
            if _has_environ_access(k.value):
                return True
                
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            if _has_environ_access(elt):
                return True
                
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if k and _has_environ_access(k): return True
            if _has_environ_access(v): return True
            
    return False

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
