import ast

def check(node, visitor):
    """
    Rule ID: METADATA_DEPENDENCY_ANOMALY
    Description: Detects suspicious dependencies (e.g. direct URL references, known bad packages).
    Severity: WARNING
    """
    targets = {'setuptools.setup', 'distutils.core.setup'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets or (func_name and func_name.endswith('.setup')):
             deps = []
             for keyword in node.keywords:
                 if keyword.arg == 'install_requires':
                     if isinstance(keyword.value, ast.List):
                         for elt in keyword.value.elts:
                             if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                 deps.append(elt.value)
             
             for dep in deps:
                 # Check for URL dependencies (often used for dependency confusion or unverified code)
                 if 'http://' in dep or 'https://' in dep or 'git+' in dep:
                      return {
                        "id": "METADATA_DEPENDENCY_ANOMALY",
                        "message": f"Direct URL dependency detected: {dep}. Risk of unverified code.",
                        "severity": "WARNING"
                    }
                 
                 # Check for known malicious packages (placeholder list)
                 # In real system this would query a DB
                 
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
