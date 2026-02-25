import ast
try:
    from app.engine.metadata_analyzer import check_typosquatting, TOP_PACKAGES
except ImportError:
    # Fallback for testing or different path structure
    pass

def check(node, visitor):
    """
    Rule ID: METADATA_TYPOSQUATTING
    Description: Detects typosquatting of popular packages.
    Severity: CRITICAL
    """
    targets = {'setuptools.setup', 'distutils.core.setup'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets or (func_name and func_name.endswith('.setup')):
             # Extract 'name' argument
             package_name = None
             for keyword in node.keywords:
                 if keyword.arg == 'name':
                     if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                         package_name = keyword.value.value
             
             if package_name:
                 # Check typosquatting
                 # Need to ensure import worked, otherwise skip
                 if 'check_typosquatting' in globals():
                     result = check_typosquatting(package_name, TOP_PACKAGES)
                     if result['is_typosquatting']:
                         return {
                            "id": "METADATA_TYPOSQUATTING",
                            "message": f"Typosquatting detected: '{package_name}' is similar to {result['similar_to']}.",
                            "severity": result['severity']
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
