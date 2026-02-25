import ast
try:
    from app.engine.metadata_analyzer import check_combosquatting, TOP_PACKAGES
except ImportError:
    pass

def check(node, visitor):
    """
    Rule ID: METADATA_COMBOSQUATTING
    Description: Detects combosquatting (popular name + suffix/prefix).
    Severity: WARNING
    """
    targets = {'setuptools.setup', 'distutils.core.setup'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets or (func_name and func_name.endswith('.setup')):
             package_name = None
             for keyword in node.keywords:
                 if keyword.arg == 'name':
                     if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                         package_name = keyword.value.value
             
             if package_name and 'check_combosquatting' in globals():
                 result = check_combosquatting(package_name, TOP_PACKAGES)
                 if result['is_combosquatting']:
                     return {
                        "id": "METADATA_COMBOSQUATTING",
                        "message": f"Combosquatting detected: '{package_name}' uses popular package '{result['base_package']}'.",
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
