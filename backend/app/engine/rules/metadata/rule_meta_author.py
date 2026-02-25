import ast
try:
    from app.engine.metadata_analyzer import validate_author_info
except ImportError:
    pass

def check(node, visitor):
    """
    Rule ID: METADATA_AUTHOR_SUSPICIOUS
    Description: Detects suspicious author names or emails (disposable emails, generic names).
    Severity: WARNING
    """
    targets = {'setuptools.setup', 'distutils.core.setup'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets or (func_name and func_name.endswith('.setup')):
             author = ""
             email = ""
             
             for keyword in node.keywords:
                 if keyword.arg == 'author':
                     if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                         author = keyword.value.value
                 elif keyword.arg == 'author_email':
                     if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                         email = keyword.value.value
             
             # If neither is present, that's also suspicious?
             # But let's check if present
             if (author or email) and 'validate_author_info' in globals():
                 result = validate_author_info(author, email)
                 if result['is_suspicious']:
                     issues = ", ".join(result['issues'])
                     return {
                        "id": "METADATA_AUTHOR_SUSPICIOUS",
                        "message": f"Suspicious author metadata detected: {issues}",
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
