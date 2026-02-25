import ast
try:
    from app.engine.metadata_analyzer import validate_description
except ImportError:
    pass

def check(node, visitor):
    """
    Rule ID: METADATA_DESC_EMPTY
    Description: Detects empty or missing package description.
    Severity: WARNING
    """
    targets = {'setuptools.setup', 'distutils.core.setup'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets or (func_name and func_name.endswith('.setup')):
             desc = ""
             name = ""
             has_desc = False
             
             for keyword in node.keywords:
                 if keyword.arg == 'description':
                     has_desc = True
                     if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                         desc = keyword.value.value
                 if keyword.arg == 'name':
                     if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                         name = keyword.value.value
             
             if not has_desc:
                  return {
                    "id": "METADATA_DESC_EMPTY",
                    "message": "Missing package description.",
                    "severity": "WARNING"
                }
             
             if 'validate_description' in globals():
                 result = validate_description(desc, name)
                 if result['is_suspicious']:
                     # We specifically check for empty here
                     if "Empty description" in result['issues']:
                         return {
                            "id": "METADATA_DESC_EMPTY",
                            "message": "Empty package description detected.",
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
