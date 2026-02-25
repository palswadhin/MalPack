import ast

def check(node, visitor):
    """
    Rule ID: EVADE_ASCII_ART_HIDING
    Description: Detects execution of code stored in types of metadata or docstrings.
    Severity: CRITICAL
    """
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name == 'exec' or func_name == 'eval':
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Name):
                    # exec(__doc__)
                    if arg0.id == '__doc__':
                        return {
                            "id": "EVADE_ASCII_ART_HIDING",
                            "message": "Execution of docstring detected: exec(__doc__).",
                            "severity": "CRITICAL"
                        }
                elif isinstance(arg0, ast.Attribute):
                    # func.__doc__
                    if arg0.attr == '__doc__':
                         return {
                            "id": "EVADE_ASCII_ART_HIDING",
                            "message": "Execution of docstring detected (attr.__doc__).",
                            "severity": "CRITICAL"
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
