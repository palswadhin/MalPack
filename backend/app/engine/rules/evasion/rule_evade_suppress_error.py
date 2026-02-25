import ast

def check(node, visitor):
    """
    Rule ID: EVADE_SUPPRESS_ERROR
    Description: Detects broad error suppression which hides malicious activity failures.
    Severity: WARNING
    """
    # 1. Check for contextlib.suppress
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        if func_name == 'contextlib.suppress':
            return {
                "id": "EVADE_SUPPRESS_ERROR",
                "message": "Explicit error suppression detected (contextlib.suppress).",
                "severity": "WARNING"
            }

    # 2. Check for bare except or catch-all Exception (requires modification to AST engine to pass Try nodes?)
    # For now, we only stick to Call nodes as per current architecture.
    # If the architecture supported it, we'd check Try nodes here.
    
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
