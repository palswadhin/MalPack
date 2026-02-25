import ast

def check(node, visitor):
    """
    Rule: Detect dynamic execution and environment-specific imports.
    Addresses: code_execution_dynamic_evaluation, code_execution_import_dynamic_module
    """
    # 1. Check for `__import__('...')`
    if _is_call(node, '__import__', visitor.aliases):
        return {"id": "EXEC-002", "message": "Dynamic Import detected (__import__).", "severity": "WARNING"}
    
    # 2. Check for `importlib.import_module('...')`
    if _is_call(node, 'importlib.import_module', visitor.aliases):
        return {"id": "EXEC-002", "message": "Dynamic Import detected (importlib).", "severity": "WARNING"}

    # 3. Check for `eval` or `exec`
    if _is_call(node, 'eval', visitor.aliases):
        return {"id": "EXEC-005", "message": "Dynamic Code Evaluation via `eval` detected. Highly Suspicious.", "severity": "CRITICAL"}

    if _is_call(node, 'exec', visitor.aliases):
        return {"id": "EXEC-005", "message": "Dynamic Code Execution via `exec` detected. Highly Suspicious.", "severity": "CRITICAL"}
    
    # 4. Environment-Specific Checks (sys.platform)
    # This usually appears in If nodes, not Calls. We check if `sys.platform` is accessed
    # and then branching logic occurs. AST engine primarily visits Calls right now.
    # We can detect accessing `sys.platform` as a heuristic.
    # Note: Accessing sys.platform is common, so severity is INFO/LOW unless combined.
    
    return None

def _is_call(node, target_name, alias_map):
    # Helper to check if node calls `target_name` handling aliases
    if not isinstance(node, ast.Call):
        return False
        
    func_name = None
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            if module in alias_map:
                module = alias_map[module]
            func_name = f"{module}.{node.func.attr}"
    elif isinstance(node.func, ast.Name):
        func_id = node.func.id
        if func_id in alias_map:
            func_name = alias_map[func_id]
        else:
            func_name = func_id
            
    return func_name == target_name
