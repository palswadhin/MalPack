import ast

def check(node, visitor):
    """
    Rule ID: EVADE_HIDDEN_PROCESS
    Description: Detects attempts to hide processes or change process names.
    Severity: CRITICAL
    """
    targets = {'setproctitle.setproctitle', 'prctl.set_name'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
            return {
                "id": "EVADE_HIDDEN_PROCESS",
                "message": f"Process name spoofing detected via {func_name}. Malware often hides by renaming itself.",
                "severity": "CRITICAL"
            }
            
        # Check for argv manipulation: sys.argv[0] = "name"
        # This is hard to detect perfectly with AST on Call nodes, actually this is an Assign node check.
        # But we can check for library calls that do similar things.
        
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
