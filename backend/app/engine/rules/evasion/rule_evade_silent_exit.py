import ast

def check(node, visitor):
    """
    Rule ID: EVADE_SILENT_EXIT
    Description: Detects attempts to silently exit the process, potentially disrupting analysis or sandboxes.
    Severity: WARNING
    """
    targets = {'sys.exit', 'os._exit', 'builtins.exit', 'builtins.quit'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        # Mapping `exit` and `quit` usage
        if func_name == 'exit' or func_name == 'quit':
             return {
                "id": "EVADE_SILENT_EXIT",
                "message": f"Direct call to {func_name}(). Can abort installation/execution.",
                "severity": "WARNING"
            }
            
        if func_name in targets:
             return {
                "id": "EVADE_SILENT_EXIT",
                "message": f"System exit detected via {func_name}().",
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
