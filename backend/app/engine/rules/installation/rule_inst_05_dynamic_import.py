import ast

def check(node, visitor):
    """
    Rule ID: INSTALL_DYNAMIC_IMPORT
    Description: Detects dynamic module imports from potentially tainted sources.
    
    importlib.import_module() with runtime-constructed names can import
    modules downloaded at runtime, bypassing static analysis.
    
    Detection:
    - import lib.import_module(variable)
    - __import__(variable)
    
    Research: Evasion technique documented in academic malware studies
    """
    func_name = _get_func_name(node, visitor.aliases)
    
    # Check for dynamic import functions
    dynamic_import_funcs = {
        'importlib.import_module',
        '__import__'
    }
    
    if func_name in dynamic_import_funcs:
        # Check if argument is a variable (not a string literal)
        if node.args:
            first_arg = node.args[0]
            
            # If argument is NOT a constant string, it's dynamic
            if not isinstance(first_arg, ast.Constant):
                return {
                    "id": "INSTALL_DYNAMIC_IMPORT",
                    "message": f"Dynamic module import detected: {func_name}(variable). "
                              f"Module name is computed at runtime, may bypass static analysis.",
                    "severity": "WARNING"
                }
            
            # Even string literals can be suspicious in certain contexts
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                module_name = first_arg.value
                # Check for obviously suspicious patterns
                if any(keyword in module_name.lower() for keyword in ['download', 'fetch', 'temp', 'tmp']):
                    return {
                        "id": "INSTALL_DYNAMIC_IMPORT",
                        "message": f"Suspicious dynamic import: {func_name}('{module_name}'). "
                                  f"Module name suggests temporary/downloaded code.",
                        "severity": "WARNING"
                    }
    
    return None

def _get_func_name(node, alias_map):
    """Helper to resolve function name."""
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
