import ast

def check(node, visitor):
    """
    Rule: Detect execution during installation (setup.py hooks).
    Addresses: code_execution_during_installation, overriding_base_install_build
    """
    targets = {'setuptools.setup', 'distutils.core.setup', 'setuptools.command.install', 'distutils.command.install'}
    
    # 1. Check for `setup(...)` calls with cmdclass argument
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        if func_name in targets or (func_name and func_name.endswith('.setup')):
             for keyword in node.keywords:
                if keyword.arg == 'cmdclass':
                    return {"id": "EXEC-001", "message": "Custom install hook detected in setup.py (cmdclass). Possible post-install execution.", "severity": "WARNING"}
    
    # 2. Check for class definitions inheriting from install commands
    # This requires visiting ClassDef nodes, which our visitor handles generically. 
    # But current ast_engine only calls rules on `Call`. 
    # We might need to expand ast_engine to visit ClassDef or handle it here if passed.
    
    return None

def _get_func_name(node, alias_map):
    # (Reuse existing logic or import util)
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
