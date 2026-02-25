import ast

def check(node, visitor):
    """
    Rule ID: EVADE_CODE_OBFUSCATION
    Description: Detects obfuscation patterns like dynamic attribute access.
    Severity: WARNING
    """
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        # 1. getattr(obj, "string") - often used to hide function names
        if func_name == 'getattr':
             # Check if second arg is a string literal that looks suspicious or constructed
             if len(node.args) >= 2:
                attr_arg = node.args[1]
                
                # If it's a constant string of a dangerous function, flag it
                if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                    if attr_arg.value in {'system', 'popen', 'run', 'call', 'eval', 'exec', 'spawn'}:
                        return {
                            "id": "EVADE_CODE_OBFUSCATION",
                            "message": f"Obfuscated call detected: getattr(..., '{attr_arg.value}').",
                            "severity": "CRITICAL"
                        }
                
                # If it's a binary operation (string concatenation), high likely obfuscation: getattr(os, 'sys' + 'tem')
                if isinstance(attr_arg, ast.BinOp):
                      return {
                            "id": "EVADE_CODE_OBFUSCATION",
                            "message": "Obfuscated attribute access (calculated string).",
                            "severity": "WARNING"
                        }

        # 2. vars()[string], globals()[string], locals()[string]
        # This requires Subscript node visiting, but maybe we can catch the Call to globals()/locals()/vars()
        # and see if it's used? Current visitor only calls check(node) for Call nodes.
        # So we can't easily check subscript usage of the result unless we change visitor.
        
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
