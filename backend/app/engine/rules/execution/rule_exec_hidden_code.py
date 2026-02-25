import ast

def check(node, visitor):
    """
    Rule ID: EXEC_HIDDEN_CODE_STRING
    Description: Detects pattern of decoding a string and immediately executing it.
    Example: exec(base64.b64decode(...))
    Severity: CRITICAL
    """
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name == 'exec' or func_name == 'eval':
            if node.args:
                arg0 = node.args[0]
                # Check if argument is a call to decode
                if isinstance(arg0, ast.Call):
                    inner_func = _get_func_name(arg0, visitor.aliases)
                    if inner_func and ('decode' in inner_func or 'unhexlify' in inner_func or 'decompress' in inner_func):
                         return {
                            "id": "EXEC_HIDDEN_CODE_STRING",
                            "message": f"Execution of decoded/hidden code detected: {func_name}({inner_func}(...))",
                            "severity": "CRITICAL"
                        }
                        
                # Check if argument is a call to join on a list (often used to assemble code)
                # exec("".join(...))
                if isinstance(arg0, ast.Call):
                    if isinstance(arg0.func, ast.Attribute) and arg0.func.attr == 'join':
                         return {
                            "id": "EXEC_HIDDEN_CODE_STRING",
                            "message": f"Execution of joined string detected: {func_name}(join(...))",
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
