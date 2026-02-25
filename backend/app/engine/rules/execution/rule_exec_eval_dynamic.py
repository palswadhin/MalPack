import ast

def check(node, visitor):
    """
    Rule ID: EXEC_EVAL_DYNAMIC
    Description: Detects use of eval(), exec(), or compile() with potentially dynamic content.
    Severity: CRITICAL
    """
    targets = {'eval', 'exec', 'compile'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        if func_name in targets:
            # Check arguments - if string literal, it might be okay (but still suspicious)
            # If variable or complex expression, it's dynamic execution
            
            is_literal = False
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    is_literal = True
            
            severity = "WARNING" if is_literal else "CRITICAL"
            message = f"Dynamic code execution detected using {func_name}()."
            
            if not is_literal:
                message += " Argument appears to be dynamic."
                
            return {
                "id": "EXEC_EVAL_DYNAMIC",
                "message": message,
                "severity": severity
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
