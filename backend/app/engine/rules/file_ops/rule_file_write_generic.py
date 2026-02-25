import ast

def check(node, visitor):
    """
    Rule ID: FILE_WRITE_GENERIC
    Description: Detects generic file write operations.
    Severity: INFO
    """
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        # open('file', 'w')
        if func_name == 'open':
             # Check mode
             if len(node.args) >= 2:
                mode = node.args[1]
                if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
                    if 'w' in mode.value or 'a' in mode.value or '+' in mode.value:
                        return {
                            "id": "FILE_WRITE_GENERIC",
                            "message": "File write operation detected.",
                            "severity": "INFO"
                        }
             
             # Check keywords
             for keyword in node.keywords:
                 if keyword.arg == 'mode':
                      if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                           if 'w' in keyword.value.value or 'a' in keyword.value.value or '+' in keyword.value.value:
                                return {
                                    "id": "FILE_WRITE_GENERIC",
                                    "message": "File write operation detected.",
                                    "severity": "INFO"
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
