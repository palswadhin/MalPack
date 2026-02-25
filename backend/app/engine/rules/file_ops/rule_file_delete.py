import ast

def check(node, visitor):
    """
    Rule ID: FILE_DELETE_DESTRUCTIVE
    Description: Detects destructive file deletion (os.remove, shutil.rmtree).
    Severity: CRITICAL
    """
    targets = {'os.remove', 'os.unlink', 'shutil.rmtree', 'os.rmdir'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
            # Check argument for context
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    path = arg0.value
                    
                    if path == '/' or path == 'C:\\' or path == '.':
                         return {
                            "id": "FILE_DELETE_DESTRUCTIVE",
                            "message": f"Destructive file deletion detected on root/cwd: {path}",
                            "severity": "CRITICAL"
                        }
                    
                    # Self deletion check: __file__
                elif isinstance(arg0, ast.Name) and arg0.id == '__file__':
                      return {
                            "id": "FILE_DELETE_DESTRUCTIVE",
                            "message": "Self-deletion detected (removing __file__).",
                            "severity": "WARNING"
                        }
                        
            return {
                "id": "FILE_DELETE_DESTRUCTIVE",
                "message": f"File deletion detected via {func_name}.",
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
