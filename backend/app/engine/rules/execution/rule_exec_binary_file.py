import ast
import os

def check(node, visitor):
    """
    Rule ID: EXEC_BINARY_FILE
    Description: Detects attempts to execute binary files or change their permissions.
    Severity: CRITICAL
    """
    exec_funcs = {'os.chmod', 'os.startfile', 'subprocess.Popen', 'subprocess.run', 'subprocess.call'}
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name == 'os.chmod':
            # Check for chmod +x (stat.S_IEXEC or 0o755/0o777)
            # This is heuristics based
            if len(node.args) == 2:
                mode = node.args[1]
                if isinstance(mode, ast.Constant):
                    # Check for executable bits (odd numbers in octal roughly)
                    # 0o755 = 493, 0o700 = 448
                    val = mode.value
                    if isinstance(val, int) and (val & 0o100): # S_IXUSR
                         return {
                            "id": "EXEC_BINARY_FILE",
                            "message": "Making file executable via os.chmod detected.",
                            "severity": "WARNING"
                        }
        
        if func_name in exec_funcs:
            # Check first argument for binary extensions
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    ext = os.path.splitext(arg0.value)[1].lower()
                    if ext in {'.exe', '.elf', '.bin', '.dll', '.so'}:
                        return {
                            "id": "EXEC_BINARY_FILE",
                            "message": f"Execution of binary file detected: {arg0.value}",
                            "severity": "CRITICAL"
                        }
                # Check for list arguments e.g. ['./mybin']
                elif isinstance(arg0, ast.List) and arg0.elts:
                    first_elt = arg0.elts[0]
                    if isinstance(first_elt, ast.Constant) and isinstance(first_elt.value, str):
                        ext = os.path.splitext(first_elt.value)[1].lower()
                        if ext in {'.exe', '.elf', '.bin', '.dll', '.so'}:
                             return {
                                "id": "EXEC_BINARY_FILE",
                                "message": f"Execution of binary file detected: {first_elt.value}",
                                "severity": "CRITICAL"
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
