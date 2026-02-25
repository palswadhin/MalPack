import ast

def check(node, visitor=None):
    """
    Rule 01: Detect subprocess usage with shell=True
    """
    # 1. Check if it is a Call node
    if not isinstance(node, ast.Call):
        return None

    # 2. Check function name (subprocess.Popen, call, run)
    is_subprocess = False
    if isinstance(node.func, ast.Attribute):
        # We look for module 'subprocess' (id) and method (attr)
        # Note: In robust AST, you'd check imports. Here we check the attribute chain.
        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
            if node.func.attr in ['Popen', 'call', 'run', 'check_output']:
                is_subprocess = True
    
    if not is_subprocess:
        return None

    # 3. Check arguments for shell=True
    for keyword in node.keywords:
        if keyword.arg == 'shell':
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                return "CRITICAL: subprocess called with shell=True. Risk of Command Injection."

    return None