import ast

def check(node, visitor):
    """
    Rule: Detect accessing environment variables (often for keys/secrets).
    Addresses: code_exfiltration_data, code_fileops_modify_system_environment
    """
    func_name = _get_func_name(node, visitor.aliases)

    if func_name == 'os.environ.get' or func_name == 'os.getenv':
        # Check arguments for sensitive keywords
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            key = node.args[0].value.upper()
            if any(s in key for s in ['KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'AWS', 'AUTH']):
                return {"id": "EXFIL-002", "message": f"Trying to access sensitive Environment Variable ({key}).", "severity": "CRITICAL"}

    return None

def _get_func_name(node, alias_map):
    parts = []
    current = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    
    if isinstance(current, ast.Name):
        name = current.id
        if name in alias_map:
            name = alias_map[name]
        parts.append(name)
    
    return ".".join(reversed(parts))
