import ast

def check(node, visitor):
    """
    Rule: Detect Obfuscation (Base64 decoding).
    Addresses: code_evasion_obfuscation, code_evasion_obfuscation_encoding
    """
    targets = {
        'base64.b64decode', 'base64.standard_b64decode', 'base64.urlsafe_b64decode',
        'zlib.decompress', 'binascii.a2b_base64', 'codecs.decode'
    }

    func_name = _get_func_name(node, visitor.aliases)

    if func_name and func_name in targets:
        # Check if the result is immediately passed to eval/exec (Would need parent pointer or improved AST)
        # For now, just a warning on usage.
        return {"id": "OBF-001", "message": f"Obfuscation detected ({func_name}). Verify decoded content.", "severity": "WARNING"}

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
