import ast

def check(node, visitor):
    """
    Rule ID: EVADE_ENCRYPTED_PAYLOAD
    Description: Detects usage of encryption libraries (cryptography, PyCrypto) which may hide payloads.
    Severity: INFO
    """
    # Focusing on decryption or key handling primarily
    targets = {
        'cryptography.fernet.Fernet', 
        'Crypto.Cipher.AES.new', 
        'Crypto.Cipher.DES.new',
        'nacl.secret.SecretBox'
    }
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
            return {
                "id": "EVADE_ENCRYPTED_PAYLOAD",
                "message": f"Encryption library usage detected: {func_name}. Malware usage: Decrypting dropped payloads.",
                "severity": "INFO" # Valid use cases exist
            }
            
        # Detect 'decrypt' method calls on anything (heuristic)
        if hasattr(node, 'func') and isinstance(node.func, ast.Attribute) and node.func.attr == 'decrypt':
             return {
                "id": "EVADE_ENCRYPTED_PAYLOAD",
                "message": "Decryption attempt detected (method '.decrypt()').",
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
