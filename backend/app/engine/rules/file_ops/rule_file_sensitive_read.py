import ast

def check(node, visitor):
    """
    Rule: Detect reading/writing of sensitive files.
    Addresses: code_fileops_read_sensitive_files, code_fileops_write_to_sensitive_location
    """
    targets = {
        '/etc/shadow', '/etc/passwd', '/etc/hosts', 
        '~/.ssh/id_rsa', '~/.aws/credentials', '.bashrc', '.zshrc',
        '/etc/cron.d', '/etc/init.d'
    }
    
    # Check open calls
    func_name = _get_func_name(node, visitor.aliases)
    
    if func_name == 'open':
        # Check arguments
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            path = node.args[0].value
            if any(t in path for t in targets):
                return {"id": "FILE-001", "message": f"Sensitive File Access detected: {path}", "severity": "CRITICAL"}
    
    return None

def _get_func_name(node, alias_map):
    if isinstance(node.func, ast.Name):
        func_id = node.func.id
        if func_id in alias_map:
            return alias_map[func_id]
        return func_id
    return None
