import ast

def check(node, visitor):
    """
    Rule: Detect Reverse Shell patterns.
    Addresses: code_netops_establish_reverse_shell
    """
    # 1. socket.connect((IP, PORT)) + subprocess.call/Popen
    # This is hard to detect via single Call node visit.
    # However, we can detect specific calls that are suspicious:
    # socket.connect with IP address
    # subprocess.call(["/bin/sh", "-i"])
    
    # Check for socket.connect
    func_name = _get_func_name(node, visitor.aliases)
    
    if func_name == 'socket.socket':
        # Just creating a socket is suspicious in a library package unless it's a known network lib
        return {"id": "NET-002", "message": "Socket creation detected. Verify network activity.", "severity": "INFO"}

    if func_name == 'pty.spawn':
        # pty.spawn("/bin/bash") is a common shell stabiliser
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            arg = node.args[0].value
            if "/bin/sh" in arg or "/bin/bash" in arg:
                return {"id": "NET-002", "message": "PTY Spawn /bin/bash detected. High probability of Reverse Shell.", "severity": "CRITICAL"}

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
