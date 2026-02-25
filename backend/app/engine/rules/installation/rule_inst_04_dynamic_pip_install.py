import ast

def check(node, visitor):
    """
    Rule ID: INSTALL_DYNAMIC_PACKAGE
    Description: Detects runtime package installation (pip install during execution).
    
    Malicious packages may install additional unlisted dependencies to avoid
    detection during initial analysis.
    
    Detection:
    - subprocess/os.system calls with 'pip install' or 'pip3 install'
    - npm install, apt install, etc.
    
    Research: Common supply chain attack pattern
    """
    func_name = _get_func_name(node, visitor.aliases)
    
    # Check for package manager invocations
    package_managers = {
        'subprocess.Popen', 'subprocess.run', 'subprocess.call', 'subprocess.check_output',
        'os.system', 'os.popen'
    }
    
    if func_name not in package_managers:
        return None
    
    # Check arguments for package installation commands
    command_str = _extract_command_string(node)
    
    if command_str:
        suspicious_commands = [
            'pip install', 'pip3 install', 'python -m pip install',
            'npm install', 'yarn add',
            'apt install', 'apt-get install',
            'yum install', 'dnf install'
        ]
        
        command_lower = command_str.lower()
        for cmd in suspicious_commands:
            if cmd in command_lower:
                return {
                    "id": "INSTALL_DYNAMIC_PACKAGE",
                    "message": f"Dynamic package installation detected: '{cmd}' via {func_name}(). "
                              f"Package may install unlisted dependencies to evade analysis.",
                    "severity": "CRITICAL"
                }
    
    return None

def _get_func_name(node, alias_map):
    """Helper to resolve function name."""
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

def _extract_command_string(node):
    """Extract command string from subprocess/os.system call."""
    # Check first positional argument (command)
    if node.args and len(node.args) > 0:
        arg = node.args[0]
        
        # String literal
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
        
        # List of strings (subprocess with list)
        if isinstance(arg, ast.List):
            parts = []
            for elt in arg.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    parts.append(elt.value)
            return ' '.join(parts)
    
    return None
