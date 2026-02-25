import ast

def check(node, visitor):
    """
    Rule ID: NETWORK_DOWNLOAD_PAYLOAD
    Description: Detects file downloads which might be second-stage payloads.
    Severity: WARNING
    """
    targets = {
        'urllib.request.urlretrieve', 
        'requests.get', 'requests.post', 
        'http.client.HTTPSConnection.request',
        'aiohttp.ClientSession.get'
    }
    
    if isinstance(node, ast.Call):
        func_name = _get_func_name(node, visitor.aliases)
        
        if func_name in targets:
             # Heuristic: simple flag on any network call in setup context is suspicious (handled by other rules)
             # Here we are detecting generic network usage that looks like a download
             # urlretrieve is a strong indicator of download-to-disk
             if func_name == 'urllib.request.urlretrieve':
                return {
                    "id": "NETWORK_DOWNLOAD_PAYLOAD",
                    "message": f"File download detected via {func_name}. Potential second-stage payload.",
                    "severity": "WARNING"
                }
             
             # For requests, check if content is being written to file? 
             # AST Analysis of data flow is hard here.
             # We will flag generic requests as INFO/WARNING depending on context?
             # Let's keep it specific to 'retrieving' things.
             
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
