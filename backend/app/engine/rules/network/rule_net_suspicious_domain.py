import ast
import re

def check(node, visitor):
    """
    Rule ID: NETWORK_SUSPICIOUS_DOMAIN
    Description: Detects connections to suspicious TLDs, IP addresses, or paste sites.
    Severity: WARNING
    """
    # Regex to extract URLs from strings in arguments
    url_regex = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    
    suspicious_tlds = {'.xyz', '.top', '.pw', '.club', '.info', '.ru', '.cn', '.tk', '.ga', '.cf', '.gq', '.ml'}
    suspicious_services = {'pastebin.com', 'hastebin.com', 'discordapp.com/api/webhooks', 'discord.com/api/webhooks', 'ngrok.io', 'webhook.site'}
    
    # We check string constants in Call arguments
    if isinstance(node, ast.Call):
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                check_res = _analyze_url(arg.value, suspicious_tlds, suspicious_services)
                if check_res:
                    return check_res
                    
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                check_res = _analyze_url(keyword.value.value, suspicious_tlds, suspicious_services)
                if check_res:
                    return check_res
                    
    return None

def _analyze_url(text, tlds, services):
    if 'http' in text:
        # Simple extraction
        for part in text.split():
            if part.startswith(('http://', 'https://')):
                # Check suspicious services
                for service in services:
                    if service in part:
                         return {
                            "id": "NETWORK_SUSPICIOUS_DOMAIN",
                            "message": f"Connection to suspicious service detected: {service}",
                            "severity": "WARNING"
                        }
                
                # Check TLDs
                for tld in tlds:
                    domain = part.split('/')[2] if len(part.split('/')) > 2 else part
                    if domain.endswith(tld):
                         return {
                            "id": "NETWORK_SUSPICIOUS_DOMAIN",
                            "message": f"Connection to suspicious TLD detected: {tld}",
                            "severity": "WARNING"
                        }
                        
                # Check raw IP
                domain = part.split('/')[2] if len(part.split('/')) > 2 else part
                # Remove port
                domain = domain.split(':')[0]
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                     return {
                        "id": "NETWORK_SUSPICIOUS_DOMAIN",
                        "message": f"Connection to raw IP address detected: {domain}",
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
