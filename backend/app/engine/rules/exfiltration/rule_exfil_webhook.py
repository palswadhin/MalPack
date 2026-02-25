import ast

def check(node, visitor):
    """
    Rule ID: EXFIL_WEBHOOK_UPLOAD
    Description: Detects usage of Discord or Slack webhooks for exfiltration.
    Severity: CRITICAL
    """
    
    if isinstance(node, ast.Call):
        # Scan arguments for webhook URLs
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if 'discord.com/api/webhooks' in arg.value or 'hooks.slack.com' in arg.value:
                     return {
                        "id": "EXFIL_WEBHOOK_UPLOAD",
                        "message": "Discord/Slack webhook detected. Common exfiltration method.",
                        "severity": "CRITICAL"
                    }
                    
        for keyword in node.keywords:
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                if 'discord.com/api/webhooks' in keyword.value.value or 'hooks.slack.com' in keyword.value.value:
                     return {
                        "id": "EXFIL_WEBHOOK_UPLOAD",
                        "message": "Discord/Slack webhook detected. Common exfiltration method.",
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
