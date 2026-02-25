import ast

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, rule_set):
        self.rule_set = rule_set
        self.findings = []
        # Track aliases: {'sp': 'subprocess', 'system': 'os.system', ...}
        self.aliases = {} 
        self.imports = set()

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.add(alias.name)
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                self.aliases[alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports.add(full_name)
            if alias.asname:
                self.aliases[alias.asname] = full_name
            else:
                self.aliases[alias.name] = full_name
        self.generic_visit(node)

    def visit_Call(self, node):
        # Pass the visitor instance (self) to the rule function so it can access aliases
        for rule_func in self.rule_set:
            result = rule_func(node, self)
            if result:
                self.findings.append({
                    "line": node.lineno,
                    "col_offset": getattr(node, "col_offset", 0),
                    "end_col_offset": getattr(node, "end_col_offset", 0),
                    "message": result.get('message'),
                    "severity": result.get('severity', 'WARNING'),
                    "rule_id": result.get('id')
                })
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Basic tracking of local aliases like `s = subprocess`
        # This is complex in static analysis, but we can do simple cases
        if isinstance(node.value, ast.Name) and node.value.id in self.aliases:
            # Propagate alias
            unknown_source = self.aliases[node.value.id]
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.aliases[target.id] = unknown_source
        self.generic_visit(node)

def run_ast_scan(content: str, rule_set: list):
    try:
        tree = ast.parse(content)
        visitor = SecurityVisitor(rule_set)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError:
        return []