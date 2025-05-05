# pickle_inspector/utils.py

import ast

def extract_full_func_name(func_node, aliases):
    """
    Resolve the full function name from an AST Call node.

    Handles:
        - Direct calls like 'pickle.load'
        - Aliased calls like 'pkl.load'
        - Bare calls like 'load' if imported directly
        - Chained calls like 'os.path.join'
    """
    if isinstance(func_node, ast.Attribute):
        parts = []
        curr = func_node
        while isinstance(curr, ast.Attribute):
            parts.insert(0, curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            base = aliases.get(curr.id, curr.id)
            parts.insert(0, base)
            return ".".join(parts)

    elif isinstance(func_node, ast.Name):
        return aliases.get(func_node.id, func_node.id)

    return ""
