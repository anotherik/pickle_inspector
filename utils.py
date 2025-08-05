# pickle_inspector/utils.py

import ast

def match_source(call_name, sources):
    """
    Check if the given function name or attribute path matches any known source.
    This helps catch patterns like request.files['file'], request.get_json, etc.
    """
    if call_name in sources:
        return True

    # Try fuzzy match for dotted attributes
    parts = call_name.split(".")
    for i in range(len(parts), 0, -1):
        partial = ".".join(parts[:i])
        if partial in sources:
            return True
    return False

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
