# pickle_inspector/utils.py

import ast
import re
import os
from pathlib import Path

def sanitize_filename(filename):
    """
    Safely sanitize a filename to prevent path traversal attacks.
    Uses Python's pathlib for safe path handling.
    """
    if not filename:
        return "unnamed"
    
    try:
        # Use pathlib to safely handle the path - this prevents path traversal
        path = Path(filename)
        safe_name = path.name
        
        # Limit length
        if len(safe_name) > 100:
            safe_name = safe_name[:100]
        
        # Ensure it's not empty
        if not safe_name:
            safe_name = "unnamed"
        
        return safe_name
        
    except Exception:
        # Fallback to safe default if anything goes wrong
        return "unnamed"

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

def get_attribute_path(node):
    """
    Gets the full attribute path from an AST node.
    """
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        base = get_attribute_path(node.value)
        return f"{base}.{node.attr}"
    else:
        return "unknown"
