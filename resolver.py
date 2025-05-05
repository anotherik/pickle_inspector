# pickle_inspector/resolver.py

import ast
from utils import extract_full_func_name
from sources_and_sinks import SINKS

def resolve_function_call(node, file_index, project_index):
    """
    Given an ast.Call node, resolve it to the actual FunctionInfo (if available).
    Returns: (func_name, FunctionInfo or None)
    """
    func_name = extract_full_func_name(node.func, file_index.imports)

    # If it's a known sink, we don't resolve further — handled separately
    if func_name in SINKS:
        return (func_name, None)

    # Try to resolve fully qualified names like 'helper.get_input'
    parts = func_name.split('.')
    if len(parts) == 2:
        alias, func = parts
        # Check if 'alias' is imported and maps to a module in our project
        module_name = file_index.imports.get(alias)
        if module_name:
            # Look for a function named 'func' in the corresponding file
            for f in project_index.files.values():
                if f.filename.endswith(f"{module_name.replace('.', '/')}.py"):
                    return (func_name, f.functions.get(func))

    # If it's a local call (e.g., 'get_input')
    elif len(parts) == 1:
        local_func = file_index.functions.get(func_name)
        if local_func:
            return (func_name, local_func)

        # Could be imported directly: 'from helper import get_input'
        full_ref = file_index.imports.get(func_name)
        if full_ref:
            _, func = full_ref.rsplit(".", 1)
            for f in project_index.files.values():
                if func in f.functions:
                    return (func_name, f.functions[func])

    return (func_name, None)

