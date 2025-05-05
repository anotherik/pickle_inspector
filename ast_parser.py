# pickle_inspector/ast_parser.py

import ast

def parse_file_to_ast(filepath):
    """
    Parse the file at `filepath` into an AST.
    Returns a tuple: (filename, AST node, source code string)
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source_code = f.read()
        tree = ast.parse(source_code, filename=filepath)
        return (filepath, tree, source_code)
    except Exception as e:
        print(f"[!] Failed to parse {filepath}: {e}")
        return (filepath, None, None)

