# pickle_inspector/ast_parser.py

import ast

try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

def print_colored(message, style="white"):
    """Print a message with color if rich is available."""
    if RICH_AVAILABLE:
        console = Console()
        console.print(message, style=style)
    else:
        print(message)

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
        print_colored(f"[!] Failed to parse {filepath}: {e}", "bold red")
        return (filepath, None, None)

