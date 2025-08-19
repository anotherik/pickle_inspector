# pickle_inspector/ast_parser.py

import ast
import warnings

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

import os

def _is_path_within_root(filepath, root):
    """Check if the given filepath is within the root directory."""
    abs_root = os.path.abspath(root)
    abs_path = os.path.abspath(filepath)
    try:
        common = os.path.commonpath([abs_root, abs_path])
    except ValueError:
        # On Windows, if drives differ, commonpath raises ValueError
        return False
    return common == abs_root

def parse_file_to_ast(filepath, verbosity="normal", safe_root=None):
    """
    Parse the file at `filepath` into an AST.
    Returns a tuple: (filename, AST node, source code string)
    """
    if safe_root is None:
        safe_root = os.getcwd()
    if not _is_path_within_root(filepath, safe_root):
        raise Exception(f"Access to file '{filepath}' is not allowed (outside of root directory '{safe_root}').")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source_code = f.read()
        
        # Configure warning suppression based on verbosity
        if verbosity == "quiet":
            # Suppress all warnings in quiet mode
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                tree = ast.parse(source_code, filename=filepath)
        elif verbosity == "normal":
            # In normal mode, suppress common warnings like invalid escape sequences
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=".*invalid escape sequence.*")
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                tree = ast.parse(source_code, filename=filepath)
        else:  # verbose mode
            # Show all warnings
            tree = ast.parse(source_code, filename=filepath)
            
        return (filepath, tree, source_code)
    except Exception as e:
        # Only print parsing errors if not in quiet mode
        if verbosity != "quiet":
            print_colored(f"[!] Failed to parse {filepath}: {e}", "bold red")
        return (filepath, None, None)

