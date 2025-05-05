# pickle_inspector/indexer.py

import ast
import shutil
import tempfile
import subprocess
from dataclasses import dataclass, field
from ast_parser import parse_file_to_ast
import os
import sys

@dataclass
class FunctionInfo:
    name: str
    node: ast.FunctionDef
    filename: str

@dataclass
class ImportInfo:
    alias: str
    real_name: str

@dataclass
class FileIndex:
    filename: str
    tree: ast.AST
    source: str
    functions: dict = field(default_factory=dict)
    imports: dict = field(default_factory=dict)

@dataclass
class ProjectIndex:
    files: dict = field(default_factory=dict)
    function_map: dict = field(default_factory=dict)

def convert_py2_file(original_path, temp_dir):
    """
    Converts a Python 2 file to Python 3 syntax using 2to3.
    Returns the path to the converted file.
    """
    temp_path = os.path.join(temp_dir, os.path.basename(original_path))
    shutil.copy(original_path, temp_path)

    try:
        subprocess.run(
            [shutil.which("python3"), "-m", "lib2to3", "-w", "-n", temp_path],
            capture_output=True,
            check=True
        )
        return temp_path
    except subprocess.CalledProcessError:
        print(f"[!] Failed to convert {original_path} with 2to3")
        return None

def normalize_indentation(filepath):
    """
    Attempts to fix indentation errors using autopep8.
    Modifies the file in-place.
    """
    try:
        subprocess.run(
            ["autopep8", "--in-place", "--aggressive", filepath],
            capture_output=True,
            check=True
        )
    except Exception:
        print(f"[!] Warning: autopep8 failed to format {filepath}")

def detect_py2_print(source_code):
    """
    Detects old-style print statements like: print "hello"
    """
    return any(
        line.strip().startswith("print ") and not line.strip().startswith("print(")
        for line in source_code.splitlines()
    )

def index_project(filepaths, py2_mode=False, skip_errors=False):
    """
    Build a global project index by parsing and analyzing each file.
    Supports optional py2 compatibility and error skipping.
    Avoids modifying original files — always parses from a temporary copy.
    """
    project_index = ProjectIndex()

    with tempfile.TemporaryDirectory() as temp_dir:
        for original_path in filepaths:
            try:
                # Load original source
                with open(original_path, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()

                temp_path = os.path.join(temp_dir, os.path.basename(original_path))
                with open(temp_path, "w", encoding="utf-8") as f:
                    f.write(code)

                # Convert Python 2 to 3 if needed
                if detect_py2_print(code):
                    if not py2_mode:
                        print(f"[!] Python 2 syntax detected in {original_path}. Use --py2-support to scan it.")
                        continue
                    subprocess.run(
                        [shutil.which("python3"), "-m", "lib2to3", "-w", "-n", temp_path],
                        capture_output=True,
                        check=True
                    )

                # Parse AST from the temp file
                filename, tree, source = parse_file_to_ast(temp_path)
                if not tree:
                    if skip_errors:
                        print(f"[!] Skipped {original_path}: unable to parse.")
                        continue
                    else:
                        print(f"[!] Error: Unable to parse {original_path}.")
                        print("    Use --skip-errors to skip this file and continue.")
                        sys.exit(1)

                # Index with the real path instead of temp
                file_index = FileIndex(
                    filename=original_path,  # keep original path for reporting
                    tree=tree,
                    source=source
                )

                visitor = IndexingVisitor(file_index)
                visitor.visit(tree)

                project_index.files[original_path] = file_index
                for fname, finfo in file_index.functions.items():
                    project_index.function_map.setdefault(fname, []).append(finfo)

            except Exception as e:
                if skip_errors:
                    print(f"[!] Skipped {original_path}: {e}")
                    continue
                else:
                    raise e

    return project_index

class IndexingVisitor(ast.NodeVisitor):
    """
    Visits nodes to extract functions and imports from a file.
    """
    def __init__(self, file_index):
        self.file_index = file_index

    def visit_Import(self, node):
        for alias in node.names:
            real_name = alias.name
            as_name = alias.asname or alias.name
            self.file_index.imports[as_name] = real_name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        if module:
            for alias in node.names:
                real_name = f"{module}.{alias.name}"
                as_name = alias.asname or alias.name
                self.file_index.imports[as_name] = real_name
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        func_info = FunctionInfo(name=node.name, node=node, filename=self.file_index.filename)
        self.file_index.functions[node.name] = func_info
        self.generic_visit(node)
