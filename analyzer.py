# pickle_inspector/analyzer.py

import ast
import time
from sources_and_sinks import SINKS, SOURCES
from resolver import resolve_function_call
from utils import extract_full_func_name
from utils import match_source
from report import print_console_report
from tqdm import tqdm
from collections import Counter

class Finding:
    """
    Represents a single vulnerability finding.
    """
    def __init__(self, sink, source, filename, lineno, risk):
        self.sink = sink
        self.source = source
        self.filename = filename
        self.lineno = lineno
        self.risk = risk

    def __str__(self):
        return (
            f"[!] Insecure deserialization detected\n"
            f"  Sink    : {self.sink}\n"
            f"  Source  : {self.source}\n"
            f"  File    : {self.filename}:{self.lineno}\n"
            f"  Risk    : {self.risk}\n"
        )

def format_elapsed(seconds):
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    minutes = int(seconds // 60)
    remaining = seconds % 60
    return f"{minutes} minute{'s' if minutes > 1 else ''}, {remaining:.2f} seconds"

def analyze_index(project_index, verbose=False):
    findings = []
    start_time = time.time()

    file_items = list(project_index.files.items())
    progress = tqdm(total=len(file_items), desc="Scanning", unit="file")

    for filename, file_index in file_items:
        visitor = SinkVisitor(file_index, project_index)
        visitor.visit(file_index.tree)
        findings.extend(visitor.findings)
        progress.update(1)

    progress.close()

    # Sort findings by risk level
    RISK_LEVELS = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (RISK_LEVELS.get(f.risk, 3), f.filename, f.lineno))

    if verbose:
        for finding in findings:
            print(str(finding))

    print_console_report(findings)
    
    print(f"\n[!] Total Findings: {len(findings)}")
    risk_counts = Counter(f.risk for f in findings)
    print("\n" + "-" * 60)
    print("[!] Risk Summary:")
    for level in ["HIGH", "MEDIUM", "LOW"]:
        if level in risk_counts:
            print(f"    {level}: {risk_counts[level]}")
    print("-" * 60)
    elapsed = time.time() - start_time
    print(f"\n[✓] Scan completed in {format_elapsed(elapsed)}.")

class SinkVisitor(ast.NodeVisitor):
    """
    Visits the AST to detect insecure deserialization sinks,
    tracks tainted file paths written via `save()`, and evaluates risk.
    """
    def __init__(self, file_index, project_index):
        self.file_index = file_index
        self.project_index = project_index
        self.findings = []
        self.tainted_files = set()  # variables tainted via file upload or path written by save()

    def visit_Assign(self, node):
        """
        Mark variables assigned from `request.files[...]` as tainted.
        """
        if isinstance(node.value, ast.Subscript):
            if (
                isinstance(node.value.value, ast.Attribute)
                and node.value.value.attr == "files"
                and isinstance(node.value.value.value, ast.Name)
                and node.value.value.value.id == "request"
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_files.add(target.id)

        self.generic_visit(node)

    def visit_Call(self, node):
        """
        Handles:
        - Calls like `file.save(path)`, where file is tainted → path becomes tainted
        - Deserialization sinks like `pickle.load(...)`
        """
        sink_name = extract_full_func_name(node.func, self.file_index.imports)

        # Taint propagation: file.save(file_path)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "save"
            and isinstance(node.func.value, ast.Name)
            and node.args
        ):
            file_var = node.func.value.id
            if file_var in self.tainted_files:
                if isinstance(node.args[0], ast.Name):
                    self.tainted_files.add(node.args[0].id)

        # Handle sink calls like pickle.load(...)
        if sink_name in SINKS:
            source_node = node.args[0] if node.args else None
            source_label, risk = self.trace_source(source_node)
            finding = Finding(
                sink=sink_name,
                source=source_label,
                filename=self.file_index.filename,
                lineno=node.lineno,
                risk=risk
            )
            self.findings.append(finding)

        self.generic_visit(node)

    def trace_source(self, node, depth=0):
        """
        Trace the origin of data passed to a deserialization sink.
        Now supports:
        - saved tainted files (via .save())
        - direct stream input via request.files['file']
        """
        if depth > 5:
            return ("unknown (recursion limit)", "MEDIUM")

        # Variable reference
        if isinstance(node, ast.Name):
            if node.id in self.tainted_files:
                return (f"{node.id} (tainted from file upload)", "HIGH")

            assign = self.find_assignment(node.id)
            if assign:
                # NEW: Detect direct assignment from request.files[...] here
                if isinstance(assign, ast.Subscript):
                    if (
                        isinstance(assign.value, ast.Attribute)
                        and assign.value.attr == "files"
                        and isinstance(assign.value.value, ast.Name)
                        and assign.value.value.id == "request"
                    ):
                        return (f"{node.id} (direct stream from request.files)", "HIGH")

                label, risk = self.trace_source(assign, depth + 1)
                lineno = getattr(assign, "lineno", "?")
                return (f"{node.id} (assigned at line {lineno}) → {label}", risk)

            return (f"{node.id} (unresolved)", "MEDIUM")

        # Function calls like open(...) or os.path.join(...)
        elif isinstance(node, ast.Call):
            func_name, func_info = resolve_function_call(node, self.file_index, self.project_index)

            if match_source(func_name, SOURCES):
                return (f"{func_name} (call)", "HIGH")

            if func_name == "open" and node.args:
                return self.trace_source(node.args[0], depth + 1)

            if func_name.endswith("os.path.join") and node.args:
                sub_labels = []
                all_safe = True
                for arg in node.args:
                    label, risk = self.trace_source(arg, depth + 1)
                    sub_labels.append(label)
                    if "unknown" in label or "input" in label or "tainted" in label:
                        all_safe = False
                joined_label = "os.path.join(" + ", ".join(sub_labels) + ")"
                return (joined_label, "LOW" if all_safe else "HIGH")

            if func_info:
                for stmt in func_info.node.body:
                    if isinstance(stmt, ast.Return):
                        return self.trace_source(stmt.value, depth + 1)

        elif isinstance(node, ast.Constant):
            return (f"constant '{node.value}'", "LOW")

        elif isinstance(node, ast.Attribute):
            attr = self.get_attribute_path(node)
        
            # Check for known tainted sources like request.form, request.args, etc.
            if attr in [
                "request.form",
                "request.args",
                "request.values",
                "request.json",
                "request.data",
                "request.POST",
                "request.GET"
            ]:
                return (f"{attr} (attribute)", "HIGH")
        
            return (f"{attr} (attribute)", "LOW")

        elif isinstance(node, ast.Subscript):
            return self.trace_source(node.value, depth + 1)

        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_label, _ = self.trace_source(node.left, depth + 1)
            right_label, _ = self.trace_source(node.right, depth + 1)
            return (f"{left_label} + {right_label}", "LOW")

        return ("unknown source", "MEDIUM")

    def find_assignment(self, varname):
        """
        Locates assignments to variables in the file, including:
        - x = ...
        - with open(...) as x
        """
        for stmt in ast.walk(self.file_index.tree):
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == varname:
                        return stmt.value
            elif isinstance(stmt, ast.With):
                for item in stmt.items:
                    if (
                        isinstance(item.optional_vars, ast.Name)
                        and item.optional_vars.id == varname
                        and isinstance(item.context_expr, ast.Call)
                    ):
                        return item.context_expr
        return None

    def get_attribute_path(self, node):
        """
        Resolves an attribute chain like `self.cache_path` to a full string.
        """
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.insert(0, current.id)
        return ".".join(parts)
