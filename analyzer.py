# pickle_inspector/analyzer.py

import ast
import time
from sources_and_sinks import SINKS, SOURCES
from resolver import resolve_function_call
from utils import extract_full_func_name
from utils import match_source
from report import print_console_report, print_verbose_findings, print_summary_with_colors, print_colored
from tqdm import tqdm
from collections import Counter

class Finding:
    """
    Represents a single vulnerability finding.
    """
    def __init__(self, sink, initial_source, flow, filename, lineno, risk, context=None):
        self.sink = sink
        self.initial_source = initial_source
        self.flow = flow
        self.filename = filename
        self.lineno = lineno
        self.risk = risk
        self.context = context or {}

    def __str__(self):
        context_str = ""
        if self.context.get('http_endpoint'):
            context_str = f"\n  Endpoint: {self.context['http_endpoint']}"
            if self.context.get('http_method'):
                context_str += f" ({self.context['http_method']})"
        elif self.context.get('operation_type') == 'file_operation':
            function_name = self.context.get('function_name', 'unknown')
            context_str = f"\n  Context: File Operation ({function_name})"
        elif self.context.get('operation_type') == 'task_execution':
            function_name = self.context.get('function_name', 'unknown')
            context_str = f"\n  Context: Task Execution ({function_name})"
        
        return (
            f"[!] Insecure deserialization detected\n"
            f"  Risk    : {self.risk}\n"
            f"  File    : {self.filename}:{self.lineno}{context_str}\n"
            f"  Source  : {self.initial_source}\n"
            f"  Flow    : {self.flow}\n"
            f"  Sink    : {self.sink}\n"
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
        try:
            visitor = SinkVisitor(file_index, project_index)
            visitor.visit(file_index.tree)
            findings.extend(visitor.findings)
        except Exception as e:
            print_colored(f"[!] Error analyzing {filename}: {e}", "bold red")
            # Continue with other files
        progress.update(1)

    progress.close()

    # Sort findings by risk level
    RISK_LEVELS = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (RISK_LEVELS.get(f.risk, 3), f.filename, f.lineno))

    if verbose:
        print_verbose_findings(findings)

    print_console_report(findings)
    
    risk_counts = Counter(f.risk for f in findings)
    print_summary_with_colors(len(findings), risk_counts)
    elapsed = time.time() - start_time
    print(f"\n[✓] Scan completed in {format_elapsed(elapsed)}.")
    
    return findings

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
        self.function_contexts = self.detect_context()
        self.current_function = None

    def visit_FunctionDef(self, node):
        """
        Track the current function being visited.
        """
        try:
            self.current_function = node.name
            self.generic_visit(node)
        except Exception:
            # Continue even if there's an error in function analysis
            pass
        finally:
            self.current_function = None

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
        try:
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
                initial_source, flow, risk = self.trace_source(source_node)
                
                # Get context for current function
                context = self.function_contexts.get(self.current_function, {})
                
                # Enhance flow description based on context type
                enhanced_flow = flow
                if context.get('http_endpoint') and 'request.' in flow:
                    endpoint = context['http_endpoint']
                    method = context.get('http_method', 'GET')
                    enhanced_flow = f"HTTP {method} {endpoint} → {flow}"
                elif context.get('operation_type') == 'file_operation':
                    function_name = context.get('function_name', 'unknown')
                    enhanced_flow = f"File Operation ({function_name}) → {flow}"
                elif context.get('operation_type') == 'task_execution':
                    function_name = context.get('function_name', 'unknown')
                    enhanced_flow = f"Task Execution ({function_name}) → {flow}"
                
                finding = Finding(
                    sink=sink_name,
                    initial_source=initial_source,
                    flow=enhanced_flow,
                    filename=self.file_index.filename,
                    lineno=node.lineno,
                    risk=risk,
                    context=context
                )
                self.findings.append(finding)

            self.generic_visit(node)
        except Exception:
            # Continue even if there's an error in call analysis
            self.generic_visit(node)

    def trace_source(self, node, depth=0):
        """
        Trace the origin of data passed to a deserialization sink.
        Returns: (initial_source, full_flow, risk)
        """
        try:
            if depth > 5:
                return ("unknown", "unknown (recursion limit)", "MEDIUM")

            # Variable reference
            if isinstance(node, ast.Name):
                if node.id in self.tainted_files:
                    return (f"{node.id} (tainted from file upload)", f"{node.id} (tainted from file upload)", "HIGH")

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
                            return (f"{node.id} (direct stream from request.files)", f"{node.id} (direct stream from request.files)", "HIGH")

                    initial_source, flow, risk = self.trace_source(assign, depth + 1)
                    lineno = getattr(assign, "lineno", "?")
                    full_flow = f"{node.id} (assigned at line {lineno}) → {flow}"
                    return (initial_source, full_flow, risk)

                return (f"{node.id} (unresolved)", f"{node.id} (unresolved)", "MEDIUM")

            # Function calls like open(...) or os.path.join(...)
            elif isinstance(node, ast.Call):
                func_name, func_info = resolve_function_call(node, self.file_index, self.project_index)

                if match_source(func_name, SOURCES):
                    # Special handling for open() calls - they should show the file being opened
                    if func_name == "open" and node.args:
                        file_path_initial, file_path_flow, file_risk = self.trace_source(node.args[0], depth + 1)
                        return (file_path_initial, f"open({file_path_flow})", file_risk)
                    else:
                        return (f"{func_name} (call)", f"{func_name} (call)", "HIGH")

                if func_name == "open" and node.args:
                    # Get the file path being opened
                    file_path_initial, file_path_flow, file_risk = self.trace_source(node.args[0], depth + 1)
                    
                    # Return the file path directly as the source
                    return (file_path_initial, f"open({file_path_flow})", file_risk)

                if func_name.endswith("os.path.join") and node.args:
                    sub_labels = []
                    all_safe = True
                    for arg in node.args:
                        initial_source, flow, risk = self.trace_source(arg, depth + 1)
                        sub_labels.append(flow)
                        if "unknown" in flow or "input" in flow or "tainted" in flow:
                            all_safe = False
                    joined_label = "os.path.join(" + ", ".join(sub_labels) + ")"
                    return (joined_label, joined_label, "LOW" if all_safe else "HIGH")

                if func_info:
                    for stmt in func_info.node.body:
                        if isinstance(stmt, ast.Return):
                            return self.trace_source(stmt.value, depth + 1)

            elif isinstance(node, ast.Constant):
                # Handle string constants (file paths)
                if isinstance(node.value, str):
                    if "pickle" in node.value.lower() or "pkl" in node.value.lower():
                        return (f"pickle file: '{node.value}'", f"'{node.value}' (pickle file)", "HIGH")
                    else:
                        return (f"file: '{node.value}'", f"'{node.value}'", "MEDIUM")
                else:
                    return (f"constant '{node.value}'", f"constant '{node.value}'", "LOW")

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
                    return (f"{attr} (attribute)", f"{attr} (attribute)", "HIGH")
            
                return (f"{attr} (attribute)", f"{attr} (attribute)", "LOW")

            elif isinstance(node, ast.Subscript):
                # Handle subscript access like request.form['yaml_data']
                value_initial, value_flow, value_risk = self.trace_source(node.value, depth + 1)
                
                # Get the subscript key if it's a string constant
                if isinstance(node.slice, ast.Constant):
                    key = node.slice.value
                    subscript_desc = f"['{key}']"
                elif isinstance(node.slice, ast.Name):
                    key = node.slice.id
                    subscript_desc = f"[{key}]"
                else:
                    subscript_desc = "[...]"
                
                # Check if this is a request form/args access
                if "request.form" in value_flow:
                    return (f"request.form{subscript_desc} (HTTP POST form data)", 
                           f"request.form{subscript_desc} (HTTP POST form data)", "HIGH")
                elif "request.args" in value_flow:
                    return (f"request.args{subscript_desc} (HTTP GET query parameter)", 
                           f"request.args{subscript_desc} (HTTP GET query parameter)", "HIGH")
                elif "request.json" in value_flow:
                    return (f"request.json{subscript_desc} (HTTP JSON body)", 
                           f"request.json{subscript_desc} (HTTP JSON body)", "HIGH")
                elif "request.files" in value_flow:
                    return (f"request.files{subscript_desc} (HTTP file upload)", 
                           f"request.files{subscript_desc} (HTTP file upload)", "HIGH")
                
                # For other subscript access, combine the flow
                combined_flow = f"{value_flow}{subscript_desc}"
                return (value_initial, combined_flow, value_risk)

            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left_initial, left_flow, _ = self.trace_source(node.left, depth + 1)
                right_initial, right_flow, _ = self.trace_source(node.right, depth + 1)
                combined_flow = f"{left_flow} + {right_flow}"
                return (left_initial, combined_flow, "LOW")

            return ("unknown source", "unknown source", "MEDIUM")
        except Exception:
            # Return safe defaults if there's an error in source tracing
            return ("error in source tracing", "error in source tracing", "MEDIUM")

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

    def detect_context(self):
        """
        Detect various types of context (HTTP, file operations, etc.) from function definitions.
        Returns a mapping of function names to their context.
        """
        function_contexts = {}
        
        for node in ast.walk(self.file_index.tree):
            if isinstance(node, ast.FunctionDef):
                context = {}
                
                # Check for Flask route decorators
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call):
                        if isinstance(decorator.func, ast.Attribute):
                            if decorator.func.attr == 'route':
                                # Extract route path
                                if decorator.args:
                                    context['http_endpoint'] = decorator.args[0].value
                                
                                # Extract HTTP methods
                                for keyword in decorator.keywords:
                                    if keyword.arg == 'methods':
                                        if isinstance(keyword.value, ast.List):
                                            methods = [elt.value for elt in keyword.value.elts]
                                            context['http_method'] = ', '.join(methods)
                                        elif isinstance(keyword.value, ast.Constant):
                                            context['http_method'] = keyword.value.value
                                break
                        elif isinstance(decorator.func, ast.Name):
                            if decorator.func.id == 'route':
                                # Django-style route
                                if decorator.args:
                                    context['http_endpoint'] = decorator.args[0].value
                                break
                
                # Detect file operation context from function name and docstring
                try:
                    if self.is_file_operation_function(node):
                        context['operation_type'] = 'file_operation'
                        context['function_name'] = node.name
                    
                    # Detect task/job context (common in Luigi, Celery, etc.)
                    if self.is_task_function(node):
                        context['operation_type'] = 'task_execution'
                        context['function_name'] = node.name
                except Exception:
                    # Skip context detection if there's an error
                    pass
                
                if context:
                    function_contexts[node.name] = context
        
        return function_contexts

    def is_file_operation_function(self, node):
        """
        Detect if a function is likely a file operation function.
        """
        # Check function name patterns
        file_patterns = [
            'load', 'save', 'read', 'write', 'open', 'close', 'extract',
            'deserialize', 'unpickle', 'import', 'export', 'backup', 'restore'
        ]
        
        if any(pattern in node.name.lower() for pattern in file_patterns):
            return True
        
        # Check docstring for file-related keywords
        if node.body and isinstance(node.body[0], ast.Expr):
            if isinstance(node.body[0].value, ast.Constant):
                try:
                    docstring = node.body[0].value.value.lower()
                    file_keywords = ['file', 'pickle', 'load', 'save', 'extract', 'deserialize']
                    if any(keyword in docstring for keyword in file_keywords):
                        return True
                except (AttributeError, TypeError):
                    # Handle cases where value is not a string (e.g., ellipsis)
                    pass
        
        return False

    def is_task_function(self, node):
        """
        Detect if a function is likely a task/job execution function.
        """
        # Check function name patterns
        task_patterns = [
            'task', 'job', 'work', 'execute', 'run', 'process', 'compute',
            'worker', 'runner', 'handler', 'do_work'
        ]
        
        if any(pattern in node.name.lower() for pattern in task_patterns):
            return True
        
        return False

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
