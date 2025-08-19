# pickle_inspector/cli.py

import os
import argparse
import warnings
from indexer import index_project
from analyzer import analyze_index

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

def discover_python_files(target, exclude_patterns=None):
    """
    Discover one or more Python files to scan.
    If a single file is passed, return it directly.
    """
    if exclude_patterns is None:
        exclude_patterns = []
    
    def should_exclude(filepath):
        """Check if file should be excluded based on patterns."""
        for pattern in exclude_patterns:
            if pattern in filepath:
                return True
        return False
    
    if os.path.isfile(target) and target.endswith(".py"):
        if should_exclude(target):
            return []
        return [os.path.abspath(target)]
    elif os.path.isdir(target):
        python_files = []
        for root, _, files in os.walk(target):
            for filename in files:
                if filename.endswith(".py"):
                    full_path = os.path.join(root, filename)
                    if not should_exclude(full_path):
                        python_files.append(full_path)
        return python_files
    return []

def main():
    """
    CLI entry point for the pickle_inspector tool.
    """
    parser = argparse.ArgumentParser(description="Detect insecure deserialization with pickle and friends.")
    parser.add_argument("target", help="Directory or Python file to scan")
    parser.add_argument("--exclude", action="append", help="Pattern to exclude from scanning (can be used multiple times)")
    parser.add_argument("--html", action="store_true", help="Generate HTML report in reports folder")
    parser.add_argument("--json", action="store_true", help="Generate JSON report in reports folder")
    parser.add_argument("--py2-support", action="store_true", help="Enable Python 2 to 3 conversion for legacy code")
    parser.add_argument("--skip-errors", action="store_true", help="Continue scanning when encountering syntax/indentation errors (default: stop on first error)")
    parser.add_argument("--verbose", action="store_true", help="Print full trace details for each finding")
    parser.add_argument("--scan-verbosity", choices=["quiet", "normal", "verbose"], default="normal", 
                       help="Control warning output: quiet (suppress warnings), normal (default), verbose (show all)")
    args = parser.parse_args()

    # Configure warning behavior based on verbosity
    if args.scan_verbosity == "quiet":
        # Suppress all warnings at the CLI level for quiet mode
        warnings.filterwarnings("ignore")
    elif args.scan_verbosity == "verbose":
        # Force all warnings to show in verbose mode
        warnings.filterwarnings("always", category=SyntaxWarning)
        warnings.filterwarnings("always", category=DeprecationWarning)
        warnings.filterwarnings("always", category=FutureWarning)

    python_files = discover_python_files(args.target, args.exclude)
    if not python_files:
        print_colored("[!] No Python files found in the target.", "bold red")
        return

    try:
        # Index and analyze
        project_index = index_project(
            python_files,
            py2_mode=args.py2_support,
            skip_errors=args.skip_errors,
            verbosity=args.scan_verbosity
        )
        findings = analyze_index(project_index, verbose=args.verbose, verbosity=args.scan_verbosity)
        
        # Generate reports if requested
        if args.html or args.json:
            from report import export_html_report, export_json_report
            from utils import sanitize_filename
            # Extract project name from target path and sanitize it
            project_name = os.path.basename(os.path.abspath(args.target))
            if project_name.endswith('.py'):
                project_name = project_name[:-3]  # Remove .py extension
            project_name = sanitize_filename(project_name)
            
            if args.html:
                export_html_report(findings, project_name)
            
            if args.json:
                # Create reports directory if it doesn't exist
                reports_dir = "reports"
                if not os.path.exists(reports_dir):
                    os.makedirs(reports_dir)
                
                # Generate timestamp for unique filename
                import datetime
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                json_filename = f"{project_name}_{timestamp}.json"
                json_output_file = os.path.join(reports_dir, json_filename)
                
                export_json_report(findings, json_output_file)

    except KeyboardInterrupt:
        print_colored("\n[-] Scan aborted by user.", "bold yellow")

if __name__ == "__main__":
    main()
