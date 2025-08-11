# pickle_inspector/cli.py

import os
import argparse
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
    parser = argparse.ArgumentParser(description="Detect insecure deserialization with pickle")
    parser.add_argument("target", help="Directory or Python file to scan")
    parser.add_argument("--exclude", action="append", help="Pattern to exclude from scanning (can be used multiple times)")
    parser.add_argument("--html", action="store_true", help="Generate HTML report in reports folder")
    parser.add_argument("--py2-support", action="store_true", help="Enable Python 2 to 3 conversion for legacy code")
    parser.add_argument("--skip-errors", action="store_true", help="Silently skip files with syntax/indentation issues")
    parser.add_argument("--verbose", action="store_true", help="Print full trace details for each finding")
    args = parser.parse_args()

    python_files = discover_python_files(args.target, args.exclude)
    if not python_files:
        print_colored("[!] No Python files found in the target.", "bold red")
        return

    try:
        # Index and analyze
        project_index = index_project(
            python_files,
            py2_mode=args.py2_support,
            skip_errors=args.skip_errors
        )
        findings = analyze_index(project_index, verbose=args.verbose)
        
        # Generate HTML report if requested
        if args.html:
            from report import export_html_report
            # Extract project name from target path
            project_name = os.path.basename(os.path.abspath(args.target))
            if project_name.endswith('.py'):
                project_name = project_name[:-3]  # Remove .py extension
            export_html_report(findings, project_name)

    except KeyboardInterrupt:
        print_colored("\n[✗] Scan aborted by user.", "bold yellow")

if __name__ == "__main__":
    main()
