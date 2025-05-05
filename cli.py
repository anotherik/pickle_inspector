# pickle_inspector/cli.py

import os
import argparse
from indexer import index_project
from analyzer import analyze_index

def discover_python_files(target):
    """
    Discover one or more Python files to scan.
    If a single file is passed, return it directly.
    """
    if os.path.isfile(target) and target.endswith(".py"):
        return [os.path.abspath(target)]
    elif os.path.isdir(target):
        python_files = []
        for root, _, files in os.walk(target):
            for filename in files:
                if filename.endswith(".py"):
                    full_path = os.path.join(root, filename)
                    python_files.append(full_path)
        return python_files
    return []

def main():
    """
    CLI entry point for the pickle_inspector tool.
    """
    parser = argparse.ArgumentParser(description="Detect insecure deserialization with pickle")
    parser.add_argument("target", help="Directory or Python file to scan")
    parser.add_argument("--py2-support", action="store_true", help="Enable Python 2 to 3 conversion for legacy code")
    parser.add_argument("--skip-errors", action="store_true", help="Silently skip files with syntax/indentation issues")
    parser.add_argument("--verbose", action="store_true", help="Print full trace details for each finding")
    args = parser.parse_args()

    python_files = discover_python_files(args.target)
    if not python_files:
        print("[!] No Python files found in the target.")
        return

    try:
        # Index and analyze
        project_index = index_project(
            python_files,
            py2_mode=args.py2_support,
            skip_errors=args.skip_errors
        )
        analyze_index(project_index, verbose=args.verbose)

    except KeyboardInterrupt:
        print("\n[✗] Scan aborted by user.")

if __name__ == "__main__":
    main()
