# pickle_inspector/report.py

import json

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

def print_console_report(findings):
    """
    Pretty-prints findings to the terminal using rich if available.
    """
    if not findings:
        print("[✓] No insecure deserialization flows detected.")
        return

    if RICH_AVAILABLE:
        console = Console()
        table = Table(title="Insecure Deserialization Findings", box=box.SIMPLE_HEAVY)
        table.add_column("File", style="cyan")
        table.add_column("Line", justify="right", style="yellow")
        table.add_column("Sink", style="bold red")
        table.add_column("Source", style="bold magenta")
        table.add_column("Risk", style="bold")

        for f in findings:
            table.add_row(f.filename, str(f.lineno), f.sink, f.source, f.risk)

        console.print(table)
    else:
        print("[!] Findings:")
        for f in findings:
            print(f"- {f.filename}:{f.lineno} | Sink: {f.sink} | Source: {f.source} | Risk: {f.risk}")

def export_json_report(findings, output_file):
    """
    Write the findings to a JSON file.
    """
    json_data = [
        {
            "file": f.filename,
            "line": f.lineno,
            "sink": f.sink,
            "source": f.source,
            "risk": f.risk,
        }
        for f in findings
    ]

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)
    print(f"[+] JSON report written to {output_file}")

