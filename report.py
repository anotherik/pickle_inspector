# pickle_inspector/report.py

import json
import os
import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

def get_risk_color(risk):
    """Get color for risk level."""
    if RICH_AVAILABLE:
        if risk == "HIGH":
            return "bold red"
        elif risk == "MEDIUM":
            return "bold orange3"
        elif risk == "LOW":
            return "bold blue"
        else:
            return "white"
    return ""

def print_colored(message, style="white"):
    """Print a message with color if rich is available."""
    if RICH_AVAILABLE:
        console = Console(width=None)  # Allow unlimited width
        console.print(message, style=style)
    else:
        print(message)

def print_console_report(findings):
    """
    Pretty-prints findings to the terminal using rich if available.
    """
    if not findings:
        print("[+] No insecure deserialization flows detected.")
        return

    if RICH_AVAILABLE:
        console = Console(width=None)  # Allow unlimited width
        table = Table(title="Insecure Deserialization Findings", box=box.SIMPLE_HEAVY, expand=True, show_header=True, header_style="bold magenta")
        table.add_column("Risk", style="bold", min_width=8)
        table.add_column("File", style="cyan", no_wrap=False, width=None)
        table.add_column("Line", justify="right", style="yellow", min_width=6)
        table.add_column("Context", style="bold blue", min_width=20)
        table.add_column("Source", style="bold magenta", no_wrap=False)
        table.add_column("Flow", style="bold green", no_wrap=False)
        table.add_column("Sink", style="bold red", min_width=15)

        for f in findings:
            risk_style = get_risk_color(f.risk)
            
            # Format context information
            context_info = ""
            if f.context.get('http_endpoint'):
                endpoint = f.context['http_endpoint']
                method = f.context.get('http_method', 'GET')
                context_info = f"{method} {endpoint}"
            elif f.context.get('operation_type') == 'file_operation':
                function_name = f.context.get('function_name', 'unknown')
                context_info = f"File Op: {function_name}"
            elif f.context.get('operation_type') == 'task_execution':
                function_name = f.context.get('function_name', 'unknown')
                context_info = f"Task: {function_name}"
            
            table.add_row(
                Text(f.risk, style=risk_style),
                Text(f.filename, style="cyan", overflow="fold"),
                str(f.lineno),
                context_info,
                Text(f.initial_source, style="bold magenta", overflow="fold"),
                Text(f.flow, style="bold green", overflow="fold"),
                Text(f.sink, style="bold red")
            )

        console.print(table)
    else:
        print("[!] Findings:")
        for f in findings:
            context_info = ""
            if f.context.get('http_endpoint'):
                endpoint = f.context['http_endpoint']
                method = f.context.get('http_method', 'GET')
                context_info = f" | Endpoint: {method} {endpoint}"
            elif f.context.get('operation_type') == 'file_operation':
                function_name = f.context.get('function_name', 'unknown')
                context_info = f" | File Op: {function_name}"
            elif f.context.get('operation_type') == 'task_execution':
                function_name = f.context.get('function_name', 'unknown')
                context_info = f" | Task: {function_name}"
            
            # Format the output with better line breaks for long paths
            print(f"- File: {f.filename}:{f.lineno}{context_info}")
            print(f"  Risk: {f.risk}")
            print(f"  Source: {f.initial_source}")
            print(f"  Flow: {f.flow}")
            print(f"  Sink: {f.sink}")
            print()  # Empty line for separation

def print_verbose_findings(findings):
    """
    Print verbose findings with colored output.
    """
    if not RICH_AVAILABLE:
        for finding in findings:
            print(str(finding))
        return

    console = Console(width=None)  # Allow unlimited width
    for finding in findings:
        # Create colored text for each field
        risk_text = Text(finding.risk, style=get_risk_color(finding.risk))
        file_text = Text(finding.filename, style="cyan")
        source_text = Text(finding.initial_source, style="bold magenta")
        flow_text = Text(finding.flow, style="bold green")
        sink_text = Text(finding.sink, style="bold red")
        
        # Print the finding with colors
        console.print(f"[!] Insecure deserialization detected", style="bold yellow")
        console.print(f"  Risk    : {risk_text}")
        
        # Add context information if available
        console.print(f"  File    : {file_text}:{finding.lineno}")
        
        if finding.context.get('http_endpoint'):
            endpoint = finding.context['http_endpoint']
            method = finding.context.get('http_method', 'GET')
            endpoint_text = Text(f"{method} {endpoint}", style="bold blue")
            console.print(f"  Endpoint: {endpoint_text}")
        elif finding.context.get('operation_type') == 'file_operation':
            function_name = finding.context.get('function_name', 'unknown')
            context_text = Text(f"File Operation: {function_name}", style="bold cyan")
            console.print(f"  Context : {context_text}")
        elif finding.context.get('operation_type') == 'task_execution':
            function_name = finding.context.get('function_name', 'unknown')
            context_text = Text(f"Task Execution: {function_name}", style="bold magenta")
            console.print(f"  Context : {context_text}")
        
        console.print(f"  Source  : {source_text}")
        console.print(f"  Flow    : {flow_text}")
        console.print(f"  Sink    : {sink_text}")
        console.print()  # Empty line for separation

def print_summary_with_colors(total_findings, risk_counts):
    """
    Print summary with colored risk levels.
    """
    if not RICH_AVAILABLE:
        print(f"\n[!] Total Findings: {total_findings}")
        print("\n" + "-" * 60)
        print("[!] Risk Summary:")
        for level in ["HIGH", "MEDIUM", "LOW"]:
            if level in risk_counts:
                print(f"    {level}: {risk_counts[level]}")
        print("-" * 60)
        return

    console = Console(width=None)  # Allow unlimited width
    console.print(f"\n[!] Total Findings: {total_findings}", style="bold white")
    console.print("\n" + "-" * 60, style="dim")
    console.print("[!] Risk Summary:", style="bold white")
    for level in ["HIGH", "MEDIUM", "LOW"]:
        if level in risk_counts:
            color = get_risk_color(level)
            console.print(f"    {level}: {risk_counts[level]}", style=color)
    console.print("-" * 60, style="dim")

def export_json_report(findings, output_file):
    """
    Write the findings to a JSON file.
    """
    json_data = {
        "scan_info": {
            "total_findings": len(findings),
            "risk_summary": {},
            "generated_at": datetime.datetime.now().isoformat()
        },
        "findings": []
    }
    
    # Count findings by risk level
    risk_counts = {}
    for finding in findings:
        risk_counts[finding.risk] = risk_counts.get(finding.risk, 0) + 1
    
    json_data["scan_info"]["risk_summary"] = risk_counts
    
    # Add detailed findings
    for f in findings:
        # Format context information
        context_info = {}
        if f.context.get('http_endpoint'):
            context_info["type"] = "http"
            context_info["endpoint"] = f.context['http_endpoint']
            context_info["method"] = f.context.get('http_method', 'GET')
        elif f.context.get('operation_type') == 'file_operation':
            context_info["type"] = "file_operation"
            context_info["function_name"] = f.context.get('function_name', 'unknown')
        elif f.context.get('operation_type') == 'task_execution':
            context_info["type"] = "task_execution"
            context_info["function_name"] = f.context.get('function_name', 'unknown')
        
        finding_data = {
            "file": f.filename,
            "line": f.lineno,
            "sink": f.sink,
            "initial_source": f.initial_source,
            "flow": f.flow,
            "risk": f.risk,
            "context": context_info
        }
        json_data["findings"].append(finding_data)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)
    print(f"[+] JSON report written to {output_file}")

def export_html_report(findings, project_name="pickle_inspector_scan"):
    """
    Write the findings to an HTML file in the reports folder.
    """
    from utils import sanitize_filename
    
    # Sanitize the project name to prevent path traversal
    project_name = sanitize_filename(project_name)
    
    # Create reports directory if it doesn't exist
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    # Generate timestamp for unique filename
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{project_name}_{timestamp}.html"
    output_file = os.path.join(reports_dir, filename)
    
    # Generate HTML content
    html_content = generate_html_content(findings, project_name, timestamp)
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"[+] HTML report written to {output_file}")
    return output_file

def generate_html_content(findings, project_name, timestamp):
    """
    Generate HTML content for the report.
    """
    risk_colors = {
        "HIGH": "#dc3545",
        "MEDIUM": "#fd7e14", 
        "LOW": "#0d6efd"
    }
    
    # Count findings by risk level
    risk_counts = {}
    for finding in findings:
        risk_counts[finding.risk] = risk_counts.get(finding.risk, 0) + 1
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pickle Inspector Report - {project_name}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header .subtitle {{
            margin-top: 10px;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .summary {{
            padding: 20px;
            background-color: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .summary-card .label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .findings-section {{
            padding: 20px;
        }}
        .findings-section h2 {{
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .finding {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .risk-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .finding-details {{
            padding: 20px;
        }}
        .detail-row {{
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 15px;
            margin-bottom: 15px;
            align-items: start;
        }}
        .detail-label {{
            font-weight: bold;
            color: #495057;
            text-transform: uppercase;
            font-size: 0.8em;
            letter-spacing: 1px;
        }}
        .detail-value {{
            color: #333;
            word-break: break-all;
            line-height: 1.5;
        }}
        .file-path {{
            font-family: 'Courier New', monospace;
            background-color: #f8f9fa;
            padding: 8px 12px;
            border-radius: 4px;
            border-left: 4px solid #007bff;
        }}
        .flow-text {{
            font-family: 'Courier New', monospace;
            background-color: #f8f9fa;
            padding: 8px 12px;
            border-radius: 4px;
            border-left: 4px solid #28a745;
            white-space: pre-wrap;
        }}
        .footer {{
            background-color: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }}
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }}
        .no-findings h3 {{
            color: #28a745;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Pickle Inspector Report</h1>
            <div class="subtitle">
                Insecure Deserialization Analysis<br>
                <small>Generated on {timestamp}</small>
            </div>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="number">{len(findings)}</div>
                    <div class="label">Total Findings</div>
                </div>
"""
    
    # Add risk level cards
    for risk_level in ["HIGH", "MEDIUM", "LOW"]:
        count = risk_counts.get(risk_level, 0)
        color = risk_colors[risk_level]
        html += f"""
                <div class="summary-card">
                    <div class="number" style="color: {color};">{count}</div>
                    <div class="label">{risk_level} Risk</div>
                </div>
"""
    
    html += """
            </div>
        </div>
        
        <div class="findings-section">
            <h2>🔍 Detailed Findings</h2>
"""
    
    if not findings:
        html += """
            <div class="no-findings">
                <h3>✅ No Vulnerabilities Found</h3>
                <p>Congratulations! No insecure deserialization vulnerabilities were detected in the scanned code.</p>
            </div>
"""
    else:
        for i, finding in enumerate(findings, 1):
            risk_color = risk_colors.get(finding.risk, "#6c757d")
            
            # Format context information
            context_info = ""
            if finding.context.get('http_endpoint'):
                endpoint = finding.context['http_endpoint']
                method = finding.context.get('http_method', 'GET')
                context_info = f"{method} {endpoint}"
            elif finding.context.get('operation_type') == 'file_operation':
                function_name = finding.context.get('function_name', 'unknown')
                context_info = f"File Operation: {function_name}"
            elif finding.context.get('operation_type') == 'task_execution':
                function_name = finding.context.get('function_name', 'unknown')
                context_info = f"Task Execution: {function_name}"
            
            html += f"""
            <div class="finding">
                <div class="finding-header">
                    <h3>Finding #{i}</h3>
                    <span class="risk-badge" style="background-color: {risk_color};">{finding.risk}</span>
                </div>
                <div class="finding-details">
                    <div class="detail-row">
                        <div class="detail-label">File</div>
                        <div class="detail-value">
                            <div class="file-path">{finding.filename}:{finding.lineno}</div>
                        </div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Context</div>
                        <div class="detail-value">{context_info or "N/A"}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Source</div>
                        <div class="detail-value">{finding.initial_source}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Flow</div>
                        <div class="detail-value">
                            <div class="flow-text">{finding.flow}</div>
                        </div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Sink</div>
                        <div class="detail-value">{finding.sink}</div>
                    </div>
                </div>
            </div>
"""
    
    html += f"""
        </div>
        
        <div class="footer">
            <p>Generated by Pickle Inspector | {project_name} | {timestamp}</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html

