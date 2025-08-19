<p align="center">
  <img src="pickle-inspector.png" alt="Pickle Inspector Logo" width="300"/>
</p>

# Pickle Inspector

`pickle_inspector` is a static analysis tool to detect **insecure deserialization vulnerabilities** in Python projects — especially those involving `pickle.load()`, `yaml.load()`, and [other unsafe sinks](#insecure-deserialization-sinks-supported). It identifies flows from user-controlled inputs to deserialization sinks, including cases like:

- `pickle.load(open(...))` with user-influenced file paths
- `pickle.load(request.files['file'])` directly from uploads
- Dangerous patterns across multiple files and function calls
- Web application contexts (Flask/Django routes)
- File operation and task execution contexts


## Insecure Deserialization Sinks Supported

The tool statically detects usage of the following **deserialization functions**, which can lead to arbitrary code execution or data tampering when handling untrusted input:

| Sink                                  | Description |
|---------------------------------------|-------------|
| `pickle.load()`                       | Code execution risk if attacker controls input |
| `pickle.loads()`                      | Same as `pickle.load` but for in-memory data |
| `pickle.Unpickler.load()`            | Can be used in custom deserialization flows, still uses pickle internally |
| `joblib.load()`                       | Common in ML pipelines, relies on pickle under the hood |
| `sklearn.externals.joblib.load()`     | Legacy scikit-learn import path for joblib, also uses pickle |
| `cloudpickle.load()`                  | Like pickle, used in distributed computing (e.g., Dask, Ray) |
| `cloudpickle.loads()`                 | In-memory variant of `cloudpickle.load()` |
| `dill.load()`                         | Extends pickle, supports serializing more object types |
| `dill.loads()`                        | Like `dill.load`, but operates on in-memory byte strings |
| `marshal.load()`                      | Can load arbitrary Python bytecode (rarely used outside stdlib) |
| `marshal.loads()`                     | Same as above but from byte strings |
| `shelve.open()`                       | Implicitly uses pickle to load persistent storage |
| `yaml.load()`                         | Unsafe: can instantiate arbitrary objects when used with default loader |
| `torch.load()`                        | Used in PyTorch — internally uses pickle, exploitable via model files |
| `torch.jit.load()`                    | Loads TorchScript models, also uses pickle internally |
| `numpy.load()`                        | Unsafe if `allow_pickle=True` (loads .npy/.npz files using pickle) |
| `pandas.read_pickle()`               | Loads DataFrames using pickle under the hood |
| `keras.models.load_model()`           | Can deserialize pickled objects inside HDF5 model files |

> ⚠️ If these functions are used with attacker-controlled input — directly or indirectly — they are flagged with appropriate **risk levels** (HIGH, MEDIUM, LOW) based on flow analysis.

Additional sinks can be added by editing `sources_and_sinks.py`.

## Features

- **Detection**: Detects insecure usage of deserialization sinks (e.g., `pickle`, `marshal`, `yaml`, `shelve`, etc.)
- **Flow Tracking**: Tracks both file-based and stream-based flows with full path visibility
- **Context Awareness**: Identifies web application contexts (Flask/Django routes), file operations, and task execution
- **Selective Scanning**: Exclude test files, virtual environments, and other patterns with `--exclude`
- **Reports**: Generate HTML reports with `--html` flag
- **Multiple Formats**: Console output, JSON export, and HTML reports
- **Legacy Support**: Python 2 syntax conversion (optional)

## Design Overview

- **AST-based analysis** (no runtime execution)
- All source code is parsed from temporary copies — your files are never modified
- Python 2 files are converted in-memory if `--py2-support` is enabled
- **Smart context detection** for web applications, file operations, and background tasks
- Taint tracking models common user-input flows, including Flask/Django

## Directory Structure

```
pickle_inspector/
├── analyzer.py           # Core sink detection & taint tracking with context awareness
├── ast_parser.py         # AST parsing with error handling
├── cli.py                # CLI interface with exclude and HTML export
├── indexer.py            # Project indexing, function/import mapping
├── resolver.py           # Call resolution
├── utils.py              # AST utilities
├── report.py             # Console, JSON & HTML reporting
├── sources_and_sinks.py  # Configurable list of dangerous functions
├── reports/              # Generated HTML and JSON reports (created automatically)
   ├── project1_20250811_134848.html
   ├── project1_20250811_134848.json
   └── project2_20250811_135230.html
```

## Installation

### Option 1: Install from GitHub (Recommended)

```bash
pip install git+https://github.com/anotherik/pickle_inspector.git
```

### Option 2: Manual Setup (Development)

```bash
git clone https://github.com/anotherik/pickle_inspector.git
cd pickle_inspector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Requirements

```
tqdm>=4.64.0           # Progress bar during scans
rich>=13.3.0           # Table output for findings and HTML generation
autopep8>=2.0.0        # Optional formatting and linting (used internally for py2 cleanup)
```

## System dependencies (not included in requirements.txt)
- Python 3.7+
- 2to3 (for --py2-support): install via your OS package manager # Standard tool for converting Python 2 code to Python 3

## Usage

After installation, you can use the `pickle-inspector` command directly:

### Basic Scanning

```bash
# Scan a directory
pickle-inspector ./my_project/

# Scan a single file
pickle-inspector ./vulnerable_app.py

# Continue scanning even when encountering parsing errors
pickle-inspector --skip-errors ./my_project/
```

### Advanced Features

```bash
# Exclude test files and virtual environments
pickle-inspector --exclude test --exclude venv --exclude __pycache__ ./project/

# Generate HTML report
pickle-inspector --html ./project/

# Generate JSON report
pickle-inspector --json ./project/

# Generate both HTML and JSON reports
pickle-inspector --html --json ./project/

# Combine multiple features
pickle-inspector --exclude test --exclude venv --html --json --verbose --skip-errors ./project/

# Python 2 support for legacy code
pickle-inspector --py2-support ./legacy_project/

# Verbose output with full trace details
pickle-inspector --verbose ./project/

# Control warning and error output (suppress SyntaxWarnings and parsing errors)
pickle-inspector --scan-verbosity quiet ./project/

```

### Development Usage

```bash
python3 cli.py --skip-errors ./my_project/
python3 cli.py --exclude test --html --skip-errors ./project/
```

## Command Line Options

| Flag              | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `--exclude`       | Pattern to exclude from scanning (can be used multiple times)              |
| `--html`          | Generate professional HTML report in `reports/` folder                     |
| `--json`          | Generate structured JSON report in `reports/` folder                       |
| `--skip-errors`   | Continue scanning when encountering syntax/indentation errors (default: stop on first error) |
| `--py2-support`   | Attempt to convert Python 2 files via `2to3` before analysis                |
| `--verbose`       | Print detailed trace information per finding                                |
| `--scan-verbosity`| Control warning and error output: `quiet` (suppress all), `normal` (default), `verbose` (show all) |

## Example Output

### Console Output (Rich Tables)

```
                                            Insecure Deserialization Findings

  Risk       File                  Line   Context                Source              Flow               Sink
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  HIGH       /home/user/project/        7   File Op: load_config   pickle file:        File Operation     pickle.load
             app.py                                                 '/config/session.   (load_config) →   
                                                                     pkl'                fd (assigned at   
                                                                                         line 6) →         
                                                                                         open('/config/s  
                                                                                         ession.pkl' (pi  
                                                                                         ckle file))      
  MEDIUM     /home/user/project/       14   POST /upload           request.form        HTTP POST /uploa  yaml.load
             app.py                                                 ['yaml_data']       d → request.form  
                                                                     (HTTP POST form    ['yaml_data'] →   
                                                                     data)              yaml.load(..., L  
                                                                                         oader=yaml.Loa  
                                                                                         der)             
```

### Verbose Output

```
[!] Insecure deserialization detected
  Risk    : HIGH
  File    : /home/user/project/app.py:7
  Context : File Operation (load_config)
  Source  : pickle file: '/config/session.pkl'
  Flow    : File Operation (load_config) → fd (assigned at line 6) → open('/config/session.pkl' (pickle file))
  Sink    : pickle.load
```

### JSON Report

The `--json` flag generates structured JSON reports in the `reports/` folder with the following structure:

**JSON Structure Example**:
```json
{
  "scan_info": {
    "total_findings": 2,
    "risk_summary": {
      "HIGH": 1,
      "MEDIUM": 1
    },
    "generated_at": "2025-08-11T16:15:17.055411"
  },
  "findings": [
    {
      "file": "/path/to/app.py",
      "line": 7,
      "sink": "pickle.load",
      "initial_source": "pickle file: '/config/session.pkl'",
      "flow": "File Operation (load_config) → fd → open('/config/session.pkl')",
      "risk": "HIGH",
      "context": {
        "type": "file_operation",
        "function_name": "load_config"
      }
    }
  ]
}
```

## Context Detection

The tool automatically detects and provides context for different types of applications:

### Web Applications
- **Flask/Django Routes**: Detects `@app.route()` decorators and HTTP methods
- **Form Data**: Identifies `request.form['field']` and `request.files['file']` patterns
- **API Endpoints**: Shows HTTP method and endpoint path

### File Operations
- **File Functions**: Detects functions with names like `load`, `save`, `read`, `write`
- **Documentation**: Analyzes docstrings for file-related keywords
- **Operations**: Shows "File Operation: function_name" context

### Background Tasks
- **Task Functions**: Identifies functions with names like `task`, `job`, `worker`, `execute`
- **Job Systems**: Common in Luigi, Celery, and other task frameworks
- **Context**: Shows "Task Execution: function_name" context

## Risk Assessment

Findings are categorized by risk level based on flow analysis:

| Risk Level | Description | Example |
|------------|-------------|---------|
| **HIGH**   | Direct user input to sink | `pickle.load(request.files['file'])` |
| **MEDIUM** | Indirect user influence | `pickle.load(open(user_provided_path))` |
| **LOW**    | Limited or no user control | `pickle.load(open('/etc/config.pkl'))` |

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
