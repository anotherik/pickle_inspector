# 🛡️ Pickle 🥒 Inspector 🔍

`pickle_inspector` is a static analysis tool to detect **insecure deserialization vulnerabilities** in Python projects — especially those involving `pickle.load()`, `yaml.load()`, and [other unsafe sinks](#insecure-deserialization-sinks-supported). It identifies flows from user-controlled inputs to deserialization sinks, including cases like:

- `pickle.load(open(...))` with user-influenced file paths
- `pickle.load(request.files['file'])` directly from uploads
- Dangerous patterns across multiple files and function calls


## Insecure Deserialization Sinks Supported

The tool statically detects usage of the following **deserialization functions**, which can lead to arbitrary code execution or data tampering when handling untrusted input:

| Sink               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `pickle.load()`    | 💥 **Code execution** risk if attacker controls input                        |
| `pickle.loads()`   | Same as `pickle.load` but for in-memory data                                |
| `yaml.load()`      | 💥 Unsafe: can instantiate arbitrary objects when used with default loader   |
| `marshal.load()`   | Can load arbitrary Python bytecode (rarely used outside core)               |
| `marshal.loads()`  | Like `marshal.load`, but on byte strings                                    |
| `shelve.open()`    | Implicitly uses `pickle` to load data from disk                             |
| `joblib.load()`    | Common in ML pipelines, relies on `pickle` under the hood                   |
| `torch.load()`     | Used in PyTorch — internally uses `pickle`, exploitable via model files     |
| `tf.keras.models.load_model()` | TensorFlow — uses HDF5 files that may include `pickle` fallback   |

> ⚠️ If these functions are used with attacker-controlled input — directly or indirectly — they are flagged with appropriate **risk levels** (HIGH, MEDIUM, LOW) based on flow analysis.

Additional sinks can be added by editing `sources_and_sinks.py`.


## ✅ Features

- Detects insecure usage of deserialization sinks (e.g., `pickle`, `marshal`, `yaml`, `shelve`, etc.)
- Tracks both file-based and stream-based flows
- Identifies tainted sources like `request.files`, `input()`, `sys.argv`, etc.
- Supports Python 2 syntax conversion (optional)
- Handles individual files or entire directories
- Progress bar and scan timing
- Graceful handling of Ctrl+C
- Results are sorted by risk severity
- Optional `--verbose` mode for full trace explanation


## 🧠 Design Overview

- **AST-based analysis** (no runtime execution)
- All source code is parsed from temporary copies — your files are never modified
- Python 2 files are converted in-memory if `--py2-support` is enabled
- Reporting uses `rich` tables (if available), falls back to plain text
- Taint tracking models common user-input flows, including Flask/Django


## 🚫 Limitations

- No inter-procedural taint tracking across files (yet)
- Doesn't cover `json.load()` or `yaml.safe_load()` (by design)
- No automatic fixing or patching — this is a detection tool


## 📁 Directory Structure

```
pickle_inspector/
├── analyzer.py           # Core sink detection & taint tracking
├── ast_parser.py         # AST parsing
├── cli.py                # CLI interface
├── indexer.py            # Project indexing, function/import mapping
├── resolver.py           # Call resolution
├── utils.py              # AST utilities
├── report.py             # Console & JSON reporting
├── sources_and_sinks.py  # Configurable list of dangerous functions
```


## 📦 Setup (Recommended: Virtual Environment)

```bash
git clone https://github.com/yourusername/pickle_inspector.git
cd pickle_inspector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🛠 Requirements

```
tqdm>=4.64.0           # Progress bar during scans
rich>=13.3.0           # Table output for findings
autopep8>=2.0.0        # Optional formatting and linting (used internally for py2 cleanup)
```

## System dependencies (not included in requirements.txt)
- Python 3.7+
- 2to3 (for --py2-support): install via your OS package manager # Standard tool for converting Python 2 code to Python 3


## 📄 Usage

### Scan a directory:

```bash
python3 cli.py --skip-errors ./my_project/
```

### Scan a single file:

```bash
python3 cli.py ./vulnerable_app.py
```

### With Python 2 support:

```bash
python3 cli.py --py2-support ./legacy_project/
```

### Verbose output (full trace detail):

```bash
python3 cli.py --verbose ./project/
```


## ⚙️ Options

| Flag              | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `--skip-errors`   | Skip files with syntax/indentation issues                                   |
| `--py2-support`   | Attempt to convert Python 2 files via `2to3` before analysis                |
| `--verbose`       | Print detailed trace information per finding                                |


## 🔍 Example Output

```
[!] Insecure deserialization detected
  Sink    : pickle.load
  Source  : f (assigned at line 12) → file (direct stream from request.files)
  File    : /path/to/app.py:14
  Risk    : HIGH

[✓] Scan completed in 2.34 seconds.
```


## 📋 Report Table (with `rich` installed)

```
Insecure Deserialization Findings

  File                          Line   Sink          Source                               Risk
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  /path/app.py                   14   pickle.load   file (direct stream from request...)   HIGH
```


## ✅ License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.


