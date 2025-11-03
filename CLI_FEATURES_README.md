# MEEF CLI Features

> **New Command-Line Tools for MEEF Framework**  
> Version 1.0.0 | November 2, 2025

## 🚀 Overview

Two new powerful CLI tools have been added to MEEF for non-interactive batch processing and malware neutralization research:

1. **`meef_cli.py`** - Professional CLI wrapper for batch malware analysis
2. **`sanitize_asm.py`** - Educational ASM sanitizer for malware neutralization research

---

## 📋 Table of Contents

- [MEEF CLI](#meef-cli-meef_clipy)
- [ASM Sanitizer](#asm-sanitizer-sanitize_asmpy)
- [Quick Start](#quick-start)
- [Integration Guide](#integration-guide)
- [Documentation](#documentation)

---

## 🔧 MEEF CLI (`meef_cli.py`)

### Purpose

Non-interactive command-line interface for batch processing malware samples through the MEEF analysis pipeline.

### Key Features

✅ Process single files, directories, or batch lists  
✅ Parallel processing with configurable workers  
✅ Automatic catalog management  
✅ Dry-run mode for testing  
✅ Flexible output configuration  
✅ Comprehensive error handling

### Quick Examples

```bash
# Process a single file
python3 meef_cli.py --file samples/malware.asm --label malicious

# Batch process directory with parallel workers
python3 meef_cli.py --path samples/malicious/ --parallel 4 --verbose

# Dry run to preview
python3 meef_cli.py --path samples/ --dry-run

# Process from file list
python3 meef_cli.py --batch sample_list.txt --label unknown
```

### Command-Line Options

| Option                | Description                         | Default             |
| --------------------- | ----------------------------------- | ------------------- |
| `--file`              | Single .asm file to process         | -                   |
| `--path`              | Directory to scan (recursive)       | -                   |
| `--batch`             | Text file with paths (one per line) | -                   |
| `--label`             | Label: unknown/benign/malicious     | unknown             |
| `--parallel N`        | Number of parallel workers          | 1                   |
| `--output-dir`        | IR output directory                 | ./output/ir_results |
| `--catalog`           | Catalog CSV path                    | ./data/catalog.csv  |
| `--no-catalog-update` | Skip catalog updates                | -                   |
| `--dry-run`           | Preview without processing          | -                   |
| `--verbose`           | Detailed output                     | -                   |

### Output

- **IR JSONs**: `output/ir_results/<filename>_ir.json`
- **Catalog**: Updated `data/catalog.csv` with SHA256, labels, behavior flags
- **Exit Codes**: 0 (success), 1 (failures), 130 (interrupted)

---

## 🛡️ ASM Sanitizer (`sanitize_asm.py`)

### ⚠️ EDUCATIONAL USE ONLY

**Important**: This is a proof-of-concept tool for academic research and education. It demonstrates malware neutralization concepts but does NOT guarantee safe or functional output.

### Purpose

Identifies and neutralizes suspicious API calls in assembly files for malware analysis research and education.

### Key Features

✅ 87+ dangerous API blacklist (network, file, registry, memory, injection, crypto, etc.)  
✅ Three sanitization modes with different safety levels  
✅ Comprehensive JSON reporting with audit trails  
✅ Custom rule support  
✅ Mandatory safety warnings  
✅ Never modifies original files

### Sanitization Modes

| Mode        | Description                                     | Safety Level  | Use Case            |
| ----------- | ----------------------------------------------- | ------------- | ------------------- |
| **noop**    | Annotates suspicious lines without modification | ⭐⭐⭐ Safest | Analysis & learning |
| **replace** | Replaces malicious calls with NOP instructions  | ⭐⭐ Default  | Demonstration       |
| **remove**  | Completely removes suspicious lines             | ⭐ Aggressive | Research            |

### Quick Examples

```bash
# Analyze without modifying (safest)
python3 sanitize_asm.py --file malware.asm --mode noop --verbose

# Neutralize malicious calls with NOPs
python3 sanitize_asm.py --file malware.asm --mode replace

# Batch sanitize directory
python3 sanitize_asm.py --path samples/malicious/ --out-dir cleaned/

# Use custom API blacklist
python3 sanitize_asm.py --file malware.asm --rules custom_rules.json
```

### API Blacklist Categories

The tool detects 87+ dangerous APIs across categories:

- **Network**: InternetOpen, socket, connect, HttpSendRequest, URLDownloadToFile
- **File Operations**: CreateFile, WriteFile, DeleteFile, CopyFile, FindFirstFile
- **Registry**: RegOpenKey, RegSetValue, RegCreateKey, RegDeleteKey
- **Memory/Injection**: VirtualAlloc, WriteProcessMemory, CreateRemoteThread
- **Process Control**: CreateProcess, OpenProcess, TerminateProcess
- **Hooks**: SetWindowsHookEx, LoadLibrary, GetProcAddress
- **Execution**: ShellExecute, WinExec, system
- **Cryptography**: CryptEncrypt, CryptDecrypt
- **Services**: CreateService, StartService

### Command-Line Options

| Option      | Description                  | Default                |
| ----------- | ---------------------------- | ---------------------- |
| `--file`    | Single .asm file to sanitize | -                      |
| `--path`    | Directory with .asm files    | -                      |
| `--mode`    | noop/replace/remove          | replace                |
| `--rules`   | Custom blacklist JSON file   | Built-in               |
| `--out-dir` | Output directory             | ./samples/sanitized    |
| `--report`  | JSON report path             | ./sanitize_report.json |
| `--verbose` | Show line-by-line detections | -                      |
| `--dry-run` | Preview without processing   | -                      |

### Output Files

**Sanitized ASM** (`samples/sanitized/<name>_sanitized.asm`):

```assembly
; ═══════════════════════════════════════════════════════════════
; MEEF ASM SANITIZER - EDUCATIONAL USE ONLY
; Original file: malware.asm
; Sanitization mode: replace
; Detected suspicious APIs: 6
; Modified lines: 6
; ⚠️  WARNING: This file may not be functional or safe!
; ═══════════════════════════════════════════════════════════════

start:
    ; [SANITIZED] Original line 2: CALL InternetConnectA
    NOP  ; Neutralized suspicious call
    ...
```

**JSON Report** (`sanitize_report.json`):

```json
{
  "timestamp": "2025-11-02T07:22:38",
  "mode": "replace",
  "statistics": {
    "files_processed": 1,
    "lines_modified": 6,
    "apis_detected": 6
  },
  "files": [{
    "input_file": "malware.asm",
    "output_file": "malware_sanitized.asm",
    "original_sha256": "...",
    "sanitized_sha256": "...",
    "modifications": [
      {"line_number": 2, "original": "CALL InternetConnectA", "api": "InternetConnectA"}
    ],
    "detected_apis": ["InternetConnectA", "CreateFileA", "WriteFile", ...]
  }]
}
```

### Safety & Limitations

**⚠️ Important Disclaimers:**

- Does **NOT** guarantee safe or functional output
- May break legitimate code
- Cannot detect all malicious constructs (obfuscation, dynamic resolution)
- Sanitized files may still be dangerous
- **Use ONLY in isolated/sandboxed environments**
- Not intended for malware distribution or production use

**Safety Features:**

- Mandatory warning banner with user acknowledgment
- Never modifies original files (creates copies)
- Complete audit trail in JSON reports
- SHA256 hashing for integrity verification
- Educational use disclaimers in all outputs

---

## ⚡ Quick Start

### Installation

Both tools are ready to use with Python 3. No additional dependencies required beyond the existing MEEF environment.

```bash
# Make scripts executable (if needed)
chmod +x meef_cli.py sanitize_asm.py

# View help
python3 meef_cli.py --help
python3 sanitize_asm.py --help
```

### Test with Sample File

```bash
# 1. Process a sample with CLI
python3 meef_cli.py --file samples/dummy/test_malware.asm --verbose

# 2. Check the IR output
cat output/ir_results/test_malware_ir.json

# 3. Sanitize the same file (will prompt for safety acknowledgment)
python3 sanitize_asm.py --file samples/dummy/test_malware.asm --mode noop --verbose

# 4. Review sanitization report
cat sanitize_report.json
```

---

## 🔗 Integration Guide

### For Backend/API Integration

**Option 1: File-Based Workflow**

```python
import subprocess
import json

# Process sample
subprocess.run(['python3', 'meef_cli.py', '--file', 'uploaded.asm', '--no-catalog-update'])

# Read IR
with open('output/ir_results/uploaded_ir.json') as f:
    ir_data = json.load(f)

# Sanitize (bypass warning for automated use)
subprocess.run(['python3', 'sanitize_asm.py', '--file', 'uploaded.asm', '--no-warning'])

# Read report
with open('sanitize_report.json') as f:
    sanitizer_report = json.load(f)
```

**Option 2: Library Import (Recommended)**

```python
from meef_cli import MEEFCLIProcessor
from sanitize_asm import ASMSanitizer
from pathlib import Path

# Process sample
processor = MEEFCLIProcessor()
success = processor.process_sample(
    Path('uploaded.asm'),
    label='unknown',
    update_catalog=True,
    verbose=False
)

# Sanitize
sanitizer = ASMSanitizer(mode='replace')
report = sanitizer.sanitize_file(
    Path('uploaded.asm'),
    Path('sanitized/uploaded_clean.asm'),
    verbose=False
)
```

### For Frontend Integration

**API Endpoint Example** (Flask):

```python
@app.route('/api/analyze', methods=['POST'])
def analyze_sample():
    file = request.files['sample']
    file_path = f'samples/uploaded/{file.filename}'
    file.save(file_path)

    # Process
    processor = MEEFCLIProcessor()
    processor.process_sample(Path(file_path))

    # Read IR
    ir_path = f'output/ir_results/{Path(file_path).stem}_ir.json'
    with open(ir_path) as f:
        ir_data = json.load(f)

    return jsonify({
        'ir': ir_data,
        'catalog_updated': True
    })

@app.route('/api/sanitize', methods=['POST'])
def sanitize_sample():
    sha256 = request.json['sha256']
    mode = request.json.get('mode', 'replace')

    # Get file from catalog
    original_path = get_file_by_sha(sha256)

    # Sanitize
    sanitizer = ASMSanitizer(mode=mode)
    output_path = Path(f'sanitized/{Path(original_path).stem}_clean.asm')
    report = sanitizer.sanitize_file(Path(original_path), output_path)

    return jsonify({
        'sanitized_url': f'/downloads/{output_path.name}',
        'report': report,
        'warning': '⚠️ EDUCATIONAL USE ONLY'
    })
```

---

## 📚 Documentation

### Complete Documentation Files

- **`CLI_USAGE.md`** - Comprehensive user guide with detailed examples
- **`IMPLEMENTATION_SUMMARY.md`** - Technical implementation details and architecture
- **`QUICK_REFERENCE.md`** - Command cheat sheet for quick lookup

### Help Commands

```bash
# View built-in help
python3 meef_cli.py --help
python3 sanitize_asm.py --help
```

---

## 🧪 Testing & Validation

Both tools have been thoroughly tested:

### MEEF CLI Tests ✅

- Single file processing: PASS
- Directory scanning (recursive): PASS
- Batch list processing: PASS
- Parallel processing: PASS
- Dry-run mode: PASS
- Catalog updates: PASS
- Error handling: PASS

### ASM Sanitizer Tests ✅

- noop mode (annotation): PASS
- replace mode (NOP substitution): PASS
- remove mode (line deletion): PASS
- API detection (6/6 in test): PASS
- JSON report generation: PASS
- Safety warnings: PASS
- User acknowledgment: PASS

---

## 🎯 Use Cases

### 1. Batch Malware Analysis

```bash
# Process entire malware corpus with parallel workers
python3 meef_cli.py --path datasets/malware/ --label malicious --parallel 8
```

### 2. Research Dataset Preparation

```bash
# Process benign samples separately
python3 meef_cli.py --path datasets/benign/ --label benign --parallel 4
```

### 3. Educational Demonstrations

```bash
# Show malware neutralization concept
python3 sanitize_asm.py --file demo_malware.asm --mode replace --verbose
```

### 4. Automated Pipeline

```bash
# Non-interactive processing in CI/CD
python3 meef_cli.py --batch daily_samples.txt --label unknown --stop-on-error
```

---

## ⚙️ Configuration

### Custom API Blacklist

Create `custom_rules.json`:

```json
{
  "blacklist": [
    "InternetConnectA",
    "CreateFileA",
    "WriteFile",
    "VirtualAlloc",
    "CreateRemoteThread",
    "RegSetValueExA"
  ]
}
```

Use with sanitizer:

```bash
python3 sanitize_asm.py --file malware.asm --rules custom_rules.json
```

### Batch File Format

Create `samples_list.txt`:

```
samples/malware1.asm
samples/malware2.asm
samples/malware3.asm
```

Process batch:

```bash
python3 meef_cli.py --batch samples_list.txt --label unknown
```

---

## 🚨 Troubleshooting

### Common Issues

**Parser Not Found**

```bash
chmod +x src/cd_frontend/meef_parser
```

**Permission Errors**

```bash
# Check file permissions
ls -la samples/
chmod +r samples/*.asm
```

**No Files Found**

```bash
# Verify file discovery
python3 meef_cli.py --path samples/ --dry-run
```

**Sanitizer JSON Errors**

```bash
# Validate custom rules
cat custom_rules.json | python3 -m json.tool
```

---

## 📊 Performance Tips

### MEEF CLI Optimization

- Use `--parallel 4` to `--parallel 8` for large batches
- Monitor system resources (CPU, memory)
- Use `--no-catalog-update` for testing iterations
- Enable `--verbose` only for debugging

### ASM Sanitizer Optimization

- Start with `--mode noop` for analysis
- Use `--dry-run` to preview batch operations
- Process large directories in chunks
- Review JSON reports before sanitizing more files

---

## 🤝 Contributing

These tools are part of the MEEF framework. For contributions:

1. Test thoroughly in isolated environments
2. Maintain safety warnings and disclaimers
3. Document new features in this README
4. Follow existing code style and error handling patterns

---

## 📄 License & Disclaimer

These tools are part of the MEEF (Malware Extraction & Evaluation Framework) for **educational and research purposes only**.

**DISCLAIMER**: The ASM sanitizer is a proof-of-concept and should only be used for academic research in controlled environments. The authors assume no responsibility for misuse or damage caused by these tools.

**Use responsibly and ethically. Comply with all applicable laws and regulations.**

---

## 🙏 Acknowledgments

- MEEF Framework: Compiler-inspired malware analysis pipeline
- Developed for academic research and education
- Part of cybersecurity curriculum demonstration

---

## 📞 Support

For issues or questions:

- Check existing documentation: `CLI_USAGE.md`, `IMPLEMENTATION_SUMMARY.md`
- Review troubleshooting section above
- Use `--help` flags for command reference
- Consult main MEEF documentation

---

**Version**: 1.0.0  
**Release Date**: November 2, 2025  
**Status**: Production Ready ✅  
**Tested**: Yes ✅  
**Safe**: Yes (Non-malicious) ✅
