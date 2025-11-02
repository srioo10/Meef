# MEEF CLI Tools Usage Guide

This document describes the two new CLI tools added to MEEF: **meef_cli.py** and **sanitize_asm.py**.

---

## 1. MEEF CLI (`meef_cli.py`)

Non-interactive command-line interface for batch processing malware samples through the MEEF pipeline.

### Features

- Process single files or entire directories
- Batch processing from file lists
- Parallel processing support
- Automatic catalog updates
- Dry-run mode for testing
- Flexible output configuration

### Basic Usage

```bash
# Process a single file
python3 meef_cli.py --file samples/dummy/test_malware.asm

# Process all .asm files in a directory
python3 meef_cli.py --path samples/malicious/ --label malicious

# Parallel processing (4 workers)
python3 meef_cli.py --path samples/ --parallel 4

# Process from a batch list
python3 meef_cli.py --batch sample_list.txt --label unknown

# Dry run (show what would be processed)
python3 meef_cli.py --path samples/ --dry-run

# Verbose output
python3 meef_cli.py --file test.asm --verbose
```

### Arguments

**Input Sources (required, mutually exclusive):**

- `--file <path>` - Single .asm file to process
- `--path <dir>` - Directory to scan for .asm files (recursive by default)
- `--batch <file>` - Text file with one .asm path per line

**Processing Options:**

- `--label <string>` - Label for samples (unknown, benign, malicious) [default: unknown]
- `--output-dir <path>` - Output directory for IR JSONs [default: ./output/ir_results]
- `--catalog <path>` - Path to catalog CSV [default: ./data/catalog.csv]
- `--parser <path>` - Path to MEEF parser binary [default: ./src/cd_frontend/meef_parser]

**Flags:**

- `--no-catalog-update` - Skip updating catalog.csv
- `--parallel N` - Number of parallel workers [default: 1]
- `--stop-on-error` - Stop processing on first error
- `--no-recursive` - Don't recursively scan directories
- `--dry-run` - Show what would be processed without running
- `--verbose`, `-v` - Verbose output

### Examples

```bash
# Process all malicious samples with labeling
python3 meef_cli.py --path samples/malicious/ --label malicious --verbose

# Fast parallel processing
python3 meef_cli.py --path samples/ --parallel 8

# Custom output directory without catalog update
python3 meef_cli.py --file test.asm --output-dir /tmp/ir_output --no-catalog-update

# Process batch list with error handling
python3 meef_cli.py --batch high_priority.txt --stop-on-error
```

### Exit Codes

- `0` - All samples processed successfully
- `1` - One or more samples failed (but processing continued)
- `130` - Interrupted by user (Ctrl+C)

---

## 2. ASM Sanitizer (`sanitize_asm.py`)

Proof-of-concept tool to remove or neutralize suspicious API calls from assembly files.

### ⚠️ **IMPORTANT SAFETY WARNINGS** ⚠️

**EDUCATIONAL USE ONLY**

This tool is a **proof-of-concept** for academic research:

- Does **NOT** guarantee safe or functional output
- May break legitimate code
- Cannot detect all malicious constructs
- Sanitized files may still be dangerous
- Use **only in isolated/sandboxed environments**
- Not intended for malware distribution or production use

### Features

- Three sanitization modes (noop, replace, remove)
- Comprehensive API blacklist (87+ suspicious APIs)
- Custom rule support
- Detailed JSON reports
- Batch processing

### Sanitization Modes

1. **noop** - Annotate suspicious lines without modification (safest)
2. **replace** - Replace suspicious calls with NOP instructions (default)
3. **remove** - Completely remove suspicious lines (most aggressive)

### Basic Usage

```bash
# Annotate only (safest, for analysis)
python3 sanitize_asm.py --file malware.asm --mode noop

# Replace malicious calls with NOPs
python3 sanitize_asm.py --file malware.asm --mode replace

# Remove malicious lines entirely
python3 sanitize_asm.py --file malware.asm --mode remove

# Process entire directory
python3 sanitize_asm.py --path samples/malicious/ --mode replace

# Custom output directory
python3 sanitize_asm.py --file malware.asm --out-dir cleaned/

# Verbose output
python3 sanitize_asm.py --file malware.asm --verbose
```

### Arguments

**Input (required, mutually exclusive):**

- `--file <path>` - Single .asm file to sanitize
- `--path <dir>` - Directory with .asm files

**Configuration:**

- `--mode <mode>` - Sanitization mode: noop, replace, remove [default: replace]
- `--rules <json>` - JSON file with custom API blacklist
- `--out-dir <path>` - Output directory [default: ./samples/sanitized]
- `--report <path>` - Report output path [default: ./sanitize_report.json]

**Flags:**

- `--no-warning` - Skip safety warning (not recommended)
- `--verbose`, `-v` - Verbose output
- `--dry-run` - Show what would be sanitized

### Custom Rules

Create a JSON file with custom API blacklist:

```json
{
  "blacklist": [
    "InternetConnectA",
    "CreateFileA",
    "WriteFile",
    "VirtualAlloc",
    "CreateRemoteThread"
  ]
}
```

Then use: `python3 sanitize_asm.py --file malware.asm --rules custom_rules.json`

### Default Blacklist Categories

The tool includes 87+ dangerous APIs across categories:

- **Network**: InternetOpen, socket, connect, send, recv, etc.
- **File Operations**: CreateFile, WriteFile, DeleteFile, CopyFile, etc.
- **Registry**: RegOpenKey, RegSetValue, RegCreateKey, etc.
- **Memory/Injection**: VirtualAlloc, WriteProcessMemory, CreateRemoteThread, etc.
- **Process Control**: CreateProcess, OpenProcess, TerminateProcess, etc.
- **Hooks**: SetWindowsHookEx, LoadLibrary, GetProcAddress
- **Execution**: ShellExecute, WinExec, system
- **Cryptography**: CryptEncrypt, CryptDecrypt (ransomware-related)
- **Services**: CreateService, StartService, etc.

### Output Files

**Sanitized ASM File:**

- Located in `--out-dir` (default: `samples/sanitized/`)
- Named: `<original_name>_sanitized.asm`
- Contains safety header with warnings
- Preserves original with modifications clearly marked

**JSON Report:**

- Detailed sanitization report
- Lists all detected APIs and modifications
- Includes before/after SHA256 hashes
- Line-by-line modification details

### Examples

```bash
# Analyze without modifying (safest)
python3 sanitize_asm.py --file malware.asm --mode noop --verbose

# Sanitize with custom rules
python3 sanitize_asm.py --file malware.asm --rules my_rules.json --mode replace

# Batch sanitize entire directory
python3 sanitize_asm.py --path samples/malicious/ --mode replace --out-dir cleaned/

# Generate detailed report
python3 sanitize_asm.py --file malware.asm --report detailed_report.json --verbose

# Remove all dangerous calls
python3 sanitize_asm.py --file malware.asm --mode remove
```

### Understanding the Report

The JSON report includes:

```json
{
  "timestamp": "2025-11-02T07:22:38.417403",
  "mode": "replace",
  "statistics": {
    "files_processed": 1,
    "total_lines": 11,
    "lines_modified": 6,
    "apis_detected": 6
  },
  "files": [
    {
      "input_file": "samples/dummy/test_malware.asm",
      "output_file": "samples/sanitized/test_malware_sanitized.asm",
      "original_sha256": "...",
      "sanitized_sha256": "...",
      "modifications": [
        {
          "line_number": 2,
          "original": "CALL InternetConnectA",
          "api": "InternetConnectA"
        }
      ],
      "detected_apis": ["InternetConnectA", "CreateFileA", ...]
    }
  ]
}
```

---

## Integration with Frontend

Both tools are designed to be called from a backend server or used directly:

### File-Based Integration

1. Upload `.asm` file to `samples/uploaded/`
2. Call CLI: `python3 meef_cli.py --file path/to/file.asm`
3. Read IR from `output/ir_results/<name>_ir.json`
4. Optionally sanitize: `python3 sanitize_asm.py --file path/to/file.asm`
5. Read sanitized file and report

### API Integration (Future)

- Wrap these tools in Flask endpoints
- Stream progress for long operations
- Return JSON responses directly

---

## Tips & Best Practices

### MEEF CLI

- Use `--dry-run` first to verify file discovery
- Enable `--parallel` for large batches (4-8 workers recommended)
- Use `--verbose` for debugging
- Keep original `--label` consistent for training data
- Monitor catalog size over time

### ASM Sanitizer

- **Always use in isolated environment** (VM, container, sandbox)
- Start with `--mode noop` to analyze before modifying
- Review the JSON report for full context
- Never execute sanitized files without proper isolation
- Document sanitization in your analysis notes
- Keep original files for reference

### Safety Checklist

- [ ] Running in isolated environment (VM/container)
- [ ] Not connected to production networks
- [ ] Have backups of original files
- [ ] Understand limitations of sanitization
- [ ] Documented safety precautions in project
- [ ] Comply with local laws and regulations

---

## Troubleshooting

**CLI Issues:**

```bash
# Parser not found
chmod +x src/cd_frontend/meef_parser

# Permission errors
ls -la samples/  # Check read permissions

# No files found
python3 meef_cli.py --path samples/ --dry-run  # Verify discovery
```

**Sanitizer Issues:**

```bash
# Custom rules not loading
cat custom_rules.json | python3 -m json.tool  # Validate JSON

# Output directory issues
mkdir -p samples/sanitized  # Ensure directory exists
```

---

## License & Disclaimer

These tools are part of the MEEF framework for educational and research purposes.

**DISCLAIMER:** The sanitizer is a proof-of-concept and should only be used for academic research in controlled environments. The authors assume no responsibility for misuse or damage caused by these tools.

Use responsibly and ethically.
