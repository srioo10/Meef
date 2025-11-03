# MEEF CLI Tools - Quick Reference Card

## MEEF CLI (meef_cli.py)

### Common Commands

```bash
# Single file
python3 meef_cli.py --file samples/test.asm

# Directory (recursive)
python3 meef_cli.py --path samples/malicious/ --label malicious

# Parallel processing
python3 meef_cli.py --path samples/ --parallel 4

# Dry run (test before running)
python3 meef_cli.py --path samples/ --dry-run

# Verbose mode
python3 meef_cli.py --file test.asm --verbose
```

### Key Options

| Option                | Description                     |
| --------------------- | ------------------------------- |
| `--file`              | Single .asm file                |
| `--path`              | Directory to scan               |
| `--batch`             | File list (one per line)        |
| `--label`             | Label: unknown/benign/malicious |
| `--parallel N`        | Use N workers                   |
| `--dry-run`           | Preview without processing      |
| `--verbose`           | Detailed output                 |
| `--no-catalog-update` | Skip catalog.csv                |

---

## ASM Sanitizer (sanitize_asm.py)

### ⚠️ EDUCATIONAL USE ONLY ⚠️

### Common Commands

```bash
# Analyze only (safest)
python3 sanitize_asm.py --file malware.asm --mode noop

# Neutralize with NOPs (default)
python3 sanitize_asm.py --file malware.asm --mode replace

# Remove malicious lines
python3 sanitize_asm.py --file malware.asm --mode remove

# Batch process directory
python3 sanitize_asm.py --path samples/malicious/ --verbose
```

### Modes

| Mode      | Action            | Safety             |
| --------- | ----------------- | ------------------ |
| `noop`    | Annotate only     | ⭐⭐⭐ Safest      |
| `replace` | Replace with NOPs | ⭐⭐ Default       |
| `remove`  | Delete lines      | ⭐ Most aggressive |

### Key Options

| Option         | Description           |
| -------------- | --------------------- |
| `--file`       | Single .asm file      |
| `--path`       | Directory to scan     |
| `--mode`       | noop/replace/remove   |
| `--rules`      | Custom blacklist JSON |
| `--out-dir`    | Output directory      |
| `--report`     | Report JSON path      |
| `--verbose`    | Show detections       |
| `--no-warning` | Skip safety prompt    |

---

## Output Locations

| Tool      | Output        | Default Path                             |
| --------- | ------------- | ---------------------------------------- |
| CLI       | IR JSON       | `output/ir_results/<name>_ir.json`       |
| CLI       | Catalog       | `data/catalog.csv`                       |
| Sanitizer | Sanitized ASM | `samples/sanitized/<name>_sanitized.asm` |
| Sanitizer | Report        | `./sanitize_report.json`                 |

---

## Quick Tests

```bash
# Test CLI
python3 meef_cli.py --file samples/dummy/test_malware.asm --verbose

# Test Sanitizer
echo "YES" | python3 sanitize_asm.py --file samples/dummy/test_malware.asm --mode noop --verbose

# View results
cat output/ir_results/test_malware_ir.json
cat sanitize_report.json
cat samples/sanitized/test_malware_sanitized.asm
```

---

## Help Commands

```bash
python3 meef_cli.py --help
python3 sanitize_asm.py --help
```

---

## Integration (For Frontend)

### File-Based

```python
# Process sample
subprocess.run(['python3', 'meef_cli.py', '--file', 'uploaded.asm'])

# Read IR
with open('output/ir_results/uploaded_ir.json') as f:
    ir = json.load(f)

# Sanitize
subprocess.run(['python3', 'sanitize_asm.py', '--file', 'uploaded.asm', '--no-warning'])

# Read report
with open('sanitize_report.json') as f:
    report = json.load(f)
```

### Library-Based (Recommended)

```python
from meef_cli import MEEFCLIProcessor
from sanitize_asm import ASMSanitizer

# Process
processor = MEEFCLIProcessor()
processor.process_sample(Path('uploaded.asm'))

# Sanitize
sanitizer = ASMSanitizer(mode='replace')
report = sanitizer.sanitize_file(input_path, output_path)
```

---

## Safety Checklist

- [ ] Running in isolated VM/container
- [ ] Not on production network
- [ ] Have backups of originals
- [ ] Understand limitations
- [ ] Comply with local laws

---

## Documentation

- **Full Guide**: `CLI_USAGE.md`
- **Implementation Details**: `IMPLEMENTATION_SUMMARY.md`
- **Help**: `--help` flag on each tool

---

**Project**: MEEF (Malware Extraction & Evaluation Framework)  
**Version**: 1.0.0  
**Date**: November 2, 2025
