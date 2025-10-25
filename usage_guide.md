#  MEEF Usage Guide

## Quick Start

### 1. **Initial Setup** (One-time)

```bash
# Make setup script executable
chmod +x setup_meef.sh

# Run setup
./setup_meef.sh
```

This will:
-  Create all necessary directories
-  Build the CD front-end parser
-  Initialize `catalog.csv`
-  Make scripts executable

---

## 2. **Prepare Your Samples**

Place your assembly files (`.asm`) in the samples directory:

```
samples/
├── benign/
│   ├── notepad.asm
│   ├── calc.asm
│   └── paint.asm
├── malicious/
│   ├── trojan.asm
│   ├── ransomware.asm
│   └── backdoor.asm
└── dummy/
    └── fake.asm
```

**Creating test samples:**

```bash
# Create a test malware sample
cat > samples/dummy/test_malware.asm << 'EOF'
start:
    CALL InternetConnectA
    CALL CreateFileA
    CALL WriteFile
    CALL RegSetValueExA
    CALL VirtualAlloc
    CALL CreateRemoteThread
    MOV EAX, EBX
    JMP end
    RET
EOF
```

---

## 3. **Run MEEF Orchestrator**

```bash
python3 meef.py
```

### Interactive Flow:

**Step 1:** Enter samples directory path (or press Enter for default `./samples`)

```
Enter path to samples directory
(Press Enter for default: ./samples)
Path: 
```

**Step 2:** View found samples

```
Found 5 sample(s):

#    Filename                                 Size         Type      
──────────────────────────────────────────────────────────────────────
1    test_malware.asm                        245 B        ASM
2    trojan.asm                              1.2 KB       ASM 
3    backdoor.asm                            3.5 KB       ASM
4    notepad.asm                             890 B        ASM 
5    calc.asm                                1.1 KB       ASM 
```

**Step 3:** Choose processing mode

```
Options:
  [A] Process ALL samples
  [#] Process specific sample (enter number)
  [Q] Quit

Your choice: 
```

- Type `A` to process **all samples**
- Type a number (e.g., `1`) to process **one specific sample**
- Type `Q` to quit

**Step 4:** Watch the magic happen! 🎉

```
======================================================================
[1/5] Processing: test_malware.asm
======================================================================

╔══════════════════════════════════════════════════════════╗
║        MEEF Compiler Design Front-End (Phase B)         ║
╚══════════════════════════════════════════════════════════╝

[*] Starting lexical & syntax analysis on: samples/dummy/test_malware.asm
[✓] Parsing successful
[*] Opcodes found: 4
[*] API calls found: 6

[*] Running semantic analysis...
[✓] Semantic analysis complete

[*] Building Control Flow Graph...
[✓] CFG built: 10 blocks, 14 edges

[*] Generating Intermediate Representation...
[✓] IR written to: output/ir_results/test_malware_ir.json

╔══════════════════════════════════════════════════════════╗
║                    Analysis Summary                      ║
╠══════════════════════════════════════════════════════════╣
║ Network Operations    : YES
║ File Operations       : YES
║ Registry Operations   : YES
║ Memory Operations     : YES
║ Code Injection        : YES
║ Cryptography          : NO 
║ Persistence           : NO 
╠══════════════════════════════════════════════════════════╣
║ CFG Complexity        : 6.00
║ Branch Density        : 1.4000
╚══════════════════════════════════════════════════════════╝

Updating catalog...
✓ Catalog updated
```

---

## 4. **Check Your Results**

### View Generated IR Files

```bash
# List all IR files
ls -lh output/ir_results/

# View a specific IR file
cat output/ir_results/test_malware_ir.json

# Pretty print with jq (if installed)
cat output/ir_results/test_malware_ir.json | jq .
```

### View Catalog

```bash
# View the catalog
cat data/catalog.csv

# Or use column for better formatting
column -t -s, data/catalog.csv
```

**Example catalog.csv:**

```csv
sha256,label,source,first_seen,local_path,ir_path,notes
a3f2e1...,malicious,local,2025-10-26 14:30:22,samples/dummy/test_malware.asm,output/ir_results/test_malware_ir.json,"network, fileops, injection"
b7c4d9...,benign,local,2025-10-26 14:31:45,samples/benign/notepad.asm,output/ir_results/notepad_ir.json,"fileops"
```

---

## 5. **Advanced Usage**

### Process Specific Directory

```bash
# Process only malicious samples
python3 meef.py
# Enter: ./samples/malicious

# Process only benign samples
python3 meef.py
# Enter: ./samples/benign
```

### Batch Process from Command Line

You can also modify `meef.py` to accept command-line arguments:

```bash
# Process all samples in a directory
python3 meef.py --path ./samples/malicious --all

# Process a specific file
python3 meef.py --file ./samples/dummy/test.asm
```

---

## 6. **Integration with ML Pipeline**

The generated IR JSON files are ready for ML training:

```python
import json
import pandas as pd

# Load IR file
with open('output/ir_results/test_malware_ir.json', 'r') as f:
    ir_data = json.load(f)

# Extract features for ML
features = {
    'uses_network': ir_data['behavior']['uses_network'],
    'uses_fileops': ir_data['behavior']['uses_fileops'],
    'uses_injection': ir_data['behavior']['uses_injection'],
    'cfg_complexity': ir_data['cfg']['cyclomatic_complexity'],
    'branch_density': ir_data['cfg']['branch_density'],
    # ... add more features
}

# Create feature vector
df = pd.DataFrame([features])
```

---

## 7. **Troubleshooting**

### Parser Not Found

```
✗ Parser not found at: ./src/cd_frontend/meef_parser
Please build it first:
  cd src/cd_frontend && make
```

**Solution:**
```bash
cd src/cd_frontend
make clean && make
cd ../..
```

### No Samples Found

```
✗ No samples found!
Supported extensions: .asm, .exe, .dll
```

**Solution:**
- Verify samples exist in the directory
- Check file extensions (must be `.asm`, `.exe`, or `.dll`)
- Ensure correct path

### Permission Denied

```
Permission denied: ./meef.py
```

**Solution:**
```bash
chmod +x meef.py
```


Happy malware hunting! 🛡️🔍
