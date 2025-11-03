# Meef

# MEeF — Malware Extraction & Evaluation Framework

## Overview
MEeF is a compiler-inspired malware analysis pipeline.  
It parses Windows executables (frontend), generates an intermediate feature representation (IR), and classifies them using ML models (backend).

## New CLI & Analysis Utilities (feature/cli-tools-and-sanitizer)

This branch adds several non-interactive, researcher-friendly tools to the MEEF workflow. They are implemented as separate scripts (no core changes to the orchestrator) and are intended for academic use only.

- `meef_cli.py` — A professional CLI wrapper for batch processing samples through the existing MEEF pipeline. Supports single files, directories, or batch lists; parallel processing; dry-run mode; and automatic catalog updates.
- `sanitize_asm.py` — An educational ASM sanitizer that detects suspicious API calls and offers three safety modes: `noop` (annotate), `replace` (NOP neutralization), and `remove` (delete lines). It produces JSON audit reports and never overwrites the original files.
- `classify_malware.py` — A heuristic classifier that scores IR JSON reports using rule-based mappings between behavior flags, API usage and opcode hints. Useful for quick triage and labeling before or alongside ML predictions.

See `CLI_FEATURES_README.md` for an in-depth feature guide and examples. A detailed taxonomy and classification guide is available in `docs/malware_classification.md`.

Notes:
- These utilities are provided for research and education. The sanitizer is a proof-of-concept and may break functionality or be incomplete; always run in isolated/sandboxed environments.
- Files created by these tools (reports, sanitized samples) are typically placed in `output/` or `samples/sanitized/` — add them to `.gitignore` if you don't want generated outputs tracked.

