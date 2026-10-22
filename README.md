# Meef

# MEeF — Malware Extraction & Evaluation Framework

## Overview

MEeF is a compiler-inspired malware analysis pipeline.  
It parses Windows executables (frontend), generates an intermediate feature representation (IR), and classifies them using ML models (backend).

## Workflow
The raw file is parsed into a control flow graph (CFG) and opcode tokens, from which IR features like API ratios and instruction density are extracted for a dual-scoring classifier (ML + behavioral heuristics).

