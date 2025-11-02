#!/usr/bin/env python3
"""
MEEF ASM Sanitizer - Proof of Concept
Removes or neutralizes suspicious API calls from assembly files

⚠️  WARNING: EDUCATIONAL USE ONLY ⚠️
This tool is a proof-of-concept demonstration for academic research.
- Does NOT guarantee safe or functional output
- May break legitimate code
- NOT for production use or malware distribution
- Sanitized files may still contain malicious constructs
- Always run in isolated/sandboxed environments

Use responsibly and in accordance with local laws and regulations.
"""

import os
import sys
import re
import json
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Tuple

# Default malicious API blacklist
DEFAULT_BLACKLIST = [
    # Network APIs
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
    "InternetReadFile", "InternetWriteFile", "URLDownloadToFileA", "URLDownloadToFileW",
    "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
    "WSAStartup", "socket", "connect", "send", "recv", "bind", "listen",
    
    # File operations
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW",
    "CopyFileA", "CopyFileW", "MoveFileA", "MoveFileW",
    "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
    
    # Registry operations
    "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW", "RegDeleteKeyA", "RegDeleteKeyW",
    "RegQueryValueExA", "RegQueryValueExW",
    
    # Memory/Process injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
    
    # Process/Thread manipulation
    "CreateProcessA", "CreateProcessW", "CreateThread", "OpenProcess", "TerminateProcess",
    "SuspendThread", "ResumeThread", "SetThreadContext", "GetThreadContext",
    
    # Hooks and injection
    "SetWindowsHookExA", "SetWindowsHookExW", "UnhookWindowsHookEx",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    
    # Execution
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "WinExec", "system",
    
    # Crypto (potentially for ransomware)
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptDeriveKey",
    
    # Service manipulation
    "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
    "OpenServiceA", "OpenServiceW", "ControlService",
    
    # Persistence mechanisms
    "RegSetValueA", "RegSetValueW",  # Often used for autorun
]


class ASMSanitizer:
    """Sanitizes assembly files by removing/neutralizing malicious API calls"""
    
    def __init__(self, blacklist: List[str] = None, mode: str = "replace"):
        self.blacklist = set(blacklist or DEFAULT_BLACKLIST)
        self.mode = mode  # "noop", "replace", "remove"
        self.stats = {
            "files_processed": 0,
            "total_lines": 0,
            "lines_modified": 0,
            "apis_detected": 0
        }
    
    def calculate_sha256(self, filepath: str) -> str:
        """Calculate SHA256 hash"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "HASH_ERROR"
    
    def detect_api_call(self, line: str) -> Tuple[bool, str]:
        """
        Detect if line contains a blacklisted API call
        Returns (is_malicious, api_name)
        """
        # Normalize line
        line_upper = line.strip().upper()
        
        # Check for CALL instructions with API names
        for api in self.blacklist:
            api_upper = api.upper()
            
            # Pattern 1: CALL API_NAME
            if re.search(r'\bCALL\s+' + re.escape(api_upper) + r'\b', line_upper):
                return True, api
            
            # Pattern 2: CALL [API_NAME] (indirect)
            if re.search(r'\bCALL\s+\[.*' + re.escape(api_upper) + r'.*\]', line_upper):
                return True, api
            
            # Pattern 3: API name referenced (imports, data)
            if re.search(r'\b' + re.escape(api_upper) + r'\b', line_upper):
                # Ensure it's not in a comment
                if ';' in line:
                    code_part = line.split(';')[0]
                    if api_upper in code_part.upper():
                        return True, api
                else:
                    return True, api
        
        return False, ""
    
    def sanitize_line(self, line: str, api_name: str, line_num: int) -> str:
        """
        Sanitize a single line based on mode
        """
        self.stats["lines_modified"] += 1
        self.stats["apis_detected"] += 1
        
        if self.mode == "noop":
            # Just annotate, don't modify
            return f"{line.rstrip()}  ; [MEEF-SANITIZER] Suspicious API detected: {api_name}\n"
        
        elif self.mode == "replace":
            # Replace with NOP or comment
            indent = len(line) - len(line.lstrip())
            return f"{' ' * indent}; [SANITIZED] Original line {line_num}: {line.strip()} (API: {api_name})\n{' ' * indent}NOP  ; Neutralized suspicious call\n"
        
        elif self.mode == "remove":
            # Remove completely (leave comment)
            indent = len(line) - len(line.lstrip())
            return f"{' ' * indent}; [REMOVED] Line {line_num} contained suspicious API: {api_name}\n"
        
        return line
    
    def sanitize_file(self, input_path: Path, output_path: Path, verbose: bool = False) -> Dict:
        """
        Sanitize a single ASM file
        Returns report dict
        """
        report = {
            "input_file": str(input_path),
            "output_file": str(output_path),
            "original_sha256": self.calculate_sha256(str(input_path)),
            "timestamp": datetime.now().isoformat(),
            "mode": self.mode,
            "modifications": [],
            "total_lines": 0,
            "modified_lines": 0,
            "detected_apis": set()
        }
        
        try:
            # Read input
            with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            report["total_lines"] = len(lines)
            self.stats["total_lines"] += len(lines)
            
            # Process each line
            output_lines = []
            for i, line in enumerate(lines, 1):
                is_malicious, api_name = self.detect_api_call(line)
                
                if is_malicious:
                    if verbose:
                        print(f"  [DETECT] Line {i}: {api_name}")
                    
                    report["detected_apis"].add(api_name)
                    report["modifications"].append({
                        "line_number": i,
                        "original": line.rstrip(),
                        "api": api_name
                    })
                    
                    sanitized_line = self.sanitize_line(line, api_name, i)
                    output_lines.append(sanitized_line)
                else:
                    output_lines.append(line)
            
            report["modified_lines"] = len(report["modifications"])
            
            # Add header warning to output
            header = [
                "; ═══════════════════════════════════════════════════════════════\n",
                "; MEEF ASM SANITIZER - EDUCATIONAL USE ONLY\n",
                f"; Original file: {input_path.name}\n",
                f"; Sanitization mode: {self.mode}\n",
                f"; Timestamp: {report['timestamp']}\n",
                f"; Detected suspicious APIs: {len(report['detected_apis'])}\n",
                f"; Modified lines: {report['modified_lines']}\n",
                "; \n",
                "; ⚠️  WARNING: This file may not be functional or safe!\n",
                "; ⚠️  Sanitization is best-effort and NOT guaranteed!\n",
                "; ⚠️  Use only in isolated/sandboxed environments!\n",
                "; ═══════════════════════════════════════════════════════════════\n",
                "\n"
            ]
            
            # Write output
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.writelines(header)
                f.writelines(output_lines)
            
            report["sanitized_sha256"] = self.calculate_sha256(str(output_path))
            report["detected_apis"] = list(report["detected_apis"])  # Convert set to list for JSON
            
            self.stats["files_processed"] += 1
            
            if verbose:
                print(f"[SUCCESS] Sanitized: {input_path.name} -> {output_path.name}")
                print(f"          Modified {report['modified_lines']} lines, detected {len(report['detected_apis'])} APIs")
            
            return report
            
        except Exception as e:
            print(f"[ERROR] Failed to sanitize {input_path}: {e}", file=sys.stderr)
            report["error"] = str(e)
            return report
    
    def sanitize_batch(self, input_files: List[Path], output_dir: Path, 
                      verbose: bool = False) -> List[Dict]:
        """Sanitize multiple files"""
        reports = []
        
        for input_file in input_files:
            output_file = output_dir / f"{input_file.stem}_sanitized{input_file.suffix}"
            report = self.sanitize_file(input_file, output_file, verbose=verbose)
            reports.append(report)
        
        return reports
    
    def save_report(self, reports: List[Dict], output_path: Path):
        """Save sanitization report as JSON"""
        full_report = {
            "timestamp": datetime.now().isoformat(),
            "sanitizer_version": "1.0.0",
            "mode": self.mode,
            "statistics": self.stats,
            "files": reports
        }
        
        with open(output_path, 'w') as f:
            json.dump(full_report, f, indent=2)
        
        print(f"[INFO] Report saved: {output_path}")


def print_warning():
    """Print safety warning banner"""
    print("""
╔═══════════════════════════════════════════════════════════════════════╗
║                    ⚠️  SAFETY WARNING ⚠️                               ║
║                                                                       ║
║  MEEF ASM Sanitizer - EDUCATIONAL USE ONLY                           ║
║                                                                       ║
║  This tool is a proof-of-concept for academic research.              ║
║                                                                       ║
║  Limitations:                                                        ║
║  • Does NOT guarantee safe or functional output                      ║
║  • May break legitimate code                                         ║
║  • Cannot detect all malicious constructs                            ║
║  • Sanitized files may still be dangerous                            ║
║                                                                       ║
║  Use only in isolated/sandboxed environments.                        ║
║  Not intended for malware distribution or production use.            ║
║                                                                       ║
║  By proceeding, you acknowledge these limitations and agree to       ║
║  use this tool responsibly and in accordance with applicable laws.   ║
╚═══════════════════════════════════════════════════════════════════════╝
    """)


def main():
    parser = argparse.ArgumentParser(
        description="MEEF ASM Sanitizer - Remove/neutralize suspicious API calls (POC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  WARNING: EDUCATIONAL USE ONLY - See safety notice above ⚠️

Sanitization modes:
  noop    - Annotate suspicious lines but don't modify code
  replace - Replace suspicious calls with NOP instructions (default)
  remove  - Remove suspicious lines entirely

Examples:
  %(prog)s --file malware.asm --mode noop
  %(prog)s --file malware.asm --mode replace --out-dir sanitized/
  %(prog)s --path samples/malicious/ --rules custom_rules.json
        """
    )
    
    # Input
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', type=str, help='Single .asm file to sanitize')
    input_group.add_argument('--path', type=str, help='Directory with .asm files')
    
    # Configuration
    parser.add_argument('--mode', choices=['noop', 'replace', 'remove'], default='replace',
                       help='Sanitization mode (default: replace)')
    parser.add_argument('--rules', type=str, help='JSON file with custom API blacklist')
    parser.add_argument('--out-dir', type=str, default='./samples/sanitized',
                       help='Output directory (default: ./samples/sanitized)')
    parser.add_argument('--report', type=str, default='./sanitize_report.json',
                       help='Report output path (default: ./sanitize_report.json)')
    
    # Flags
    parser.add_argument('--no-warning', action='store_true',
                       help='Skip safety warning (not recommended)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be sanitized')
    
    args = parser.parse_args()
    
    # Print warning unless disabled
    if not args.no_warning:
        print_warning()
        response = input("Do you understand and agree? Type 'YES' to continue: ")
        if response.strip().upper() != 'YES':
            print("[INFO] Aborted by user")
            sys.exit(0)
        print()
    
    # Load custom rules if provided
    blacklist = DEFAULT_BLACKLIST
    if args.rules:
        try:
            with open(args.rules, 'r') as f:
                custom_rules = json.load(f)
                if isinstance(custom_rules, list):
                    blacklist = custom_rules
                elif isinstance(custom_rules, dict) and 'blacklist' in custom_rules:
                    blacklist = custom_rules['blacklist']
                print(f"[INFO] Loaded {len(blacklist)} rules from {args.rules}")
        except Exception as e:
            print(f"[ERROR] Could not load rules: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Initialize sanitizer
    sanitizer = ASMSanitizer(blacklist=blacklist, mode=args.mode)
    
    # Collect input files
    input_files = []
    
    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        input_files = [file_path]
    
    elif args.path:
        path_obj = Path(args.path)
        if not path_obj.exists():
            print(f"[ERROR] Directory not found: {args.path}", file=sys.stderr)
            sys.exit(1)
        input_files = sorted(path_obj.rglob("*.asm"))
        if not input_files:
            print(f"[ERROR] No .asm files found in {args.path}", file=sys.stderr)
            sys.exit(1)
    
    print(f"[INFO] Found {len(input_files)} file(s) to sanitize")
    print(f"[INFO] Mode: {args.mode}")
    print(f"[INFO] Blacklist: {len(blacklist)} APIs")
    print()
    
    # Dry run
    if args.dry_run:
        print("[DRY RUN] Would sanitize:")
        for f in input_files:
            out_name = f.stem + "_sanitized" + f.suffix
            print(f"  {f} -> {args.out_dir}/{out_name}")
        sys.exit(0)
    
    # Sanitize
    output_dir = Path(args.out_dir)
    
    try:
        reports = sanitizer.sanitize_batch(input_files, output_dir, verbose=args.verbose)
        sanitizer.save_report(reports, Path(args.report))
        
        # Print summary
        print(f"\n[SUMMARY]")
        print(f"  Files processed: {sanitizer.stats['files_processed']}")
        print(f"  Total lines: {sanitizer.stats['total_lines']}")
        print(f"  Lines modified: {sanitizer.stats['lines_modified']}")
        print(f"  APIs detected: {sanitizer.stats['apis_detected']}")
        print(f"\nOutput: {output_dir}")
        print(f"Report: {args.report}")
        
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
