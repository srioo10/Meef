#!/usr/bin/env python3
"""
MEEF CLI - Command-line interface for MEEF Orchestrator
Non-interactive batch processing with argparse support
"""

import os
import sys
import argparse
import subprocess
import json
import hashlib
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Optional
import concurrent.futures

class MEEFCLIProcessor:
    """Non-interactive MEEF processor for CLI usage"""
    
    def __init__(self, parser_path: str = "./src/cd_frontend/meef_parser",
                 output_dir: str = "./output/ir_results",
                 catalog_path: str = "./data/catalog.csv"):
        self.parser_path = parser_path
        self.output_dir = output_dir
        self.catalog_path = catalog_path
        self.success_count = 0
        self.failure_count = 0
        
    def calculate_sha256(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"[ERROR] Hashing {filepath}: {e}", file=sys.stderr)
            return "HASH_ERROR"
    
    def find_asm_files(self, path: str, recursive: bool = True) -> List[Path]:
        """Find all .asm files in path"""
        path_obj = Path(path)
        
        if path_obj.is_file():
            if path_obj.suffix.lower() == '.asm':
                return [path_obj]
            else:
                print(f"[WARNING] {path} is not a .asm file, skipping")
                return []
        
        if not path_obj.is_dir():
            print(f"[ERROR] Path does not exist: {path}", file=sys.stderr)
            return []
        
        if recursive:
            return sorted(path_obj.rglob("*.asm"))
        else:
            return sorted(path_obj.glob("*.asm"))
    
    def run_parser(self, input_file: Path, output_file: Path, verbose: bool = False) -> bool:
        """Run MEEF parser on a single file"""
        try:
            # Ensure output directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Check parser exists and is executable
            if not Path(self.parser_path).exists():
                print(f"[ERROR] Parser not found: {self.parser_path}", file=sys.stderr)
                return False
            
            # Run parser
            cmd = [self.parser_path, str(input_file), str(output_file)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if verbose and result.stdout:
                print(result.stdout)
            
            if result.returncode != 0:
                print(f"[ERROR] Parser failed for {input_file.name}", file=sys.stderr)
                if result.stderr:
                    print(f"  {result.stderr}", file=sys.stderr)
                return False
            
            return True
            
        except subprocess.TimeoutExpired:
            print(f"[ERROR] Parser timeout for {input_file.name}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[ERROR] Parser exception for {input_file.name}: {e}", file=sys.stderr)
            return False
    
    def update_catalog(self, sample_path: Path, ir_path: Path, label: str = "unknown") -> None:
        """Update catalog.csv with sample metadata"""
        sha256 = self.calculate_sha256(str(sample_path))
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M")
        source = "local"
        
        # Infer label from path if not specified
        if label == "unknown":
            path_str = str(sample_path).lower()
            if "malicious" in path_str or "malware" in path_str:
                label = "malicious"
            elif "benign" in path_str or "clean" in path_str:
                label = "benign"
        
        # Extract behavior notes from IR
        behavior_notes = []
        try:
            with open(ir_path, 'r') as f:
                ir_data = json.load(f)
                behavior = ir_data.get('behavior', {})
                
                if behavior.get('uses_network'): behavior_notes.append("network")
                if behavior.get('uses_fileops'): behavior_notes.append("fileops")
                if behavior.get('uses_registry'): behavior_notes.append("registry")
                if behavior.get('uses_memory'): behavior_notes.append("memory")
                if behavior.get('uses_injection'): behavior_notes.append("injection")
                if behavior.get('uses_crypto'): behavior_notes.append("crypto")
                if behavior.get('uses_persist'): behavior_notes.append("persistence")
        except Exception:
            pass
        
        notes = ", ".join(behavior_notes) if behavior_notes else "none"
        
        # Ensure catalog directory exists
        Path(self.catalog_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Check existing entries
        file_exists = Path(self.catalog_path).exists()
        existing_hashes = set()
        
        if file_exists:
            try:
                with open(self.catalog_path, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        existing_hashes.add(row.get('sha256', ''))
            except Exception:
                pass
        
        # Write header if new file
        if not file_exists or Path(self.catalog_path).stat().st_size == 0:
            with open(self.catalog_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['sha256', 'label', 'source', 'first_seen', 'local_path', 'ir_path', 'notes'])
        
        # Append entry if hash is new
        if sha256 not in existing_hashes:
            with open(self.catalog_path, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([sha256, label, source, timestamp, str(sample_path), str(ir_path), notes])
    
    def process_sample(self, sample_path: Path, label: str = "unknown", 
                      update_catalog: bool = True, verbose: bool = False) -> bool:
        """Process a single sample"""
        # Generate output path
        ir_filename = sample_path.stem + "_ir.json"
        ir_path = Path(self.output_dir) / ir_filename
        
        if verbose:
            print(f"[INFO] Processing {sample_path.name}...")
        
        # Run parser
        success = self.run_parser(sample_path, ir_path, verbose=verbose)
        
        if success:
            if update_catalog:
                self.update_catalog(sample_path, ir_path, label)
            if verbose:
                print(f"[SUCCESS] {sample_path.name} -> {ir_path}")
            self.success_count += 1
        else:
            self.failure_count += 1
        
        return success
    
    def process_batch(self, samples: List[Path], label: str = "unknown",
                     update_catalog: bool = True, verbose: bool = False,
                     parallel: int = 1, stop_on_error: bool = False) -> None:
        """Process multiple samples"""
        print(f"[INFO] Processing {len(samples)} sample(s)...")
        
        if parallel > 1:
            # Parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {
                    executor.submit(self.process_sample, sample, label, update_catalog, verbose): sample
                    for sample in samples
                }
                
                for future in concurrent.futures.as_completed(futures):
                    sample = futures[future]
                    try:
                        success = future.result()
                        if not success and stop_on_error:
                            print(f"[ERROR] Stopping on error as requested", file=sys.stderr)
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                    except Exception as e:
                        print(f"[ERROR] Exception processing {sample.name}: {e}", file=sys.stderr)
                        self.failure_count += 1
                        if stop_on_error:
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
        else:
            # Sequential processing
            for sample in samples:
                success = self.process_sample(sample, label, update_catalog, verbose)
                if not success and stop_on_error:
                    print(f"[ERROR] Stopping on error as requested", file=sys.stderr)
                    break
        
        # Print summary
        print(f"\n[SUMMARY]")
        print(f"  ✓ Successful: {self.success_count}")
        print(f"  ✗ Failed: {self.failure_count}")


def main():
    parser = argparse.ArgumentParser(
        description="MEEF CLI - Non-interactive malware analysis pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file samples/dummy/test.asm
  %(prog)s --path samples/malicious/ --label malicious --parallel 4
  %(prog)s --batch samples_list.txt --output-dir custom_output/
  %(prog)s --file test.asm --no-catalog-update --dry-run
        """
    )
    
    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', type=str, help='Single .asm file to process')
    input_group.add_argument('--path', type=str, help='Directory to scan for .asm files')
    input_group.add_argument('--batch', type=str, help='Text file with one .asm path per line')
    
    # Processing options
    parser.add_argument('--label', type=str, default='unknown',
                       help='Label for samples (unknown, benign, malicious)')
    parser.add_argument('--output-dir', type=str, default='./output/ir_results',
                       help='Output directory for IR JSONs (default: ./output/ir_results)')
    parser.add_argument('--catalog', type=str, default='./data/catalog.csv',
                       help='Path to catalog CSV (default: ./data/catalog.csv)')
    parser.add_argument('--parser', type=str, default='./src/cd_frontend/meef_parser',
                       help='Path to MEEF parser binary (default: ./src/cd_frontend/meef_parser)')
    
    # Flags
    parser.add_argument('--no-catalog-update', action='store_true',
                       help='Skip updating catalog.csv')
    parser.add_argument('--parallel', type=int, default=1, metavar='N',
                       help='Number of parallel workers (default: 1)')
    parser.add_argument('--stop-on-error', action='store_true',
                       help='Stop processing on first error')
    parser.add_argument('--no-recursive', action='store_true',
                       help='Do not recursively scan directories')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be processed without running')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize processor
    processor = MEEFCLIProcessor(
        parser_path=args.parser,
        output_dir=args.output_dir,
        catalog_path=args.catalog
    )
    
    # Collect samples
    samples = []
    
    if args.file:
        file_path = Path(args.file)
        if file_path.exists() and file_path.suffix.lower() == '.asm':
            samples = [file_path]
        else:
            print(f"[ERROR] File not found or not .asm: {args.file}", file=sys.stderr)
            sys.exit(1)
    
    elif args.path:
        samples = processor.find_asm_files(args.path, recursive=not args.no_recursive)
        if not samples:
            print(f"[ERROR] No .asm files found in {args.path}", file=sys.stderr)
            sys.exit(1)
    
    elif args.batch:
        try:
            with open(args.batch, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        file_path = Path(line)
                        if file_path.exists() and file_path.suffix.lower() == '.asm':
                            samples.append(file_path)
                        else:
                            print(f"[WARNING] Skipping invalid path: {line}")
        except Exception as e:
            print(f"[ERROR] Could not read batch file: {e}", file=sys.stderr)
            sys.exit(1)
    
    if not samples:
        print("[ERROR] No samples to process", file=sys.stderr)
        sys.exit(1)
    
    # Dry run
    if args.dry_run:
        print(f"[DRY RUN] Would process {len(samples)} sample(s):")
        for i, sample in enumerate(samples, 1):
            ir_name = sample.stem + "_ir.json"
            print(f"  {i}. {sample} -> {args.output_dir}/{ir_name}")
        sys.exit(0)
    
    # Process samples
    try:
        processor.process_batch(
            samples=samples,
            label=args.label,
            update_catalog=not args.no_catalog_update,
            verbose=args.verbose,
            parallel=args.parallel,
            stop_on_error=args.stop_on_error
        )
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user", file=sys.stderr)
        sys.exit(130)
    
    # Exit code based on results
    if processor.failure_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
