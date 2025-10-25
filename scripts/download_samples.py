#!/usr/bin/env python3
"""
MalwareBazaar Sample Downloader
Downloads malware samples from MalwareBazaar API
"""

import requests
import json
import hashlib
from pathlib import Path
from datetime import datetime
import time

class MalwareBazaarDownloader:
    def __init__(self, output_dir="samples/malicious"):
        self.api_url = "https://mb-api.abuse.ch/api/v1/"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def query_recent_samples(self, limit=10):
        """Query recent malware samples"""
        print(f"\n[*] Querying MalwareBazaar for recent samples...")
        
        data = {
            'query': 'get_recent',
            'selector': limit
        }
        
        try:
            response = requests.post(self.api_url, data=data, timeout=30)
            result = response.json()
            
            if result.get('query_status') == 'ok':
                samples = result.get('data', [])
                print(f"[✓] Found {len(samples)} samples")
                return samples
            else:
                print(f"[✗] Query failed: {result.get('query_status')}")
                return []
                
        except Exception as e:
            print(f"[✗] Error querying API: {e}")
            return []
    
    def query_by_tag(self, tag, limit=10):
        """Query samples by tag (e.g., 'ransomware', 'trojan')"""
        print(f"\n[*] Querying samples with tag: {tag}")
        
        data = {
            'query': 'get_taginfo',
            'tag': tag,
            'limit': limit
        }
        
        try:
            response = requests.post(self.api_url, data=data, timeout=30)
            result = response.json()
            
            if result.get('query_status') == 'ok':
                samples = result.get('data', [])
                print(f"[✓] Found {len(samples)} samples with tag '{tag}'")
                return samples
            else:
                print(f"[✗] Query failed: {result.get('query_status')}")
                return []
                
        except Exception as e:
            print(f"[✗] Error querying API: {e}")
            return []
    
    def download_sample(self, sha256_hash):
        """Download a specific sample by SHA256"""
        print(f"\n[*] Downloading sample: {sha256_hash[:16]}...")
        
        data = {
            'query': 'get_file',
            'sha256_hash': sha256_hash
        }
        
        try:
            response = requests.post(self.api_url, data=data, timeout=60)
            
            if response.status_code == 200:
                # Save the zip file
                output_file = self.output_dir / f"{sha256_hash}.zip"
                with open(output_file, 'wb') as f:
                    f.write(response.content)
                
                print(f"[✓] Downloaded: {output_file}")
                print(f"    Password: 'infected' (standard)")
                return output_file
            else:
                print(f"[✗] Download failed: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[✗] Error downloading: {e}")
            return None
    
    def display_samples(self, samples):
        """Display sample information"""
        print(f"\n{'='*80}")
        print(f"{'#':<4} {'SHA256':<20} {'File Type':<12} {'Signature':<25} {'Tags'}")
        print(f"{'='*80}")
        
        for idx, sample in enumerate(samples[:20], 1):  # Show first 20
            sha256 = sample.get('sha256', 'N/A')[:16] + "..."
            file_type = sample.get('file_type', 'N/A')
            signature = sample.get('signature', 'Generic')[:23]
            tags = ', '.join(sample.get('tags', [])[:2])
            
            print(f"{idx:<4} {sha256:<20} {file_type:<12} {signature:<25} {tags}")
        
        print(f"{'='*80}\n")
    
    def save_metadata(self, samples, filename="malware_metadata.json"):
        """Save sample metadata for later use"""
        metadata_file = self.output_dir / filename
        
        with open(metadata_file, 'w') as f:
            json.dump(samples, f, indent=2)
        
        print(f"[✓] Metadata saved to: {metadata_file}")
    
    def interactive_download(self):
        """Interactive download mode"""
        print("\n" + "="*80)
        print("          MalwareBazaar Sample Downloader")
        print("="*80)
        print("\n⚠️  WARNING: You are about to download REAL MALWARE!")
        print("   - Only use in isolated VM")
        print("   - Never execute downloaded files")
        print("   - Keep files password protected (password: 'infected')")
        print("\n" + "="*80)
        
        confirm = input("\nContinue? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("Aborted.")
            return
        
        print("\nOptions:")
        print("  [1] Download recent samples")
        print("  [2] Download by tag (ransomware, trojan, etc.)")
        print("  [3] Download specific SHA256")
        print("  [Q] Quit")
        
        choice = input("\nYour choice: ").strip()
        
        if choice == '1':
            limit = input("How many samples? (default 10): ").strip()
            limit = int(limit) if limit.isdigit() else 10
            
            samples = self.query_recent_samples(limit)
            if samples:
                self.display_samples(samples)
                self.save_metadata(samples)
                
                download = input("\nDownload these samples? (yes/no): ").strip().lower()
                if download == 'yes':
                    for sample in samples[:limit]:
                        sha256 = sample.get('sha256')
                        if sha256:
                            self.download_sample(sha256)
                            time.sleep(2)  # Be nice to the API
        
        elif choice == '2':
            print("\nPopular tags: ransomware, trojan, banker, stealer, loader, rat")
            tag = input("Enter tag: ").strip()
            limit = input("How many samples? (default 10): ").strip()
            limit = int(limit) if limit.isdigit() else 10
            
            samples = self.query_by_tag(tag, limit)
            if samples:
                self.display_samples(samples)
                self.save_metadata(samples, f"malware_{tag}_metadata.json")
                
                download = input("\nDownload these samples? (yes/no): ").strip().lower()
                if download == 'yes':
                    for sample in samples[:limit]:
                        sha256 = sample.get('sha256')
                        if sha256:
                            self.download_sample(sha256)
                            time.sleep(2)
        
        elif choice == '3':
            sha256 = input("Enter SHA256 hash: ").strip()
            self.download_sample(sha256)
        
        elif choice.upper() == 'Q':
            print("Goodbye!")
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    downloader = MalwareBazaarDownloader()
    
    try:
        downloader.interactive_download()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n[✗] Fatal error: {e}")
