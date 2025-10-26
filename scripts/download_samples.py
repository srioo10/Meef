#!/usr/bin/env python3
"""
MalwareBazaar Sample Downloader (with API Key support)
Downloads malware samples from MalwareBazaar API
"""

import requests
import json
from pathlib import Path
from datetime import datetime
import time
import sys
import os

class MalwareBazaarDownloader:
    def __init__(self, api_key=None, output_dir="samples/malicious"):
        self.api_url = "https://mb-api.abuse.ch/api/v1/"
        self.api_key = api_key or os.environ.get('MALWAREBAZAAR_API_KEY')
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def get_api_key(self):
        """Get API key from user or environment"""
        if self.api_key:
            return self.api_key
        
        # Check if stored in a config file
        config_file = Path('.malwarebazaar_api_key')
        if config_file.exists():
            with open(config_file, 'r') as f:
                self.api_key = f.read().strip()
                print(f"[✓] Loaded API key from {config_file}")
                return self.api_key
        
        # Ask user
        print("\n" + "="*70)
        print("MalwareBazaar API Key Required")
        print("="*70)
        print("\nYou need an API key to download samples.")
        print("\n1. Go to: https://bazaar.abuse.ch/api/")
        print("2. Click 'Request API Key'")
        print("3. Fill out the form (it's free!)")
        print("4. You'll receive the key via email")
        print("\n" + "="*70)
        
        api_key = input("\nEnter your API key (or press Enter to skip): ").strip()
        
        if api_key:
            # Save for future use
            save = input("Save API key for future use? (yes/no): ").strip().lower()
            if save == 'yes':
                with open(config_file, 'w') as f:
                    f.write(api_key)
                os.chmod(config_file, 0o600)  # Read/write for owner only
                print(f"[✓] API key saved to {config_file}")
            
            self.api_key = api_key
            return self.api_key
        
        return None
        
    def query_recent_samples(self, limit=10):
        """Query recent malware samples"""
        print(f"\n[*] Querying MalwareBazaar for recent samples...")
        
        if not self.api_key:
            print("[✗] API key required for this operation")
            return []
        
        headers = {
            'API-KEY': self.api_key,
            'User-Agent': 'MEEF-Research-Tool'
        }
        
        data = {
            'query': 'get_recent',
            'selector': str(limit)
        }
        
        try:
            response = requests.post(
                self.api_url, 
                data=data,
                headers=headers,
                timeout=30
            )
            
            print(f"[DEBUG] Status Code: {response.status_code}")
            
            if response.status_code == 401:
                print(f"[✗] Unauthorized - Invalid API key")
                print(f"    Get your API key from: https://bazaar.abuse.ch/api/")
                return []
            
            if response.status_code != 200:
                print(f"[✗] HTTP Error: {response.status_code}")
                print(f"[DEBUG] Response: {response.text[:200]}")
                return []
            
            try:
                result = response.json()
            except json.JSONDecodeError as e:
                print(f"[✗] JSON decode error: {e}")
                return []
            
            if result.get('query_status') == 'ok':
                samples = result.get('data', [])
                print(f"[✓] Found {len(samples)} samples")
                return samples
            else:
                print(f"[✗] Query failed: {result.get('query_status')}")
                return []
                
        except requests.exceptions.Timeout:
            print("[✗] Request timed out. Try again later.")
            return []
        except Exception as e:
            print(f"[✗] Error: {e}")
            return []
    
    def query_by_tag(self, tag, limit=10):
        """Query samples by tag"""
        print(f"\n[*] Querying samples with tag: {tag}")
        
        if not self.api_key:
            print("[✗] API key required for this operation")
            return []
        
        headers = {
            'API-KEY': self.api_key,
            'User-Agent': 'MEEF-Research-Tool'
        }
        
        data = {
            'query': 'get_taginfo',
            'tag': tag,
            'limit': str(limit)
        }
        
        try:
            response = requests.post(
                self.api_url,
                data=data,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 401:
                print(f"[✗] Unauthorized - Invalid API key")
                return []
            
            if response.status_code != 200:
                print(f"[✗] HTTP Error: {response.status_code}")
                return []
            
            result = response.json()
            
            if result.get('query_status') == 'ok':
                samples = result.get('data', [])
                print(f"[✓] Found {len(samples)} samples with tag '{tag}'")
                return samples
            else:
                print(f"[✗] Query failed: {result.get('query_status')}")
                return []
                
        except Exception as e:
            print(f"[✗] Error: {e}")
            return []
    
    def download_sample(self, sha256_hash):
        """Download a specific sample by SHA256"""
        print(f"\n[*] Downloading sample: {sha256_hash[:16]}...")
        
        if not self.api_key:
            print("[✗] API key required for downloads")
            return None
        
        headers = {
            'API-KEY': self.api_key,
            'User-Agent': 'MEEF-Research-Tool'
        }
        
        data = {
            'query': 'get_file',
            'sha256_hash': sha256_hash
        }
        
        try:
            response = requests.post(
                self.api_url,
                data=data,
                headers=headers,
                timeout=60
            )
            
            if response.status_code == 401:
                print(f"[✗] Unauthorized - Invalid API key")
                return None
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                
                if 'application/json' in content_type:
                    result = response.json()
                    print(f"[✗] Download failed: {result.get('query_status')}")
                    return None
                
                # Save the zip file
                output_file = self.output_dir / f"{sha256_hash}.zip"
                with open(output_file, 'wb') as f:
                    f.write(response.content)
                
                print(f"[✓] Downloaded: {output_file}")
                print(f"    Password: 'infected'")
                return output_file
            else:
                print(f"[✗] Download failed: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[✗] Error: {e}")
            return None
    
    def display_samples(self, samples):
        """Display sample information"""
        if not samples:
            print("[✗] No samples to display")
            return
        
        print(f"\n{'='*90}")
        print(f"{'#':<4} {'SHA256':<20} {'File Type':<12} {'Signature':<25} {'Tags'}")
        print(f"{'='*90}")
        
        for idx, sample in enumerate(samples[:20], 1):
            sha256 = sample.get('sha256', 'N/A')[:16] + "..."
            file_type = sample.get('file_type', 'N/A')
            signature = sample.get('signature', 'Generic')[:23]
            tags = ', '.join(sample.get('tags', [])[:2])
            
            print(f"{idx:<4} {sha256:<20} {file_type:<12} {signature:<25} {tags}")
        
        print(f"{'='*90}\n")
    
    def save_metadata(self, samples, filename="malware_metadata.json"):
        """Save sample metadata"""
        if not samples:
            return
        
        metadata_file = self.output_dir / filename
        with open(metadata_file, 'w') as f:
            json.dump(samples, f, indent=2)
        
        print(f"[✓] Metadata saved to: {metadata_file}")
    
    def interactive_download(self):
        """Interactive download mode"""
        print("\n" + "="*90)
        print("          MalwareBazaar Sample Downloader")
        print("="*90)
        print("\n⚠️  WARNING: You are about to download REAL MALWARE!")
        print("   - Only use in isolated VM")
        print("   - Never execute downloaded files")
        print("   - Keep files password protected (password: 'infected')")
        print("\n" + "="*90)
        
        # Get API key
        api_key = self.get_api_key()
        if not api_key:
            print("\n[✗] Cannot proceed without API key")
            print("    Get one from: https://bazaar.abuse.ch/api/")
            return
        
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
            limit = input("How many samples? (default 10, max 100): ").strip()
            limit = int(limit) if limit.isdigit() else 10
            limit = min(limit, 100)
            
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
                            time.sleep(2)
        
        elif choice == '2':
            print("\nPopular tags:")
            print("  - ransomware, trojan, banker, stealer")
            print("  - loader, rat, downloader, backdoor")
            
            tag = input("\nEnter tag: ").strip()
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
        import traceback
        traceback.print_exc()
