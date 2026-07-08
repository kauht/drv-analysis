#!/usr/bin/env python3
"""
Extract .sys driver files from installers (zip, 7z, Inno Setup, NSIS, etc.)
Outputs extracted drivers to a target directory with SHA256 tracking.
"""

import os
import sys
import json
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Set

def sha256_file(fpath: str) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(fpath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def load_extracted_hashes(hash_file: str) -> Set[str]:
    """Load previously extracted driver hashes to avoid re-extracting."""
    if not os.path.exists(hash_file):
        return set()
    try:
        with open(hash_file, 'r') as f:
            data = json.load(f)
            return set(data.get('extracted_hashes', []))
    except:
        return set()

def save_extracted_hashes(hash_file: str, hashes: Set[str]):
    """Save extracted driver hashes."""
    with open(hash_file, 'w') as f:
        json.dump({'extracted_hashes': list(hashes)}, f, indent=2)

def try_7z(archive: str, output_dir: str) -> List[str]:
    """Extract using 7z (handles .zip, .7z, Inno SFX, NSIS, .cab, etc.)"""
    try:
        result = subprocess.run(['7za', 'l', archive], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return []

        # List all .sys files in archive
        sys_files = [line.split()[-1] for line in result.stdout.split('\n') if line.strip().endswith('.sys')]

        extracted = []
        for sys_file in sys_files:
            try:
                # Extract single file
                out_file = os.path.join(output_dir, os.path.basename(sys_file))
                result = subprocess.run(['7za', 'x', archive, sys_file, f'-o{output_dir}', '-y'],
                                      capture_output=True, timeout=30)
                if result.returncode == 0 and os.path.exists(out_file):
                    extracted.append(out_file)
            except:
                pass

        return extracted
    except:
        return []

def try_innoextract(archive: str, output_dir: str) -> List[str]:
    """Extract using innoextract (Inno Setup installers)"""
    try:
        # List files first
        result = subprocess.run(['innoextract', '-l', archive], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return []

        sys_files = [line.split()[-1] for line in result.stdout.split('\n') if '.sys' in line.lower()]

        extracted = []
        for sys_file in sys_files:
            try:
                # Extract specific .sys file
                out_file = os.path.join(output_dir, os.path.basename(sys_file))
                result = subprocess.run(['innoextract', '-e', '-m', '-I', sys_file, archive, '-d', output_dir],
                                      capture_output=True, timeout=30)
                if result.returncode == 0:
                    # innoextract extracts to subdirs, search recursively
                    for root, dirs, files in os.walk(output_dir):
                        for f in files:
                            if f.endswith('.sys') and f not in [os.path.basename(x) for x in extracted]:
                                extracted.append(os.path.join(root, f))
            except:
                pass

        return extracted
    except:
        return []

def extract_from_archive(archive: str, output_dir: str) -> List[str]:
    """Attempt extraction using available tools in order of reliability."""
    os.makedirs(output_dir, exist_ok=True)

    archive_lower = archive.lower()
    extracted = []

    # Try 7z first (most compatible)
    extracted.extend(try_7z(archive, output_dir))

    # Try innoextract for .exe (likely Inno Setup)
    if archive_lower.endswith('.exe') and not extracted:
        extracted.extend(try_innoextract(archive, output_dir))

    return list(set(extracted))  # Deduplicate

def process_directory(input_dir: str, output_dir: str, hash_file: str) -> Dict:
    """Process all archives in a directory."""
    results = {
        'total_archives': 0,
        'extracted_count': 0,
        'new_drivers': [],
        'skipped_duplicates': [],
        'extraction_failures': []
    }

    extracted_hashes = load_extracted_hashes(hash_file)

    for fname in os.listdir(input_dir):
        fpath = os.path.join(input_dir, fname)
        if not os.path.isfile(fpath):
            continue

        # Only process archives
        if not any(fname.lower().endswith(ext) for ext in ['.zip', '.7z', '.exe', '.rar', '.cab']):
            continue

        results['total_archives'] += 1
        print(f"[*] Processing: {fname}")

        temp_dir = tempfile.mkdtemp()
        try:
            extracted = extract_from_archive(fpath, temp_dir)

            if not extracted:
                results['extraction_failures'].append(fname)
                print(f"    ❌ Extraction failed (manual extraction needed)")
                continue

            for driver_path in extracted:
                driver_hash = sha256_file(driver_path)
                driver_name = os.path.basename(driver_path)

                if driver_hash in extracted_hashes:
                    results['skipped_duplicates'].append((driver_name, driver_hash[:8]))
                    print(f"    ⏭️  Skipped duplicate: {driver_name} ({driver_hash[:8]}...)")
                else:
                    out_path = os.path.join(output_dir, f"{driver_name}_{driver_hash[:8]}")
                    os.makedirs(out_path, exist_ok=True)

                    # Copy driver and store metadata
                    out_driver = os.path.join(out_path, driver_name)
                    with open(driver_path, 'rb') as src, open(out_driver, 'wb') as dst:
                        dst.write(src.read())

                    # Save metadata
                    metadata = {
                        'sha256': driver_hash,
                        'filename': driver_name,
                        'source_archive': fname,
                        'source_path': driver_path
                    }
                    with open(os.path.join(out_path, 'metadata.json'), 'w') as f:
                        json.dump(metadata, f, indent=2)

                    results['new_drivers'].append((driver_name, driver_hash))
                    extracted_hashes.add(driver_hash)
                    results['extracted_count'] += 1
                    print(f"    ✅ Extracted: {driver_name} ({driver_hash[:8]}...)")

        finally:
            # Cleanup temp
            for f in os.listdir(temp_dir):
                try:
                    fpath = os.path.join(temp_dir, f)
                    if os.path.isfile(fpath):
                        os.remove(fpath)
                    elif os.path.isdir(fpath):
                        import shutil
                        shutil.rmtree(fpath, ignore_errors=True)
                except:
                    pass
            try:
                os.rmdir(temp_dir)
            except:
                pass

    # Save updated hashes
    save_extracted_hashes(hash_file, extracted_hashes)

    return results

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python extract_drivers.py <input_archives_dir> [output_drivers_dir] [hash_tracking_file]")
        print("Example: python extract_drivers.py ./downloads ./extracted_drivers ./data/checked_hashes.json")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './extracted_drivers'
    hash_file = sys.argv[3] if len(sys.argv) > 3 else './data/checked_hashes.json'

    if not os.path.isdir(input_dir):
        print(f"Error: {input_dir} is not a directory")
        sys.exit(1)

    print(f"[+] Scanning: {input_dir}")
    print(f"[+] Output: {output_dir}")
    print(f"[+] Hash tracking: {hash_file}")
    print()

    results = process_directory(input_dir, output_dir, hash_file)

    print()
    print(f"=== Summary ===")
    print(f"Total archives scanned: {results['total_archives']}")
    print(f"New drivers extracted: {results['extracted_count']}")
    print(f"Duplicate drivers skipped: {len(results['skipped_duplicates'])}")
    print(f"Failed extractions (manual needed): {len(results['extraction_failures'])}")

    if results['extraction_failures']:
        print(f"\nFailed on: {', '.join(results['extraction_failures'][:5])}")

    print(f"\nExtracted drivers stored in: {os.path.abspath(output_dir)}")
