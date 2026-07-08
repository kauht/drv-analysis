#!/usr/bin/env python3
"""
Batch analyze extracted drivers using drvinspect.
Filters by signature validity, heuristic score, and IOCTL count.
Outputs candidates for DrvEye static analysis.
"""

import os
import sys
import json
import subprocess
import hashlib
from pathlib import Path
from typing import List, Dict

def sha256_file(fpath: str) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(fpath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def run_drvinspect(driver_path: str) -> Dict:
    """Run drvinspect on a driver, parse output for score and IOCTL count."""
    result = {
        'score': 0,
        'ioctl_count': 0,
        'signature_valid': False,
        'error': None,
        'raw_output': ''
    }

    try:
        # Run drvinspect with all analysis flags
        proc = subprocess.run(['drvinspect', driver_path, '--check', '--score', '--ioctl'],
                            capture_output=True, text=True, timeout=30)
        result['raw_output'] = proc.stdout + proc.stderr

        if proc.returncode != 0:
            result['error'] = f"drvinspect returned {proc.returncode}"
            return result

        output = proc.stdout

        # Parse output
        for line in output.split('\n'):
            if 'score' in line.lower() and '/' in line:
                # Try to extract score like "Score: 7/10"
                try:
                    parts = line.split('/')
                    score_part = parts[0].split()[-1]
                    result['score'] = int(score_part)
                except:
                    pass

            if 'ioctl' in line.lower() and 'count' in line.lower():
                try:
                    parts = line.split(':')
                    count = int(parts[-1].strip())
                    result['ioctl_count'] = count
                except:
                    pass

            if 'signature' in line.lower() and 'valid' in line.lower():
                result['signature_valid'] = 'yes' in line.lower() or 'valid' in line.lower()

        return result

    except subprocess.TimeoutExpired:
        result['error'] = 'Analysis timeout'
        return result
    except FileNotFoundError:
        result['error'] = 'drvinspect not found (must be in PATH or current dir)'
        return result
    except Exception as e:
        result['error'] = str(e)
        return result

def analyze_directory(driver_dir: str, min_score: int = 4, min_ioctl: int = 1) -> Dict:
    """Analyze all drivers in a directory."""
    results = {
        'total_drivers': 0,
        'analyzed': 0,
        'candidates': [],
        'filtered_low_score': [],
        'filtered_no_ioctl': [],
        'errors': []
    }

    # Find all .sys files
    sys_files = []
    for root, dirs, files in os.walk(driver_dir):
        for fname in files:
            if fname.lower().endswith('.sys'):
                sys_files.append(os.path.join(root, fname))

    results['total_drivers'] = len(sys_files)
    print(f"[+] Found {len(sys_files)} .sys files")
    print(f"[+] Min score threshold: {min_score}/10")
    print(f"[+] Min IOCTL count: {min_ioctl}")
    print()

    for i, driver_path in enumerate(sys_files, 1):
        driver_name = os.path.basename(driver_path)
        driver_hash = sha256_file(driver_path)

        print(f"[{i}/{len(sys_files)}] Analyzing: {driver_name}... ", end='', flush=True)

        analysis = run_drvinspect(driver_path)
        results['analyzed'] += 1

        if analysis['error']:
            print(f"❌ ERROR: {analysis['error']}")
            results['errors'].append({
                'filename': driver_name,
                'path': driver_path,
                'error': analysis['error']
            })
            continue

        score = analysis['score']
        ioctl_count = analysis['ioctl_count']
        sig_valid = analysis['signature_valid']

        # Filter
        if score < min_score:
            print(f"⏭️  Score too low ({score}/{10})")
            results['filtered_low_score'].append({
                'filename': driver_name,
                'sha256': driver_hash,
                'score': score
            })
            continue

        if ioctl_count < min_ioctl:
            print(f"⏭️  No IOCTLs found")
            results['filtered_no_ioctl'].append({
                'filename': driver_name,
                'sha256': driver_hash
            })
            continue

        # Passed filters
        print(f"✅ CANDIDATE (score: {score}/10, IOCTLs: {ioctl_count}, sig: {sig_valid})")
        results['candidates'].append({
            'filename': driver_name,
            'sha256': driver_hash,
            'path': driver_path,
            'score': score,
            'ioctl_count': ioctl_count,
            'signature_valid': sig_valid
        })

    return results

def save_results(results: Dict, output_file: str):
    """Save analysis results to JSON."""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved: {output_file}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python batch_analyze.py <driver_directory> [--min-score N] [--min-ioctl N] [--output results.json]")
        print("Example: python batch_analyze.py ./extracted_drivers --min-score 4 --min-ioctl 1 --output analysis.json")
        sys.exit(1)

    driver_dir = sys.argv[1]
    min_score = 4
    min_ioctl = 1
    output_file = 'batch_analysis_results.json'

    # Parse args
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--min-score' and i + 1 < len(sys.argv):
            min_score = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--min-ioctl' and i + 1 < len(sys.argv):
            min_ioctl = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--output' and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    if not os.path.isdir(driver_dir):
        print(f"Error: {driver_dir} is not a directory")
        sys.exit(1)

    print(f"[+] Analyzing drivers in: {driver_dir}")
    print()

    results = analyze_directory(driver_dir, min_score=min_score, min_ioctl=min_ioctl)

    print()
    print("=== Summary ===")
    print(f"Total drivers found: {results['total_drivers']}")
    print(f"Successfully analyzed: {results['analyzed']}")
    print(f"Passed filters (BYOVD candidates): {len(results['candidates'])}")
    print(f"Filtered (low score): {len(results['filtered_low_score'])}")
    print(f"Filtered (no IOCTLs): {len(results['filtered_no_ioctl'])}")
    print(f"Analysis errors: {len(results['errors'])}")

    if results['candidates']:
        print()
        print("=== Top Candidates (by score) ===")
        sorted_candidates = sorted(results['candidates'], key=lambda x: x['score'], reverse=True)
        for cand in sorted_candidates[:10]:
            print(f"  {cand['filename']:40} | Score: {cand['score']:2}/10 | IOCTLs: {cand['ioctl_count']:3} | {cand['sha256'][:8]}...")

    if results['errors']:
        print()
        print("=== Analysis Errors ===")
        for err in results['errors'][:5]:
            print(f"  {err['filename']}: {err['error']}")

    save_results(results, output_file)
