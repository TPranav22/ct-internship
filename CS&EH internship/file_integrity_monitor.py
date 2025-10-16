import os
import hashlib
import json
import argparse
import sys
from datetime import datetime

# Define a constant for the default baseline file name
BASELINE_FILENAME = "file_integrity_baseline.json"
# Define the hashing algorithm to use
HASH_ALGORITHM = "sha256"

def calculate_hash(filepath):
    """
    Calculates the hash of a file using the specified algorithm.
    Reads the file in chunks to handle large files efficiently.

    Args:
        filepath (str): The absolute or relative path to the file.

    Returns:
        str: The hexadecimal hash digest of the file, or None if the file cannot be read.
    """
    try:
        # Create a new hash object
        hasher = hashlib.new(HASH_ALGORITHM)
        # Open the file in binary read mode
        with open(filepath, 'rb') as f:
            # Read the file in 4KB chunks
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        # Return the hexadecimal representation of the hash
        return hasher.hexdigest()
    except (IOError, PermissionError) as e:
        print(f"Warning: Could not read file '{filepath}': {e}", file=sys.stderr)
        return None

def create_baseline(directory, baseline_file):
    """
    Scans a directory recursively, calculates hashes for all files,
    and saves the results to a baseline JSON file.

    Args:
        directory (str): The path to the directory to scan.
        baseline_file (str): The path where the baseline JSON file will be saved.
    """
    print(f"Creating a new integrity baseline for '{directory}'...")
    baseline_data = {
        "metadata": {
            "directory": os.path.abspath(directory),
            "creation_date": datetime.utcnow().isoformat(),
            "hash_algorithm": HASH_ALGORITHM
        },
        "files": {}
    }

    # Walk through the directory tree
    for root, _, files in os.walk(directory):
        for filename in files:
            # Construct the full file path
            filepath = os.path.join(root, filename)
            # Calculate the hash of the file
            file_hash = calculate_hash(filepath)
            if file_hash:
                # Get the relative path to store in the baseline for portability
                relative_path = os.path.relpath(filepath, directory)
                baseline_data["files"][relative_path] = file_hash
    
    # Save the baseline data to the specified file
    try:
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=4)
        print(f"Successfully created baseline at '{baseline_file}' with {len(baseline_data['files'])} files.")
    except (IOError, PermissionError) as e:
        print(f"Error: Could not write baseline file '{baseline_file}': {e}", file=sys.stderr)

def check_integrity(directory, baseline_file):
    """
    Compares the current state of a directory against a saved baseline file
    and reports any changes.

    Args:
        directory (str): The path to the directory to check.
        baseline_file (str): The path to the baseline JSON file to compare against.
    """
    # Check if the baseline file exists
    if not os.path.exists(baseline_file):
        print(f"Error: Baseline file '{baseline_file}' not found.", file=sys.stderr)
        print("Please create a baseline first using the 'baseline' command.", file=sys.stderr)
        return

    print(f"Checking integrity of '{directory}' against '{baseline_file}'...")
    
    # Load the baseline data
    try:
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error: Could not read or parse baseline file '{baseline_file}': {e}", file=sys.stderr)
        return

    baseline_files = baseline_data.get("files", {})
    current_files = {}

    # Scan the current state of the directory
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            relative_path = os.path.relpath(filepath, directory)
            current_files[relative_path] = calculate_hash(filepath)

    # Use sets for efficient comparison
    baseline_set = set(baseline_files.keys())
    current_set = set(current_files.keys())

    # Find new, deleted, and potentially modified files
    new_files = current_set - baseline_set
    deleted_files = baseline_set - current_set
    common_files = baseline_set.intersection(current_set)

    modified_files = []
    ok_files_count = 0
    has_changes = False

    # Check common files for modifications
    for relative_path in common_files:
        if baseline_files[relative_path] != current_files[relative_path]:
            modified_files.append(relative_path)
            has_changes = True
        else:
            ok_files_count += 1
    
    # --- Report Generation ---
    print("\n--- Integrity Check Report ---")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 30)

    if new_files:
        has_changes = True
        print(f"\n[+] NEW FILES ({len(new_files)}):")
        for f in sorted(new_files):
            print(f"  - {f}")

    if deleted_files:
        has_changes = True
        print(f"\n[-] DELETED FILES ({len(deleted_files)}):")
        for f in sorted(deleted_files):
            print(f"  - {f}")

    if modified_files:
        has_changes = True
        print(f"\n[!] MODIFIED FILES ({len(modified_files)}):")
        for f in sorted(modified_files):
            print(f"  - {f}")
    
    print(f"\n[=] UNCHANGED FILES: {ok_files_count}")

    print("-" * 30)
    if not has_changes:
        print("\nResult: OK. No changes detected.")
    else:
        print("\nResult: CHANGES DETECTED.")
    print("--- End of Report ---\n")


def main():
    """Main function to parse command-line arguments and run the tool."""
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor using hash values.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Create subparsers for 'baseline' and 'check' commands
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- Baseline Command ---
    parser_baseline = subparsers.add_parser(
        "baseline",
        help="Create a new baseline hash database for a directory."
    )
    parser_baseline.add_argument(
        "directory",
        type=str,
        help="The directory to scan for creating the baseline."
    )
    parser_baseline.add_argument(
        "-f", "--file",
        type=str,
        default=BASELINE_FILENAME,
        help=f"Path to save the baseline file (default: {BASELINE_FILENAME})."
    )

    # --- Check Command ---
    parser_check = subparsers.add_parser(
        "check",
        help="Check the integrity of a directory against a baseline."
    )
    parser_check.add_argument(
        "directory",
        type=str,
        help="The directory to check."
    )
    parser_check.add_argument(
        "-f", "--file",
        type=str,
        default=BASELINE_FILENAME,
        help=f"Path of the baseline file to use for comparison (default: {BASELINE_FILENAME})."
    )

    args = parser.parse_args()

    # Validate that the specified directory exists
    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found at '{args.directory}'", file=sys.stderr)
        sys.exit(1)

    # Execute the appropriate function based on the command
    if args.command == "baseline":
        create_baseline(args.directory, args.file)
    elif args.command == "check":
        check_integrity(args.directory, args.file)

if __name__ == "__main__":
    main()
