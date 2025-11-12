#!/usr/bin/env python3

"""
NPM Dependency Audit Script

This script automates the full workflow for auditing NPM dependencies
1.  Finds all repositories in a GitHub org containing 'package.json' or 'package-lock.json'.
2.  For each repo, uses the Git Trees API to get a file list (skipping node_modules).
3.  For each file found, fetches its content directly via the API.
    - Handles large files by automatically using the Git Blobs API.
4.  Scans the content for:
    a) A target list of vulnerable package names.
    b) The Remote Dynamic Dependency (RDD) technique (suspicious URLs).
"""

import os
import argparse
import json
import subprocess
import sys
import shutil
import base64
from urllib.parse import urlparse  # Import for URL parsing

# --- Dependency Check --------------------------------------------------------


def check_dependencies():
    """Verify that 'gh' is installed."""
    print("Checking for required tools (gh)...")
    if not shutil.which("gh"):
        print(
            "ERROR: 'gh' command not found. Please install the GitHub CLI ('gh') and ensure it's in your PATH.",
            file=sys.stderr,
        )
        print("See: https://cli.github.com/", file=sys.stderr)
        sys.exit(1)
    print("Required tools are present.")


# --- Step 1: Find Files (Hybrid API Approach) -----------------------------


def find_files_to_scan(org_name):
    """
    Finds all 'package-lock.json' and 'package.json' files in the org

    Step 1: Use 'gh search' to find REPOSITORIES (not files) that contain a match.
    Step 2: For each repo, use the Git Trees API to get a 100% accurate file list.
    Step 3: Filter that list for the package files and return.
    """
    print(f"\n--- Step 1: Finding files in '{org_name}' org... ---")

    # --- Part 1: Find all REPOS that match ---
    print("Searching for repositories containing package.json or package-lock.json...")
    command = [
        "gh",
        "search",
        "code",
        "--filename",
        "package-lock.json",
        "--filename",
        "package.json",
        "--owner",
        org_name,
        "--limit",
        "1000",
        "--json",
        "repository",
    ]

    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=True, encoding="utf-8"
        )
        data = json.loads(result.stdout)

        # De-duplicate the list of repositories
        repos = {}
        for item in data:
            repo_name = item["repository"]["nameWithOwner"]
            if repo_name not in repos:
                repos[repo_name] = item["repository"]

        repo_list = list(repos.values())
        print(f"Found {len(repo_list)} unique repositories to scan.")

    except subprocess.CalledProcessError as e:
        print(f"ERROR: 'gh search' command failed.", file=sys.stderr)
        print(f"STDERR: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON output from 'gh'.", file=sys.stderr)
        print(f"Output was: {result.stdout}", file=sys.stderr)
        sys.exit(1)

    # --- Part 2: Get file list for each repo ---
    print(
        f"\nFetching accurate file trees for {len(repo_list)} repos (this may take a moment)..."
    )
    all_files_to_scan = []

    for i, repo in enumerate(repo_list):
        repo_name = repo["nameWithOwner"]
        print(f"  [{i+1}/{len(repo_list)}] Scanning repo: {repo_name}")

        # 1. Get the default branch for the repo
        try:
            repo_details_cmd = ["gh", "api", f"/repos/{repo_name}"]
            repo_result = subprocess.run(
                repo_details_cmd,
                capture_output=True,
                text=True,
                check=True,
                encoding="utf-8",
            )
            repo_data = json.loads(repo_result.stdout)
            default_branch = repo_data.get("default_branch")
            if not default_branch:
                print(
                    f"    [WARN] Could not determine default branch for {repo_name}. Skipping.",
                    file=sys.stderr,
                )
                continue
        except Exception as e:
            print(
                f"    [WARN] Failed to get details for {repo_name}. Skipping. Error: {e}",
                file=sys.stderr,
            )
            continue

        # 2. Get the full recursive file tree for that branch
        try:
            tree_cmd = [
                "gh",
                "api",
                f"/repos/{repo_name}/git/trees/{default_branch}?recursive=1",
            ]
            tree_result = subprocess.run(
                tree_cmd, capture_output=True, text=True, check=True, encoding="utf-8"
            )
            tree_data = json.loads(tree_result.stdout)

            if tree_data.get("truncated") == True:
                print(
                    f"    [WARN] File tree for {repo_name} is TRUNCATED (too many files)."
                )
                print(f"    Scan for this repo may be incomplete.")

            # 3. Filter the tree for our target files
            found_in_repo = 0
            for item in tree_data.get("tree", []):
                file_path = item.get("path")
                if file_path and (
                    file_path.endswith("package-lock.json")
                    or file_path.endswith("package.json")
                ):

                    # --- Filter out node_modules ---
                    if "/node_modules/" in file_path or file_path.startswith(
                        "node_modules/"
                    ):
                        continue
                    # --- End filter ---

                    file_info = {"repository": repo, "path": file_path}
                    all_files_to_scan.append(file_info)
                    found_in_repo += 1
            print(f"    Found {found_in_repo} matching files in {repo_name}.")

        except subprocess.CalledProcessError as e:
            # This often happens for empty repositories
            print(
                f"    [INFO] Could not get file tree for {repo_name} (likely empty). Skipping.",
                file=sys.stderr,
            )
            print(f"    Error: {e.stderr}", file=sys.stderr)

    print(f"\nFound {len(all_files_to_scan)} total files to scan.")
    return all_files_to_scan


# --- Step 2: Fetch File Content (Replaces Clone Repos) ---------------------


def get_file_content(repo_name, file_path):
    """
    Fetches the content of a single file using the 'gh api'.
    Returns the decoded string content, or None on failure.
    This version is hardened to handle large files by using the Git Blobs API.
    """
    file_identifier = f"{repo_name}:{file_path}"
    contents_api_url = f"/repos/{repo_name}/contents/{file_path}"
    command = ["gh", "api", contents_api_url]

    try:
        # --- First attempt: Use the Contents API (fast) ---
        result = subprocess.run(
            command, capture_output=True, text=True, check=True, encoding="utf-8"
        )
        data = json.loads(result.stdout)

        if data.get("type") != "file":
            print(
                f"    [INFO] Path {file_identifier} is not a file (e.g., submodule). Skipping.",
                file=sys.stderr,
            )
            return None

        encoding = data.get("encoding")
        content = data.get("content")

        if encoding == "base64" and content:
            # Common case: file content is in the response.
            return base64.b64decode(content).decode("utf-8")

        if encoding == "base64" and (content == "" or content is None):
            # Empty file, encoded.
            return ""

        # --- Second attempt: File is likely too large for Contents API ---
        # If content is missing, use the Git Blobs API via the 'git_url'.
        git_url = data.get("git_url")
        if git_url:
            print(
                f"    [INFO] File {file_identifier} may be large. Fetching via Git Blobs API..."
            )

            try:
                parsed_url = urlparse(git_url)
                api_path = parsed_url.path
                if not api_path.startswith("/repos/"):
                    # This should not happen, but as a safeguard
                    print(
                        f"    [ERROR] Invalid git_url for {file_identifier}: {git_url}",
                        file=sys.stderr,
                    )
                    return None
            except Exception as e:
                print(
                    f"    [ERROR] Could not parse git_url {git_url} for {file_identifier}: {e}",
                    file=sys.stderr,
                )
                return None

            blob_command = ["gh", "api", api_path]

            blob_result = subprocess.run(
                blob_command,
                capture_output=True,
                text=True,
                check=True,
                encoding="utf-8",
            )
            blob_data = json.loads(blob_result.stdout)

            if blob_data.get("encoding") == "base64" and blob_data.get("content"):
                return base64.b64decode(blob_data["content"]).decode("utf-8")
            else:
                print(
                    f"    [ERROR] Git Blobs API call for {file_identifier} did not return valid content.",
                    file=sys.stderr,
                )
                return None

        # --- Fallback: Handle truly empty files ---
        if encoding == "none" or not content:
            # This is a truly empty file.
            print(f"    [INFO] File {file_identifier} appears to be empty.")
            return ""  # Return empty string for the JSON parser to fail on.

        print(
            f"    [ERROR] Unknown encoding/content state for {file_identifier}: {encoding}",
            file=sys.stderr,
        )
        return None

    except subprocess.CalledProcessError as e:
        if "404" in e.stderr:
            print(
                f"    [ERROR] File not found (404) for {file_identifier}. Skipping.",
                file=sys.stderr,
            )
        else:
            print(
                f"    [ERROR] 'gh api' command failed for {file_identifier}",
                file=sys.stderr,
            )
            print(f"    STDERR: {e.stderr}", file=sys.stderr)
        return None
    except json.JSONDecodeError:
        print(
            f"    [ERROR] Failed to parse JSON output from 'gh api' for {file_identifier}",
            file=sys.stderr,
        )
        return None
    except Exception as e:
        print(
            f"    [ERROR] Failed to decode content for {file_identifier}: {e}",
            file=sys.stderr,
        )
        return None


# --- Step 3: Scan Content (Modified from Scan Files) -----------------------


def get_v1_dependencies_recursively(dependencies_obj, names_set, rdd_urls_set):
    """
    (Unchanged helper function)
    Recursively walks a v1 'dependencies' object (which is nested)
    and adds all package names and suspicious 'resolved' URLs.
    """
    if not isinstance(dependencies_obj, dict):
        return

    for pkg_name, pkg_details in dependencies_obj.items():
        if not isinstance(pkg_details, dict):
            continue

        # 1. Add the package name itself
        names_set.add(pkg_name)

        # 2. Check for RDD URLs
        if "resolved" in pkg_details:
            resolved_url = pkg_details["resolved"]
            if isinstance(resolved_url, str) and (
                "://" in resolved_url or resolved_url.startswith("file:")
            ):
                if "registry.npmjs.org" not in resolved_url:
                    rdd_urls_set.add(resolved_url)

        # 3. Add packages from 'requires' (dependencies of this package)
        if "requires" in pkg_details and isinstance(pkg_details["requires"], dict):
            names_set.update(pkg_details["requires"].keys())

        # 4. Recurse into nested 'dependencies' (if they exist)
        if "dependencies" in pkg_details and isinstance(
            pkg_details["dependencies"], dict
        ):
            get_v1_dependencies_recursively(
                pkg_details["dependencies"], names_set, rdd_urls_set
            )


def check_package_lock_content(content_string, package_names_to_find, file_identifier):
    """
    Scans package-lock.json *content* for:
    1. A list of target package names.
    2. Suspicious URLs in 'resolved' fields (RDD technique).

    Returns: (list_of_found_packages, list_of_found_rdd_urls)
    """
    try:
        data = json.loads(content_string)
    except Exception as e:
        # This is expected for empty files
        print(
            f"    [INFO] Failed to parse JSON from {file_identifier} (file may be empty or malformed): {e}"
        )
        return [], []

    found_packages = []
    found_rdd_urls = set()
    package_names_in_lockfile = set()

    lockfile_version = data.get("lockfileVersion", 1)

    if lockfile_version == 1:
        # Version 1: Has a nested 'dependencies' object.
        top_level_deps = data.get("dependencies", {})
        get_v1_dependencies_recursively(
            top_level_deps, package_names_in_lockfile, found_rdd_urls
        )

    else:
        # Version 2 or 3: Has a flat 'packages' object.
        all_package_definitions = data.get("packages", {}).items()

        for pkg_path, pkg_details in all_package_definitions:
            if not isinstance(pkg_details, dict):
                continue

            # --- 1. Package Name Scan ---
            if "name" in pkg_details:
                package_names_in_lockfile.add(pkg_details["name"])
            if "dependencies" in pkg_details and isinstance(
                pkg_details["dependencies"], dict
            ):
                package_names_in_lockfile.update(pkg_details["dependencies"].keys())
            if "devDependencies" in pkg_details and isinstance(
                pkg_details["devDependencies"], dict
            ):
                package_names_in_lockfile.update(pkg_details["devDependencies"].keys())
            if "peerDependencies" in pkg_details and isinstance(
                pkg_details["peerDependencies"], dict
            ):
                package_names_in_lockfile.update(pkg_details["peerDependencies"].keys())

            # --- 2. RDD (URL) Scan ---
            if "resolved" in pkg_details:
                resolved_url = pkg_details["resolved"]
                # Check for any protocol handler (://) or the file: protocol.
                if isinstance(resolved_url, str) and (
                    "://" in resolved_url or resolved_url.startswith("file:")
                ):
                    # Whitelist the official NPM registry
                    if "registry.npmjs.org" not in resolved_url:
                        found_rdd_urls.add(resolved_url)

    # Check the built list of package names against the target list
    for pkg_to_find in package_names_to_find:
        if pkg_to_find in package_names_in_lockfile:
            found_packages.append(pkg_to_find)

    return found_packages, list(found_rdd_urls)


def check_package_json_content(content_string, file_identifier):
    """
    Scans package.json *content* for http/https URLs in dependencies.
    Returns: list_of_found_rdd_urls
    """
    found_rdd_urls = set()
    try:
        data = json.loads(content_string)
    except Exception as e:
        # This is expected for empty files
        print(
            f"    [INFO] Failed to parse JSON from {file_identifier} (file may be empty or malformed): {e}"
        )
        return []

    # List of fields to check
    dependency_fields = ["dependencies", "devDependencies", "peerDependencies"]

    for field in dependency_fields:
        if field in data and isinstance(data[field], dict):
            for pkg_name, version_string in data[field].items():
                # Check for any protocol handler (://) or the file: protocol.
                if isinstance(version_string, str) and (
                    "://" in version_string or version_string.startswith("file:")
                ):
                    found_rdd_urls.add(f"{pkg_name}: {version_string}")

    return list(found_rdd_urls)


def read_packages_from_file(file_path):
    """Read newline-delimited package names from a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            packages = [line.strip() for line in f if line.strip()]
        return packages
    except Exception as e:
        print(f"Failed to read package list file {file_path}: {e}", file=sys.stderr)
        return None  # Return None to indicate failure


def run_api_scan(files_to_scan, packages_file):
    """
    Orchestrates the API scanning portion of the script.
    This version is DRY: it uses a single loop.
    """
    print(f"\n--- Step 2: Scanning {len(files_to_scan)} files via API... ---")

    # Read package names from file
    package_names = read_packages_from_file(packages_file)
    if package_names is None:
        print(f"Exiting due to error reading {packages_file}.", file=sys.stderr)
        sys.exit(1)

    if not package_names:
        print(
            f"No packages to check from {packages_file}. Continuing with RDD scan only."
        )

    print(f"Searching for {len(package_names)} packages...")
    print(f"Packages to find: {package_names}")

    total_pkg_found = 0
    total_rdd_found = 0

    num_package_lock_files = sum(
        1 for f in files_to_scan if f["path"].endswith("package-lock.json")
    )
    num_package_json_files = len(files_to_scan) - num_package_lock_files

    print(
        f"\nFound {num_package_lock_files} package-lock.json file(s) and {num_package_json_files} package.json file(s) to fetch."
    )

    # --- Single Scan Loop (DRY) ---
    print("\n--- Scanning all file content ---")

    for file_info in files_to_scan:
        repo_name = file_info["repository"]["nameWithOwner"]
        file_path = file_info["path"]
        file_identifier = f"{repo_name}:{file_path}"

        print("-------------------------------------")
        print(f"Fetching & Scanning {file_identifier}...")

        content = get_file_content(repo_name, file_path)
        if content is None:
            print(f"  [ERROR] Skipping file due to fetch error.")
            continue

        if file_path.endswith("package-lock.json"):
            found_packages, found_urls = check_package_lock_content(
                content, package_names, file_identifier
            )

            if found_packages:
                print(f"  [PACKAGE FOUND] Packages in this file: {found_packages}")
                total_pkg_found += len(found_packages)
            else:
                print(f"  [PACKAGE OK] No specified packages found in this file.")

            if found_urls:
                print(
                    f"  [RDD FOUND] Suspicious URLs in 'resolved' field: {found_urls}"
                )
                total_rdd_found += len(found_urls)

        elif file_path.endswith("package.json"):
            # package.json only scans for RDD
            found_urls = check_package_json_content(content, file_identifier)

            if found_urls:
                print(f"  [RDD FOUND] HTTP dependencies in package.json: {found_urls}")
                total_rdd_found += len(found_urls)

    print("-------------------------------------")
    print("\n--- Scan complete ---")
    print(f"Found {total_pkg_found} total instances of specified packages.")
    print(
        f"Found {total_rdd_found} total instances of suspicious URLs (RDD technique)."
    )


# --- Main Orchestrator -------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Run a full NPM dependency audit (find, clone, scan).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python npm_api_scanner.py --org <MyGitHubOrg> --packages-file packages.txt
""",
    )
    parser.add_argument("--org", required=True, help="GitHub organization to search.")
    parser.add_argument(
        "--packages-file",
        required=True,
        help="Path to text file containing list of npm packages (e.g., 'packages.txt').",
    )

    args = parser.parse_args()

    # 1. Check for 'gh'
    check_dependencies()

    # 2. Step 1: Find all files
    files_to_scan = find_files_to_scan(args.org)

    if not files_to_scan:
        print("No matching files found. Exiting.")
        sys.exit(0)

    # 3. Step 2 & 3: Fetch content and Scan
    run_api_scan(files_to_scan, args.packages_file)

    print("\n--- Full audit complete. ---")


if __name__ == "__main__":
    main()
