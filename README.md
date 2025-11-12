NPM Dependency Audit Tool
1. Overview
This tool audits NPM dependencies across an entire GitHub organization.

It performs a three-stage, API-driven process:

- Find Repos: Searches the organization for all repositories containing package.json or package-lock.json.

- Get File List: For each repo, it uses the Git Trees API to get a list of all matching files (skipping node_modules).

- Fetch & Scan: It fetches the content of each file in memory and performs two deep scans:

    - Package Name Scan: Checks for the presence of packages from a user-provided list.

    - RDD Scan: Hunts for the Remote Dynamic Dependency (RDD) technique, where a dependency points to a suspicious URL (http://, git://, file:, etc.).

2. Prerequisites
Python 3.x

GitHub CLI (gh)

You must be authenticated with gh auth login with permissions to read the organization's repositories.

3. Usage
Step 1: Define Target Packages
Create a packages.txt file (or any name) with the package names you wish to find, one per line. (If you only want to run the RDD scan, you can provide an empty file).

Step 2: Run the Audit
Execute the script from your terminal:

python npm_scanner.py --org <ORG_NAME> --packages-file <PATH_TO_PACKAGES.txt>

Arguments:

--org (Required): The name of the GitHub organization to scan.

--packages-file (Required): The path to your text file containing the list of packages.

Step 3: Review Results
The script will print its progress. Pay attention to the final summary and these key alerts during the scan:

[PACKAGE FOUND]: A package from your list was found in the file.

[RDD FOUND]: A dependency is being loaded from a non-standard URL.

4. Scanner Mechanism
The script's scanning logic is comprehensive:

Package Scan: It correctly parses all package-lock.json versions (v1, v2, and v3) and inspects all dependency types (top-level, dev, peer, and transitive).

RDD Scan: It checks package.json files for URL-based dependencies and package-lock.json files for any resolved field pointing to a non-standard registry (i.e., not registry.npmjs.org).

Large File Handling: The script automatically uses the Git Blobs API to fetch large package-lock.json files that are not available via the standard Contents API.