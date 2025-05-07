import importlib.util
import subprocess
import os
import sys
import json
import platform # Import platform to check OS


def get_site_packages_path():
    """
    Finds the path to the site-packages directory for the current environment.
    More robustly handles different environments and OS.
    """
    try:
        # Use pip to find the site-packages directory
        # This is generally the most reliable method
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'show', 'pip'],
            capture_output=True, text=True, check=True, encoding='utf-8' # Specify encoding
        )
        for line in result.stdout.splitlines():
            if line.startswith('Location:'):
                # The site-packages directory is the parent of the pip location
                location = line.split(':', 1)[1].strip()
                # On some systems (like virtualenvs), this is the site-packages path directly
                # On others, the actual site-packages is a subdir (e.g., lib/pythonX.Y/site-packages)
                # pip show Location is usually the *parent* of site-packages in standard installs
                # Let's try to find the actual site-packages dir within this location
                site_packages_subdir = f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
                potential_path = os.path.join(location, site_packages_subdir)
                if os.path.isdir(potential_path):
                    return os.path.normpath(potential_path) # Normalize path
                else:
                    # Fallback for simpler structures (like in virtualenvs)
                    return os.path.normpath(location) # Normalize path
    except Exception:
        # Fallback to a common site-packages location if pip show fails
        # This is less reliable but can work in some cases
        for path in sys.path:
            # Look for paths containing 'site-packages' or 'dist-packages'
            if ('site-packages' in path or 'dist-packages' in path) and os.path.isdir(path):
                return os.path.normpath(path) # Normalize path
    return None

def get_package_path(package_name):
    """
    Finds the installation path of a specific package using pip show primarily,
    with importlib as a fallback. Handles OS path differences.
    Returns the path to the package's root directory (where its modules/code reside).
    """
    try:
        # Method 1: Use pip show (Most reliable for package root)
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'show', package_name],
            capture_output=True, text=True, check=True, encoding='utf-8' # Specify encoding
        )
        for line in result.stdout.splitlines():
            if line.startswith('Location:'):
                location = line.split(':', 1)[1].strip()
                # pip show Location is the *parent* directory of the package's code.
                # The actual package code is in a subdirectory named after the package.
                # Handle potential differences (e.g., hyphens vs underscores)
                # We need to check common variations of the package directory name
                package_dir_name_variations = [
                    package_name,
                    package_name.replace('-', '_'),
                    package_name.replace('_', '-')
                ]
                # Check potential paths within the location
                for var_name in package_dir_name_variations:
                    potential_path = os.path.join(location, var_name)
                    # Check if it's a directory containing an __init__.py or a single file module
                    # Checking for __init__.py is a common heuristic for packages
                    if os.path.isdir(potential_path) and os.path.exists(os.path.join(potential_path, '__init__.py')):
                        return os.path.normpath(potential_path) # Normalize path
                    # Also check if the location itself contains a single file module matching the name
                    elif os.path.exists(os.path.join(location, f"{var_name}.py")):
                        return os.path.normpath(location) # Return parent dir for single file module
                    # Check if the potential path is the package root directly (less common via pip show location)
                    elif os.path.isdir(potential_path): # Could be a namespace package without __init__.py
                         return os.path.normpath(potential_path)


        # If pip show didn't find the Location or the subdir within it
        print(f"Warning: 'pip show' could not definitively find package path for {package_name}. Falling back to importlib.")

    except (subprocess.CalledProcessError, FileNotFoundError):
        # Package not found via pip show or pip command failed
        print(f"Warning: 'pip show {package_name}' failed. Falling back to importlib.")
        pass # Fallback to importlib

    except Exception as e:
        print(f"Warning: An error occurred using 'pip show' for {package_name}: {e}. Falling back to importlib.")
        pass # Fallback to importlib

    # Method 2: Fallback to importlib.util.find_spec (Less reliable for root path, better for module path)
    try:
        spec = importlib.util.find_spec(package_name)
        if spec and spec.origin:
            # spec.origin is typically the path to the __init__.py or the single module file
            # We want the parent directory for packages
            if spec.origin.endswith('__init__.py'):
                 return os.path.normpath(os.path.dirname(spec.origin)) # Normalize path
            elif spec.origin.endswith('.py'):
                 return os.path.normpath(os.path.dirname(spec.origin)) # For single file modules, return parent dir
            else:
                 return os.path.normpath(spec.origin) # For other origins (e.g., compiled modules)
    except Exception as e:
        print(f"Warning: An error occurred using 'importlib.util.find_spec' for {package_name}: {e}.")
        pass

    print(f"Could not determine installation path for package: {package_name}")
    return None


def normalize_bandit_path(bandit_filename):
    """
    Normalizes the path output by Bandit for comparison with OS paths.
    Bandit often uses forward slashes even on Windows.
    """
    # Replace forward slashes with OS-specific separators if needed,
    # but Bandit usually outputs forward slashes consistently.
    # Let's normalize the OS path for comparison instead.
    return bandit_filename # Assume Bandit output is consistent enough


def run_unsafe_code_scan(package_data):
    results = []
    site_packages_path = get_site_packages_path()

    if not site_packages_path or not os.path.exists(site_packages_path):
        return [{'error': 'Could not determine site-packages path or path does not exist.'}]

    # Get exclusion paths using the more robust get_package_path
    exclude_dirs = [
        os.path.normpath(os.path.dirname(__file__)), # Exclude the directory where the script is
        get_package_path('bandit') # Exclude bandit itself
    ]
    # Filter out None values and ensure paths exist for exclusion
    exclude_args = [f'--exclude={d}' for d in exclude_dirs if d and os.path.exists(d)]

    command = [sys.executable, '-m', 'bandit', '-r', site_packages_path, '-f', 'json'] + exclude_args

    try:
        # Use run instead of Popen/communicate for simpler handling of stdout/stderr
        process = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', check=False) # check=False to handle non-zero return codes

        # Check for actual execution errors in stderr
        if process.returncode != 0:
             # Bandit returns non-zero for findings (B) and errors (E)
             # Check stderr for actual errors, not just findings summary
             if process.stderr and ("error" in process.stderr.lower() or "exception" in process.stderr.lower()):
                  return [{'error': f'Bandit execution error: {process.stderr.strip()}'}]
             # If stderr is empty or doesn't contain error keywords, it might just be findings
             # We can proceed to parse stdout if stdout is not empty
             if not process.stdout and not process.stderr:
                 return [{'error': 'Bandit command returned non-zero but produced no output.'}]


        # Parse the JSON output from stdout
        stdout = process.stdout.strip()
        if not stdout:
             # Bandit might produce no output if no issues found and no errors
             # This is not necessarily an error, just means no unsafe code found
             return [{'package': 'Scan Summary', 'issues': [], 'info': 'Bandit scan completed with no findings.'}]

        try:
            bandit_output = json.loads(stdout)
            all_issues = bandit_output.get('results', [])
            bandit_errors = bandit_output.get('errors', []) # Check for errors reported *in* the JSON output
        except json.JSONDecodeError:
             # If JSON parsing fails, it's likely an error in Bandit's output format
             return [{'error': f'Failed to parse Bandit JSON output. Raw output: {stdout[:500]}...'}] # Show start of output for debugging


        # Organize issues by package
        package_issues = {}
        # Initialize with all known packages
        for pkg in package_data:
             package_issues[pkg['name']] = []


        for issue in all_issues:
            # Bandit reports file paths, need to map back to packages
            filename = issue.get('filename', '')
            normalized_filename = os.path.normpath(filename) # Normalize for comparison

            package_name = "Unknown" # Default if we can't determine the package

            # Attempt to map the file path back to a package
            # This is a heuristic and might not be perfect
            for pkg in package_data:
                pkg_path = get_package_path(pkg['name'])
                if pkg_path:
                    # Normalize the package path for comparison
                    normalized_pkg_path = os.path.normpath(pkg_path)
                    # Check if the normalized filename starts with the normalized package path
                    if normalized_filename.startswith(normalized_pkg_path):
                        package_name = pkg['name']
                        break # Found the package for this issue

            if package_name not in package_issues:
                # This could happen if a package was found by get_package_path but not in package_data
                # Or if the "Unknown" package needs initialization
                package_issues[package_name] = []


            # Format the issue details
            issue_details = {
                'severity': issue.get('issue_severity', 'N/A'),
                'confidence': issue.get('issue_confidence', 'N/A'),
                'text': issue.get('issue_text', 'N/A'),
                'code': issue.get('code', 'N/A'),
                'line_number': issue.get('line_number', 'N/A'),
                'filename': filename # Keep original filename for display
            }
            package_issues[package_name].append(issue_details)

        # Format the results for the GUI
        # Include all packages from package_data, even if they had no issues
        results = [{'package': name, 'issues': package_issues.get(name, [])} for name in package_issues.keys()]

        # Include errors reported by Bandit in its JSON output
        if bandit_errors:
            results.append({'package': 'Bandit Scan Errors', 'errors': bandit_errors})


    except FileNotFoundError:
        # This specifically catches if the 'python' executable or 'bandit' module is not found
        return [{'error': 'Bandit not found. Make sure it is installed (`pip install bandit`) and accessible in your environment.'}]
    except Exception as e:
        # Catch any other unexpected exceptions during the subprocess call or processing
        return [{'error': f'An unexpected error occurred during Bandit scan execution: {e}'}]

    return results

# Keep the existing get_package_path for potential use in mapping
# (The function is defined earlier now)


# Example Usage (for testing)
if __name__ == '__main__':
    # Simulate package_data (get actual installed packages for better testing)
    print("Detecting installed packages for simulation...")
    try:
        # This requires scanner.py to be available
        from scanner import detect_installed_packages
        simulated_package_data = detect_installed_packages() or []
        if not simulated_package_data:
            print("No packages detected in environment. Using hardcoded examples.")
            simulated_package_data = [
                {'name': 'requests', 'version': '2.28.1'},
                {'name': 'flask', 'version': '2.2.2'},
                {'name': 'some_non_existent_package', 'version': '1.0'},
                {'name': 'this_script', 'version': '1.0'} # Example to show exclusion
            ]
    except ImportError:
        print("scanner.py not found. Using hardcoded package examples.")
        simulated_package_data = [
            {'name': 'requests', 'version': '2.28.1'},
            {'name': 'flask', 'version': '2.2.2'},
            {'name': 'some_non_existent_package', 'version': '1.0'},
            {'name': 'this_script', 'version': '1.0'} # Example to show exclusion
        ]


    print(f"Simulating scan for {len(simulated_package_data)} packages...")
    scan_results = run_unsafe_code_scan(simulated_package_data)

    if scan_results and 'error' in scan_results[0]:
        print(f"Scan Error: {scan_results[0]['error']}")
    else:
        print("\n--- Scan Results ---")
        found_issues = False
        for pkg_result in scan_results:
            print(f"\nPackage: {pkg_result.get('package', 'N/A')}")
            if 'issues' in pkg_result:
                if pkg_result['issues']:
                    found_issues = True
                    for issue in pkg_result['issues']:
                        print(f"  - Severity: {issue.get('severity')}, Confidence: {issue.get('confidence')}")
                        print(f"    Text: {issue.get('text')}")
                        print(f"    File: {issue.get('filename')}:{issue.get('line_number')}")
                elif 'info' in pkg_result:
                     print(f"  {pkg_result['info']}")
                else:
                    print("  No unsafe code issues found.")
            elif 'error' in pkg_result:
                 print(f"  Error scanning: {pkg_result['error']}")
            elif 'errors' in pkg_result: # Handle Bandit's internal errors
                 print("  Bandit Internal Errors:")
                 for bandit_err in pkg_result['errors']:
                      print(f"    - {bandit_err}")


        if not found_issues and not any('error' in res or 'errors' in res for res in scan_results):
             print("\nBandit scan completed: No unsafe code issues found in any scanned package.")
