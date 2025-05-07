import subprocess
import json
from collections import defaultdict

# License Checking Configuration
RISKY_LICENSES = {
    "GPL": "High", "GPLv2": "High", "GPLv3": "High", "AGPL": "High",
    "LGPL": "Medium", "MPL": "Medium", "CDDL": "Medium", "EPL": "Medium"
}

# Caching the results to avoid redundant calls (though less critical with pip show)
cached_licenses = defaultdict(dict)

# Function to evaluate license risks
def evaluate_license(package_name, license_string):
    license_key = license_string.upper()
    risk_level = "Low"  # Default risk level

    for risky, level in RISKY_LICENSES.items():
        if risky in license_key:
            risk_level = level
            break

    return {
        "package": package_name,
        "license": license_string or "Unknown",
        "risk": risk_level,
        "reason": (
            f"{license_string} may impose restrictions"
            if risk_level != "Low" else "License appears low risk or unknown"
        )
    }

# Function to fetch license info using pip show
def fetch_license_info_pip_show(package_name):
    if package_name in cached_licenses:
        return cached_licenses[package_name]

    try:
        # Run pip show and capture the output
        result = subprocess.run(
            ["pip", "show", package_name],
            capture_output=True,
            text=True,
            check=True  # Raise an exception if the command fails
        )
        output = result.stdout

        license = "Unknown"
        # Parse the output to find the License line
        for line in output.splitlines():
            if line.startswith("License:"):
                license = line.split(":", 1)[1].strip()
                break

        eval_result = evaluate_license(package_name, license)
        cached_licenses[package_name] = eval_result  # Cache the result
        return eval_result

    except subprocess.CalledProcessError as e:
        # This happens if the package is not found
        return {"package": package_name, "error": f"Package not found or pip show failed: {e.stderr.strip()}"}
    except FileNotFoundError:
        return {"package": package_name, "error": "pip command not found. Is Python installed and in your PATH?"}
    except Exception as e:
        return {"package": package_name, "error": f"An unexpected error occurred: {str(e)}"}

# Function to check licenses for multiple packages using pip show
def check_licenses_pip_show(package_names):
    results = []
    for name in package_names:
        results.append(fetch_license_info_pip_show(name))
    return results

# Run the license check with multiple packages using pip show
def run_license_check(package_names):
    # We no longer need asyncio for this approach
    return check_licenses_pip_show(package_names)

# Example Usage
if __name__ == "__main__":
    # Make sure these packages are installed in your current environment
    packages = ["requests", "numpy", "pandas", "nonexistent-package"]
    results = run_license_check(packages)
    for result in results:
        print(result)
