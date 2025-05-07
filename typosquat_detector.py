import json
import sys
import unittest

# Levenshtein distance function
def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def extract_package_names(package_data, verbose=True):
    package_names = []
    if isinstance(package_data, list):
        for item in package_data:
            if isinstance(item, str):
                package_names.append(item)
            elif isinstance(item, dict) and 'name' in item:
                package_names.append(item['name'])
            else:
                if verbose:
                    print(f"Skipping invalid item in list: {item}", file=sys.stderr)
    elif isinstance(package_data, dict) and 'name' in package_data:
        package_names.append(package_data['name'])
    elif isinstance(package_data, str):
        package_names.append(package_data)
    elif isinstance(package_data, dict) and isinstance(package_data.get('packages'), list):
        package_names = [pkg['name'] for pkg in package_data['packages'] if isinstance(pkg, dict) and 'name' in pkg]
    else:
        if verbose:
            print("Invalid input format.  Must be a list of strings or a list/dict of dicts with a 'name' key.", file=sys.stderr)

    return list(set(package_names))

def run_typosquat_check(package_data, verbose=True, filter_vulnerabilities=False):
    known_packages = {
        'requests', 'flask', 'django', 'numpy', 'tensorflow', 'pandas', 'scikit-learn', 'matplotlib', 'pytest', 'sqlalchemy',
        'beautifulsoup4', 'scrapy', 'lxml', 'pillow', 'selenium', 'notebook', 'jupyter', 'scipy', 'torch', 'transformers',
        'nltk', 'spacy', 'fastapi', 'uvicorn', 'gunicorn', 'boto3', 'openai', 'cryptography', 'httpx', 'aiohttp',
        'pydantic', 'pyyaml', 'pyinstaller', 'pytz', 'python-dateutil', 'virtualenv', 'black', 'mypy', 'flake8', 'coverage'
    }

    package_names = extract_package_names(package_data, verbose=verbose)
    results = []

    for pkg in package_names:
        for known in known_packages:
            dist = levenshtein(pkg.lower(), known.lower())
            if 0 < dist <= 2:
                results.append({
                    'package': pkg,
                    'suspicious_match': known,
                    'levenshtein_distance': dist,
                    'issue': 'Possible typosquatting'
                })
                break

    if filter_vulnerabilities:
        results = [r for r in results if 'issue' in r]

    if verbose and not results:
        print("No typosquatting issues found or an error occurred.", file=sys.stderr)

    return results

def _test_typosquat_check():
    print("\nRunning test stub for run_typosquat_check...")
    test_input = ['requests', 'flask', 'djando', 'requessts', 'numpy']
    results = run_typosquat_check(test_input, verbose=False)

    assert isinstance(results, list), "Result should be a list"
    print(f"Found {len(results)} potential issues (test stub).")

    filtered_results = run_typosquat_check(test_input, verbose=False, filter_vulnerabilities=True)
    print(f"Found {len(filtered_results)} filtered issues (test stub).")

if __name__ == "__main__":
    package_list = ['requests', 'flask', 'djando', 'numpy', 'tensoflow', 'requests']
    print("Running check with direct list:")
    results = run_typosquat_check(package_list)

    if results:
        print("Typosquatting issues found:")
        print(json.dumps(results, indent=2))
    else:
        print("No typosquatting issues found or an error occurred.")

    package_data_dict = {
        "packages": [
            {"name": "pandas"},
            {"name": "scikit-learn"},
            {"name": "matplotib"}
        ]
    }
    print("\nRunning check with dictionary input:")
    results_dict = run_typosquat_check(package_data_dict, filter_vulnerabilities=True)

    if results_dict:
        print("Typosquatting issues found from dictionary input (filtered for vulnerabilities):")
        print(json.dumps(results_dict, indent=2))
    else:
        print("No typosquatting issues found from dictionary input (filtered) or an error occurred.")

    try:
        print("\nRunning check from top_10_packages.json:")
        with open('top_10_packages.json', 'r') as f:
            top_10_data = json.load(f)
        results_file = run_typosquat_check(top_10_data)
        if results_file:
            print("Typosquatting issues found from file:")
            print(json.dumps(results_file, indent=2))
        else:
            print("No typosquatting issues found from file or an error occurred.")
    except FileNotFoundError:
        print("\nError: top_10_packages.json not found.")
    except json.JSONDecodeError as e:
        print(f"\nError decoding JSON from top_10_packages.json: {e}")

    _test_typosquat_check()
