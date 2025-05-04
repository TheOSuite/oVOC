# scanner.py
from packaging.requirements import Requirement
import pkg_resources

def parse_requirements(file_content):
    # … your existing code …
    # unchanged
    pass

def detect_installed_packages():
    """
    Returns a list of {"name": package_name, "version": version} for each
    distribution in the current environment.
    """
    return [
        {"name": dist.project_name, "version": dist.version}
        for dist in pkg_resources.working_set
    ]

def write_requirements_file(filename="requirements.txt"):
    """
    Writes out a requirements.txt listing all installed packages.
    """
    pkgs = detect_installed_packages()
    with open(filename, "w") as f:
        for pkg in sorted(pkgs, key=lambda p: p["name"].lower()):
            f.write(f"{pkg['name']}=={pkg['version']}\n")
    return filename
