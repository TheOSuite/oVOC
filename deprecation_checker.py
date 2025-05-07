import subprocess
import tempfile
import os
import shutil
import venv
import re
import spacy  # Import the spacy module

# --- SpaCy Setup ---
# Load a small English language model. Adjust the model name if needed.
try:
    nlp = spacy.load("en_core_web_sm")
    print("SpaCy model 'en_core_web_sm' loaded successfully.")
except OSError:
    print("SpaCy model 'en_core_web_sm' not found. Please run 'python -m spacy download en_core_web_sm'")
    print("Falling back to regex-based extraction for deprecation warnings.")
    nlp = None # Set nlp to None if the model cannot be loaded

# --- End SpaCy Setup ---


def run_deprecation_check(package_data, use_venv=True, temp_dir=None):
    """
    Checks for deprecation warnings in specified Python packages using pip show,
    attempting to extract more context using spaCy if available.

    Args:
        package_data (list): A list of dictionaries, where each dictionary
                             represents a package with 'name' and 'version' keys.
        use_venv (bool): Whether to use a virtual environment for installation.
                         Defaults to True.
        temp_dir (str or None): The path to a temporary directory to use. If None,
                                a new temporary directory will be created.

    Returns:
        list: A list of dictionaries containing the results for each package
              and any overall errors.
    """
    results = []
    created_temp_dir = False

    if temp_dir is None:
        temp_dir = tempfile.mkdtemp()
        created_temp_dir = True
    else:
        # Ensure the provided temporary directory exists
        os.makedirs(temp_dir, exist_ok=True)

    # Determine the pip executable based on whether a venv is used
    pip_executable = 'pip'
    venv_dir = None

    if use_venv:
        venv_dir = os.path.join(temp_dir, '.venv')
        try:
            print(f"Creating virtual environment in: {venv_dir}")
            venv.create(venv_dir, with_pip=True)
            # Construct the path to the pip executable within the venv
            if os.name == 'nt':  # Windows
                pip_executable = os.path.join(venv_dir, 'Scripts', 'pip')
            else:  # Unix/Linux/macOS
                pip_executable = os.path.join(venv_dir, 'bin', 'pip')
            print(f"Using pip executable: {pip_executable}")
        except Exception as e:
            results.append({"error": f"Failed to create virtual environment: {str(e)}"})
            # Clean up the temporary directory if it was created by the script
            if created_temp_dir:
                try:
                    shutil.rmtree(temp_dir)
                except OSError as e:
                    results.append({"error": f"Warning: Unable to remove temporary directory: {e}"})
            return results # Exit if venv creation fails

    try:
        # Aggregate all package requirements into one file
        req_file = os.path.join(temp_dir, 'requirements.txt')
        with open(req_file, 'w') as f:
            for pkg in package_data:
                name = pkg.get('name')
                version = pkg.get('version')
                if name and version:
                    f.write(f"{name}=={version}\n")
                else:
                    results.append({"package": name, "error": "Missing 'name' or 'version' for package."})
                    # We don't continue here because we still want to try installing valid packages

        # Install all packages in the requirements.txt at once
        print(f"Installing packages from {req_file} using {pip_executable}")
        try:
            subprocess.run([pip_executable, 'install', '-r', req_file],
                           cwd=temp_dir,
                           check=True,
                           capture_output=True,
                           text=True,
                           env=os.environ.copy()) # Pass current environment variables
        except subprocess.CalledProcessError as e:
            stderr_output = e.stderr
            # Attempt to find which package failed from the stderr output
            failed_package = "Unknown"
            for line in stderr_output.splitlines():
                if "ERROR:" in line and "Could not find a version" in line:
                    # Basic attempt to extract the package name from the error line
                    parts = line.split("for requirement")
                    if len(parts) > 1:
                        failed_package = parts[1].split("from versions")[0].strip()
                        break # Found a potential failed package

            results.append({"error": f"Failed to install packages. Potential failed package: {failed_package}. Error: {stderr_output.strip()}"})
            # We continue to check for deprecation warnings on packages that might have installed successfully,
            # but the installation error is reported.

        # Check for deprecation warnings
        for pkg in package_data:
            name = pkg.get('name')
            if name: # Only check packages that had a name
                try:
                    # Check if the package was likely installed successfully before running pip show
                    # This is a heuristic based on the installation error message.
                    # A more robust check would be to parse pip list output.
                    installation_failed_for_this_pkg = False
                    for result in results:
                        if result.get('error') and f"Potential failed package: {name}" in result.get('error'):
                            installation_failed_for_this_pkg = True
                            break

                    if installation_failed_for_this_pkg:
                         results.append({"package": name, "error": "Skipping deprecation check due to installation failure."})
                         continue

                    print(f"Checking for deprecation warnings for {name} using {pip_executable} show")
                    output = subprocess.check_output([pip_executable, 'show', name],
                                                     cwd=temp_dir,
                                                     stderr=subprocess.STDOUT,
                                                     text=True,
                                                     env=os.environ.copy()) # Pass current environment variables

                    found_deprecation = False
                    deprecation_details = [] # Store multiple deprecation warnings for a package

                    # Process the entire output of pip show for NLP analysis if nlp is available
                    doc = None
                    if nlp:
                         doc = nlp(output)

                    for line in output.splitlines():
                        if "deprecated" in line.lower():
                            found_deprecation = True
                            details = {"warning_line": line.strip()}

                            # --- NLP Extraction Attempt (using spaCy) ---
                            if doc and line.strip(): # Ensure doc is available and line is not empty
                                try:
                                    # Find the span in the doc corresponding to this line
                                    # This is a bit tricky as spaCy processes the whole text.
                                    # A more robust approach would be to process each line separately with spaCy
                                    # if line breaks are important for context, but processing the whole text
                                    # allows for cross-line dependencies if spaCy handles them.
                                    # For simplicity here, we'll just process the individual line for now.
                                    line_doc = nlp(line.strip())

                                    # Basic rule: Look for verbs like "use", "recommend", "switch"
                                    # and try to find their direct objects or related phrases
                                    suggested_alternatives = []
                                    reasons = []
                                    removal_versions = []

                                    for token in line_doc:
                                        # Look for suggestions
                                        if token.lemma_ in ["use", "recommend", "switch", "replace"] and token.dep_ == "ROOT":
                                            # Try to capture the phrase following the verb
                                            # This is still a heuristic
                                            alternative_phrase = " ".join(t.text for t in token.rights)
                                            if alternative_phrase:
                                                suggested_alternatives.append(alternative_phrase.strip())

                                        # Look for reasons (simple pattern after "because" or "due to")
                                        if token.lower_ in ["because", "due"] and token.head.lemma_ == "be": # e.g., "is deprecated because..."
                                             reason_phrase = " ".join(t.text for t in token.rights)
                                             if reason_phrase:
                                                 reasons.append(reason_phrase.strip())
                                        elif token.lower_ in ["because", "due"] and token.dep_ == "prep": # e.g., "deprecated due to..."
                                             reason_phrase = " ".join(t.text for t in token.rights)
                                             if reason_phrase:
                                                 reasons.append(reason_phrase.strip())

                                        # Look for removal versions (simple pattern after "in version" or "in future versions")
                                        if token.lower_ == "version" and token.head.lower_ == "in":
                                            removal_version_phrase = " ".join(t.text for t in token.rights)
                                            if removal_version_phrase:
                                                removal_versions.append(token.head.text + " " + token.text + " " + removal_version_phrase.strip())
                                        elif token.lower_ == "versions" and token.head.lower_ == "future":
                                            removal_versions.append(token.head.text + " " + token.text)


                                    if suggested_alternatives:
                                        details["suggested_alternatives"] = suggested_alternatives
                                    if reasons:
                                        details["reasons"] = reasons
                                    if removal_versions:
                                        details["removal_versions"] = removal_versions

                                except Exception as nlp_e:
                                    details["nlp_extraction_error"] = str(nlp_e)
                                    details["nlp_status"] = "NLP extraction failed for this line."


                            # --- Fallback to Regex (if NLP not available or fails) ---
                            if "suggested_alternatives" not in details and "nlp_status" not in details:
                                match_alternative = re.search(r"deprecated.*?use (.*?)[.;,\n]", line, re.IGNORECASE)
                                if match_alternative:
                                    details["suggested_alternative_regex"] = match_alternative.group(1).strip()

                                match_reason = re.search(r"deprecated.*?because (.*?)[.;,\n]", line, re.IGNORECASE)
                                if match_reason:
                                    details["reason_regex"] = match_reason.group(1).strip()
                            # --- End Fallback ---


                            deprecation_details.append(details)

                    if found_deprecation:
                         results.append({"package": name, "deprecation_warnings": deprecation_details})
                    else:
                         results.append({"package": name, "status": "No obvious deprecation warnings found."})


                except subprocess.CalledProcessError as e:
                    stderr_output = e.stderr
                    results.append({"package": name, "error": f"Pip show failed: {stderr_output.strip()}"})
                except FileNotFoundError:
                    results.append({"package": name, "error": "pip not found in the virtual environment path."})
                except Exception as e:
                    results.append({"package": name, "error": f"An unexpected error occurred during pip show: {str(e)}"})
            else:
                 pass # Handled when creating requirements.txt

    except FileNotFoundError:
        results.append({"error": "pip not found. Please ensure pip is installed and accessible."})
    except Exception as e:
        results.append({"error": f"An unexpected error occurred during the main process: {str(e)}"})
    finally:
        if created_temp_dir:
            print(f"Cleaning up temporary directory: {temp_dir}")
            try:
                shutil.rmtree(temp_dir)
            except OSError as e:
                results.append({"error": f"Warning: Unable to remove temporary directory: {e}"})
        elif temp_dir and os.path.exists(temp_dir):
            print(f"Keeping temporary directory: {temp_dir} (as it was provided)")

    return results

# Example Usage:
if __name__ == "__main__":
    package_list = [
        {"name": "requests", "version": "2.25.1"},
        {"name": "numpy", "version": "1.20.3"},
        {"name": "six", "version": "1.16.0"}, # 'six' sometimes has deprecation warnings depending on Python version
        {"name": "nonexistent-package", "version": "99.99.99"},
        {"name": "another-nonexistent-package", "version": "1.0.0"},
        {"name": "package-without-version", "name": "some-package"},
        # Add more packages here, especially ones you know have deprecation warnings
        # {"name": "distutils", "version": "0.3.1"}, # Example of a package that is often deprecated in newer Pythons
        # {"name": "asyncio", "version": "3.4.3"}, # Example from stdlib, might not show warnings in pip show
    ]

    print("Running deprecation check with virtual environment and spaCy context extraction:")
    results_with_venv = run_deprecation_check(package_list, use_venv=True)
    for result in results_with_venv:
        print(result)

    # print("\nRunning deprecation check without virtual environment (use with caution!):")
    # results_without_venv = run_deprecation_check(package_list, use_venv=False)
    # for result in results_without_venv:
    #     print(result)
