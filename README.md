```markdown
# eVOC: Vulnerable and Outdated Components Tester

## Overview

**Vulnerable and Outdated Components Tester (eVOC)** is a Python tool designed to help you identify security vulnerabilities and outdated dependencies in your Python projects. By leveraging the OSV (Open Source Vulnerabilities) API, eVOC scans your project's `requirements.txt` file, provides detailed vulnerability information, and suggests secure, updated versions of your dependencies.

## Features

*   **Requirements Parsing:** Automatically loads and parses Python package requirements from a `requirements.txt` file.
*   **Vulnerability Detection:** Queries the OSV API to check each package for known security vulnerabilities.
*   **Secure Version Suggestions:** Recommends the latest secure version for packages found to be vulnerable.
*   **Reporting:** Export scan results to comprehensive CSV or JSON reports.
*   **Interactive GUI:** A user-friendly graphical interface for easy interaction and detailed vulnerability viewing.

## Installation

### Prerequisites

*   Python 3.7 or higher

### Steps

1.  **Clone the Repository:**

    ```bash
    git clone https://github.com/fish-hue/eVOC.git
    cd eVOC
    ```

2.  **Set Up a Virtual Environment:**

    It's highly recommended to use a virtual environment to manage project dependencies.

    ```bash
    python -m venv venv
    ```

    *   **Activate the virtual environment:**
        *   **Linux/macOS:**
            ```bash
            source venv/bin/activate
            ```
        *   **Windows:**
            ```bash
            venv\Scripts\activate
            ```

3.  **Install Dependencies:**

    Install the required packages using pip:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Running the GUI

Launch the graphical user interface by running the `gui.py` script from within the activated virtual environment:

```bash
python gui.py
```

### Steps to Use the GUI:

1.  **Load `requirements.txt`:**
    *   Click the "Load requirements.txt" button.
    *   Select your project's `requirements.txt` file.
    *   eVOC will parse the file and list the detected packages.

2.  **Scan for Vulnerabilities:**
    *   After loading the requirements, click the "Scan for Vulnerabilities" button.
    *   eVOC will query the OSV API for each package and display the number of vulnerabilities found.

3.  **View Vulnerability Details:**
    *   Double-click on any package in the results list to open a window with detailed vulnerability information, including CVE IDs, severity, and references.

4.  **Export Reports:**
    *   Click the "Export Report" button.
    *   Choose to save the scan results in either CSV or JSON format.

### Example `requirements.txt` Format:

Your `requirements.txt` file should list your dependencies with their versions:

```ini
flask==1.1.2
requests==2.25.0
numpy==1.19.5
```

## Code Structure

*   `gui.py`: The main script for the graphical user interface.
*   `scanner.py`: Handles parsing of the `requirements.txt` file.
*   `vuln_checker.py`: Interacts with the OSV API to check for vulnerabilities.
*   `report.py`: Manages the generation and export of CSV and JSON reports.

## Dependencies

*   `requests`: For making synchronous HTTP requests.
*   `aiohttp`: For asynchronous HTTP requests (used for potentially faster API calls).
*   `asyncio`: The core library for running asynchronous tasks.
*   `tkinter`: The standard Python library for creating the GUI.
*   `packaging`: For robust parsing of package names and versions from `requirements.txt`.

## Contributing

We welcome contributions to eVOC! If you'd like to contribute, please follow these steps:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes and commit them with clear messages.
4.  Push your branch to your fork.
5.  Submit a pull request to the main repository.

Please ensure your code adheres to good practices and includes appropriate tests if applicable.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

*   The OSV (Open Source Vulnerabilities) project for providing the vulnerability data.
*   The developers of the libraries used in this project.

```

