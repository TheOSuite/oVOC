import csv
import json
import datetime
# from tkinter import messagebox # Removed as GUI handles this

__all__ = ["export_csv", "export_json", "export_html"]

# Helper function to safely get nested values
def _safe_get(data, keys, default=''):
    """Safely gets a value from nested dictionaries/lists."""
    if not isinstance(keys, list):
        keys = [keys]
    value = data
    try:
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            elif isinstance(value, list) and isinstance(key, int) and len(value) > key:
                 value = value[key]
            else:
                return default # Key not found or invalid structure
            if value is None: # Handle None explicitly
                return default
        return value if value is not None else default
    except (AttributeError, TypeError, IndexError):
        return default # Handle errors during access


def export_csv(filename, packages, results_data, root):
    # results_data is now a dictionary like {'vulnerability': [...], 'license': [...], ...}
    try:
        if not filename.lower().endswith('.csv'):
            raise ValueError('The filename must end with .csv')

        all_rows = []

        # --- Include Vulnerability Results ---
        vuln_results = results_data.get('vulnerability', [])
        if vuln_results:
            all_rows.append({'Report Type': 'Vulnerabilities'}) # Section header
            all_rows.append({}) # Empty row for spacing

            # Add robustness check here too
            if len(packages) != len(vuln_results):
                 all_rows.append({
                      'Report Type': '', 'Package': 'Error', 'Version': '',
                      'CVE ID': '', 'Severity': '', 'Summary': 'Mismatch between package list and vulnerability results.'
                 })
            else:
                for pkg, result in zip(packages, vuln_results):
                    # Check if 'result' is actually a dictionary before proceeding
                    if not isinstance(result, dict):
                         all_rows.append({
                             'Report Type': '', 'Package': _safe_get(pkg, 'name'), 'Version': _safe_get(pkg, 'version'),
                             'CVE ID': '', 'Severity': '', 'Summary': 'Error: Unexpected result format for this package.'
                         })
                         continue # Skip to the next package result

                    name = _safe_get(pkg, 'name')
                    version = _safe_get(pkg, 'version')
                    vulns = _safe_get(result, 'vulns', [])

                    if not vulns:
                         all_rows.append({
                             'Report Type': '', 'Package': name, 'Version': version,
                             'CVE ID': 'None', 'Severity': '', 'Summary': ''
                         })
                    else:
                        for vuln in vulns:
                            # Check if 'vuln' is actually a dictionary before proceeding
                            if not isinstance(vuln, dict):
                                all_rows.append({
                                    'Report Type': '', 'Package': name, 'Version': version,
                                    'CVE ID': '', 'Severity': '', 'Summary': 'Error: Unexpected vulnerability format.'
                                })
                                continue # Skip to the next item in the vulns list

                            all_rows.append({
                                'Report Type': '', # Keep blank after the first row for this package
                                'Package': name,
                                'Version': version,
                                'CVE ID': _safe_get(vuln, 'id'),
                                'Severity': _safe_get(vuln, ['severity', 0, 'score']),
                                'Summary': _safe_get(vuln, 'summary'),
                                'Reference URL': _safe_get(vuln, ['references', 0, 'url'])
                            })
            all_rows.append({}) # Add empty row after section


        # --- Include License Results ---
        license_results = results_data.get('license', [])
        if license_results:
            all_rows.append({'Report Type': 'Licenses'}) # Section header
            all_rows.append({}) # Empty row for spacing

            for item in license_results:
                # Check if 'item' is actually a dictionary
                if not isinstance(item, dict):
                     all_rows.append({
                          'Report Type': '', 'Package': 'Error', 'License': '', 'Risk Level': '',
                          'Error Details': 'Unexpected license result format.'
                     })
                     continue # Skip to the next item

                all_rows.append({
                    'Report Type': '',
                    'Package': _safe_get(item, 'package'),
                    'License': _safe_get(item, 'license'),
                    'Risk Level': _safe_get(item, 'risk')
                })
            all_rows.append({}) # Add empty row after section


        # --- Include Deprecation Results ---
        deprecation_results = results_data.get('deprecation', [])
        if deprecation_results:
            all_rows.append({'Report Type': 'Deprecations'}) # Section header
            all_rows.append({}) # Empty row for spacing

            for item in deprecation_results:
                 # Check if 'item' is actually a dictionary
                if not isinstance(item, dict):
                     all_rows.append({
                          'Report Type': '', 'Package': 'Error', 'Message': '',
                          'Error Details': 'Unexpected deprecation result format.'
                     })
                     continue # Skip to the next item

                all_rows.append({
                    'Report Type': '',
                    'Package': _safe_get(item, 'Package'), # Assuming these keys
                    'Message': _safe_get(item, 'Message')  # Assuming these keys
                })
            all_rows.append({}) # Add empty row after section


        # --- Include Unsafe Code Results ---
        unsafe_code_results = results_data.get('unsafe_code', [])
        if unsafe_code_results:
            all_rows.append({'Report Type': 'Unsafe Code'})  # Section header
            all_rows.append({})  # Empty row for spacing

            # Assuming unsafe_code results are flattened in the GUI callback,
            # but let's be safe and handle nested if needed.
            for pkg_result in unsafe_code_results:
                # Check if 'pkg_result' is actually a dictionary
                if not isinstance(pkg_result, dict):
                    all_rows.append({
                        'Report Type': '', 'Package': 'Error', 'Severity': '', 'Confidence': '', 'Text': '', 'File': '',
                        'Error Details': 'Unexpected unsafe code package result format.'
                    })
                    continue  # Skip to the next item

                pkg_name = _safe_get(pkg_result, 'package')
                issues = _safe_get(pkg_result, 'issues', [])

                if issues:
                    first_issue = True
                    for issue in issues:
                        # Check if 'issue' is actually a dictionary
                        if not isinstance(issue, dict):
                            all_rows.append({
                                'Report Type': '', 'Package': pkg_name, 'Severity': '', 'Confidence': '', 'Text': '', 'File': '',
                                'Error Details': 'Unexpected unsafe code issue format.'
                            })
                            continue # Skip to the next item

                        all_rows.append({
                            'Report Type': '',
                            'Package': pkg_name,
                            'Severity': _safe_get(issue, 'severity'),
                            'Confidence': _safe_get(issue, 'confidence'),
                            'Text': _safe_get(issue, 'text'),
                            'File': f"{_safe_get(issue, 'filename', 'N/A')}:{_safe_get(issue, 'line_number', 'N/A')}"
                        })
                elif 'error' in pkg_result:
                    all_rows.append({
                        'Report Type': '', 'Package': pkg_name, 'Error': _safe_get(pkg_result, 'error')
                    })
                # No entry for packages with no unsafe code issues to keep report concise


            all_rows.append({}) # Add empty row after section


        # --- Include Typosquatting Results ---
        typosquat_results = results_data.get('typosquatting', [])
        if typosquat_results:
            all_rows.append({'Report Type': 'Typosquatting'}) # Section header
            all_rows.append({}) # Empty row for spacing

            for item in typosquat_results:
                # Check if 'item' is actually a dictionary
                if not isinstance(item, dict):
                     all_rows.append({
                          'Report Type': '', 'Suspect Package': 'Error', 'Likely Target': '', 'Similarity': '',
                          'Error Details': 'Unexpected typosquatting result format.'
                     })
                     continue # Skip to the next item

                all_rows.append({
                    'Report Type': '',
                    'Suspect Package': _safe_get(item, 'Suspect Package'), # Assuming these keys
                    'Likely Target': _safe_get(item, 'Likely Target'),     # Assuming these keys
                    'Similarity': _safe_get(item, 'Similarity')           # Assuming these keys
                })
            all_rows.append({}) # Add empty row after section


        # Determine all unique fieldnames across all sections
        # This is important because DictWriter needs a single list of fieldnames
        # We'll build this list from the headers we added and the keys in the data rows
        combined_fieldnames = []
        # Explicitly add headers first in a desired order
        header_fields = ['Report Type', 'Package', 'Version', 'CVE ID', 'Severity', 'Confidence', 'Text', 'File',
                         'License', 'Risk Level', 'Message', 'Suspect Package', 'Likely Target', 'Similarity',
                         'Reference URL', 'Error', 'Error Details'] # Add potential error fields

        for field in header_fields:
             if field not in combined_fieldnames:
                 combined_fieldnames.append(field)

        # Add any other keys found in the data rows that weren't in headers
        for row in all_rows:
             for key in row.keys():
                 if key not in combined_fieldnames:
                     combined_fieldnames.append(key)


        if not combined_fieldnames or all(row.get('Report Type') == '' for row in all_rows if row.get('Report Type') is not None):
             # Check if combined_fieldnames is empty or only contains empty rows (no actual data sections)
             # This is a slightly more robust check for no data
             # Removing the messagebox here as the GUI handles it
             # messagebox.showwarning('Export Warning', 'No scan results available to export.')
             # Instead, raise an exception if there's no data to export
             if not any(row for row in all_rows if any(row.values())): # Check if any row has any non-empty value
                 raise ValueError('No scan results available to export.')
             # If there are rows but only headers/empty, proceed to write header and empty rows

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=combined_fieldnames)
            writer.writeheader()
            # Write rows, ensuring all rows have all combined_fieldnames (DictWriter handles missing keys)
            writer.writerows(all_rows)

        # messagebox.showinfo('Export Successful', f'CSV report saved to {filename}') # GUI handles this
    except Exception as e:
        # messagebox.showerror('Error', str(e)) # GUI handles this
        raise e # Re-raise the exception so the GUI can handle it


def export_json(filename, packages, results_data, root):
    # results_data is now a dictionary
    try:
        if not filename.lower().endswith('.json'):
            raise ValueError('The filename must end with .json')

        # The JSON structure can directly reflect the results_data dictionary
        output = {
            'generation_timestamp': datetime.datetime.now().isoformat(),
            'packages_scanned': [{'name': pkg.get('name', ''), 'version': pkg.get('version', '')} for pkg in packages],
            'scan_results': results_data # Include the entire results_data dictionary
        }

        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(output, jsonfile, indent=2)

        # messagebox.showinfo('Export Successful', f'JSON report saved to {filename}') # GUI handles this
    except Exception as e:
        # messagebox.showerror('Error', str(e)) # GUI handles this
        raise e # Re-raise the exception so the GUI can handle it


def export_html(filename, packages, results_data, root):
    # results_data is now a dictionary
    try:
        if not filename.lower().endswith('.html'):
            raise ValueError('The filename must end with .html')

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Package Scan Report</title>')
            f.write('<style>')
            f.write('body{font-family:sans-serif;margin:20px;}')
            f.write('h1, h2 {color:#333;}')
            f.write('table{border-collapse:collapse;width:100%;margin-bottom:20px;}')
            f.write('th,td{border:1px solid #ddd;padding:10px;text-align:left;word-break:break-word;}') # Added word-break
            f.write('th{background:#f2f2f2;font-weight:bold;}')
            f.write('tr:nth-child(even){background-color:#f9f9f9;}')
            f.write('a {color:#0066cc;text-decoration:none;}')
            f.write('a:hover {text-decoration:underline;}')
            f.write('.section-header th {background-color: #e0e0e0; font-size: 1.1em;}')
            f.write('.no-issues {font-style: italic; color: #777;}')
            f.write('</style>')
            f.write('</head><body>')
            f.write(f'<h1>Package Scan Report</h1><p>Generated: {timestamp}</p>')

            # --- Include Vulnerability Results ---
            vuln_results = results_data.get('vulnerability', [])
            f.write('<h2>Vulnerability Scan Results</h2>')
            if not vuln_results:
                f.write('<p class="no-issues">No vulnerability scan results available or no packages found.</p>')
            else:
                f.write('<table>')
                f.write('<tr class="section-header"><th colspan="5">Vulnerabilities by Package</th></tr>')
                f.write('<tr><th>Package</th><th>Version</th><th>CVE ID</th><th>Severity</th><th>Summary</th></tr>')

                # Ensure packages and vuln_results have the same length before zipping
                if len(packages) != len(vuln_results):
                     f.write('<tr><td colspan="5" style="color: red;">Error: Mismatch between package list and vulnerability results.</td></tr>')
                else:
                    for pkg, result in zip(packages, vuln_results):
                        # Check if 'result' is actually a dictionary before proceeding
                        if not isinstance(result, dict):
                             f.write(f'<tr><td>{_safe_get(pkg, "name")}</td><td>{_safe_get(pkg, "version")}</td><td colspan="3" style="color: red;">Error: Unexpected result format for this package.</td></tr>')
                             continue # Skip to the next package result

                        name = _safe_get(pkg, 'name')
                        version = _safe_get(pkg, 'version')
                        vulns = _safe_get(result, 'vulns', [])

                        if not vulns:
                            f.write(f'<tr><td>{name}</td><td>{version}</td><td colspan="3" class="no-issues">None</td></tr>')
                        else:
                            first_vuln = True
                            for vuln in vulns:
                                # Check if 'vuln' is actually a dictionary before proceeding
                                if not isinstance(vuln, dict):
                                     # Handle unexpected format within the vulns list
                                     f.write(f'<tr><td>{name}</td><td>{version}</td><td colspan="3" style="color: red;">Error: Unexpected vulnerability format.</td></tr>')
                                     continue # Skip to the next item in the vulns list

                                cve = _safe_get(vuln, 'id')
                                sev = _safe_get(vuln, ['severity', 0, 'score'])
                                summ = _safe_get(vuln, 'summary')
                                url = _safe_get(vuln, ['references', 0, 'url'])
                                f.write('<tr>')
                                if first_vuln:
                                    f.write(f'<td>{name}</td><td>{version}</td>')
                                    first_vuln = False
                                else:
                                    f.write('<td></td><td></td>') # Empty cells for subsequent vulns
                                f.write(f'<td><a href="{url or "#"}">{cve or "N/A"}</a></td><td>{sev}</td><td>{summ}</td></tr>')


                f.write('</table>')

            # --- Include License Results ---
            license_results = results_data.get('license', [])
            f.write('<h2>License Check Results</h2>')
            if not license_results:
                 f.write('<p class="no-issues">No license check results available.</p>')
            else:
                f.write('<table>')
                f.write('<tr class="section-header"><th colspan="3">Licenses by Package</th></tr>')
                f.write('<tr><th>Package</th><th>License</th><th>Risk Level</th></tr>')
                for item in license_results:
                     # Check if 'item' is actually a dictionary
                    if not isinstance(item, dict):
                        f.write(f'<tr><td colspan="3" style="color: red;">Error: Unexpected license result format.</td></tr>')
                        continue # Skip to the next item

                    f.write('<tr>')
                    f.write(f'<td>{_safe_get(item, "package")}</td>')
                    f.write(f'<td>{_safe_get(item, "license")}</td>')
                    f.write(f'<td>{_safe_get(item, "risk")}</td>')
                    f.write('</tr>')
                f.write('</table>')

            # --- Include Deprecation Results ---
            deprecation_results = results_data.get('deprecation', [])
            f.write('<h2>Deprecation Check Results</h2>')
            if not deprecation_results:
                 f.write('<p class="no-issues">No deprecation issues found.</p>')
            else:
                f.write('<table>')
                f.write('<tr class="section-header"><th colspan="2">Deprecation Issues</th></tr>')
                f.write('<tr><th>Package</th><th>Message</th></tr>')
                for item in deprecation_results:
                    # Check if 'item' is actually a dictionary
                    if not isinstance(item, dict):
                        f.write(f'<tr><td colspan="2" style="color: red;">Error: Unexpected deprecation result format.</td></tr>')
                        continue # Skip to the next item

                    f.write('<tr>')
                    f.write(f'<td>{_safe_get(item, "Package")}</td>') # Assuming these keys
                    f.write(f'<td>{_safe_get(item, "Message")}</td>')  # Assuming these keys
                    f.write('</tr>')
                f.write('</table>')

            # --- Include Unsafe Code Results ---
            unsafe_code_results = results_data.get('unsafe_code', [])
            f.write('<h2>Unsafe Code Scan Results</h2>')
            if not unsafe_code_results or all(isinstance(res, dict) and 'error' in res for res in unsafe_code_results if res): # Check if no issues or only errors
                 if any(isinstance(res, dict) and 'error' in res for res in unsafe_code_results if res):
                     f.write('<p class="no-issues">Bandit encountered errors during scanning.</p>')
                     for res in unsafe_code_results:
                         if isinstance(res, dict) and 'error' in res:
                             f.write(f'<p style="color: red;">Error for {res.get("package", "Unknown")}: {_safe_get(res, "error")}</p>')
                 else:
                    f.write('<p class="no-issues">No unsafe code issues found.</p>')
            else:
                f.write('<table>')
                f.write('<tr class="section-header"><th colspan="5">Unsafe Code Issues</th></tr>')
                f.write('<tr><th>Package</th><th>Severity</th><th>Confidence</th><th>Text</th><th>File</th></tr>')
                for pkg_result in unsafe_code_results:
                    # Check if 'pkg_result' is actually a dictionary
                    if not isinstance(pkg_result, dict):
                        f.write(f'<tr><td colspan="5" style="color: red;">Error: Unexpected unsafe code package result format.</td></tr>')
                        continue # Skip to the next item


                    pkg_name = _safe_get(pkg_result, 'package')
                    issues = _safe_get(pkg_result, 'issues', [])

                    if issues:
                        first_issue = True
                        for issue in issues:
                            # Check if 'issue' is actually a dictionary
                            if not isinstance(issue, dict):
                                f.write(f'<tr><td>{pkg_name}</td><td colspan="4" style="color: red;">Error: Unexpected unsafe code issue format.</td></tr>')
                                continue # Skip to the next item

                            f.write('<tr>')
                            if first_issue:
                                f.write(f'<td>{pkg_name}</td>')
                                first_issue = False
                            else:
                                f.write('<td></td>')
                            f.write(f'<td>{_safe_get(issue, "severity")}</td>')
                            f.write(f'<td>{_safe_get(issue, "confidence")}</td>')
                            f.write(f'<td>{_safe_get(issue, "text")}</td>')
                            f.write(f'<td>{_safe_get(issue, "filename", "N/A")}:{_safe_get(issue, "line_number", "N/A")}</td>')
                            f.write('</tr>')
                    elif 'error' in pkg_result:
                        # Include error rows in the table structure
                        f.write(f'<tr><td>{pkg_name}</td><td colspan="4" style="color: red;">Error: {_safe_get(pkg_result, "error")}</td></tr>')


                f.write('</table>')


            # --- Include Typosquatting Results ---
            typosquat_results = results_data.get('typosquatting', [])
            f.write('<h2>Typosquatting Detection Results</h2>')
            if not typosquat_results:
                 f.write('<p class="no-issues">No potential typosquatting packages detected.</p>')
            else:
                f.write('<table>')
                f.write('<tr class="section-header"><th colspan="3">Typosquatting Candidates</th></tr>')
                f.write('<tr><th>Suspect Package</th><th>Likely Target</th><th>Similarity</th></tr>')
                for item in typosquat_results:
                    # Check if 'item' is actually a dictionary
                    if not isinstance(item, dict):
                        f.write(f'<tr><td colspan="3" style="color: red;">Error: Unexpected typosquatting result format.</td></tr>')
                        continue # Skip to the next item

                    f.write('<tr>')
                    f.write(f'<td>{_safe_get(item, "Suspect Package")}</td>') # Assuming these keys
                    f.write(f'<td>{_safe_get(item, "Likely Target")}</td>')     # Assuming these keys
                    f.write(f'<td>{_safe_get(item, "Similarity")}</td>')           # Assuming these keys
                    f.write('</tr>')
                f.write('</table>')


            f.write('</body></html>')

        # messagebox.showinfo('Export Successful', f'HTML report saved to {filename}') # GUI handles this
    except Exception as e:
        # messagebox.showerror('Error', str(e)) # GUI handles this
        raise e # Re-raise the exception so the GUI can handle it
