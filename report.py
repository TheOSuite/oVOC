import csv
import json
import datetime
from tkinter import messagebox

__all__ = ["export_csv", "export_json", "export_html"]

def export_csv(filename, packages, results, root):
    try:
        if not filename.endswith('.csv'):
            raise ValueError('The filename must end with .csv')

        rows = []
        for pkg, result in zip(packages, results):
            for vuln in result.get('vulns', []) or []:
                rows.append({
                    'Package': pkg.get('name', ''),
                    'Version': pkg.get('version', ''),
                    'CVE ID': vuln.get('id', ''),
                    'Severity': vuln.get('severity', [{}])[0].get('score', ''),
                    'Summary': vuln.get('summary', '')
                })

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Package', 'Version', 'CVE ID', 'Severity', 'Summary']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        messagebox.showinfo('Export Successful', f'CSV report saved to {filename}')
    except Exception as e:
        messagebox.showerror('Error', str(e))


def export_json(filename, packages, results, root):
    try:
        if not filename.endswith('.json'):
            raise ValueError('The filename must end with .json')

        output = []
        for pkg, result in zip(packages, results):
            output.append({
                'package': pkg.get('name', ''),
                'version': pkg.get('version', ''),
                'vulnerabilities': result.get('vulns', []) or []
            })

        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(output, jsonfile, indent=2)

        messagebox.showinfo('Export Successful', f'JSON report saved to {filename}')
    except Exception as e:
        messagebox.showerror('Error', str(e))


def export_html(filename, packages, results, root):
    try:
        if not filename.endswith('.html'):
            raise ValueError('The filename must end with .html')

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Vulnerability Report</title>')
            f.write('<style>body{font-family:sans-serif;} table{border-collapse:collapse;width:100%;}')
            f.write('th,td{border:1px solid #ccc;padding:8px;text-align:left;} th{background:#f2f2f2;}</style>')
            f.write('</head><body>')
            f.write(f'<h1>Vulnerability Report</h1><p>Generated: {timestamp}</p>')
            f.write('<table>')
            f.write('<tr><th>Package</th><th>Version</th><th>CVE ID</th><th>Severity</th><th>Summary</th></tr>')

            for pkg, result in zip(packages, results):
                name = pkg.get('name', '')
                version = pkg.get('version', '')
                vulns = result.get('vulns', []) or []
                if not vulns:
                    f.write(f'<tr><td>{name}</td><td>{version}</td><td colspan="3">None</td></tr>')
                else:
                    for vuln in vulns:
                        cve = vuln.get('id', '')
                        sev = vuln.get('severity', [{}])[0].get('score', '')
                        summ = vuln.get('summary', '')
                        url = vuln.get('references', [{}])[0].get('url', '')
                        f.write(f'<tr><td>{name}</td><td>{version}</td>')
                        f.write(f'<td><a href="{url}">{cve}</a></td><td>{sev}</td><td>{summ}</td></tr>')

            f.write('</table></body></html>')

        messagebox.showinfo('Export Successful', f'HTML report saved to {filename}')
    except Exception as e:
        messagebox.showerror('Error', str(e))
