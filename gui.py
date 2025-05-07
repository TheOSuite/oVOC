import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from scanner import parse_requirements, detect_installed_packages, write_requirements_file
from vuln_checker import run_vulnerability_check
from license_checker import run_license_check
from report import export_csv, export_json, export_html
# Import the specific check functions directly
# Ensure these modules and functions exist and are correctly implemented
try:
    from deprecation_checker import run_deprecation_check
except ImportError:
    run_deprecation_check = None # Handle missing module gracefully
    print("Warning: deprecation_checker module not found.")

try:
    from unsafe_code_scanner import run_unsafe_code_scan
except ImportError:
    run_unsafe_code_scan = None
    print("Warning: unsafe_code_scanner module not found.")

try:
    from typosquat_detector import run_typosquat_check
except ImportError:
    run_typosquat_check = None
    print("Warning: typosquat_detector module not found.")


import webbrowser
import threading
import subprocess
import os
import shutil
import atexit
import sys # Import sys to use sys.executable

TEMP_DIR = "temp_scan_data"

class VulnerabilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerable & Outdated Python Components")
        self.root.geometry("1200x600")

        self.package_data = []
        self.results_data = {}

        self._prepare_temp_dir()
        atexit.register(self._cleanup_temp_files)

        self.create_widgets()
        # self.load_env()  # Comment out or remove this line to prevent automatic scan on startup

    def _prepare_temp_dir(self):
        if os.path.exists(TEMP_DIR):
            try:
                shutil.rmtree(TEMP_DIR)
            except OSError as e:
                print(f"Warning: Could not remove temporary directory {TEMP_DIR}: {e}")
        try:
            os.makedirs(TEMP_DIR, exist_ok=True) # Use exist_ok=True for robustness
        except OSError as e:
            print(f"Warning: Could not create temporary directory {TEMP_DIR}: {e}")


    def _cleanup_temp_files(self):
        if os.path.exists(TEMP_DIR):
            try:
                shutil.rmtree(TEMP_DIR)
                print(f"Cleaned up temporary directory: {TEMP_DIR}")
            except OSError as e:
                print(f"Warning: Could not clean up temporary directory {TEMP_DIR}: {e}")


    def create_widgets(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=5)

        self.load_button = ttk.Button(btn_frame, text="Load requirements.txt", command=self.load_file)
        self.load_button.pack(side=tk.LEFT)

        self.env_button = ttk.Button(btn_frame, text="Scan Environment", command=self.load_env)
        self.env_button.pack(side=tk.LEFT, padx=5)

        self.scan_button = ttk.Button(btn_frame, text="Scan for Vulnerabilities", command=self.scan, state=tk.DISABLED)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.suggest_button = ttk.Button(btn_frame, text="Suggest Updates", command=self.show_suggestions, state=tk.DISABLED)
        self.suggest_button.pack(side=tk.LEFT, padx=5)

        self.export_button = ttk.Button(btn_frame, text="Export Report", command=self.export_report, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.license_button = ttk.Button(btn_frame, text="Check Licenses", command=self.check_licenses, state=tk.DISABLED)
        self.license_button.pack(side=tk.LEFT, padx=5)

        self.deprecation_button = ttk.Button(btn_frame, text="Check Deprecations", command=self.run_deprecation_scan, state=tk.DISABLED)
        self.deprecation_button.pack(side=tk.LEFT, padx=5)
        # Disable deprecation button if module is missing
        if run_deprecation_check is None:
             self.deprecation_button.config(state=tk.DISABLED, text="Check Deprecations (Module Missing)")


        self.unsafe_code_button = ttk.Button(btn_frame, text="Scan Unsafe Code", command=self.run_unsafe_code_scan, state=tk.DISABLED)
        self.unsafe_code_button.pack(side=tk.LEFT, padx=5)
        # Disable unsafe code button if module is missing
        if run_unsafe_code_scan is None:
             self.unsafe_code_button.config(state=tk.DISABLED, text="Scan Unsafe Code (Module Missing)")


        self.typosquat_button = ttk.Button(btn_frame, text="Detect Typosquatting", command=self.run_typosquat_scan, state=tk.DISABLED)
        self.typosquat_button.pack(side=tk.LEFT, padx=5)
        # Disable typosquatting button if module is missing
        if run_typosquat_check is None:
             self.typosquat_button.config(state=tk.DISABLED, text="Detect Typosquatting (Module Missing)")


        self.progress = ttk.Progressbar(frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(0,10))

        # Status bar
        self.status_label = ttk.Label(frame, text="Ready", anchor=tk.W)
        self.status_label.pack(fill=tk.X, pady=(5,0))


        # Notebook for different views (Scan Summary / Details)
        self.notebook = ttk.Notebook(frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab for Main Vulnerability Treeview
        main_scan_frame = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(main_scan_frame, text='Vulnerability Scan')

        self.tree = ttk.Treeview(main_scan_frame, columns=("Package", "Version", "Vulnerabilities"), show="headings")
        self.tree.heading("Package", text="Package")
        self.tree.heading("Version", text="Version")
        self.tree.heading("Vulnerabilities", text="Vulnerabilities")
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.show_details)

        # You can add more tabs here for a Scan Summary or other views later


    def _set_status(self, message):
        """Updates the status bar label."""
        # Use after_idle to ensure this runs when the GUI is free
        self.root.after_idle(lambda: self.status_label.config(text=message))

    def _run_in_thread(self, target_function, on_complete_callback=None, *args, **kwargs):
        """Helper to run a function in a daemon thread with UI state management."""
        def thread_target():
            try:
                self._set_status(f"Running: {target_function.__name__}...") # Indicate which scan is running
                results = target_function(*args, **kwargs)
                self.root.after(0, lambda: self._on_thread_complete(results, on_complete_callback))
            except Exception as e:
                 self.root.after(0, lambda: self._on_thread_error(e, target_function.__name__))

        self._set_ui_state(disabled=True)
        self.progress.start(10)
        thread = threading.Thread(target=thread_target, daemon=True)
        thread.start()

    def _on_thread_complete(self, results, on_complete_callback):
        """Called in the main thread when a background task completes."""
        self.progress.stop()
        self._set_ui_state(disabled=False)
        self._set_status("Ready")
        if on_complete_callback:
            try:
                on_complete_callback(results)
            except Exception as e:
                messagebox.showerror("Callback Error", f"An error occurred in the completion callback:\n{str(e)}")


    def _on_thread_error(self, error, task_name="a background task"):
        """Called in the main thread when a background task raises an error."""
        self.progress.stop()
        self._set_ui_state(disabled=False)
        self._set_status(f"Error during {task_name}")
        messagebox.showerror("Error", f"An error occurred during {task_name}:\n{str(error)}")


    def run_deprecation_scan(self):
        if run_deprecation_check is None:
             messagebox.showwarning("Module Missing", "The 'deprecation_checker' module is not available.")
             return
        if not self.package_data:
            messagebox.showwarning("No Packages", "Load or scan packages first.")
            return
        self._run_in_thread(run_deprecation_check, self._display_deprecation_results, self.package_data)

    def _display_deprecation_results(self, results):
        """Handles displaying results from the deprecation check."""
        self.results_data['deprecation'] = results
        self._display_results_in_new_window(
            "Deprecation Check Results",
            results,
            ['Package', 'Message'] # Adjust columns based on actual results structure
        )


    def run_unsafe_code_scan(self):
        if run_unsafe_code_scan is None:
             messagebox.showwarning("Module Missing", "The 'unsafe_code_scanner' module is not available.")
             return
        if not self.package_data:
            messagebox.showwarning("No Packages", "Load or scan packages first.")
            return
        self._run_in_thread(run_unsafe_code_scan, self._display_unsafe_code_results, self.package_data)


    def _display_unsafe_code_results(self, results):
        """
        Handles displaying results from the unsafe code scan in a new window.
        Processes the structured results from run_unsafe_code_scan.
        """
        self.results_data['unsafe_code'] = results

        # Flatten the structured results into a list of dictionaries for the Treeview
        flat_results = []
        has_issues = False
        has_errors = False
        has_info = False

        for item in results:
            package_name = item.get('package', 'N/A')

            if 'issues' in item and item['issues']:
                has_issues = True
                for issue in item['issues']:
                    flat_results.append({
                        'Type': 'Issue', # Indicate row type
                        'Package': package_name,
                        'Severity': issue.get('severity', 'N/A'),
                        'Confidence': issue.get('confidence', 'N/A'),
                        'Text': issue.get('text', 'N/A'),
                        'File': f"{issue.get('filename', 'N/A')}:{issue.get('line_number', 'N/A')}",
                        'Details': issue.get('code', 'N/A') # Display code snippet in Details
                    })
            elif 'errors' in item and item['errors']: # Bandit internal errors
                 has_errors = True
                 for err in item['errors']:
                      # Errors in Bandit JSON are often dicts
                      flat_results.append({
                           'Type': 'Bandit Error', # Indicate row type
                           'Package': package_name,
                           'Details': f"Code: {err.get('code', 'N/A')}, Filename: {err.get('filename', 'N/A')}, Reason: {err.get('reason', 'N/A')}"
                      })
            elif 'error' in item: # Execution error or single error string
                 has_errors = True
                 flat_results.append({
                      'Type': 'Execution Error', # Indicate row type
                      'Package': package_name,
                      'Details': item['error'] # The error message string
                 })
            elif 'info' in item: # Info message (e.g., no findings)
                 has_info = True
                 flat_results.append({
                      'Type': 'Info', # Indicate row type
                      'Package': package_name,
                      'Details': item['info']
                 })
            # Packages with no issues, errors, or info are simply not added to flat_results


        # Determine columns dynamically based on the types of results found
        # This makes the display window more flexible
        if has_issues:
            columns = ['Type', 'Package', 'Severity', 'Confidence', 'Text', 'File', 'Details']
        elif has_errors:
             columns = ['Type', 'Package', 'Details']
        elif has_info:
             columns = ['Type', 'Package', 'Details']
        else:
            # If no issues, errors, or info were found (shouldn't happen with 'info' message, but as a fallback)
            columns = ['Type', 'Package', 'Details']


        self._display_results_in_new_window(
            "Unsafe Code Scan Results",
            flat_results,
            columns # Use the dynamically determined columns
        )


    def run_typosquat_scan(self):
        if run_typosquat_check is None:
             messagebox.showwarning("Module Missing", "The 'typosquat_detector' module is not available.")
             return
        if not self.package_data:
            messagebox.showwarning("No Packages", "Load or scan packages first.")
            return
        self._run_in_thread(run_typosquat_check, self._display_typosquat_results, self.package_data)

    def _display_typosquat_results(self, results):
        """Handles displaying results from the typosquatting check."""
        self.results_data['typosquatting'] = results
        self._display_results_in_new_window(
            "Typosquatting Detection Results",
            results,
            ['Suspect Package', 'Likely Target', 'Similarity'] # Adjust columns
        )


    def _display_results_in_new_window(self, title, results_list, columns):
        """Helper function to display results in a new Toplevel window."""
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("1000x600") # Slightly larger window for more columns
        win.transient(self.root) # Make the new window stay on top of the main window

        frame = ttk.Frame(win, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        if not results_list:
            ttk.Label(frame, text="No results found.").pack(pady=20) # Updated message
            return

        # Add a filter entry and label
        filter_frame = ttk.Frame(frame)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        filter_entry = ttk.Entry(filter_frame)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        tree = ttk.Treeview(frame, columns=columns, show='headings')
        for col in columns:
            tree.heading(col, text=col, command=lambda c=col: self._sort_treeview(tree, c, False)) # Add sorting
            # Attempt to set a default width, adjust as needed
            # Adjust column widths based on typical content
            width = 100 # Default width
            if col == 'Package':
                 width = 150
            elif col == 'Text' or col == 'Details':
                 width = 300 # Wider for descriptive text
            elif col == 'File':
                 width = 250
            elif col in ['Severity', 'Confidence', 'Type']:
                 width = 80
            tree.column(col, width=width, anchor=tk.W)


        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Add a scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Store the original data and populate the treeview
        tree.original_data = results_list # Store for filtering/sorting
        self._populate_treeview(tree, results_list)

        # Bind filter entry
        filter_entry.bind("<KeyRelease>", lambda event: self._filter_treeview(tree, filter_entry.get()))

    def _populate_treeview(self, tree, data):
        """Helper to clear and populate a treeview with data."""
        tree.delete(*tree.get_children())
        for item in data:
             # Ensure values match the columns defined for the treeview
             values = [item.get(col, '') for col in tree['columns']] # Use '' instead of 'N/A' for empty cells
             tree.insert('', tk.END, values=values)


    def _filter_treeview(self, tree, filter_text):
        """Filters the Treeview based on the filter text."""
        filtered_data = []
        if filter_text:
            filter_text_lower = filter_text.lower()
            for item in tree.original_data:
                # Check if the filter text is in any of the item's values
                # Ensure value is converted to string before lower() and find()
                if any(str(value).lower().find(filter_text_lower) != -1 for value in item.values()):
                    filtered_data.append(item)
        else:
            filtered_data = tree.original_data # No filter, show all

        self._populate_treeview(tree, filtered_data)

    def _sort_treeview(self, tree, col, reverse):
        """Sorts the Treeview by a given column."""
        # Get the data from the treeview
        # Convert values to appropriate types for sorting if possible (e.g., numbers)
        def sort_key(item_value):
             value = item_value[0] # The actual value from the column
             try:
                  # Attempt to convert to float for numerical sorting (e.g., Severity/Confidence scores)
                  return float(value)
             except (ValueError, TypeError):
                  # Otherwise, use string comparison (case-insensitive)
                  return str(value).lower()

        data = [(tree.set(child, col), child) for child in tree.get_children('')]

        # Sort the data using the custom sort_key
        data.sort(key=sort_key, reverse=reverse)

        # Rearrange the items in the treeview
        for index, (val, child) in enumerate(data):
            tree.move(child, '', index)

        # Reverse the sort order for the next click
        tree.heading(col, command=lambda: self._sort_treeview(tree, col, not reverse))


    def _set_ui_state(self, disabled):
        state = tk.DISABLED if disabled else tk.NORMAL
        for btn in [self.load_button, self.env_button, self.scan_button, self.suggest_button,
                    self.export_button, self.license_button, self.deprecation_button,
                    self.unsafe_code_button, self.typosquat_button]:
            # Only disable buttons if the module is available
            if btn == self.deprecation_button and run_deprecation_check is None:
                 btn.config(state=tk.DISABLED)
            elif btn == self.unsafe_code_button and run_unsafe_code_scan is None:
                 btn.config(state=tk.DISABLED)
            elif btn == self.typosquat_button and run_typosquat_check is None:
                 btn.config(state=tk.DISABLED)
            else:
                btn.config(state=state)


    def load_file(self, path=None): # Added optional path argument
        if path is None:
            path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            try:
                with open(path, 'r') as f:
                    content = f.read()
                    self.package_data = parse_requirements(content) or []
                    self.results_data = {} # Clear previous results

                    if self.package_data:
                        messagebox.showinfo("Loaded", f"{len(self.package_data)} packages loaded.")
                        self._set_ui_state(disabled=False)
                        self._set_status(f"Loaded {len(self.package_data)} packages from {os.path.basename(path)}")
                        self.tree.delete(*self.tree.get_children()) # Clear treeview
                        # Populate treeview initially
                        for pkg in self.package_data:
                            self.tree.insert('', tk.END, values=(pkg['name'], pkg['version'], 0))
                    else:
                        messagebox.showwarning("No Packages", "No valid packages found in the file.")
                        self.package_data = [] # Ensure package_data is empty
                        self._set_ui_state(disabled=True) # Disable buttons
                        self._set_status("No valid packages found in the file.")
                        self.tree.delete(*self.tree.get_children()) # Clear treeview
            except Exception as e:
                 messagebox.showerror("Error", f"Failed to load requirements file:\n{str(e)}")
                 self.package_data = []
                 self._set_ui_state(disabled=True)
                 self._set_status("Error loading file.")
                 self.tree.delete(*self.tree.get_children())


    def load_env(self):
        try:
            self._set_status("Scanning installed environment...")
            self.package_data = detect_installed_packages() or []
            self.results_data = {} # Clear previous results
            req_file_path = os.path.join(TEMP_DIR, "requirements.txt") # Define temp file path
            write_requirements_file(req_file_path) # Pass the path to write_requirements_file

            messagebox.showinfo("Environment", f"Detected {len(self.package_data)} packages.\nSaved to {req_file_path}")
            self.tree.delete(*self.tree.get_children())
            if self.package_data:
                for pkg in self.package_data:
                    self.tree.insert('', tk.END, values=(pkg['name'], pkg['version'], 0))
                self._set_ui_state(disabled=False)
                self._set_status(f"Detected {len(self.package_data)} packages in the environment.")
            else:
                self._set_ui_state(disabled=True) # Disable buttons if no packages detected
                self._set_status("No packages detected in the environment.")
        except Exception as e:
             messagebox.showerror("Error", f"Failed to scan environment:\n{str(e)}")
             self.package_data = []
             self._set_ui_state(disabled=True)
             self._set_status("Error scanning environment.")
             self.tree.delete(*self.tree.get_children())


    def scan(self): # This is the main vulnerability scan
        if not self.package_data:
            messagebox.showwarning("No Data", "Load or scan environment first.")
            return
        self._run_in_thread(run_vulnerability_check, self._on_vuln_scan_complete, self.package_data)

    def _on_vuln_scan_complete(self, results):
        """Handles displaying results from the main vulnerability scan."""
        self.results_data['vulnerability'] = results
        # Update the main treeview with vulnerability counts
        self.tree.delete(*self.tree.get_children()) # Clear previous entries
        for i, res in enumerate(results):
            pkg = self.package_data[i]
            # Ensure res is a dictionary before accessing 'vulns'
            count = len(res.get('vulns', []) or []) if isinstance(res, dict) else 0
            self.tree.insert('', tk.END, values=(pkg['name'], pkg['version'], count))

        self.suggest_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.NORMAL)


    def check_licenses(self):
        if not self.package_data:
            messagebox.showwarning("No Packages", "Load or scan packages first.")
            return
        self._run_in_thread(run_license_check, self._on_license_check_complete, [pkg['name'] for pkg in self.package_data])

    def _on_license_check_complete(self, results):
        """Handles displaying results from the license check."""
        self.results_data['license'] = results
        # Use the _display_results_in_new_window helper
        self._display_results_in_new_window(
            "License Check Results",
            results,
            ['package', 'license', 'risk'] # Adjust columns based on actual results structure
        )


    def show_details(self, event):
        sel = self.tree.selection()
        if not sel: return
        # Get the index from the selection. Ensure it's a valid index.
        try:
            idx = self.tree.index(sel[0])
            pkg = self.package_data[idx]
        except (IndexError, ValueError):
            print("Error: Could not get package details from treeview selection.")
            return


        # Get vulnerability results for this package
        vuln_results = self.results_data.get('vulnerability')
        if not vuln_results or idx >= len(vuln_results):
             messagebox.showinfo("Details", f"No vulnerability scan results available for {pkg['name']}.")
             return

        pkg_vuln_data = vuln_results[idx]

        # Check if pkg_vuln_data is a dictionary before getting 'vulns'
        if not isinstance(pkg_vuln_data, dict):
             messagebox.showinfo("Details", f"Invalid vulnerability result format for {pkg['name']}.")
             return

        vulns = pkg_vuln_data.get('vulns', []) or []

        win = tk.Toplevel(self.root)
        win.title(f"{pkg['name']} {pkg['version']} Vulnerability Details")
        win.geometry('600x400')
        win.transient(self.root) # Make the new window stay on top

        if not vulns:
            tk.Label(win, text='No vulnerabilities found for this package.').pack(pady=20)
            return

        # Use a scrolled text or a listbox for potentially many vulnerabilities
        vuln_text = tk.Text(win, wrap=tk.WORD)
        vuln_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        for v in vulns:
            # Check if v is a dictionary before accessing keys
            if not isinstance(v, dict):
                 vuln_text.insert(tk.END, "Error: Unexpected vulnerability format.\n", 'normal')
                 vuln_text.insert(tk.END, "-"*30 + "\n\n", 'normal')
                 continue # Skip to the next item

            vuln_id = v.get('id', 'N/A')
            severity_data = v.get('severity', [{}]) # Get the first item or an empty dict
            # Ensure severity_data is a list and has at least one item
            severity = severity_data[0].get('score', 'N/A') if isinstance(severity_data, list) and severity_data else 'N/A' # Safely get score

            summary = v.get('summary', 'No summary available.')
            references = v.get('references', [])
            # Ensure references is a list and has at least one item
            link = references[0].get('url', '') if isinstance(references, list) and references else '' # Safely get first link

            vuln_text.insert(tk.END, f"ID: {vuln_id}\n", 'bold')
            vuln_text.insert(tk.END, f"Severity: {severity}\n", 'normal')
            vuln_text.insert(tk.END, f"Summary: {summary}\n\n", 'normal')
            if link:
                vuln_text.insert(tk.END, f"Reference: {link}\n", 'link')
                vuln_text.tag_config('link', foreground='blue', underline=1)
                vuln_text.tag_bind('link', '<Button-1>', lambda e, url=link: webbrowser.open(url))
                # Restore cursor when leaving the link area
                # Use win.config instead of self.root.config
                vuln_text.tag_bind('link', '<Enter>', lambda e: win.config(cursor="hand2"))
                vuln_text.tag_bind('link', '<Leave>', lambda e: win.config(cursor=""))

            vuln_text.insert(tk.END, "-"*30 + "\n\n", 'normal')

        vuln_text.config(state=tk.DISABLED) # Make text read-only
        vuln_text.tag_config('bold', font='TkDefaultFont 9 bold')


    def show_suggestions(self):
        # Suggestions are based on the main vulnerability scan results
        vuln_results = self.results_data.get('vulnerability')
        if not vuln_results:
            messagebox.showwarning("No Scan", "Run vulnerability scan first to get suggestions.")
            return

        # Ensure vuln_results is a list before zipping and iterating
        if not isinstance(vuln_results, list):
             messagebox.showwarning("Invalid Results", "Vulnerability results format is unexpected.")
             return

        suggestions = [(i, pkg['name'], pkg['version'], res.get('latest_secure_version'))
                       for i,(pkg,res) in enumerate(zip(self.package_data,vuln_results))
                       if isinstance(res, dict) and res and res.get('latest_secure_version')] # Added isinstance check

        if not suggestions:
            messagebox.showinfo("Up to date", "No suggestions for vulnerable packages.")
            return

        win=tk.Toplevel(self.root)
        win.title('Update Suggestions')
        win.geometry('550x350')
        win.transient(self.root) # Make the new window stay on top

        tree=ttk.Treeview(win, columns=('Package','Current','Suggested'), show='headings', selectmode='extended')
        tree.heading('Package', text='Package')
        tree.heading('Current', text='Current')
        tree.heading('Suggested', text='Suggested')
        tree.pack(fill=tk.BOTH, expand=True)
        for idx,name,cur,sug in suggestions:
            tree.insert('',tk.END,iid=str(idx),values=(name,cur,sug))
        btn_frame=ttk.Frame(win)
        btn_frame.pack(fill=tk.X, pady=5)
        upd_btn=ttk.Button(btn_frame, text='Update Selected', command=lambda: self.update_selected(tree))
        upd_btn.pack(side=tk.LEFT, padx=5)

    def update_selected(self, tree):
        sel = tree.selection()
        if not sel:
            messagebox.showwarning('No Selection','Select rows to update.')
            return
        self._set_ui_state(disabled=True)
        self._set_status("Running updates...")
        # Pass the tree widget to the thread target so it can get the data safely
        threading.Thread(target=self._run_updates, args=(sel, tree), daemon=True).start()


    def _run_updates(self, selection, tree):
        errors=[]
        vuln_results = self.results_data.get('vulnerability')
        if not vuln_results: # Should not happen if suggestions were shown, but good safety
             errors.append("Vulnerability scan results not available for updates.")
             self.root.after(0, lambda: self.on_updates_complete(errors))
             return

        # Get the data from the treeview items before starting updates
        items_to_update = []
        for iid in selection:
             item_values = tree.item(iid, 'values')
             if len(item_values) >= 3:
                  package_name = item_values[0]
                  suggested_version = item_values[2]
                  items_to_update.append((package_name, suggested_version))
             else:
                  errors.append(f"Could not get update info for selected item {iid}.")

        if not items_to_update:
             errors.append("No valid items selected for update.")
             self.root.after(0, lambda: self.on_updates_complete(errors))
             return

        for package_name, target in items_to_update:
            try:
                if target and target != 'N/A': # Ensure there is a valid target version
                    self._set_status(f"Updating {package_name} to {target}...")
                    # Use sys.executable to ensure the correct pip is used
                    # Added --disable-pip-version-check to potentially speed up pip
                    # Use --no-cache-dir to avoid potential caching issues with updates
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', '--disable-pip-version-check', '--no-cache-dir', f"{package_name}=={target}"])
                else:
                    errors.append(f"{package_name}: No secure version suggested or target is N/A.")
            except Exception as e:
                errors.append(f"Failed to update {package_name}: {e}")

        self.root.after(0, lambda: self.on_updates_complete(errors))


    def on_updates_complete(self, errors):
        self._set_ui_state(disabled=False)
        if errors:
            messagebox.showerror('Update Errors','\n'.join(errors))
            self._set_status("Updates completed with errors.")
        else:
            messagebox.showinfo('Updates Applied','Selected packages updated successfully.')
            self._set_status("Updates applied successfully.")
        # Recommend rescanning after updates
        messagebox.showinfo("Rescan Recommended", "It's recommended to rescan your environment after updating packages.")


    def export_report(self):
        # You might want to include all scan results in the report
        # The export_html function would need to be updated to accept a dictionary of results
        filetypes = [("HTML files", "*.html"), ("CSV files", "*.csv")]
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=filetypes)

        if not path:
            self._set_status("Export canceled.")
            return

        filename, ext = os.path.splitext(path)
        if ext.lower() not in ['.html', '.csv']:
             # Default to html if no recognized extension
             ext = '.html'
             path = filename + ext

        try:
            self._set_status("Exporting report...")
            if ext.lower() == '.html':
                 # Pass all results data to the export function
                 export_html(path, self.package_data, self.results_data, self.root)
            elif ext.lower() == '.csv':
                 # You'll need to implement export_csv to handle self.results_data
                 # This is a placeholder call
                 # export_csv(path, self.package_data, self.results_data)
                 # Check if export_csv is fully implemented for all data types before enabling
                 messagebox.showwarning("Not Implemented", "CSV export is not yet fully implemented with all scan types.")
                 self._set_status("CSV export not fully implemented.")
                 return # Stop here for now

            messagebox.showinfo("Success", f"Report successfully exported to:\n{os.path.abspath(path)}")
            self._set_status(f"Report exported to {os.path.basename(path)}")
            print(f"Report exported to: {path}")
        except Exception as e:
            import traceback # Import the traceback module
            traceback.print_exc() # This will print the full traceback to the console

            messagebox.showerror("Error", f"Failed to export report:\n{e}")
            self._set_status("Error exporting report.")
            print(f"Error exporting report: {e}")

if __name__=='__main__':
    root=tk.Tk()
    app=VulnerabilityApp(root)
    root.mainloop()
