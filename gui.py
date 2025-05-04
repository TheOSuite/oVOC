import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from scanner import parse_requirements, detect_installed_packages, write_requirements_file
from vuln_checker import run_vulnerability_check
from report import export_csv, export_json
import webbrowser
import threading
import subprocess

class VulnerabilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerable & Outdated Python Components")
        self.root.geometry("800x600")  # increased height for buttons

        self.package_data = []
        self.results_data = []

        self.create_widgets()

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

        # Progress bar
        self.progress = ttk.Progressbar(frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(0,10))

        # Results tree
        self.tree = ttk.Treeview(frame, columns=("Package", "Version", "Vulnerabilities"), show="headings")
        self.tree.heading("Package", text="Package")
        self.tree.heading("Version", text="Version")
        self.tree.heading("Vulnerabilities", text="Vulnerabilities")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.bind("<Double-1>", self.show_details)

    def load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, 'r') as f:
                content = f.read()
                self.package_data = parse_requirements(content) or []
                if self.package_data:
                    messagebox.showinfo("Loaded", f"{len(self.package_data)} packages loaded.")
                    self.scan_button.config(state=tk.NORMAL)
                else:
                    messagebox.showwarning("No Packages", "No valid packages found.")

    def load_env(self):
        self.package_data = detect_installed_packages() or []
        req_file = write_requirements_file()
        messagebox.showinfo("Environment", f"Detected {len(self.package_data)} packages.\nSaved to {req_file}")
        self.tree.delete(*self.tree.get_children())
        for pkg in self.package_data:
            self.tree.insert('', tk.END, values=(pkg['name'], pkg['version'], 0))
        if self.package_data:
            self.scan_button.config(state=tk.NORMAL)

    def scan(self):
        if not self.package_data:
            messagebox.showwarning("No Data", "Load or scan environment first.")
            return
        self._set_ui_state(disabled=True)
        self.tree.delete(*self.tree.get_children())
        self.progress.start(10)
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        results = run_vulnerability_check(self.package_data) or []
        self.root.after(0, lambda: self.on_scan_complete(results))

    def on_scan_complete(self, results):
        self.progress.stop()
        self.results_data = results
        for i, res in enumerate(results):
            pkg = self.package_data[i]
            count = len(res.get('vulns', []) or [])
            self.tree.insert('', tk.END, values=(pkg['name'], pkg['version'], count))
        self._set_ui_state(disabled=False)

    def show_details(self, event):
        sel = self.tree.selection()
        if not sel: return
        idx = self.tree.index(sel[0])
        pkg = self.package_data[idx]
        vulns = self.results_data[idx].get('vulns', []) or []
        win = tk.Toplevel(self.root)
        win.title(f"{pkg['name']} {pkg['version']} Details")
        win.geometry('600x400')
        if not vulns:
            tk.Label(win, text='No vulnerabilities.').pack(pady=20)
            return
        for v in vulns:
            frame = ttk.LabelFrame(win, text=v.get('id',''), padding=10)
            frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            ttk.Label(frame, text=f"Severity: {v.get('severity',[{'score':'N/A'}])[0]['score']}").pack(anchor='w')
            ttk.Label(frame, text=v.get('summary',''), wraplength=550).pack(anchor='w')
            link = v.get('references',[{'url':''}])[0]['url']
            lbl = ttk.Label(frame, text=link, foreground='blue', cursor='hand2')
            lbl.pack(anchor='w')
            lbl.bind('<Button-1>', lambda e, url=link: webbrowser.open(url))

    def show_suggestions(self):
        if not self.results_data:
            messagebox.showwarning("No Scan", "Run scan first.")
            return
        suggestions = [(i, pkg['name'], pkg['version'], res.get('latest_secure_version'))
                       for i,(pkg,res) in enumerate(zip(self.package_data,self.results_data)) if res.get('latest_secure_version')]
        if not suggestions:
            messagebox.showinfo("Up to date", "No suggestions.")
            return
        win=tk.Toplevel(self.root)
        win.title('Update Suggestions')
        win.geometry('550x350')
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
        threading.Thread(target=self._run_updates, args=(sel,), daemon=True).start()

    def _run_updates(self, selection):
        errors=[]
        for iid in selection:
            idx=int(iid)
            pkg=self.package_data[idx]
            target=self.results_data[idx].get('latest_secure_version')
            if target:
                try:
                    subprocess.check_call(['pip','install',f"{pkg['name']}=={target}"])
                except Exception as e:
                    errors.append(f"{pkg['name']}: {e}")
        self.root.after(0, lambda: self.on_updates_complete(errors))

    def on_updates_complete(self, errors):
        self._set_ui_state(disabled=False)
        if errors:
            messagebox.showerror('Update Errors','\n'.join(errors))
        else:
            messagebox.showinfo('Updates Applied','Selected packages updated successfully.')

    def export_report(self):
        # Only HTML export now
        filetypes = [("HTML files", "*.html")]
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=filetypes)
        if not path:
            return

        try:
            from report import export_html
            export_html(path, self.package_data, self.results_data, self.root)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export HTML report: {e}")

    def _set_ui_state(self, disabled):
        state='disabled' if disabled else 'normal'
        for w in [self.load_button,self.env_button,self.scan_button,self.suggest_button,self.export_button]:
            w.config(state=state)

if __name__=='__main__':
    root=tk.Tk()
    app=VulnerabilityApp(root)
    root.mainloop()
