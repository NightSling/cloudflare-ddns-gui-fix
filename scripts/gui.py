import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import os
import sys
import json
import threading
import time
import subprocess

# Add project root to the Python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)

from scripts.config import load_config, save_config

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cloudflare DDNS Configurator")
        self.geometry("800x650")

        self.config_data = load_config()
        self.service_name = "cloudflare-ddns.service"
        self.log_file_path = os.path.join(PROJECT_ROOT, 'logs', 'ddns.log')

        # --- Main Layout ---
        main_container = ttk.Frame(self)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.create_service_widgets(main_container)
        self.create_notebook_widgets(main_container)

        # --- Threads for updates ---
        self.start_update_threads()

    def create_service_widgets(self, parent):
        service_frame = ttk.LabelFrame(parent, text="Service Control")
        service_frame.pack(fill=tk.X, pady=5)
        
        control_frame = ttk.Frame(service_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        self.status_canvas = tk.Canvas(control_frame, width=20, height=20)
        self.status_canvas.pack(side=tk.LEFT, padx=(0, 10))
        self.status_indicator = self.status_canvas.create_oval(2, 2, 18, 18, fill="red")

        ttk.Button(control_frame, text="Start", command=lambda: self.run_systemctl("start")).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop", command=lambda: self.run_systemctl("stop")).pack(side=tk.LEFT, padx=5)

    def create_notebook_widgets(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        config_tab = ttk.Frame(notebook)
        logs_tab = ttk.Frame(notebook)
        notebook.add(config_tab, text="Configuration")
        notebook.add(logs_tab, text="Logs")

        self.create_config_tab(config_tab)
        self.create_logs_tab(logs_tab)

    def create_config_tab(self, parent):
        # --- General Settings ---
        general_frame = ttk.LabelFrame(parent, text="General")
        general_frame.pack(fill=tk.X, padx=5, pady=5)

        self.a_var = tk.BooleanVar(value=self.config_data.get("a", True))
        ttk.Checkbutton(general_frame, text="Enable IPv4 (A records)", variable=self.a_var).pack(anchor=tk.W)

        self.aaaa_var = tk.BooleanVar(value=self.config_data.get("aaaa", True))
        ttk.Checkbutton(general_frame, text="Enable IPv6 (AAAA records)", variable=self.aaaa_var).pack(anchor=tk.W)
        
        self.purge_var = tk.BooleanVar(value=self.config_data.get("purgeUnknownRecords", False))
        ttk.Checkbutton(general_frame, text="Purge Unknown Records", variable=self.purge_var).pack(anchor=tk.W)

        ttl_frame = ttk.Frame(general_frame)
        ttl_frame.pack(fill=tk.X, anchor=tk.W)
        ttk.Label(ttl_frame, text="TTL (in seconds):").pack(side=tk.LEFT)
        self.ttl_var = tk.StringVar(value=self.config_data.get("ttl", 300))
        ttk.Entry(ttl_frame, textvariable=self.ttl_var, width=10).pack(side=tk.LEFT)

        # --- Cloudflare Settings ---
        cf_frame = ttk.LabelFrame(parent, text="Cloudflare Account")
        cf_frame.pack(fill=tk.X, padx=5, pady=5)
        
        cf_config = self.config_data.get("cloudflare", [{}])[0]
        auth = cf_config.get("authentication", {})
        api_key_info = auth.get("api_key", {})

        self.api_token_var = tk.StringVar(value=auth.get("api_token", ""))
        self.api_key_var = tk.StringVar(value=api_key_info.get("api_key", ""))
        self.email_var = tk.StringVar(value=api_key_info.get("account_email", ""))
        self.zone_id_var = tk.StringVar(value=cf_config.get("zone_id", ""))

        ttk.Label(cf_frame, text="API Token:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(cf_frame, textvariable=self.api_token_var, width=60).grid(row=0, column=1, sticky=tk.EW, padx=5)
        ttk.Label(cf_frame, text="API Key:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(cf_frame, textvariable=self.api_key_var, width=60).grid(row=1, column=1, sticky=tk.EW, padx=5)
        ttk.Label(cf_frame, text="Account Email:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(cf_frame, textvariable=self.email_var, width=60).grid(row=2, column=1, sticky=tk.EW, padx=5)
        ttk.Label(cf_frame, text="Zone ID:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(cf_frame, textvariable=self.zone_id_var, width=60).grid(row=3, column=1, sticky=tk.EW, padx=5)
        cf_frame.columnconfigure(1, weight=1)

        # --- Subdomains ---
        self.subdomain_frame = ttk.LabelFrame(parent, text="Subdomains")
        self.subdomain_frame.pack(fill=tk.X, padx=5, pady=5)
        self.subdomain_entries = []
        
        for sub in cf_config.get("subdomains", []):
            self.add_subdomain_entry(sub.get("name", ""), sub.get("proxied", False))

        ttk.Button(self.subdomain_frame, text="Add Subdomain", command=self.add_subdomain_entry).pack(pady=5)
        
        # --- Save Button ---
        ttk.Button(parent, text="Save and Restart Service", command=self.save_and_restart).pack(pady=10)

    def add_subdomain_entry(self, name="", proxied=False):
        frame = ttk.Frame(self.subdomain_frame)
        frame.pack(fill=tk.X, pady=2)

        name_var = tk.StringVar(value=name)
        proxied_var = tk.BooleanVar(value=proxied)

        ttk.Label(frame, text="Name:").pack(side=tk.LEFT, padx=5)
        entry = ttk.Entry(frame, textvariable=name_var)
        entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        check = ttk.Checkbutton(frame, text="Proxied", variable=proxied_var)
        check.pack(side=tk.LEFT, padx=5)

        remove_button = ttk.Button(frame, text="Remove", command=lambda: self.remove_subdomain_entry(frame))
        remove_button.pack(side=tk.LEFT, padx=5)
        
        self.subdomain_entries.append((frame, name_var, proxied_var))

    def remove_subdomain_entry(self, frame):
        for i, (f, _, _) in enumerate(self.subdomain_entries):
            if f == frame:
                self.subdomain_entries.pop(i)
                break
        frame.destroy()

    def create_logs_tab(self, parent):
        self.log_viewer = scrolledtext.ScrolledText(parent, wrap=tk.WORD)
        self.log_viewer.pack(fill=tk.BOTH, expand=True)

    def start_update_threads(self):
        threading.Thread(target=self.update_logs, daemon=True).start()
        threading.Thread(target=self.update_status, daemon=True).start()

    def run_systemctl(self, command):
        try:
            subprocess.run(["systemctl", command, self.service_name], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            if "permission" in e.stderr.lower() or "authentication" in e.stderr.lower():
                password = simpledialog.askstring("Sudo Password", "Enter your password:", show='*')
                if password:
                    sudo_command = f"echo {password} | sudo -S systemctl {command} {self.service_name}"
                    subprocess.run(sudo_command, shell=True, check=True, capture_output=True)
            else:
                messagebox.showerror("Error", f"Failed to run systemctl {command}: {e.stderr}")

    def save_and_restart(self):
        self.save_config_from_ui()
        self.run_systemctl("restart")

    def save_config_from_ui(self):
        try:
            new_config = {
                "a": self.a_var.get(),
                "aaaa": self.aaaa_var.get(),
                "purgeUnknownRecords": self.purge_var.get(),
                "ttl": int(self.ttl_var.get()),
                "cloudflare": [
                    {
                        "authentication": {
                            "api_token": self.api_token_var.get(),
                            "api_key": {
                                "api_key": self.api_key_var.get(),
                                "account_email": self.email_var.get()
                            }
                        },
                        "zone_id": self.zone_id_var.get(),
                        "subdomains": [
                            {"name": name_var.get(), "proxied": proxied_var.get()}
                            for _, name_var, proxied_var in self.subdomain_entries
                        ]
                    }
                ]
            }
            save_config(new_config)
            self.config_data = new_config
            messagebox.showinfo("Success", "Configuration saved successfully.")
        except ValueError:
            messagebox.showerror("Error", "Invalid TTL value. It must be an integer.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")

    def update_logs(self):
        if not os.path.exists(self.log_file_path):
            os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)
            with open(self.log_file_path, 'w') as f: pass
        while True:
            try:
                with open(self.log_file_path, 'r') as f:
                    logs = f.read()
                    if self.log_viewer.get("1.0", tk.END).strip() != logs.strip():
                        self.log_viewer.delete("1.0", tk.END)
                        self.log_viewer.insert(tk.END, logs)
                        self.log_viewer.see(tk.END)
            except Exception:
                pass # Avoid showing errors in the log viewer itself
            time.sleep(1)

    def update_status(self):
        while True:
            is_active = False
            try:
                result = subprocess.run(["systemctl", "is-active", self.service_name], capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip() == "active":
                    is_active = True
            except Exception:
                is_active = False # Default to inactive on any error
            
            fill_color = "green" if is_active else "red"
            self.status_canvas.itemconfig(self.status_indicator, fill=fill_color)
            time.sleep(5)

if __name__ == "__main__":
    app = App()
    app.mainloop()
