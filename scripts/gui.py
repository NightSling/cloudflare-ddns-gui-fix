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

        # Main container
        main_container = ttk.Frame(self)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Service control section
        service_frame = ttk.LabelFrame(main_container, text="Service Control")
        service_frame.pack(fill=tk.X, pady=5)
        self.create_service_widgets(service_frame)

        # Notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        # Configuration Tab
        config_tab = ttk.Frame(self.notebook)
        self.notebook.add(config_tab, text="Configuration")
        self.create_config_widgets(config_tab)

        # Logs Tab
        logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(logs_tab, text="Logs")
        self.log_viewer = scrolledtext.ScrolledText(logs_tab, wrap=tk.WORD)
        self.log_viewer.pack(fill=tk.BOTH, expand=True)

        # Threads for updates
        self.log_thread = threading.Thread(target=self.update_logs, daemon=True)
        self.log_thread.start()

        self.status_thread = threading.Thread(target=self.update_status, daemon=True)
        self.status_thread.start()

    def create_service_widgets(self, parent):
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        self.status_canvas = tk.Canvas(control_frame, width=20, height=20)
        self.status_canvas.pack(side=tk.LEFT, padx=(0, 10))
        self.status_indicator = self.status_canvas.create_oval(2, 2, 18, 18, fill="red")

        self.start_button = ttk.Button(control_frame, text="Start", command=lambda: self.run_systemctl("start"))
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop", command=lambda: self.run_systemctl("stop"))
        self.stop_button.pack(side=tk.LEFT, padx=5)

    def create_config_widgets(self, parent):
        # --- General Settings ---
        general_frame = ttk.LabelFrame(parent, text="General")
        general_frame.pack(fill=tk.X, padx=5, pady=5)

        self.a_var = tk.BooleanVar(value=self.config_data.get("a", True))
        ttk.Checkbutton(general_frame, text="Enable IPv4 (A records)", variable=self.a_var).pack(anchor=tk.W)

        self.aaaa_var = tk.BooleanVar(value=self.config_data.get("aaaa", True))
        ttk.Checkbutton(general_frame, text="Enable IPv6 (AAAA records)", variable=self.aaaa_var).pack(anchor=tk.W)
        
        self.purge_var = tk.BooleanVar(value=self.config_data.get("purgeUnknownRecords", False))
        ttk.Checkbutton(general_frame, text="Purge Unknown Records", variable=self.purge_var).pack(anchor=tk.W)

        ttk.Label(general_frame, text="TTL (in seconds):").pack(anchor=tk.W, side=tk.LEFT)
        self.ttl_var = tk.StringVar(value=self.config_data.get("ttl", 300))
        ttk.Entry(general_frame, textvariable=self.ttl_var).pack(anchor=tk.W, side=tk.LEFT)

        # --- Cloudflare Settings (simplified for now) ---
        cf_frame = ttk.LabelFrame(parent, text="Cloudflare")
        cf_frame.pack(fill=tk.X, padx=5, pady=5, expand=True)
        
        # For simplicity, we'll handle the first Cloudflare config entry
        cf_config = self.config_data.get("cloudflare", [{}])[0]
        auth = cf_config.get("authentication", {})
        api_key_info = auth.get("api_key", {})

        ttk.Label(cf_frame, text="API Token:").pack(anchor=tk.W)
        self.api_token_var = tk.StringVar(value=auth.get("api_token", ""))
        ttk.Entry(cf_frame, textvariable=self.api_token_var, width=50).pack(fill=tk.X)

        ttk.Label(cf_frame, text="API Key:").pack(anchor=tk.W)
        self.api_key_var = tk.StringVar(value=api_key_info.get("api_key", ""))
        ttk.Entry(cf_frame, textvariable=self.api_key_var, width=50).pack(fill=tk.X)

        ttk.Label(cf_frame, text="Account Email:").pack(anchor=tk.W)
        self.email_var = tk.StringVar(value=api_key_info.get("account_email", ""))
        ttk.Entry(cf_frame, textvariable=self.email_var, width=50).pack(fill=tk.X)

        ttk.Label(cf_frame, text="Zone ID:").pack(anchor=tk.W)
        self.zone_id_var = tk.StringVar(value=cf_config.get("zone_id", ""))
        ttk.Entry(cf_frame, textvariable=self.zone_id_var, width=50).pack(fill=tk.X)

        # --- Subdomains (very simplified) ---
        subdomain_frame = ttk.LabelFrame(cf_frame, text="Subdomains")
        subdomain_frame.pack(fill=tk.X, padx=5, pady=5, expand=True)
        self.subdomain_entries = []
        for sub in cf_config.get("subdomains", []):
            frame = ttk.Frame(subdomain_frame)
            frame.pack(fill=tk.X)
            name_var = tk.StringVar(value=sub.get("name", ""))
            proxied_var = tk.BooleanVar(value=sub.get("proxied", False))
            ttk.Label(frame, text="Name:").pack(side=tk.LEFT)
            ttk.Entry(frame, textvariable=name_var).pack(side=tk.LEFT, expand=True, fill=tk.X)
            ttk.Checkbutton(frame, text="Proxied", variable=proxied_var).pack(side=tk.LEFT)
            self.subdomain_entries.append((name_var, proxied_var))

        # --- Save Button ---
        save_button = ttk.Button(parent, text="Save and Restart Service", command=self.save_and_restart)
        save_button.pack(pady=10)

    def run_systemctl(self, command):
        try:
            subprocess.run(["systemctl", command, self.service_name], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            if "permission" in e.stderr.decode().lower() or "authentication" in e.stderr.decode().lower():
                password = simpledialog.askstring("Sudo Password", "Enter your password:", show='*')
                if password:
                    sudo_command = f"echo {password} | sudo -S systemctl {command} {self.service_name}"
                    subprocess.run(sudo_command, shell=True, check=True, capture_output=True)
            else:
                messagebox.showerror("Error", f"Failed to run systemctl {command}: {e.stderr.decode()}")

    def save_and_restart(self):
        self.save_config_from_ui()
        self.run_systemctl("restart")

    def save_config_from_ui(self):
        try:
            # Reconstruct the config data from UI elements
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
                            for name_var, proxied_var in self.subdomain_entries
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
            except Exception as e:
                self.log_viewer.delete("1.0", tk.END)
                self.log_viewer.insert(tk.END, f"Error reading log file: {e}")
            time.sleep(1)

    def update_status(self):
        while True:
            try:
                result = subprocess.run(["systemctl", "is-active", self.service_name], capture_output=True, text=True)
                is_active = result.stdout.strip() == "active"
                if "failed" in result.stdout.strip().lower():
                     password = simpledialog.askstring("Sudo Password", "Enter your password:", show='*')
                     if password:
                        sudo_command = f"echo {password} | sudo -S systemctl is-active {self.service_name}"
                        result = subprocess.run(sudo_command, shell=True, capture_output=True, text=True)
                        is_active = result.stdout.strip() == "active"
                
                fill_color = "green" if is_active else "red"
                self.status_canvas.itemconfig(self.status_indicator, fill=fill_color)
            except Exception:
                self.status_canvas.itemconfig(self.status_indicator, fill="red")
            time.sleep(5)

if __name__ == "__main__":
    app = App()
    app.mainloop()
