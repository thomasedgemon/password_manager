import tkinter as tk
from tkinter import messagebox
import os 
import csv
import json
import platform
from storage import init_csv

APP_NAME = 'passwordmanager'



def prompt_for_config():
    config_root = tk.Tk()
    config_root.withdraw()  #hide root window

    def submit_config():
        csv_path = csv_entry.get().strip()
        theme = theme_var.get()
        if not csv_path.endswith(".csv"):
            messagebox.showerror("Invalid Input", "Please enter a valid CSV file path.")
            return
        
        # Initialize CSV if it doesn't exist
        if not init_csv(csv_path):
            return  # Don't save config if CSV creation failed
        
        config = {
            "csv_path": csv_path,
            "theme": theme
        }
        save_config(config)
        messagebox.showinfo("Saved", f"Config saved to {config_path}")
        config_window.destroy()
        config_root.destroy()  #close hidden root window after config done

    config_window = tk.Toplevel()
    config_window.title("Initial Config Setup")
    config_window.geometry("400x200")

    tk.Label(config_window, text="Enter path to CSV file:").pack(pady=(10, 5))
    csv_entry = tk.Entry(config_window, width=50)
    csv_entry.pack()

    tk.Label(config_window, text="Choose theme:").pack(pady=(15, 5))
    theme_var = tk.StringVar(value="light")
    tk.Radiobutton(config_window, text="Light Mode", variable=theme_var, value="light").pack()
    tk.Radiobutton(config_window, text="Dark Mode", variable=theme_var, value="dark").pack()

    submit_btn = tk.Button(config_window, text="Save & Continue", command=submit_config)
    submit_btn.pack(pady=10)

    config_window.grab_set()  
    config_window.wait_window()

def save_config(config):
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

def load_config():
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return None
    return None

def open_config_dialog(parent, config, apply_callback=None):
    def save_and_apply():
        csv_path = csv_entry.get().strip()
        theme = theme_var.get()

        if not csv_path.endswith(".csv"):
            messagebox.showerror("Invalid Input", "Please enter a valid CSV file path.")
            return

        # Initialize CSV if it doesn't exist
        if not init_csv(csv_path):
            return  # Don't save config if CSV creation failed

        config["csv_path"] = csv_path
        config["theme"] = theme
        save_config(config)

        if apply_callback:
            apply_callback(config)
        config_window.destroy()

    config_window = tk.Toplevel(parent)
    config_window.title("Settings")
    config_window.geometry("400x200")

    tk.Label(config_window, text="CSV file path:").pack(pady=(10, 5))
    csv_entry = tk.Entry(config_window, width=50)
    csv_entry.insert(0, config.get("csv_path", ""))
    csv_entry.pack()

    tk.Label(config_window, text="Theme:").pack(pady=(15, 5))
    theme_var = tk.StringVar(value=config.get("theme", "light"))
    tk.Radiobutton(config_window, text="Light", variable=theme_var, value="light").pack()
    tk.Radiobutton(config_window, text="Dark", variable=theme_var, value="dark").pack()

    submit_btn = tk.Button(config_window, text="Save", command=save_and_apply)
    submit_btn.pack(pady=10)

def apply_theme(root, label, config):
    theme = config.get("theme", "light")
    if theme == "dark":
        bg = "#2e2e2e"
        fg = "#ffffff"
    else:
        bg = "#f0f0f0"
        fg = "#000000"
    
    root.configure(bg=bg)
    label.configure(bg=bg, fg=fg)
    
    # Apply theme to all labels in the app
    for widget in root.winfo_children():
        if isinstance(widget, tk.Label):
            widget.configure(bg=bg, fg=fg)
        elif isinstance(widget, tk.Frame):
            widget.configure(bg=bg)
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    child.configure(bg=bg, fg=fg)

def read_csv(csv_path, master_password):
    with open(csv_path, newline='') as csvfile:  
        reader = csv.DictReader(csvfile)
        for row in reader:
            print(row['Label'])  # Changed from 'column_name' to 'Label'

def get_config_path():
    system = platform.system()
    home = os.path.expanduser("~")
    
    if system == "Windows":
        base = os.getenv("APPDATA", os.path.join(home, "AppData", "Roaming"))
    elif system == "Darwin":  #mac
        base = os.path.join(home, "Library", "Application Support")
    else:  #linux
        base = os.path.join(home, ".config")
    
    config_dir = os.path.join(base, APP_NAME)
    os.makedirs(config_dir, exist_ok=True)  #ensure dir exists
    return os.path.join(config_dir, "config.txt")

config_path = get_config_path()