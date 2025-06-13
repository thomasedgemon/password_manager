import tkinter as tk 
import cryptography
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import csv
import pandas as pd
import sys
import platform
from tkinter import messagebox
import os
import json

APP_NAME = 'passwordmanager'

ciphertext = ''
in_session_memory = ''
log = []

root = tk.Tk()
root.geometry("600x400") 
root.resizable(False, False) 
root.title("Password Manager")

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

def read_csv(master_password):
    with open('filename.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            print(row['column_name'])  #access by column header

def new_password(master_password):
    #need fields for common name, plaintext password
    #need submit button to write a new row to the csv. 
    return 

def update_password(master_password):
    return 

def change_master_password():
    return

def decrypt(master_password, common_name):
    #perform decryption
    
    #display label and decrypted password as str for 10 seconds, then
    clear_displayed_password()
    return

def encrypt(master_password, common_name, password):
    return

def clear_displayed_password():
    #do this automatically after ten seconds 
    return

def reset_master_password(old_master_password, new_master_password):
    #1. decrypt each row of file, hold in memory
    #2. use new password to encrypt each row
    #3. rewrite each new row. 
    #. erase passwords from session memory. 
    return

def display_session_memory():
    #bool: is master password currently in-memory?
    return

def clear_session_memory():
    return

def load_ciphertext():
    #load common names into a dropdown which can be selected from for decryption
    print("ciphertext loaded")

def prompt_for_config():
    config_root = tk.Tk()
    config_root.withdraw()  #hide root window

    def submit_config():
        csv_path = csv_entry.get().strip()
        theme = theme_var.get()
        if not csv_path.endswith(".csv"):
            messagebox.showerror("Invalid Input", "Please enter a valid CSV file path.")
            return
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

def is_ciphertext_loaded():
    return

def open_config_dialog(parent, config, apply_callback=None):
    def save_and_apply():
        csv_path = csv_entry.get().strip()
        theme = theme_var.get()

        if not csv_path.endswith(".csv"):
            messagebox.showerror("Invalid Input", "Please enter a valid CSV file path.")
            return

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

def main_app(config):
    root = tk.Tk()
    root.title("PasswordManager")
    root.geometry("400x600")
    label = tk.Label(root, text=f"Using CSV:\n{config['csv_path']}", font=("Arial", 12))
    label.pack(pady=20)
    frame = tk.Frame(root)
    frame.pack(pady=20)
    master_password = tk.Entry(frame, width=30)
    master_password.grid(row=0, column=0, padx=(0, 10)) 
    apply_theme(root, label, config)

    def open_settings():
        open_config_dialog(root, config, lambda new_config: apply_theme(root, label, new_config))

    def clear_field():
        displayed_password.config(state="normal")  # temporarily unlock it
        displayed_password.delete(0, tk.END)
        displayed_password.config(state="readonly")

    settings_btn = tk.Button(root, text="Settings", command=open_settings)
    settings_btn.pack(pady=10)
    #more buttons here
    #load csv into memory when user inputs mp and presses "load csv" button
    load_csv = tk.Button(root, text="Load CSV", command = load_ciphertext)
    #decrypt a given password when user inputs mp and presses "decrypt" button
    give_plaintext = tk.Button(frame, text="decrypt", command=lambda: decrypt(master_password.get()))
    load_csv.pack(pady=10)
    give_plaintext.pac(pady=10)
    #make readonly field where password is displayed
    displayed_password = tk.Entry(root, width=50)
    displayed_password.insert(0, "DecryptedPassword123!")
    displayed_password.config(state="readonly")
    displayed_password.pack(pady=10)

    #make readonly field dipslaying bool for if mp is in memory
    in_memory = tk.Entry(root, width=50)
    in_memory.insert(0, "True")
    in_memory.config(state="readonly")
    in_memory.pack(pady=10)

    root.after(10000, clear_field)
    root.mainloop()

#entry into the app:::::
config_path = get_config_path()
config = load_config()
if not config:
    prompt_for_config()
    config = load_config()

if config:
    main_app(config)
else:
    print("Config not created. Exiting.")
    sys.exit(1)



#first dataflow, using app for the first time:
#1. open program. DONE
#2. search for hardcoded config destination. DONE
#3. force init config if not exists. DONE
#4. if config not init, close program. DONE 

#second dataflow, now that config is init:
#1. static field for master password entry
#2. build out function to add a password to the csv, along with its common name 
#3. 
#4.
#5.