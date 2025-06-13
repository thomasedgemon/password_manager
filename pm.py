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
root.geometry("600x400") #pixel dimensions
root.resizable(False, False) 
root.title("Password Manager")

def get_config_path():
    system = platform.system()
    home = os.path.expanduser("~")
    
    if system == "Windows":
        base = os.getenv("APPDATA", os.path.join(home, "AppData", "Roaming"))
    elif system == "Darwin":  # macOS
        base = os.path.join(home, "Library", "Application Support")
    else:  # Linux and other Unix-like
        base = os.path.join(home, ".config")
    
    config_dir = os.path.join(base, APP_NAME)
    os.makedirs(config_dir, exist_ok=True)  # Ensure the directory exists
    return os.path.join(config_dir, "config.txt")


def read_csv(master_password):
    with open('filename.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            print(row['column_name'])  # access by column header

def new_password(master_password):
    return 

def update_password(master_password):
    return 

def change_master_password():
    return

def decrypt(master_password, common_name):
    #display label and decrypted password as str for 10 seconds, then
    clear_displayed_password()
    return

def encrypt(master_password, common_name, password):
    #require double entry of master password
    return

def clear_displayed_password():
    return

def reset_master_password(old_master_password, new_master_password):
    #1. decrypt each row of file, hold in memory
    #2. use new password to encrypt each row
    #3. rewrite new row. 
    #. erase passwords from session memory. 
    return

def display_session_memory():
    #bool: is master password currently in-memory?
    return

def clear_session_memory():
    return

def move_ciphertext(master_password):
    return

def load_ciphertext():
    print("ciphertext loaded")

def prompt_for_config():
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

    config_window = tk.Tk()
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

    config_window.mainloop()

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

def load_common_names():
    return

config_path = get_config_path()

def main(csv_path):
    button = tk.Button(root, text="load ciphertext", command=load_ciphertext)
    button.pack(pady=20)  # Add some vertical spacing
    root.mainloop()


csv_path = load_config()
if not csv_path:
    prompt_for_config()
    csv_path = load_config()

if csv_path:
    main(csv_path)
else:
    print("Config not created. Exiting.")
    sys.exit(1)



#first dataflow, using app for the first time:
#1. open program. DONE
#2. search for hardcoded config destination. DONE
#3. force init config if not exists. DONE
#4. if config not init, close program. DONE 

