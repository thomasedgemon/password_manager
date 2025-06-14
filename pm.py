import tkinter as tk 
import cryptography
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from os import urandom
import csv
import pandas as pd
import sys
import platform
from tkinter import messagebox
import json
import secrets
import string

APP_NAME = 'passwordmanager'

session_master_password = None

salt_size = 16
key_size = 32  #for aes256
iv_size = 16 
iterations = 600000
backend = default_backend()

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

def init_csv(csv_path):
    """Initialize CSV file with Label and Ciphertext columns if it doesn't exist"""
    if not os.path.exists(csv_path):
        try:
            with open(csv_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Label', 'Ciphertext'])  # Write header row
            print(f"Initialized new CSV file at: {csv_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create CSV file: {str(e)}")
            return False
    return True

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

def read_csv(csv_path, master_password):
    with open(csv_path, newline='') as csvfile:  
        reader = csv.DictReader(csvfile)
        for row in reader:
            print(row['Label'])  # Changed from 'column_name' to 'Label'

def new_password(master_password):
    #need fields for common name, plaintext password
    #need submit button to write a new row to the csv. 
    return 

def update_password(master_password):
    return 

def change_master_password():
    return

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return kdf.derive(password.encode())

def decrypt(master_password, common_name, ciphertext):
    #perform decryption
    
    #display label and decrypted password as str for 10 seconds, then
    clear_displayed_password()
    return

def encrypt(master_password, common_name, plaintext):
    #probably use aes-gcm
    #derive key with with iv and salt via pbkdf
    #pad data
    #encrypt with key
    #pull in data from user-inputted fields which don't yet exist. 
    salt = os.urandom(salt_size)
    iv = os.urandom(iv_size)  # Fixed: was 'iv' instead of 'iv_size'
    key = derive_key(master_password, salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combine salt, iv, ciphertext
    blob = salt + iv + ciphertext
    return base64.b64encode(blob).decode()
    #save as common name, ciphertext to csv
    #wipe master password from session memory
    #wipe fields where user inputted common name and plaintext password.

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

def load_ciphertext(csv_path):
    """Load labels into a dropdown which can be selected from for decryption"""
    try:
        with open(csv_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            labels = []
            for row in reader:
                labels.append(row['Label'])  # Changed from 'common_name' to 'Label'
            return labels
    except FileNotFoundError:
        messagebox.showerror("Error", f"CSV file not found: {csv_path}")
        return []
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load CSV: {str(e)}")
        return []

def is_ciphertext_loaded():
    return

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

def generate_a_password(master_password, common_name):
    length = 16
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def display_session_memory():
    """Returns True if master password is currently in-memory, False otherwise"""
    global session_master_password
    return session_master_password is not None

def set_session_password(password):
    """Store master password in session memory (used internally by operations)"""
    global session_master_password
    session_master_password = password

def clear_session_memory():
    """Clear master password from session memory"""
    global session_master_password
    session_master_password = None
    print("Session memory cleared")

def get_session_password():
    """Get the master password from session memory"""
    global session_master_password
    return session_master_password

def update_memory_display(in_memory_field):
    """Update the in-memory display field"""
    status = "True" if display_session_memory() else "False"
    in_memory_field.config(state="normal")
    in_memory_field.delete(0, tk.END)
    in_memory_field.insert(0, status)
    in_memory_field.config(state="readonly")

def main_app(config):
    root = tk.Tk()
    root.title("PasswordManager")
    root.geometry("400x600")
    
    csv_path = config['csv_path']  # Extract CSV path from config
    
    label = tk.Label(root, text=f"Using CSV:\n{csv_path}", font=("Arial", 12))
    label.pack(pady=20)
    frame = tk.Frame(root)
    frame.pack(pady=20)
    
    # Master Password field with label
    master_password_label = tk.Label(frame, text="Master Password:")
    master_password_label.grid(row=0, column=0, sticky="w", pady=(0, 5))
    master_password = tk.Entry(frame, width=30, show="*")  # Added show="*" for password hiding
    master_password.grid(row=0, column=1, padx=(10, 0), pady=(0, 5))
    
    # Plaintext password field with label
    plaintext_label = tk.Label(frame, text="Password to Encrypt:")
    plaintext_label.grid(row=1, column=0, sticky="w", pady=(5, 5))
    plaintext = tk.Entry(frame, width=30)
    plaintext.grid(row=1, column=1, padx=(10, 0), pady=(5, 5))
    
    # Common name field with label
    common_name_label = tk.Label(frame, text="Label:")
    common_name_label.grid(row=2, column=0, sticky="w", pady=(5, 10))
    common_name = tk.Entry(frame, width=30)
    common_name.grid(row=2, column=1, padx=(10, 0), pady=(5, 10))
    
    # Apply theme
    apply_theme(root, label, config)

    def open_settings():
        open_config_dialog(root, config, lambda new_config: apply_theme(root, label, new_config))

    def clear_field():
        """Clear all user-input fields and session memory"""
        displayed_password.config(state="normal")
        displayed_password.delete(0, tk.END)
        displayed_password.config(state="readonly")
        # Clear input fields
        master_password.delete(0, tk.END)
        plaintext.delete(0, tk.END)
        common_name.delete(0, tk.END)
        # Clear session memory
        clear_session_memory()
        update_memory_display(in_memory)

    settings_btn = tk.Button(root, text="Settings", command=open_settings)
    settings_btn.pack(pady=10)

    #load csv into memory when user inputs mp and presses "load csv" button
    load_csv = tk.Button(root, text="Load CSV", command=lambda: load_ciphertext(csv_path))
    #decrypt a given password when user inputs mp and presses "decrypt" button
    give_plaintext = tk.Button(frame, text="decrypt", command=lambda: decrypt(master_password.get()))
    #add a row to the csv with common name. 
    add_password = tk.Button(frame, text="add a new password", command=lambda: new_password(master_password.get()))
    #add a button to generate a new, random password
    generate_password = tk.Button(frame, text="generate a new password", command=lambda: generate_a_password(master_password.get()))

    #use grid for buttons in frame, pack for buttons in root
    load_csv.pack(pady=10)
    give_plaintext.grid(row=3, column=1, pady=10)
    add_password.grid(row=4, column=1, pady=10)
    generate_password.grid(row=5, column=1, pady=10)

    #make readonly field where password is displayed with label
    displayed_password_label = tk.Label(root, text="Decrypted Password:")
    displayed_password_label.pack(pady=(10, 0))
    displayed_password = tk.Entry(root, width=50)
    displayed_password.insert(0, "DecryptedPassword123!")
    displayed_password.config(state="readonly")
    displayed_password.pack(pady=(0, 10))

    #make readonly field displaying bool for if mp is in memory with label
    in_memory_label = tk.Label(root, text="Master Password in Memory:")
    in_memory_label.pack(pady=(10, 0))
    in_memory = tk.Entry(root, width=50)
    in_memory.insert(0, "True")
    in_memory.config(state="readonly")
    in_memory.pack(pady=(0, 10))

    root.after(60000, clear_field) #clear all user-input fields after 60 seconds
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
