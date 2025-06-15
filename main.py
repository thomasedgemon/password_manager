import tkinter as tk
import sys
from .config import apply_theme, open_config_dialog, get_config_path, prompt_for_config, load_config
from .session import clear_session_memory, update_memory_display
from .storage import load_ciphertext
from .crypto import decrypt, encrypt
from .password_utils import new_password, generate_a_password
APP_NAME = 'passwordmanager'

def main_app(config):
    root = tk.Tk()
    root.title("PasswordManager")
    root.geometry("700x700")
    
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
