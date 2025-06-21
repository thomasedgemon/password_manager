import tkinter as tk
import sys
from config import apply_theme, open_config_dialog, prompt_for_config, load_config
from session import clear_session_memory, update_memory_display
from storage import load_ciphertext
from crypto import decrypt, encrypt
from password_utils import generate_a_password, remove_a_password

APP_NAME = 'passwordmanager'

def main_app(config):
    root = tk.Tk()
    root.title("PasswordManager")
    root.geometry("700x700")
    
    csv_path = config['csv_path']
    log_messages = []

    # -- Top-level label --
    label = tk.Label(root, text=f"Using CSV:\n{csv_path}", font=("Arial", 12))
    label.pack(pady=20)

    frame = tk.Frame(root)
    frame.pack(pady=10)

    # -- Input fields with labels --
    tk.Label(frame, text="Master Password:").grid(row=0, column=0, sticky="e", pady=(0, 5))
    master_password = tk.Entry(frame, width=30, show="*")
    master_password.grid(row=0, column=1, padx=(10, 0), pady=(0, 5))

    tk.Label(frame, text="Password to Encrypt:").grid(row=1, column=0, sticky="e", pady=(5, 5))
    plaintext = tk.Entry(frame, width=30)
    plaintext.grid(row=1, column=1, padx=(10, 0), pady=(5, 5))

    tk.Label(frame, text="Label:").grid(row=2, column=0, sticky="e", pady=(5, 5))
    common_name = tk.Entry(frame, width=30)
    common_name.grid(row=2, column=1, padx=(10, 0), pady=(5, 5))

    tk.Label(frame, text="Select Saved Label:").grid(row=3, column=0, sticky="e", pady=(5, 10))
    selected_label = tk.StringVar()
    selected_label.set("Select label")
    dropdown = tk.OptionMenu(frame, selected_label, "Loading...")
    dropdown.grid(row=3, column=1, sticky="w", pady=(5, 10))

    def refresh_dropdown():
        labels = load_ciphertext(csv_path)
        if labels:
            selected_label.set(labels[0])
            menu = dropdown["menu"]
            menu.delete(0, "end")
            for label in labels:
                menu.add_command(label=label, command=lambda value=label: selected_label.set(value))

    refresh_dropdown()

    # -- Helper functions --
    def log_action(message):
        log_messages.append(message)
        if len(log_messages) > 5:
            log_messages.pop(0)
        log_display.config(state="normal")
        log_display.delete(0, tk.END)
        for msg in log_messages:
            log_display.insert(tk.END, msg)
        log_display.config(state="disabled")

    def clear_displayed_password_field():
        displayed_password.config(state="normal")
        displayed_password.delete(0, tk.END)
        displayed_password.config(state="readonly")

    def handle_decryption():
        label = selected_label.get()
        mp = master_password.get()
        if not label or label == "Select label":
            log_action("⚠️ No label selected.")
            return
        if not mp:
            log_action("⚠️ Master password is required.")
            return
        result = decrypt(mp, label, csv_path)
        if result:
            displayed_password.config(state="normal")
            displayed_password.delete(0, tk.END)
            displayed_password.insert(0, result)
            displayed_password.config(state="readonly")
            log_action(f"🔓 Decrypted '{label}'")
            root.after(10000, clear_displayed_password_field)
        else:
            log_action(f"❌ Failed to decrypt '{label}'")

    def clear_field():
        displayed_password.config(state="normal")
        displayed_password.delete(0, tk.END)
        displayed_password.config(state="readonly")
        master_password.delete(0, tk.END)
        plaintext.delete(0, tk.END)
        common_name.delete(0, tk.END)
        clear_session_memory()
        update_memory_display(in_memory)

    def open_settings():
        open_config_dialog(root, config, lambda new_config: apply_theme(root, label, new_config))

    # -- Buttons: organized into grid --
    add_password = tk.Button(
        frame, text="Encrypt & Save",
        command=lambda: (
            encrypt(master_password.get(), common_name.get(), plaintext.get(), csv_path),
            refresh_dropdown(),
            log_action(f"Encrypted '{common_name.get()}'"),
            master_password.delete(0, tk.END),
            common_name.delete(0, tk.END),
            plaintext.delete(0, tk.END),
            root.after(10000, clear_displayed_password_field)
        )
    )
    add_password.grid(row=4, column=0, pady=5, sticky="e")

    give_plaintext = tk.Button(frame, text="Decrypt", command=handle_decryption)
    give_plaintext.grid(row=4, column=1, pady=5, sticky="w")

    generate_password = tk.Button(
        frame, text="Generate Password",
        command=lambda: generate_a_password(master_password.get())
    )
    generate_password.grid(row=5, column=0, pady=5, sticky="e")

    remove_entry = tk.Button(frame, text='remove an entry', command=remove_a_password)
    remove_entry.grid(row=5, column=2, pady=5, sticky="w")

    clear_memory = tk.Button(
        frame, text="Clear Memory",
        command=lambda: (
            clear_session_memory(),
            update_memory_display(in_memory),
            log_action("Cleared memory")
        )
    )
    clear_memory.grid(row=5, column=1, pady=5, sticky="w")

    # -- Settings button (root level) --
    settings_btn = tk.Button(root, bd=3, relief="raised", text="Settings", command=open_settings)
    settings_btn.pack(pady=10)

    # -- Decrypted password field --
    displayed_password_label = tk.Label(root, text="Decrypted Password:")
    displayed_password_label.pack()
    displayed_password = tk.Entry(root, width=50, state="readonly")
    displayed_password.pack(pady=(0, 10))

    # -- Master password in memory field --
    in_memory_label = tk.Label(root, text="Master Password in Memory:")
    in_memory_label.pack()
    in_memory = tk.Entry(root, width=50)
    in_memory.insert(0, "False")
    in_memory.config(state="readonly")
    in_memory.pack(pady=(0, 10))

    # -- Activity log --
    log_label = tk.Label(root, text="Activity Log:")
    log_label.pack(pady=(10, 0))
    log_display = tk.Listbox(root, height=5, width=60)
    log_display.pack(pady=(0, 10))
    log_display.config(state="disabled")

    apply_theme(root, label, config)
    root.after(60000, clear_field)
    root.mainloop()


#entry into the app:::::

config = load_config()
if not config:
    prompt_for_config()
    config = load_config()

if config:
    main_app(config)
else:
    print("Config not created. Exiting.")
    sys.exit(1)
