import tkinter as tk

session_master_password = None

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

def is_ciphertext_loaded():
    return

def clear_displayed_password():
    #do this automatically after ten seconds 
    return