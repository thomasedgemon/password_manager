import string
import secrets

def generate_a_password(master_password, common_name):
    length = 16
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def remove_a_password(master_password, common_name):
    return 

def update_password(master_password):
    return 

def change_master_password():
    return

def reset_master_password(old_master_password, new_master_password):
    #1. decrypt each row of file, hold in memory
    #2. use new password to encrypt each row
    #3. rewrite each new row. 
    #. erase passwords from session memory. 
    return