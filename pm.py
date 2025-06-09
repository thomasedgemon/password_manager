import tkinter as tk 
import cryptography
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
import csv
import pandas as pd

ciphertext = ''
in_session_memory = ''
log = []

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

