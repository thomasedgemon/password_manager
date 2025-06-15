import os 
from tkinter import messagebox
import csv

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

def load_ciphertext(csv_path):
    """Load labels into a dropdown which can be selected from for decryption"""
    try:
        with open(csv_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            labels = []
            for row in reader:
                labels.append(row['Label'])  
            return labels
    except FileNotFoundError:
        messagebox.showerror("Error", f"CSV file not found: {csv_path}")
        return []
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load CSV: {str(e)}")
        return []

