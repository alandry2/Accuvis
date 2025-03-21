import hashlib
import os
import json
from tkinter import Tk, filedialog

def calculate_hash(file_path):
    #Calculates the SHA-256 hash of a given file
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        return None

def save_hashes(hashes, filename="file_hashes.json"):
    """Saves file hashes to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(hashes, f, indent=4)

def load_hashes(filename="file_hashes.json"):
    """Loads file hashes from a JSON file."""
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return {}

#using the Tk python library and filedialog function to prompt a dialog box for specific file selection
def select_files():
    root = Tk()
    root.withdraw() #this hides the main window
    file_path = filedialog.askopenfilenames(title="Select files to monitor")
    return list(file_path)

def monitor_files(file_list):
    """Monitors a list of files for integrity changes."""
    hashes = load_hashes()
    for file in file_list:
        new_hash = calculate_hash(file)
        if new_hash is None:
            print(f"[WARNING] {file} not found!")
            continue
        
        if file in hashes:
            if hashes[file] != new_hash:
                print(f"[ALERT] {file} has been modified!")
            else:
                print(f"[OK] {file} is unchanged.")
        else:
            print(f"[NEW] Tracking new file: {file}")
        
        hashes[file] = new_hash
    
    save_hashes(hashes)
    
# Main function test monitor
if __name__ == "__main__":
    #files_to_monitor = [r"C:\Users\Admin\Desktop\testhash.txt"]  # you need the r in front of string for structure of the path
    files_to_monitor = select_files()
    monitor_files(files_to_monitor)
