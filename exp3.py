import customtkinter
from tkinter import *
import tkinter as tk
import tkinter as ttk
from tkinter import Canvas, Button, PhotoImage
import os
import hashlib
import csv
from concurrent.futures import ThreadPoolExecutor
import time
import yara
import datetime
from tkinter import filedialog, Tk 
from tkinter import messagebox
import subprocess
# Global variables
total_files = 0
infected_files = 0
start_time = time.time()
infected_file_paths = []


###################### GUI START ########################
# System setting
customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("blue")

# Our app Frame
app = customtkinter.CTk()
app.geometry("720x480")
app.title("Final Year Project")

# Adding UI Element
title = customtkinter.CTkLabel(app, text="Scan Your Computer", font=("Helvetica", 30), padx=30)
title.pack(padx=10, pady=10, anchor="w")



# Quick scan label and button
quick_scan_type_frame = customtkinter.CTkFrame(master=app)  # Create a frame
quick_scan_type_frame.pack(padx=20, pady=20,anchor="center")  # Pack the frame with padding
quick_scan_label = customtkinter.CTkLabel(
    master=quick_scan_type_frame,
    text="Run a quick scan\nCheck the most common malware hiding in your computer",
    font=("Helvetica", 16),
    width=600,  # Adjust width as needed
    justify=tk.LEFT,  # Left-align text within the label
    anchor="w",
)
quick_scan_label.pack(padx=10, pady=5)

# Quick scan button
quick_scan_button = customtkinter.CTkButton(
    master=quick_scan_type_frame, text="Quick Scan", font=("Helvetica", 20), corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=lambda:scan_system32()
)
quick_scan_button.place(relx=0.99, rely=0.52, anchor="e")  # Align to the right side

# Custom scan label and button
custom_scan_type_frame = customtkinter.CTkFrame(master=app)  # Create a frame
custom_scan_type_frame.pack(padx=20, pady=20)  # Pack the frame with padding
custom_scan_label = customtkinter.CTkLabel(
    master=custom_scan_type_frame,
    text="Run a custom scan\nChoose which files and folders to check for malware",
    font=("Helvetica", 16),
    width=600,  # Adjust width as needed
    justify=tk.LEFT,  # Left-align text within the label
    anchor="w",
)
custom_scan_label.pack(padx=10, pady=5)
# Custom Scan Button
custom_scan_button = customtkinter.CTkButton(
    master=custom_scan_type_frame, text="Custom Scan", font=("Helvetica", 20),corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=lambda: select_files()
)
custom_scan_button.place(relx=0.99, rely=0.52, anchor="e")  # Align to the right side

# Full scan label and button
full_scan_type_frame = customtkinter.CTkFrame(master=app)  # Create a frame
full_scan_type_frame.pack(padx=20, pady=20)  # Pack the frame with padding
full_scan_label = customtkinter.CTkLabel(
    master=full_scan_type_frame,
    text="Run a full scan\nCheck your entire computer for malware",
    font=("Helvetica", 16),
    width=600,  # Adjust width as needed
    justify=tk.LEFT,  # Left-align text within the label
    anchor="w",
)
full_scan_label.pack(padx=10, pady=5)
# Full scan Button
full_scan_button = customtkinter.CTkButton(
    master=full_scan_type_frame, text="Full Scan", font=("Helvetica", 20),corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=lambda: scan_system32()
)
full_scan_button.place(relx=0.99, rely=0.52, anchor="e")  # Align to the right side

# Cancel Button
def exit_gui():
    app.destroy()

Cancel = customtkinter.CTkButton(app, text="Cancel",font=("Helvetica", 20),corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=exit_gui)
Cancel.place(relx=0.73 , rely=0.80)
######################### GUI END #############################

######################### SYSTEM 32 SCAN ######################
# Function to compute MD5 hash of a file
def compute_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        data = f.read(4194304)  # Read file in larger chunks (4 MB)
        while data:
            hasher.update(data)
            data = f.read(4194304)
    return hasher.hexdigest()

# Function to compare MD5 hash with the dataset
def compare_md5_with_dataset(file_md5, dataset):
    return file_md5 in dataset

# Function to scan a single file
def scan_single_file(file_path, dataset):
    global infected_files

    try:
        file_md5 = compute_md5(file_path)
        is_infected = compare_md5_with_dataset(file_md5, dataset)
        if is_infected:
            infected_files += 1
            print(f"File '{file_path}' is potentially malicious!")
            infected_file_paths.append(file_path)
        else:
            print(f"File '{file_path}' seems clean.")
    except PermissionError as e:
        print(f"Permission error: {e}. Skipping file: {file_path}")


# Function to scan the System32 folder and display progress
def scan_system32():
    global total_files

    quick_scan_type_frame.destroy()
    full_scan_type_frame.destroy()
    custom_scan_type_frame.destroy()
    title.destroy()
    
    #frame2 = customtkinter.CTkFrame(master=app)  # Create a frame
    #frame2.pack(padx=20, pady=20,anchor="center")  # Pack the frame with padding

    #Scanning = customtkinter.CTkLabel(app, text="Scanning in Progress .....", font=("Helvetica", 30), padx=30)
    #Scanning.pack(padx=10, pady=10, anchor="w")


    
    

    

    system32_path = os.path.join(os.environ['SystemRoot'], 'System32')
    file_list = []

    for root_dir, _, files in os.walk(system32_path):
        for file in files:
            file_path = os.path.join(root_dir, file)
            file_list.append(file_path)

    num_threads = os.cpu_count() * 2
    batch_size = 50  # Experiment with different batch sizes

    total_files = len(file_list)
    processed_files = 0

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        dataset = load_dataset('known_signature.csv')
        for i in range(0, total_files, batch_size):
            batch_files = file_list[i:i + batch_size]
            executor.map(scan_single_file, batch_files, [dataset] * len(batch_files))

            processed_files += len(batch_files)
            progress_percentage = (processed_files / total_files) * 100
            #progress_bar["value"] = progress_percentage
            #scanning_window.update_idletasks()  # Update the GUI to show the progress

    # Print scan results after completion
    print_scan_results()

# Function to load the dataset from a CSV file
def load_dataset(dataset_file):
    dataset = set()
    with open(dataset_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            dataset.add(row['md5'])
    return dataset

# Function to print scan results
def print_scan_results():
    global total_files
    global infected_files
    global infected_file_paths
    global start_time
    
    # Destroy previous frames and labels
    quick_scan_type_frame.destroy()
    full_scan_type_frame.destroy()
    custom_scan_type_frame.destroy()
    title.destroy()
    
    # Create a new frame for scan results
    result_frame = customtkinter.CTkFrame(master=app)
    result_frame.place(relx=0.5, rely=0.5, anchor="center")
    
    # Display scan completion message
    scan_completion_label = customtkinter.CTkLabel(master=result_frame, text="Scanning Done !!", font=("Helvetica", 30), padx=30)
    scan_completion_label.pack(padx=5, pady=5)
    
    # Display scan results
    total_files_label = customtkinter.CTkLabel(master=result_frame, text=f"Total files: {total_files}", font=("Helvetica", 16))
    total_files_label.pack(padx=10, pady=10)
    
    infected_files_label = customtkinter.CTkLabel(master=result_frame, text=f"Infected files: {infected_files}", font=("Helvetica", 16))
    infected_files_label.pack(padx=10, pady=10)
    
    # Button to display infected file paths
    def show_infected_file_paths():
        messagebox.showinfo("Infected File Paths", "\n".join(infected_file_paths))
    
    infected_file_paths_button = customtkinter.CTkButton(master=result_frame, text="Infected File Paths", font=("Helvetica", 20), corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=show_infected_file_paths)
    infected_file_paths_button.pack(padx=10, pady=10)
    
    scan_duration_label = customtkinter.CTkLabel(master=result_frame, text=f"Scan duration: {time.time() - start_time:.2f} seconds", font=("Helvetica", 16))
    scan_duration_label.pack(padx=10, pady=10)

    # Toggle button for firewall
    firewall_enabled = False

    def toggle_firewall():
        nonlocal firewall_enabled
        firewall_enabled = not firewall_enabled
        firewall_button.configure(text="Turn Off Firewall" if firewall_enabled else "Turn On Firewall")
        # Enable or disable firewall based on the state
        if firewall_enabled:
            enable_firewall()
        else:
            disable_firewall()


    firewall_button_frame = customtkinter.CTkFrame(master=result_frame)
    firewall_button_frame.pack(padx=2, pady=2)

    firewall_button = customtkinter.CTkButton(master=firewall_button_frame, text="Turn On Firewall", font=("Helvetica", 20), corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=toggle_firewall)
    firewall_button.pack(padx=2, pady=2)






#########################  SYSTEM 32 END ######################


#########################Full Scan Starts #######################
def fullscan():
  global total_files

  # Scan the entire system instead of just System32
  root_dir = os.path.join(os.environ['SystemRoot'])  # Start from system root

  file_list = []
  for root_dir, _, files in os.walk(root_dir):
    # Exclude specific directories if needed (e.g., temporary folders)
    if any(exclude in root_dir for exclude in ["\\Temp\\", "\\System Volume Information\\"]):
      continue  # Skip excluded directories

    for file in files:
      file_path = os.path.join(root_dir, file)
      file_list.append(file_path)

  # Rest of the code remains the same...
  num_threads = os.cpu_count() * 2
  batch_size = 50  # Experiment with different batch sizes

  total_files = len(file_list)
  processed_files = 0

  with ThreadPoolExecutor(max_workers=num_threads) as executor:
    dataset = load_dataset('known_signature.csv')
    for i in range(0, total_files, batch_size):
      batch_files = file_list[i:i + batch_size]
      executor.map(scan_single_file, batch_files, [dataset] * len(batch_files))

      processed_files += len(batch_files)
      progress_percentage = (processed_files / total_files) * 100
      print(f"Scanning progress: {progress_percentage:.2f}% ({processed_files}/{total_files})")

  print_scan_results()

#########################Full Scan Ends #########################

#########################Custom Scan Starts #####################
def select_files():
    quick_scan_type_frame.destroy()
    full_scan_type_frame.destroy()
    custom_scan_type_frame.destroy()
    title.destroy()
    scan_completion_label = customtkinter.CTkLabel(master=app, text="Scanning Done !!", font=("Helvetica", 30), padx=30)
    scan_completion_label.place(relx=0.3, rely=0.1)
    open_report_button = customtkinter.CTkButton(app, text="Open report",font=("Helvetica", 20),corner_radius=32,hover_color="#4158D0",border_color="#FFCC70",border_width=1, command=open_report)
    open_report_button.place(relx=0.42 , rely=0.3)





    root = Tk()
    root.withdraw()  # Hide the main window
    filepath = filedialog.askopenfilename()
    if filepath:
        # Load YARA rules
        rules = yara.compile(filepath="malware_rules.yara")

        # Open log file in append mode
        log_file = open("malware_scan_log.txt", "a")

        # Write scan report header
        log_file.write(f"====================================================\n")
        log_file.write(f"** Malware Scan Report **\n")
        log_file.write(f"====================================================\n")
        log_file.write(f"Scan Date & Time: {datetime.datetime.now()}\n")
        log_file.write(f"Scanned File: {filepath}\n\n")

        # Scan the selected file for malicious patterns
        matches = rules.match(filepath=filepath)

        # Write scan results
        if matches:
            log_file.write(f"** Malicious Patterns Found! **\n\n")
            for match in matches:
                log_file.write(f"Rule: {match.rule}\n")
                log_file.write(f"Description: {match.description}\n")
                log_file.write(f"Tags: {', '.join(match.tags)}\n\n")  # Join tags with commas
        else:
            log_file.write(f"** No Malicious Patterns Detected. **\n")

        # Close the log file
        log_file.write(f"====================================================\n")
        log_file.close()

        print("Scan completed. Check malware_scan_log.txt for results.")
    else:
        print("No file selected. Exiting...")

#########################Custom Scan Ends #######################

######open report ###########
def open_report():
    try:
        with open("malware_scan_log.txt", "r") as file:
            content = file.read()
            # Create a new window to display the content
            report_window = tk.Toplevel(app)
            report_window.title("Malware Scan Report")
            report_text = tk.Text(report_window)
            report_text.insert(tk.END, content)
            report_text.pack()
    except FileNotFoundError:
        messagebox.showerror("Error", "The file 'malware_scan_log.txt' does not exist.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


#######open report ends ############

##########################FireWall Settings######################
def enable_firewall():
    try:
        # PowerShell command to enable Windows Defender Firewall with Advanced Security
        powershell_command = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
        
        # Run the PowerShell command
        subprocess.run(["powershell", "-Command", powershell_command], check=True)
        
        print("Firewall has been enabled with the best possible security settings.")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print("Failed to enable the firewall.")

def disable_firewall():
    try:
        # PowerShell command to disable Windows Defender Firewall with Advanced Security
        powershell_command = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"
        
        # Run the PowerShell command
        subprocess.run(["powershell", "-Command", powershell_command], check=True)
        
        print("Firewall has been disabled.")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print("Failed to disable the firewall.")
##########################Firewall Settings Ends ################



# Run app
app.mainloop()