## Antivirus Project - Final Year Project

This project implements a basic antivirus program with a graphical user interface (GUI) built using Python and customtkinter. 

**Features:**

* **Scans files:** Analyzes files within a specified directory.
* **MD5 Hashing:** Calculates MD5 hashes for comparison with known malware signatures.
* **Signature-based Detection:** Compares MD5 hashes to a dataset of known malware signatures (CSV file).
* **Multi-Threaded Scanning:** Utilizes multiple threads for efficient scanning.
* **GUI Progress:** Displays scanning progress and results.
* **Scan Results:** Provides details on total scanned files, infected files found, infected file paths, and scan duration.

**Getting Started:**

1. **Prerequisites:** Python 3.x

2. **Install Dependencies:**
   - Open a terminal or command prompt.
   - Navigate to the project directory using the `cd` command.
   - Install the required libraries using `pip install -r requirements.txt`. This file should list all the necessary libraries (customtkinter, hashlib, csv, os, time, concurrent.futures). If you don't have `requirements.txt`, you can install the libraries individually using `pip install <library_name>`.

3. **Running the Project:**
   - Open `antivirus_project.py` in a Python IDE or code editor.
   - Run the script (F5 or similar).

**Customization:**

* **Scan Location:** Modify the `scan_system32` function to specify a different directory for scanning.
* **Malware Dataset:** Update the `known_signatures.csv` file with the latest known malware MD5 signatures.

**Limitations:**

* Signature-based detection can have limitations. New malware might not be detected until its signature is added to the dataset.
* Scanning system directories like System32 might require administrative privileges. Make sure your program requests these permissions if necessary.

**Disclaimer:**

This project is for educational purposes only and is not intended as a complete antivirus solution. Consider implementing additional security features like behavioral analysis for a more comprehensive approach.

**Further Development:**

* Integrate additional security measures beyond signature-based detection.
* Enhance the user interface for a more user-friendly experience.
* Implement real-time scanning capabilities.

**Note:** This project uses customtkinter for a visually appealing GUI. You can replace it with the standard Tkinter library if preferred.
