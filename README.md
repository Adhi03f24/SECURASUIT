
# README

## Overview

Welcome to Adhi03f24's SECURASUIT! This tool is a comprehensive security assessment utility built using Python and Tkinter for the GUI. It offers various functionalities including SSH and SMB brute-force attacks, PDF password cracking, web login brute-forcing, and network port scanning. This tool is intended for educational purposes and should only be used in environments where you have explicit permission to perform such actions.

## Features

1. **SSH Bruteforce**
   - Attempts to brute-force SSH passwords using a provided list of passwords.

2. **SMB Bruteforce**
   - Attempts to brute-force SMB passwords using a provided list of passwords.

3. **PDF Password Crack**
   - Attempts to unlock password-protected PDF files using a provided list of passwords.

4. **Web Login Bruteforce**
   - Attempts to brute-force web login credentials using a provided list of passwords.

5. **Network Port Scan**
   - Scans a specified range of ports on a given IP address to identify open ports.

## Prerequisites

- Python 3.x
- Required Python libraries:
  - `tkinter`
  - `paramiko`
  - `smbprotocol`
  - `pikepdf`
  - `requests`
  - `logging`

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Adhi03f24/SECURASUIT.git
   ```

2. Install the required Python libraries:
   ```bash
   pip install paramiko smbprotocol pikepdf requests
   ```
   or
   ```bash
   pip install -r .\requirements.txt
   ```

4. Ensure you have the `tkinter` library installed. This is usually included with Python, but if not, you can install it using your package manager.

## Usage

1. **Create the Batch File:**

   Save the following content in a file named `SECURASUIT.bat`:

   ```bash
   @echo off
   python "C:\path\to\SECURASUIT.py"
   pause
   ```

   Replace `C:\path\to\SECURASUIT.py` with the actual path to the Python script.

2. **Run the Tool:**

   Simply double-click the `SECURASUIT.bat` file to start the tool. This will open the GUI.

3. **GUI Usage:**

   - Choose a service from the list of options.
   - Fill in the required fields (IP address, username, password list file, etc.).
   - Click the corresponding button to execute the selected service.

## Detailed Description of Functions

### Main Functions

- **print_welcome_message()**
  - Decodes and prints an encrypted welcome message.

- **ssh_bruteforce(ip, username, password)**
  - Attempts to connect to an SSH server using the provided credentials.

- **smb_bruteforce(ip, username, password)**
  - Attempts to connect to an SMB server using the provided credentials.

- **pdf_password_crack(pdf_path, password)**
  - Attempts to unlock a PDF file using the provided password.

- **web_login_bruteforce(url, username, password)**
  - Attempts to log in to a web service using the provided credentials.

- **execute_bruteforce(service_function, args, password_list, num_threads=5)**
  - Executes the brute-force function using multiple threads.

- **unlock_pdf(pdf_file, wordlist_file)**
  - Attempts to unlock a PDF file using a list of passwords.

- **scan_ports(ip_address, start_port, end_port)**
  - Scans a range of ports on a given IP address.

### GUI Functions

- **browse_password_file_ssh(password_file_entry_ssh)**
  - Opens a file dialog to select a password list file for SSH.

- **browse_password_file_smb(password_file_entry_smb)**
  - Opens a file dialog to select a password list file for SMB.

- **browse_pdf_file(pdf_file_entry)**
  - Opens a file dialog to select a PDF file.

- **browse_wordlist_file(wordlist_file_entry)**
  - Opens a file dialog to select a wordlist file.

- **browse_password_file_web(password_file_entry_web)**
  - Opens a file dialog to select a password list file for web login.

## Logging

All activities are logged in `security_assessment.log` with timestamps and details of successes and failures.

## Disclaimer

This tool is intended for educational purposes only. Unauthorized use of this tool on systems without explicit permission is illegal and unethical. Always ensure you have permission before conducting security assessments.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Contact

For any questions or issues, please contact ADHI03F24.

---

Enjoy using the tool and stay ethical!
