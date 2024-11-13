import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime
import os
import json
import subprocess
import threading
import time

class LogMonitoringApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Monitoring Tool")
        self.alert_type = None  # Initialize the alert_type attribute
        self.failed_login_count = 0  # Counter for failed login attempts
        
        # Server build instructions button
        add_host_btn = tk.Button(root, text="Server Build Instructions", command=self.show_server_build_instructions)
        add_host_btn.pack(pady=10)
        
        # Server build instructions button
        add_host_btn = tk.Button(root, text="Host adding Instructions", command=self.show_host_add_instructions)
        add_host_btn.pack(pady=10)
        
        # Button to open the add host interface
        self.add_host_button = tk.Button(root, text="Add Host", command=self.open_add_host_window)
        self.add_host_button.pack(pady=10)

        # Frame for control buttons
        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=10)
        
        # Load Hosts button
        load_button = tk.Button(control_frame, text="Host List", command=self.display_hosts)
        load_button.pack(pady=10)
        
        # Monitor button to start the host monitoring process
        monitor_btn = tk.Button(root, text="Monitor", command=self.show_host_list)
        monitor_btn.pack(pady=10)
        
        '''# Stop Monitoring Button
        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_button.pack(pady=5)'''

        # Frame to display each host in a structured manner
        self.hosts_frame = tk.Frame(self.root)
        self.hosts_frame.pack(pady=10, fill="x")

        # Scrolled Text widget for status messages
        self.output_display = scrolledtext.ScrolledText(self.root, width=50, height=10, wrap=tk.WORD)
        self.output_display.pack(pady=10)

        # Load hosts from JSON
        self.hosts = self.fetch_hosts_from_json()

    def show_server_build_instructions(self):
        instructions_window = tk.Toplevel(self.root)
        instructions_window.title("Server Build Instructions")
        instructions_window.geometry("500x400")
        
        instructions_text = scrolledtext.ScrolledText(instructions_window, wrap=tk.WORD, width=60, height=20)
        instructions_text.pack(pady=10, padx=10, fill="both", expand=True)
        
        instructions = r"""Guide for connecting from PowerShell on Windows to a Linux system over SSH:

            ### Step 1: Ensure SSH Client is Enabled on Windows

            Most recent versions of Windows 10 and 11 come with the OpenSSH client pre-installed. To confirm:

            1. Open **PowerShell** and type:
               ```powershell
               ssh
               ```
               If SSH is installed, you’ll see the usage instructions. If not, you can install it through **Settings** > **Apps** > **Optional features** and add **OpenSSH Client**.

            ### Step 2: Obtain the Linux System’s IP Address

            1. On your Linux machine, open a terminal and type:
               ```bash
               ip a
               ```
               or
               ```bash
               ifconfig
               ```
            2. Note the IP address associated with your active network interface (usually `eth0` or `wlan0`).

            ### Step 3: Generate SSH Key on Windows (Optional)

            To enable passwordless login:

            1. In **PowerShell**, generate an SSH key pair by typing:
               ```powershell
               ssh-keygen -t rsa -b 2048
               ```
            2. Save the key to the default location (usually `C:\Users\YourUsername\.ssh\id_rsa`).

            ### Step 4: Copy SSH Key to the Linux System (Optional)

            1. To copy the SSH key to your Linux system, use:
               ```powershell
               ssh-copy-id username@linux_ip
               ```
               Replace `username` with your Linux user account and `linux_ip` with the IP address of the Linux system.

               If `ssh-copy-id` is unavailable, manually copy the content of `C:\Users\YourUsername\.ssh\id_rsa.pub` and paste it into the `~/.ssh/authorized_keys` file on the Linux system.

            ### Step 5: Connect from PowerShell to the Linux System

            1. Use the following command to connect:
               ```powershell
               ssh username@linux_ip
               ```
               Replace `username` with your Linux username and `linux_ip` with the Linux machine’s IP address.

            2. If it’s your first connection, type `yes` to accept the SSH key fingerprint.

            ### Step 6: Automate Connection with SSH Key (If Set Up)

            After setting up the SSH key, subsequent connections should not require a password, allowing automated access for monitoring tasks or data transfers from Windows PowerShell to the Linux system."""
        instructions_text.insert(tk.END, instructions)
        instructions_text.configure(state="disabled")  # Make the text read-only

        close_button = tk.Button(instructions_window, text="Close", command=instructions_window.destroy)
        close_button.pack(pady=10)
        
    def show_host_add_instructions(self):
        instructions_window = tk.Toplevel(self.root)
        instructions_window.title("Add Host Instructions")
        instructions_window.geometry("500x400")
        
        instructions_text = scrolledtext.ScrolledText(instructions_window, wrap=tk.WORD, width=60, height=20)
        instructions_text.pack(pady=10, padx=10, fill="both", expand=True)
        
        instructions = r"""For Linux:
        Once you've generated an SSH public key on your Windows system in PowerShell, here’s what to do on the Linux side:

            1. **Copy the Public Key from Windows:**
               - In PowerShell, display the content of your public key:
                 ```powershell
                 type $env:USERPROFILE\.ssh\id_rsa.pub
                 ```
               - Copy the output (the entire line that starts with `ssh-rsa`).

            2. **Access the Linux System:**
               - Log in to your Linux system (you may still need to use your username and password if SSH keys aren’t set up yet).

            3. **Create or Open the `authorized_keys` File:**
               - On your Linux system, open a terminal and ensure you are in your home directory:
                 ```bash
                 cd ~
                 ```
               - Create a new directory in .ssh or if exists open the `~/.ssh/authorized_keys` file:
                 ```bash
                 mkdir -p ~/.ssh
                 nano ~/.ssh/authorized_keys
                 ```
               
            4. **Paste the Public Key:**
               - Paste the public key (copied from PowerShell) into the `authorized_keys` file.
               - Make sure the key is on a single line. Each key should be separate if you have multiple keys in this file.

            5. **Save and Close `authorized_keys`:**
               - In `nano`, press `Ctrl + X`, then `Y` to confirm, and press `Enter` to save.

            6. **Set Permissions on the `~/.ssh` Directory and `authorized_keys` File:**
               - It’s important that the `.ssh` directory and `authorized_keys` file have the correct permissions:
                 ```bash
                 chmod 700 ~/.ssh
                 chmod 600 ~/.ssh/authorized_keys
                 ```

            7. **Test the Connection from PowerShell:**
               - Back in PowerShell on your Windows machine, attempt to SSH into the Linux system:
                 ```powershell
                 ssh username@linux_ip
                 ```
               - Replace `username` with your Linux username and `linux_ip` with the IP address of your Linux machine.

            If everything is set up correctly, you should now be able to log in without needing a password. This setup is helpful for secure, automated access.
        """
        instructions_text.insert(tk.END, instructions)
        instructions_text.configure(state="disabled")  # Make the text read-only

        close_button = tk.Button(instructions_window, text="Close", command=instructions_window.destroy)
        close_button.pack(pady=10)    

    def save_hosts_to_json(self):
        with open("hosts.json", "w") as file:
            json.dump(self.hosts, file, indent=4)

    def fetch_hosts_from_json(self):
        if os.path.exists("hosts.json"):
            with open("hosts.json", "r") as file:
                return json.load(file)
        return []

    def open_add_host_window(self):
        add_host_window = tk.Toplevel(self.root)
        add_host_window.title("Add Host")

        tk.Label(add_host_window, text="Enter Username:").pack(pady=5)
        username_entry = tk.Entry(add_host_window, width=30)
        username_entry.pack(pady=5)
        
        tk.Label(add_host_window, text="Enter IP Address:").pack(pady=5)
        ip_entry = tk.Entry(add_host_window, width=30)
        ip_entry.pack(pady=5)
        
        save_button = tk.Button(add_host_window, text="Save Host", 
                                command=lambda: self.add_host(username_entry.get(), ip_entry.get(), add_host_window))
        save_button.pack(pady=10)

    def add_host(self, username, ip, window):
        if not hasattr(self, 'hosts'):
            self.hosts = []

        self.hosts.append({'username': username, 'ip': ip})
        self.save_hosts_to_json()
        window.destroy()

    def display_hosts(self):
        hosts_window = tk.Toplevel(self.root)
        hosts_window.title("Host List")
        hosts_window.geometry("400x300")

        hosts_frame = tk.Frame(hosts_window)
        hosts_frame.pack(fill="both", expand=True, padx=10, pady=10)

        if not self.hosts:
            tk.Label(hosts_frame, text="No hosts available to display.").pack()
            return

        for host in self.hosts:
            username = host.get("username")
            ip = host.get("ip")

            host_frame = tk.Frame(hosts_frame, bd=1, relief="solid", padx=5, pady=5)
            host_frame.pack(fill="x", pady=5)

            tk.Label(host_frame, text=f"Host: {username} @ {ip}", font=("Helvetica", 10, "bold")).grid(row=0, column=0, padx=5, sticky="w")

            check_button = tk.Button(
                host_frame, 
                text="Check Connection", 
                command=lambda u=username, i=ip: self.check_ssh_and_take_action(u, i)
            )
            check_button.grid(row=0, column=1, padx=5)

        close_button = tk.Button(hosts_window, text="Close", command=hosts_window.destroy)
        close_button.pack(pady=10)

    def check_ssh_and_take_action(self, username, ip):
        self.output_display.delete(1.0, tk.END)
        self.output_display.insert(tk.END, f"Checking connection to {username}@{ip}...\n")
        
        powershell_command = f'Start-Process powershell -ArgumentList "ssh -i C:/Users/Laptop Care/.ssh/id_rsa {username}@{ip} exit" -NoNewWindow -Wait'
        
        try:
            result = subprocess.run(['powershell', '-Command', powershell_command], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.output_display.insert(tk.END, f"Connection to {username}@{ip} was successful!\n")
            else:
                self.show_instruction_message(username, ip)
        except subprocess.TimeoutExpired:
            self.show_instruction_message(username, ip)
        except Exception as e:
            self.output_display.insert(tk.END, f"Error occurred: {e}. Please check your settings.\n")
            self.show_instruction_message(username, ip)

    def show_instruction_message(self, username, ip):
        messagebox.showinfo("Connection Failed", f"Unable to connect to {username}@{ip}. Please check your network or SSH settings.")

    def show_host_list(self):
        hosts_window = tk.Toplevel(self.root)
        hosts_window.title("Host List")
        hosts_window.geometry("450x350")

        hosts_frame = tk.Frame(hosts_window)
        hosts_frame.pack(fill="both", expand=True, padx=10, pady=10)

        if not self.hosts:
            tk.Label(hosts_frame, text="No hosts available to display.").pack()
            return

        for host in self.hosts:
            username = host.get("username")
            ip = host.get("ip")

            host_frame = tk.Frame(hosts_frame, bd=1, relief="solid", padx=5, pady=5)
            host_frame.pack(fill="x", pady=5)

            tk.Label(host_frame, text=f"Host: {username} @ {ip}", font=("Helvetica", 10, "bold")).grid(row=0, column=0, padx=5, sticky="w")

            check_button = tk.Button(
                host_frame, 
                text="Check Connection", 
                command=lambda u=username, i=ip: self.check_ssh_and_take_action(u, i)
            )
            check_button.grid(row=0, column=2, padx=5)

            alert_button = tk.Button(
                host_frame,
                text="Alert Options",
                command=lambda u=username, i=ip: self.open_alert_options_window(u, i)
            )
            alert_button.grid(row=0, column=1, padx=5)

        close_button = tk.Button(hosts_window, text="Close", command=hosts_window.destroy)
        close_button.pack(pady=10)

    def open_alert_options_window(self, username, ip):
        alert_window = tk.Toplevel(self.root)
        alert_window.title("Select Alert Type")

        tk.Label(alert_window, text="Select how you want to receive alerts for this host:").pack(pady=10)

        tk.Button(
            alert_window,
            text="Message Alert",
            command=lambda: self.set_alert_type_and_monitor("message", username, ip, alert_window)
        ).pack(pady=5)

        tk.Button(
            alert_window,
            text="Email Alert",
            command=lambda: self.open_email_details_window(username, ip, alert_window)
        ).pack(pady=5)

        tk.Button(alert_window, text="Close", command=alert_window.destroy).pack(pady=10)

    def set_alert_type_and_monitor(self, alert_type, username, ip, window):
        self.alert_type = alert_type  # Set the alert type (message or email)
        window.destroy()  # Close the alert options window
        self.monitor_logs(username, ip)  # Start monitoring logs

    def open_email_details_window(self, username, ip, alert_window):
        alert_window.destroy()  # Close the alert options window

        email_window = tk.Toplevel(self.root)
        email_window.title("Email Alert Details")

        tk.Label(email_window, text="Enter Email 'From' Address:").pack(pady=5)
        from_entry = tk.Entry(email_window, width=30)
        from_entry.pack(pady=5)

        tk.Label(email_window, text="Enter Email 'To' Address:").pack(pady=5)
        to_entry = tk.Entry(email_window, width=30)
        to_entry.pack(pady=5)

        tk.Label(email_window, text="Enter Email Password:").pack(pady=5)
        password_entry = tk.Entry(email_window, show="*", width=30)
        password_entry.pack(pady=5)

        tk.Button(
            email_window,
            text="Save and Monitor",
            command=lambda: self.save_email_details_and_monitor(
                from_entry.get(), to_entry.get(), password_entry.get(), username, ip, email_window
            )
        ).pack(pady=10)

    def save_email_details_and_monitor(self, from_addr, to_addr, password, username, ip, email_window):
        # Save the email details
        self.email_details = {"from": from_addr, "to": to_addr, "password": password}
        self.alert_type = "email"
        email_window.destroy()
        self.monitor_logs(username, ip)

    def monitor_logs(self, username, ip):
        self.output_display.delete(1.0, tk.END)
        self.output_display.insert(tk.END, f"Starting log monitoring for {username}@{ip}...\n")
        
        # Start monitoring logs in a separate thread to avoid freezing the GUI
        self.is_monitoring = True
        monitoring_thread = threading.Thread(target=self.monitor_logs_thread, args=(username, ip))
        monitoring_thread.start()

    def monitor_logs_thread(self, username, ip):
        try:
            # Command to fetch authentication logs via PowerShell
            command = f'powershell -Command "ssh {username}@{ip} journalctl -f | Select-String authentication"'

            # Start the process to execute the command in PowerShell
            with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
                while self.is_monitoring:  # Continue until `self.stop_monitoring` is True
                    output = proc.stdout.readline()
                    if output:
                        self.output_display.insert(tk.END, output)
                        self.output_display.see(tk.END)

                        # Check for "authentication failure" in the output to trigger alert
                        if "authentication failure" in output.lower():
                            alert_message = f"Authentication failure occurred for {username}@{ip}! Action needed!"
                            
                            # Show alert and pause monitoring until acknowledged
                            acknowledged = self.show_message_alert(alert_message)
                            
                            # Stop monitoring if acknowledgment is canceled
                            if not acknowledged:
                                proc.terminate()
                                self.is_monitoring = False
                                self.output_display.insert(tk.END, "Monitoring stopped.\n")
                                break

                        # Send email alert if configured
                        elif self.alert_type == "email" and hasattr(self, 'email_details'):
                            self.send_email_alert(alert_message, self.email_details)
                        
                        # Delay for next log collection
                        time.sleep(0.5)
        
        except Exception as e:
            self.output_display.insert(tk.END, f"Error occurred during log monitoring: {e}\n")


    def show_message_alert(self, message):
        # Configure a "red alert" style warning box
        alert_box = tk.Toplevel(self.root)
        alert_box.title("Critical Log Alert!")
        alert_box.config(bg="red")
        
        # Display message in alert box with critical style
        tk.Label(alert_box, text=message, font=("Arial", 12), bg="red", fg="white", padx=20, pady=20).pack()
        
        # Create a button to acknowledge the alert
        acknowledge_button = tk.Button(alert_box, text="Acknowledge", font=("Arial", 10), bg="white", fg="red", 
                                       command=lambda: (alert_box.destroy(), setattr(self, 'stop_monitoring', False)))
        acknowledge_button.pack(pady=10)

        # Wait for user interaction to proceed
        alert_box.transient(self.root)
        alert_box.grab_set()
        self.root.wait_window(alert_box)

        # Return True if acknowledged, allowing monitoring to continue
        return True

    
    '''def show_message_alert(self, username, ip):
        alert_message = f"Authentication failure for {username}@{ip}! Action needed!"
        messagebox.showwarning("Log Alert", alert_message)'''
        

    def send_email_alert(self, message, email_details):
        from smtplib import SMTP
        try:
            with SMTP("smtp.gmail.com", 587) as smtp:
                smtp.starttls()
                smtp.login(email_details["from"], email_details["password"])
                smtp.sendmail(
                    email_details["from"],
                    email_details["to"],
                    f"Subject: Log Alert\n\n{message}"
                )
                self.output_display.insert(tk.END, "Email alert sent successfully.\n")
        except Exception as e:
            self.output_display.insert(tk.END, f"Failed to send email alert: {e}\n")

    def stop_monitoring(self):
        self.is_monitoring = False
        self.output_display.insert(tk.END, "Stopping log monitoring...\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogMonitoringApp(root)
    root.mainloop()
