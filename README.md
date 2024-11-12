# Real-time-log-monitoring

Log Monitoring and Alerting Tool

This project is a real-time log monitoring tool designed for Security Operations Centers (SOC) and system administrators. It connects from a Windows system using PowerShell to monitor authentication logs on a Linux machine. The tool alerts the user of any critical events (such as "authentication failure") through an on-screen red alert or email notification.

Features

Real-time Monitoring: Continuously monitors authentication logs for specific keywords.

Custom Alerts: Supports on-screen alert pop-ups with red-alert styling and email notifications for critical events.

Acknowledgment Mechanism: Pauses monitoring until the user acknowledges the alert, ensuring no critical events are missed.

Easy SSH Setup: Uses PowerShell to establish a secure SSH connection from Windows to Linux.


Requirements

Windows with PowerShell installed.

Python (for GUI and email functionality).

SSH Access: SSH should be configured to connect from your Windows system to the Linux server.

Linux System: The monitored system should support journalctl for logging.


Usage

1. Run the Monitoring Tool: Open PowerShell and execute the following command:

python monitor.py


2. Enter the Linux System Details: In the GUI, enter the Linux username, IP address, and choose your alert type (on-screen message or email).


3. Start Monitoring: Click "Start Monitoring" to begin real-time log monitoring. A red alert or email will be triggered upon detecting critical events.


4. Stop Monitoring: Click "Stop Monitoring" to terminate the session safely.



Sample Alerts

On-Screen Alert: Pop-up alert with a red background and acknowledgment button.

Email Alert: Sends a detailed alert message to the configured email address.


Google Drive link for POC

https://drive.google.com/file/d/16eTcMKylwzd8sZHKLj1h0Ye-FWv5s0fj/view?usp=drivesdk

Contact

For questions or collaboration, feel free to reach out via GitHub.


---

This README.md provides a complete overview of the tool’s functionality, setup instructions, and usage guidance, making it easy for others to get started.

