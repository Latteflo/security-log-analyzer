"""
Platform-specific utilities for Security Log Analyzer
"""

import os
import sys
import platform
import tempfile
import subprocess

def get_os_name():
    """Return the name of the operating system"""
    system = platform.system()
    if system == "Darwin":
        return "macOS"
    return system

def get_log_directories():
    """Return common log directories based on the operating system"""
    system = get_os_name()
    
    if system == "Windows":
        return [
            r"C:\Windows\System32\winevt\Logs",
            r"C:\Windows\System32\LogFiles",
            r"C:\inetpub\logs\LogFiles"
        ]
    elif system == "macOS":
        return [
            "/var/log",
            "/Library/Logs",
            "~/Library/Logs"
        ]
    else:  # Linux and others
        return [
            "/var/log",
            "/var/log/audit",
            "/var/log/apache2",
            "/var/log/nginx"
        ]

def open_file_in_os(file_path):
    """Open a file with the default application based on OS"""
    system = get_os_name()
    
    try:
        if system == "Windows":
            os.startfile(file_path)
        elif system == "macOS":
            subprocess.call(["open", file_path])
        else:  # Linux and others
            subprocess.call(["xdg-open", file_path])
        return True
    except Exception as e:
        print(f"Error opening file: {e}")
        return False

def get_temp_directory():
    """Get a cross-platform temporary directory"""
    return tempfile.gettempdir()

def create_desktop_shortcut(script_path, shortcut_name="Security Log Analyzer"):
    """Create a desktop shortcut for the application based on OS"""
    system = get_os_name()
    
    try:
        if system == "Windows":
            import winshell
            from win32com.client import Dispatch
            
            desktop = winshell.desktop()
            path = os.path.join(desktop, f"{shortcut_name}.lnk")
            
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(path)
            shortcut.Targetpath = sys.executable
            shortcut.Arguments = script_path
            shortcut.WorkingDirectory = os.path.dirname(script_path)
            shortcut.save()
            
        elif system == "macOS":
            desktop = os.path.expanduser("~/Desktop")
            path = os.path.join(desktop, f"{shortcut_name}.command")
            
            with open(path, 'w') as f:
                f.write(f"#!/bin/bash\n")
                f.write(f"cd {os.path.dirname(script_path)}\n")
                f.write(f"python3 {script_path} \"$@\"\n")
                
            os.chmod(path, 0o755)
            
        else:  # Linux and others
            desktop = os.path.expanduser("~/Desktop")
            path = os.path.join(desktop, f"{shortcut_name}.desktop")
            
            with open(path, 'w') as f:)
                f.write("[Desktop Entry]\n")
                f.write(f"Name={shortcut_name}\n")
                f.write("Type=Application\n")
                f.write(f"Exec=python3 {script_path}\n")
                f.write(f"Path={os.path.dirname(script_path)}\n")
                f.write("Terminal=true\n")
                
            os.chmod(path, 0o755)
            
        return True
    except Exception as e:
        print(f"Error creating shortcut: {e}")
        return False