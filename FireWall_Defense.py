import subprocess

def enable_firewall():
    subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], capture_output=True, text=True)

def disable_firewall():
    subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "off"], capture_output=True, text=True)

