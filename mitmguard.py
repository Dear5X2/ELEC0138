import scapy.all as scapy
import time
import subprocess
import os
import subprocess
import re

def get_gateway_mac(ip):
    # Run the arp command and capture its output
    result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
    
    if result.returncode == 0:  # Check if command was successful
        # Use regular expression to search for the MAC address in the output
        match = re.search(r"(\w\w-\w\w-\w\w-\w\w-\w\w-\w\w)", result.stdout)
        if match:
            return match.group(1)  # Return the MAC address
        else:
            return "MAC address not found"
    else:
        return "ARP command failed"

def detect_arp_spoofing(gateway_ip,interface):
    print("Starting ARP spoofing detection...")
    legitimate_mac = get_gateway_mac(gateway_ip)
    if not legitimate_mac:
        print("Failed to obtain legitimate MAC address. Exiting...")
        return
    
    print(f"Legitimate MAC address of Gateway {gateway_ip} is {legitimate_mac}")
    
    try:
        while True:
            current_mac = get_gateway_mac(gateway_ip)
            if current_mac != legitimate_mac:
                print(f"ARP spoofing detected! Expected {legitimate_mac}, but found {current_mac}")
                disable_network_interface(interface,enable=False)
                break
            time.sleep(10)  # Check every 10 seconds
    except KeyboardInterrupt:
        print("Stopping ARP spoofing detection.")

def disable_network_interface(interface,enable=False):
    action = 'enable' if enable else 'disable'
    command = ['netsh', 'interface', 'set', 'interface', 'name='+interface, action]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print(f'network has been {action}d successfully for preventing the arp spoofing.')
        else:
            print(f'Failed to {action} Wi-Fi. Error: {result.stderr}')
    except Exception as e:
        print(f'An error occurred: {e}')




if __name__ == "__main__":
    GATEWAY_IP = '192.168.137.1'  # Gateway IP address
    interface = 'WLAN'  # Name of the interface as seen in 'Control Panel\Network and Internet\Network Connections'
    
    detect_arp_spoofing(GATEWAY_IP,interface)
