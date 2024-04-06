from scapy.all import *
import threading, os, platform

# Dictionary to hold IP addresses and their associated MACs
arp_table = {}

def get_interface_name():
    # 这个函数仅用于演示。你需要根据实际情况手动指定接口名称或编写代码自动获取。
    if platform.system() == "Windows":
        return "以太网"  # Windows 接口名称示例
    elif platform.system() == "Linux":
        return "eth0"  # Linux 接口名称示例
    elif platform.system() == "Darwin":  # macOS
        return "en0"  # macOS 接口名称示例

def disconnect_network_windows():
    print("[*] Disconnecting network on Windows...")
    os.system("ipconfig /release")

def disconnect_network_linux(interface_name):
    print(f"[*] Disconnecting network on Linux for interface {interface_name}...")
    os.system(f"sudo ifconfig {interface_name} down")  # 或使用 'sudo ip link set {interface_name} down'

def disconnect_network_mac(interface_name):
    print(f"[*] Disconnecting network on macOS for interface {interface_name}...")
    os.system(f"sudo ifconfig {interface_name} down")

def monitor_arp_packets(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        source_ip = packet[ARP].psrc
        source_mac = packet[ARP].hwsrc

        if source_ip in arp_table and arp_table[source_ip] != source_mac:
            print(f"[*] Potential ARP Spoofing Detected! {source_ip} has been associated with {arp_table[source_ip]} and now with {source_mac}")
            # 断开网络连接
            interface_name = get_interface_name()
            if platform.system() == "Windows":
                disconnect_network_windows()
            elif platform.system() == "Linux":
                disconnect_network_linux(interface_name)
            elif platform.system() == "Darwin":  # macOS
                disconnect_network_mac(interface_name)
        else:
            arp_table[source_ip] = source_mac
            print(f"ARP Table Updated: {source_ip} is associated with {source_mac}")

def arp_monitoring(interface_name):
    print("[*] Starting ARP Spoof Detector.")
    sniff(store=False, prn=monitor_arp_packets, filter="arp", iface=interface_name)

if __name__ == "__main__":
    interface_name = get_interface_name()  # 确保替换成你的实际网络接口名
    detector_thread = threading.Thread(target=arp_monitoring, args=(interface_name,))
    detector_thread.start()
