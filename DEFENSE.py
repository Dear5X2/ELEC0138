from scapy.all import *
from FireWall_Defense import enable_firewall

def detect_syn_flooding(pkt_count_threshold, time_interval):
    # Start capturing
    interface = "WLAN"
    filter_str = f"src host {get_if_addr(interface)} and tcp and ip"
    packets = sniff(iface=interface,filter=filter_str,timeout=time_interval)

    # Count the number of SYN requests captured
    syn_packets = [pkt for pkt in packets if pkt.haslayer(TCP)]  # SYN flag is set
    syn_count = len(syn_packets)


    if syn_count > pkt_count_threshold:
        return True
    else:
        return False


if __name__ == "__main__":
    PACKET_COUNT_THRESHOLD = 800  # SYN request threhold
    TIME_INTERVAL = 1  # tiem interval (seconds)

    while True:
        if detect_syn_flooding(PACKET_COUNT_THRESHOLD, TIME_INTERVAL):
            print("Detected SYN flooding attack!")
            # Enable Firewall
            enable_firewall()
        else:
            print("No SYN flooding attack detected.")
        time.sleep(TIME_INTERVAL)
