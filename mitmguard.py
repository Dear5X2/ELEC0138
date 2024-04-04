import os
import time
from datetime import datetime

class NetworkGuard:
    def __init__(self):
        self.gateway_mac_original = None
        self.gateway_ip = None
        self.list_of_macs = []
        self.network_connected = False

    def fetch_initial_gateway_details(self):
        """获取并设置初始网关的MAC和IP地址。"""
        arp_output = os.popen('arp -a').read()
        self.network_connected = len(arp_output.splitlines()) >= 10
        for line in arp_output.splitlines():
            if line and "Interface" not in line and "Internet" not in line:
                self.gateway_mac_original = line.split()[1]
                self.gateway_ip = line.split()[0]
                break

    def refresh_mac_list(self):
        """刷新网络上的MAC地址列表。"""
        self.list_of_macs = [
            line.split()[1] for line in os.popen('arp -a').read().splitlines()
            if line and "Interface" not in line and "Internet" not in line
        ]

    def monitor_network_for_intrusion(self):
        """持续监控网络寻找入侵迹象。"""
        while True:
            time.sleep(2)
            if not self.network_connected:
                print("网络连接丢失，尝试重连...")
                self.attempt_reconnection()
            else:
                print("网络监控中...")
                self.refresh_mac_list()
                if self.gateway_mac_original not in self.list_of_macs:
                    print("可能发现ARP攻击！")
                    self.log_intrusion_attempt()
                    self.disconnect_from_network()
                else:
                    self.refresh_mac_list()

    def attempt_reconnection(self):
        """尝试重新建立网络连接。"""
        self.fetch_initial_gateway_details()
        if self.network_connected:
            print("网络重新连接成功。")

    def disconnect_from_network(self):
        """从网络断开连接。"""
        os.system("netsh wlan disconnect")
        print("为了安全，网络已断开连接。")

    def log_intrusion_attempt(self):
        """记录入侵尝试到日志文件。"""
        with open("intrusion_logs.txt", "a") as log_file:
            log_file.write(f"异常ARP表：\n{os.popen('arp -a').read()}\n检测时间：{datetime.now()}\n")

if __name__ == "__main__":
    protector = NetworkGuard()
    protector.fetch_initial_gateway_details()
    protector.refresh_mac_list()
    protector.monitor_network_for_intrusion()
