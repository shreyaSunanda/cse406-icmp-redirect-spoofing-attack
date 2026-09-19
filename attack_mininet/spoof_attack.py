from scapy.all import IP, ICMP, send


packet = IP(
    src="192.168.10.10",      # victim ip
    dst="192.168.20.10"      #  Server IP
) / ICMP(
    type=8                     # 8 = Echo Request
)

send(packet, iface="wlp2s0", count=5, verbose=True)
