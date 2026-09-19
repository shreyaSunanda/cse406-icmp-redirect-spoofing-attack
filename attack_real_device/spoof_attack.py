from scapy.all import IP, ICMP, send


#packet = IP(
#    src="10.218.8.108",      # Victim IP (spoofed)
#    dst="10.218.8.170"       # Server IP (iPad)
#) / ICMP(
#    type=8                    # 8 = Echo Request
#)

#send(packet, iface="wlp2s0", count=5, verbose=True)

#defence code 
packet = IP(
    src="10.218.8.108",    # friend er IP (spoofed)
    dst="10.218.8.57"      # friend er laptop IP (target)
) / ICMP(type=8)

send(packet, iface="wlp2s0", count=5, verbose=True)
