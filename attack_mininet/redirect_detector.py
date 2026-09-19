from scapy.all import sniff, IP, ICMP

TRUSTED_GATEWAY = "192.168.10.1"

def detect_redirect(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 5:
        src = pkt[IP].src
        gw  = pkt[ICMP].gw
        if str(gw) != TRUSTED_GATEWAY:
            print(f"[ALERT] Fake ICMP Redirect! src={src}, "
                  f"suggested gateway={gw}")
        else:
            print(f"[INFO] Legitimate redirect from {src}, gateway={gw}")

sniff(iface="victim-eth0", filter="icmp", prn=detect_redirect, store=0)