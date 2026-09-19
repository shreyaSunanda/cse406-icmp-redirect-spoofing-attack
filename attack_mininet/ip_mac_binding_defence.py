#!/usr/bin/env python3
import argparse
import time
from scapy.all import sniff, Ether, IP, ICMP

# Learned bindings live here: { ip: mac }
learned_bindings = {}
learning = True
learn_until = 0.0


def check_packet(pkt):
    global learning

    if not (pkt.haslayer(Ether) and pkt.haslayer(IP)):
        return

    src_ip = pkt[IP].src
    src_mac = pkt[Ether].src

    # Still in the learning window: just record what we see.
    if learning:
        if time.time() >= learn_until:
            learning = False
            print(f"[*] Learning window closed. {len(learned_bindings)} bindings recorded.")
        else:
            if src_ip not in learned_bindings:
                learned_bindings[src_ip] = src_mac
                print(f"[LEARN] {src_ip} -> {src_mac}")
            return

    expected_mac = learned_bindings.get(src_ip)

    if expected_mac is None:
        # First time seeing this IP after learning ended; record it
        # cautiously (a real deployment might instead alert here too).
        learned_bindings[src_ip] = src_mac
        print(f"[NEW]   First sighting of {src_ip} -> {src_mac}")
        return

    if src_mac.lower() != expected_mac.lower():
        icmp_type = pkt[ICMP].type if pkt.haslayer(ICMP) else "N/A"
        print(
            f"[ALERT] Possible IP spoofing detected!\n"
            f"        Claimed source IP : {src_ip}\n"
            f"        Learned MAC       : {expected_mac}\n"
            f"        Actual MAC seen   : {src_mac}\n"
            f"        ICMP type         : {icmp_type}\n"
        )
    else:
        # Comment this out if it's too noisy during normal testing.
        print(f"[OK]    {src_ip} matches its learned MAC ({src_mac})")


def main():
    global learn_until

    parser = argparse.ArgumentParser(description="Detect IP spoofing via auto-learned IP-MAC bindings")
    parser.add_argument("--iface", required=True, help="Network interface to sniff on, e.g. r1-eth0")
    parser.add_argument("--learn-seconds", type=int, default=20,
                         help="How long to passively learn IP-MAC bindings before enforcing them")
    args = parser.parse_args()

    learn_until = time.time() + args.learn_seconds
    print(f"[*] Monitoring interface {args.iface}")
    print(f"[*] Learning phase: {args.learn_seconds}s (send only NORMAL traffic now)")
    sniff(iface=args.iface, filter="icmp", prn=check_packet, store=False)


if __name__ == "__main__":
    main()
