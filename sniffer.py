from scapy.all import *
import json
from datetime import datetime
recent_packets = []

service_map = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    67: "DHCP",
    68: "DHCP",
    546: "DHCPv6",
    547: "DHCPv6"
}


def packet_callback(packet):
    global recent_packets

    src = "-"
    dst = "-"
    protocol = "-"
    sport = "-"
    dport = "-"
    service = "-"

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst

    elif ARP in packet:
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
        protocol = "ARP"

    if TCP in packet:
        protocol = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        service = service_map.get(sport) or service_map.get(dport) or "-"

    elif UDP in packet:
        protocol = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        service = service_map.get(sport) or service_map.get(dport) or "-"

    elif ICMP in packet:
        protocol = "ICMP"

    recent_packets.insert(0, {
	"time": datetime.now().strftime("%H:%M:%S"),
        "source": src,
        "destination": dst,
        "protocol": protocol,
        "sport": sport,
        "dport": dport,
        "service": service
    })

    # Keep only latest 50 packets
    recent_packets = recent_packets[:500]

    # Save to JSON
    with open("packets.json", "w") as f:
        json.dump(recent_packets, f, indent=4)

    print(recent_packets[0])


sniff(iface="eth0", prn=packet_callback, store=False)
