from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime


packet_count = 0


print("Starting Network Sniffer...")
print("Press Ctrl + C to stop.\n")


def packet_callback(packet):
    global packet_count

    if packet.haslayer(IP):

        packet_count += 1

        ip_layer = packet[IP]

        print("=" * 60)
        print("Packet Number :", packet_count)
        print("Time          :", datetime.now().strftime("%H:%M:%S"))

        print("Source IP     :", ip_layer.src)
        print("Destination IP:", ip_layer.dst)


        if packet.haslayer(TCP):
            print("Protocol      : TCP")
            print("Source Port   :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)


        elif packet.haslayer(UDP):
            print("Protocol      : UDP")
            print("Source Port   :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)


        else:
            print("Protocol      : Other")


        print("Packet Length :", len(packet), "bytes")
        print("=" * 60)



sniff(prn=packet_callback, store=False)