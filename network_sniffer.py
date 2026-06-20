from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    print("\n" + "=" * 50)

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Convert protocol number to name
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = str(protocol)

        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol_name}")

        if packet.haslayer(TCP):
            print("Transport Layer: TCP")
        elif packet.haslayer(UDP):
            print("Transport Layer: UDP")

        if packet.payload:
            payload = bytes(packet.payload)

            try:
                print(f"Payload        : {payload[:100].decode(errors='ignore')}")
            except:
                print("Payload        : Unable to decode")

def main():
    print("Network Sniffer Started...")
    print("Capturing 20 packets...")

    sniff(prn=packet_callback, store=False, count=20)

    print("\nCapture Complete!")

if __name__ == "__main__":
    main()