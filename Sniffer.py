from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

TARGET_INTERFACE = None 
BPF_FILTER = "" 
PACKET_COUNT = 0

def handle_packet(packet):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        proto_num = packet[IP].proto
        protocol = 'unknown'

        if proto_num == 1:
            protocol = 'ICMP'
        elif proto_num == 6:
            protocol = 'TCP'
        elif proto_num == 17:
            protocol = 'UDP'
        
        src_port = ''
        dst_port = ''

        if packet.haslayer(TCP):
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)

        elif packet.haslayer(UDP):
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)

        elif protocol == 'ICMP':
            src_port = 'N/A (Ping)'
            dst_port = 'N/A (Ping)'
        
        else:
            src_port = 'N/A'
            dst_port = 'N/A'

        if packet.haslayer(Raw):
            raw_bytes = packet[Raw].load
            payload_data = raw_bytes.decode('utf-8', errors='ignore')

            if len(payload_data) > 50:
               payload_data = payload_data[:50] + '...'

        print("=========================================")
        print(f"Time Stamp       : {current_time}")
        print(f"Source IP        : {src_ip}")
        print(f"Destination IP   : {dst_ip}")
        print(f"Protocol         : {protocol}")
        print(f"Source Port      : {src_port}")
        print(f"Destination Port : {dst_port}")
        print(f"Packet Size      : {len(packet)} bytes")
        print(f"Payload          : {payload_data}")
        print("=========================================\n")

def main():
    print("==========================================================")
    print("        CodeAlpha Network Packet Sniffer Active           ")
    print("==========================================================")
    print(f"[*] Monitoring Traffic on interface: {TARGET_INTERFACE or 'Default'}")
    print(f"[*] BPF Filter rule: '{BPF_FILTER or 'None (All traffic)'}'")
    print("[*] Press Ctrl+C to terminate the sniffer gracefully.\n")
    
    try:
        sniff(iface=TARGET_INTERFACE, 
              filter=BPF_FILTER,
              count=PACKET_COUNT, 
              prn=handle_packet, 
              store=False)
    except KeyboardInterrupt:
        print("\n[!] Sniffer terminated by user.")
    except PermissionError:
       print("\n[!] ERROR: Permission Denied!")
       print("[!] Packet sniffing requires Administrative/Root privileges.")
       print("[!] Please run the script with 'sudo' or as an Administrator.")

if __name__ == '__main__':
    main()
    