from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw
import logging
from datetime import datetime

# Generate log file name based on the current date and time
log_filename = datetime.now().strftime("log_%Y%m%d_%H%M%S.txt")

# Configure logging to write to the dynamically generated log file
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(message)s')

def packet_callback(packet):
    try:
        packet_info = "\n" + "="*50 + "\n"
        packet_info += f"Time: {packet.time}\n"

        # Ethernet layer
        if packet.haslayer(Ether):
            eth = packet[Ether]
            packet_info += f"Source MAC: {eth.src}\n"
            packet_info += f"Destination MAC: {eth.dst}\n"

        # IP layer
        if packet.haslayer(IP):
            ip = packet[IP]
            packet_info += f"Source IP: {ip.src}\n"
            packet_info += f"Destination IP: {ip.dst}\n"
            packet_info += f"Protocol: {ip.proto}\n"

        # TCP layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            packet_info += f"Source Port: {tcp.sport}\n"
            packet_info += f"Destination Port: {tcp.dport}\n"
            packet_info += f"Flags: {tcp.flags}\n"

        # UDP layer
        if packet.haslayer(UDP):
            udp = packet[UDP]
            packet_info += f"Source Port: {udp.sport}\n"
            packet_info += f"Destination Port: {udp.dport}\n"

        # ICMP layer
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            packet_info += f"Type: {icmp.type}\n"
            packet_info += f"Code: {icmp.code}\n"

        # Raw layer
        if packet.haslayer(Raw):
            raw = packet[Raw]
            packet_info += f"Raw Payload: {raw.load}\n"

        # Log the packet info
        logging.info(packet_info)
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def validate_interface(interface):
    try:
        # Test sniffing on the specified interface to ensure it's valid
        sniff(iface=interface, count=1)
        return True
    except:
        return False

if __name__ == "__main__":
    # Prompt the user to enter a valid network interface
    while True:
        user_interface = input("Enter a network interface: ")
        if validate_interface(user_interface):
            break
        else:
            print(f"Invalid interface '{user_interface}'. Please try again.")

    interface = user_interface
    
    print(f"Starting network sniffer on interface {interface}")
    try:
        # Start sniffing on the specified interface
        sniff(iface=interface, prn=packet_callback, store=0)
    except PermissionError:
        print("Permission error: Please run the script with sudo.")
    except Exception as e:
        print(f"An error occurred: {e}")
