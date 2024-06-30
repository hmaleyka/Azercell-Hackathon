from scapy.all import rdpcap

def count_packets(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Get the total number of packets
    total_packets = len(packets)

    # Return the total number of packets
    return total_packets\
    
    # Example usage
#pcap_file = 'a.pcap'
#total_packets = count_packets(pcap_file)
#print(f"Total number of packetss: {total_packets}")

####
####
####

from scapy.all import rdpcap, IP, TCP, UDP

def extract_conversations(pcap_file):
    packets = rdpcap(pcap_file)
    
    conversations = {}

    for pkt in packets:
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst

            if TCP in pkt:
                proto = 'TCP'
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                proto = 'UDP'
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                continue

            conv_id = f"{ip_src}:{sport} -> {ip_dst}:{dport} ({proto})"

            if conv_id not in conversations:
                conversations[conv_id] = []
            
            conversations[conv_id].append(pkt)

    return conversations

def print_conversations(conversations):
    for conv_id, packets in conversations.items():
        print(f"Conversation: {conv_id}")
        for pkt in packets:
            if TCP in pkt or UDP in pkt:  # Exclude other packet types
                pkt_size = len(pkt)
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                if TCP in pkt:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                elif UDP in pkt:
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                

def detect_anomalies(conversations):
    anomalies = []
    fin_count = 0
    rst_count = 0
    for conv_id, packets in conversations.items():
        for pkt in packets:
            pkt_size = len(pkt)
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                
                # Check for packet size anomaly
                if pkt_size > 1500:
                    anomalies.append((conv_id, pkt_size, 'Large packet size'))
                
                # Check for unexpected port usage
                if sport in {23, 25, 3389} or dport in {23, 25, 3389}:
                    anomalies.append((conv_id, f"{sport}->{dport}", 'Unexpected port usage'))
                
                # Check for FIN packet
                if pkt[TCP].flags & 0x01:  # FIN flag
                    fin_count += 1
                
                # Check for RST packet
                if pkt[TCP].flags & 0x04:  # RST flag
                    rst_count += 1
    
    return anomalies, fin_count, rst_count

def detect_connection_loss(conversations):
    lost_connections = []
    for conv_id, packets in conversations.items():
        connection_lost = False
        for pkt in packets:
            if TCP in pkt:
                # Detect RST packet
                if pkt[TCP].flags & 0x04:  # RST flag
                    connection_lost = True
                    reason = 'Connection reset (RST packet)'
                    break
                # Detect FIN packet without corresponding ACK
                elif pkt[TCP].flags & 0x01:  # FIN flag
                    connection_lost = True
                    reason = 'Connection closed (FIN packet)'
                    break
        
        if connection_lost:
            lost_connections.append((conv_id, reason))
    
    return lost_connections

def print_anomalies(anomalies):
    if anomalies:
        print("Anomalies detected:")
        for anomaly in anomalies:
            if anomaly[2] != 'Large packet size':
                print(f"Conversation: {anomaly[0]}, Detail: {anomaly[1]}, Reason: {anomaly[2]}")
    else:
        print("No anomalies detected.")

def print_lost_connections(lost_connections):
    if lost_connections:
        print("Lost Connections detected:")
        for connection in lost_connections:
            print(f"Conversation: {connection[0]}, Reason: {connection[1]}")
    else:
        print("No lost connections detected.")

#
#Rule
#
from scapy.all import *

def analyze_pcap(pcap_file, rules):
    packets = rdpcap(pcap_file)
    results = []

    # Apply user-defined rules
    for rule in rules:
        results.extend([packet for packet in packets if rule(packet)])

    return results

def load_rules_from_file(file_path):
    rules = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                # Ignore empty lines and comments
                if line.strip() and not line.startswith("#"):
                    rules.append(eval(line.strip()))
    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except Exception as e:
        print(f"Error loading rules from file: {e}")

    return rules

def main(pcap_file,rules_file ):
      # Assuming the rules file is named "ru.txt" in the same directory

    # Load rules from file
    rules = load_rules_from_file(rules_file)

    if not rules:
        print("No rules loaded. Exiting.")
        return

    results = analyze_pcap(pcap_file, rules)

    print("Results:")
    for packet in results:
        print(packet.summary())

if __name__ == "__main__":
    main()