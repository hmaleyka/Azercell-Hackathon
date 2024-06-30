import scapy
from statistic import count_packets,main
from statistic import extract_conversations,print_conversations,detect_anomalies
from statistic import print_anomalies,detect_connection_loss,print_lost_connections

pcap_file = input("Write pcap file path: ")
rules_file = input("Write rules file path: ")

total_packets = count_packets(pcap_file)
print(f"\nTotal number of packetss: {total_packets}")

if __name__ == "__main__":
    pcap_file = "a.pcap"  # Replace with your pcap file path
    conversations = extract_conversations(pcap_file)
    print("\nConversation\n")
    print_conversations(conversations)
    anomalies, fin_count, rst_count = detect_anomalies(conversations)
    print("\nLost connection\n")
    print_anomalies(anomalies)
    lost_connections = detect_connection_loss(conversations)
    print_lost_connections(lost_connections)
    print("\nTotal FIN Packets:", fin_count)
    print("Total RST Packets:", rst_count)
    print("Total Lost Connection Packets:",fin_count+rst_count)


print ("Alert\n")
if __name__ == "__main__":
    main(pcap_file,rules_file)

   