from scapy.all import *
import os

# Function to process packets
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        # Print details of the packet
        print(f"Time: {packet.time} | Source IP: {ip_layer.src} | Destination IP: {ip_layer.dst} | Protocol: {ip_layer.proto}")
        
        # Check if the packet has a TCP or UDP layer and print details
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP - Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP - Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
        
        print(f"Payload: {bytes(packet)}\n")

# Ask user for the protocol to filter
protocol = input("Enter the protocol to filter (tcp/udp/all): ").strip().lower()
if protocol not in ["tcp", "udp", "all"]:
    print("Invalid protocol. Using 'all' by default.")

# Specify the output file
output_file = "captured_packets.pcap"

# Start sniffing packets
print("Starting packet capture. Press CTRL+C to stop.")
if protocol == "tcp":
    sniff(prn=packet_callback, filter="tcp", store=0, iface="Ethernet")
elif protocol == "udp":
    sniff(prn=packet_callback, filter="udp", store=0, iface="Ethernet")
else:
    sniff(prn=packet_callback, store=0, iface="Ethernet")

# Save captured packets to a pcap file
wrpcap(output_file, sniffed_packets)
print(f"Captured packets saved to {output_file}")
