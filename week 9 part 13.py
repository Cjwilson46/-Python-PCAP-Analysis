import os
from scapy.all import rdpcap, IP, TCP, UDP

# Directory where your PCAP files arre located
directory_path = r'C:\Users\Administrator\Downloads\PCAP-SAMPLES1'

def process_and_print_pcap(file_path):
    packets = rdpcap(file_path)
    # Define the format for the table headers and rows
    header_format = "{:<20} {:<20} {:<10}"
    row_format = "{:<20} {:<20} {:<10}"

    # Print the table header
    print(header_format.format("SRC-IP:PORT", "DST-IP:PORT", "PROTOCOL"))
    print("-" * 60)  # Print a line to separate headers from the rows

    for packet in packets:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = ""
            src_port = ""
            dst_port = ""

            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = str(packet[TCP].sport)
                dst_port = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = str(packet[UDP].sport)
                dst_port = str(packet[UDP].dport)

            # Print each row of data
            print(row_format.format(f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}", protocol))

# Main script execution
if __name__ == '__main__':
    print("PCAP PROCESSOR v 1.0 AUGUST 2021")

    # Verify the directory exists
    if not os.path.exists(directory_path):
        print(f"Directory {directory_path} not found.")
        exit(1)

    # List all PCAP files in the directory
    pcap_files = [f for f in os.listdir(directory_path) if f.endswith('.pcap')]

    if not pcap_files:
        print("No PCAP files found in the directory.")
        exit(1)

    # Process each PCAP file
    for filename in pcap_files:
        file_path = os.path.join(directory_path, filename)
        print(f"Processing file: {filename}")
        process_and_print_pcap(file_path)

    print("PCAP processing completed for all files.")
