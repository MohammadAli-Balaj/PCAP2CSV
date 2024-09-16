import pyshark
import pandas as pd
from tqdm import tqdm

def pcap_to_dataframe(pcap_file):
    # Open the pcap file with PyShark
    cap = pyshark.FileCapture(pcap_file)

    # Prepare a list to store packet data
    packet_data = []
    
    # Loop over packets with a progress bar
    for packet in tqdm(cap, desc="Reading packets from PCAP"):
        packet_info = {}

        # Try to extract as much info as possible from each layer
        try:
            # General packet info
            packet_info['timestamp'] = packet.sniff_time
            packet_info['length'] = packet.length

            # Ethernet Layer (if available)
            if hasattr(packet, 'eth'):
                packet_info['eth_src'] = packet.eth.src
                packet_info['eth_dst'] = packet.eth.dst

            # IP Layer (if available)
            if hasattr(packet, 'ip'):
                packet_info['ip_src'] = packet.ip.src
                packet_info['ip_dst'] = packet.ip.dst
                packet_info['ip_version'] = packet.ip.version
                packet_info['ip_ihl'] = packet.ip.hdr_len
                packet_info['ip_tos'] = packet.ip.dsfield
                packet_info['ip_ttl'] = packet.ip.ttl
                packet_info['ip_protocol'] = packet.ip.proto
                packet_info['ip_flags'] = packet.ip.flags

            # TCP Layer (if available)
            if hasattr(packet, 'tcp'):
                packet_info['tcp_srcport'] = packet.tcp.srcport
                packet_info['tcp_dstport'] = packet.tcp.dstport
                packet_info['tcp_seq'] = packet.tcp.seq
                packet_info['tcp_ack'] = packet.tcp.ack
                packet_info['tcp_flags'] = packet.tcp.flags

            # UDP Layer (if available)
            if hasattr(packet, 'udp'):
                packet_info['udp_srcport'] = packet.udp.srcport
                packet_info['udp_dstport'] = packet.udp.dstport
                packet_info['udp_length'] = packet.udp.length

            # DNS Layer (if available)
            if hasattr(packet, 'dns'):
                packet_info['dns_query'] = packet.dns.qry_name
                packet_info['dns_query_type'] = packet.dns.qry_type

            # HTTP Layer (if available)
            if hasattr(packet, 'http'):
                packet_info['http_method'] = packet.http.request_method
                packet_info['http_host'] = packet.http.host
                packet_info['http_uri'] = packet.http.request_uri
                packet_info['http_user_agent'] = packet.http.user_agent

            # Extract other general packet info as string (optional for debugging)
            packet_info['raw_info'] = str(packet)

        except AttributeError:
            # If the packet doesn't have certain fields, skip them
            continue

        # Append the packet info to the list
        packet_data.append(packet_info)

    # Convert the list of packet data into a DataFrame
    df = pd.DataFrame(packet_data)

    return df

def save_to_csv(df, output_csv):
    # Save DataFrame to CSV
    df.to_csv(output_csv, index=False)
    print(f"Data successfully written to {output_csv}")

if __name__ == "__main__":
    # Input PCAP file
    pcap_file = "data.pcap"
    
    # Output CSV file
    output_csv = "output.csv"
    
    # Convert PCAP to DataFrame
    df = pcap_to_dataframe(pcap_file)
    
    # Save DataFrame to CSV
    save_to_csv(df, output_csv)
