import pyshark
import pandas as pd
import os

# Load the pcap file (only TCP zero-length packets)
pcap_file = "/home/lab512/Downloads/WhatsApp_1.pcap"
cap = pyshark.FileCapture(pcap_file, display_filter="tcp")

# Dictionary to store cumulative bytes per flow
flows = {}

# Process packets
for pkt in cap:
    try:
        # Extract TCP info
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        src_port = pkt.tcp.srcport
        dst_port = pkt.tcp.dstport
        seq = int(pkt.tcp.seq)  # Sequence number
        ack = int(pkt.tcp.ack)  # Acknowledgment number
        length = int(pkt.tcp.len) if hasattr(pkt.tcp, "len") else 0  # TCP payload length

        # Define flow_id as (A, A_port, B, B_port) in a fixed order
        if (src_ip, src_port) < (dst_ip, dst_port):
            flow_id = (src_ip, src_port, dst_ip, dst_port)
            is_sender_A = True  # A → B direction
        else:
            flow_id = (dst_ip, dst_port, src_ip, src_port)
            is_sender_A = False  # B → A direction

        # Initialize flow tracking if not exists
        if flow_id not in flows:
            flows[flow_id] = [(0, 0)]  # Initial state: (bytes_sent_by_A, bytes_sent_by_B)

        # Get the last recorded bytes tuple
        last_A, last_B = flows[flow_id][-1]

        # Update bytes depending on sender
        if is_sender_A:
            last_A = ack  # Sender is A (increment A's bytes)
        else:
            last_B = ack  # Sender is B (increment B's bytes)

        # Append updated tuple to flow tracking
        flows[flow_id].append((last_A, last_B))

    except AttributeError:
        continue  # Ignore packets without required fields

# Print result
print("Cumulative Bytes per Flow:")
for flow, values in flows.items():
    print(f"Flow {flow}: {values}")

# Convert to DataFrame for analysis
flow_data = []
for flow, values in flows.items():
    for i, (bytes_A, bytes_B) in enumerate(values):
        flow_data.append([flow, i, bytes_A, bytes_B])

df = pd.DataFrame(flow_data, columns=["Flow ID", "Packet Index", "Bytes Sent by A", "Bytes Sent by B"])

# Save CSV output
output_dir = "/home/lab512/dataset_csv"
os.makedirs(output_dir, exist_ok=True)
csv_path = os.path.join(output_dir, "WhatsApp_1_flows.csv")
df.to_csv(csv_path, index=False)

print("CSV file created successfully!")
