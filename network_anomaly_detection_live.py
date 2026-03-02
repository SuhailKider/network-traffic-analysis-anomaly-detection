from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time
import logging
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

CAPTURE_DURATION = 60
CONTAMINATION_RATE = 0.01
RANDOM_STATE = 42

logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s | ANOMALY | %(message)s"
)

packet_records = []
previous_packet_time = None


def extract_features(packet):
    global previous_packet_time

    if IP not in packet:
        return None

    current_time = time.time()
    inter_arrival_time = 0 if previous_packet_time is None else current_time - previous_packet_time
    previous_packet_time = current_time

    src_port = 0
    dst_port = 0
    tcp_flags = 0

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = int(packet[TCP].flags)
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return {
        "Packet_Size": len(packet),
        "Protocol": packet[IP].proto,
        "Src_Port": src_port,
        "Dst_Port": dst_port,
        "TCP_Flags": tcp_flags,
        "Inter_Arrival_Time": inter_arrival_time
    }


def packet_handler(packet):
    features = extract_features(packet)
    if features:
        packet_records.append(features)


print(f"[INFO] Starting live packet capture for {CAPTURE_DURATION} seconds...")
sniff(prn=packet_handler, store=False, timeout=CAPTURE_DURATION)
print("[INFO] Packet capture completed.")

df = pd.DataFrame(packet_records)
print(f"[INFO] Total packets captured: {len(df)}")

df.to_csv("captured_traffic.csv", index=False)

X = df[
    ["Packet_Size", "Protocol", "Src_Port",
     "Dst_Port", "TCP_Flags", "Inter_Arrival_Time"]
]

model = IsolationForest(
    n_estimators=100,
    contamination=CONTAMINATION_RATE,
    random_state=RANDOM_STATE
)

df["Anomaly"] = model.fit_predict(X)

anomalies = df[df["Anomaly"] == -1]
normal = df[df["Anomaly"] == 1]

print(f"[ALERT] Total anomalies detected: {len(anomalies)}")

for _, row in anomalies.iterrows():
    logging.info(
        f"Size={row['Packet_Size']} | "
        f"Proto={row['Protocol']} | "
        f"SrcPort={row['Src_Port']} | "
        f"DstPort={row['Dst_Port']} | "
        f"IAT={row['Inter_Arrival_Time']:.6f}"
    )

anomalies.to_csv("detected_anomalies.csv", index=False)

plt.figure()
plt.scatter(normal.index, normal["Packet_Size"], label="Normal", alpha=0.5)
plt.scatter(anomalies.index, anomalies["Packet_Size"], label="Anomaly", alpha=0.9)
plt.xlabel("Packet Index")
plt.ylabel("Packet Size (Bytes)")
plt.title("Isolation Forest Anomaly Detection Results")
plt.legend()
plt.show()

print("[INFO] Anomaly detection completed successfully.")
