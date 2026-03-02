# Network Traffic Anomaly Detection

This project focuses on analyzing captured network traffic and detecting anomalous behavior within the network.  
It was developed as part of a **Cryptography and Network Security coursework** to demonstrate practical network monitoring and security analysis techniques.

The system processes captured packet data, analyzes traffic patterns, and identifies potential suspicious or abnormal network activity.

---

## Project Objectives

- Capture and analyze network traffic
- Identify abnormal patterns in packet communication
- Detect potential indicators of compromise
- Monitor logs for suspicious activity

---

## Tools and Technologies

- Python
- Network traffic datasets (CSV)
- Log analysis
- Basic anomaly detection techniques

---


### File Description

**network_anomaly_detection_live.py**  
Python script used to analyze network traffic data and detect anomalies.

**captured_traffic.csv**  
Contains captured network traffic data used for analysis.

**detected_anomalies.csv**  
Stores records of detected abnormal traffic patterns identified during analysis.

**alerts.log**  
Log file containing alerts generated during anomaly detection.

---

## Features

- Network traffic analysis
- Detection of suspicious network behavior
- Log monitoring and alert generation
- Basic anomaly detection for security monitoring

---

## Example Use Cases

This type of analysis can help detect:

- Unusual traffic spikes
- Suspicious connection attempts
- Possible scanning activity
- Abnormal packet behavior

---

## Skills Demonstrated

- Network traffic analysis
- Security monitoring
- Python scripting for security analysis
- Log analysis and anomaly detection
- Basic network security investigation techniques

---

## Learning Outcome

This project helped strengthen practical knowledge in:

- Network monitoring
- Traffic analysis
- Security event detection
- Working with network datasets and logs

---


## How to Run

1. Clone the repository

git clone (https://github.com/SuhailKider/network-traffic-analysis-anomaly-detection)

2. Navigate to the project folder

cd network-traffic-analysis-anomaly-detection

3. Run the detection script

python network_anomaly_detection_live.py

## Example Detection Output

The anomaly detection script analyzes captured network traffic and flags suspicious patterns.

Example output generated during analysis:

[ANOMALY] Size=139 | Proto=6 | SrcPort=443 | DstPort=62246 | IAT=0.107
[ANOMALY] Size=189 | Proto=6 | SrcPort=443 | DstPort=61902 | IAT=0.450
[ANOMALY] Size=79  | Proto=17 | SrcPort=59879 | DstPort=53 | IAT=0.356

These alerts indicate packets that deviate from normal network behavior
based on traffic characteristics such as packet size, protocol type,
port usage, and inter-arrival timing.

## Author

Suhail Kider  
Cybersecurity Graduate | CCNA Candidate
