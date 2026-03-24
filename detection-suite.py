"""
Advanced Cybersecurity Detection Suite
--------------------------------------
Modules:
1. Network Capture & Statistical Feature Extraction
2. Active Reconnaissance Detection (Nmap)
3. Application-Layer Analysis (Burp Suite API)
4. Homomorphic Encryption of Features
5. Cross-Layer Correlation and Threat Flagging
"""

# =========================
# Section 1: Network Capture & Statistical Features
# =========================
import pyshark
import pandas as pd
import numpy as np
import asyncio

def capture_network_traffic(interface='eth0', packet_count=500):
    eventloop = asyncio.new_event_loop()
    asyncio.set_event_loop(eventloop)

    print("[*] Starting network capture...")
    capture = pyshark.LiveCapture(interface=interface, eventloop=eventloop)
    packet_data = []

    for pkt in capture.sniff_continuously(packet_count=packet_count):
        try:
            packet_data.append({
                'src': pkt.ip.src if hasattr(pkt, 'ip') else None,
                'dst': pkt.ip.dst if hasattr(pkt, 'ip') else None,
                'src_port': pkt[pkt.transport_layer].srcport if hasattr(pkt, 'transport_layer') else None,
                'dst_port': pkt[pkt.transport_layer].dstport if hasattr(pkt, 'transport_layer') else None,
                'protocol': pkt.highest_layer,
                'length': int(pkt.length),
                'timestamp': pkt.sniff_timestamp,
                'flags': pkt.tcp.flags if hasattr(pkt, 'tcp') else None
            })
        except AttributeError:
            continue

    df = pd.DataFrame(packet_data)
    stats = df.groupby('protocol')['length'].agg([np.mean, np.std, np.max, np.min])
    stats.reset_index(inplace=True)
    print("[*] Network statistics computed:")
    print(stats.head())
    df.to_csv("network_capture.csv", index=False)
    stats.to_csv("network_stats.csv", index=False)
    return stats

# =========================
# Section 2: Active Recon Detection with Nmap
# =========================
import nmap

# Function to get a list of nmap targets from the user so we don't have to hardcode
# IP ranges in, which could be a security issue
def get_nmap_targets():
    targets = []
    add_more_targets = True

    while add_more_targets:
        target = input("Input a new target. Enter IP Address or IP Addr/Subnet mask (e.g. 192.168.1.0/24)\n? ")
        target = target.strip()

        if not (target == None or target == ""):
            targets.append(target)

        print("Current targets: " + ", ".join(targets))

        while True:
            add_more = input("Add more targets? (Y/N) ? ")

            if add_more.lower() == "y" or add_more.lower() == "yes":
                add_more_targets = True
                break
            elif add_more.lower() == "n" or add_more.lower() == "no":
                add_more_targets = False
                break
            else:
                continue

    return targets


def detect_active_recon(targets=['192.168.1.0/24'], sudo=True):
    if targets == None:
        targets = get_nmap_targets()

    print("[*] Running Nmap scans...")
    nm = nmap.PortScanner()
    all_results = []

    for target in targets:
        nm.scan(hosts=target, arguments='-sS -p 1-1024', sudo=sudo)
        for host in nm.all_hosts():
            host_data = {
                'host': host,
                'state': nm[host].state(),
                'open_ports': 0
            }
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        host_data['open_ports'] += 1
            all_results.append(host_data)

    nmap_df = pd.DataFrame(all_results)
    print("[*] Nmap scan completed.")
    print(nmap_df.head())
    nmap_df.to_csv("nmap_results.csv", index=False)
    return nmap_df

# =========================
# Section 3: Application-Layer Analysis via Burp Suite API
# =========================
import requests

def burp_application_scan(api_url='http://127.0.0.1:1337/v0.1/scan'):
    print("[*] Fetching Burp Suite scan results...")
    try:
        response = requests.get(api_url)
        scans = response.json()
    except Exception as e:
        print("Error fetching Burp Suite data:", e)
        return pd.DataFrame()

    all_issues = []
    for scan in scans.get('scans', []):
        host = scan.get('target', 'unknown')
        high_severity_issues = sum(1 for i in scan.get('issues', []) if i['severity'] == 'High')
        all_issues.append({'host': host, 'high_severity_issues': high_severity_issues})

    burp_df = pd.DataFrame(all_issues)
    burp_df.to_csv("burp_results.csv", index=False)
    print("[*] Burp Suite data processed.")
    return burp_df

# =========================
# Section 4: Homomorphic Encryption of Features
# =========================
from Pyfhel import Pyfhel
def encrypt_features(feature_vector):
    HE = Pyfhel()
    HE.contextGen(scheme='CKKS', n=2**14, scale=2**30)
    HE.keyGen()

    plaintext = HE.encodeFrac(feature_vector)
    ciphertext = HE.encryptPtxt(plaintext)
    decrypted = HE.decryptFrac(ciphertext)
    print("[*] Original Features:", feature_vector)
    print("[*] Decrypted after encryption:", decrypted)
    return ciphertext, HE

# =========================
# Section 5: Cross-Layer Correlation & Threat Detection
# =========================
def correlate_and_flag_threats():
    print("[*] Correlating data layers and flagging threats...")
    try:
        network_stats = pd.read_csv('network_stats.csv')
        nmap_results = pd.read_csv('nmap_results.csv')
        burp_results = pd.read_csv('burp_results.csv')
    except FileNotFoundError as e:
        print("Error: Data files not found. Run previous steps first.", e)
        return

    combined = network_stats.merge(nmap_results, left_on='protocol', right_on='host', how='outer')
    combined = combined.merge(burp_results, left_on='protocol', right_on='host', how='outer')
    combined.fillna(0, inplace=True)

    def threat_score(row):
        score = 0
        if row.get('open_ports', 0) > 5:
            score += 2
        if row.get('high_severity_issues', 0) > 0:
            score += 3
        if row.get('mean', 0) > 1000:  # from packet length statistics
            score += 1
        return score

    combined['threat_score'] = combined.apply(threat_score, axis=1)
    combined['threat_flag'] = combined['threat_score'] >= 4
    combined.to_csv("cross_layer_analysis.csv", index=False)
    print("[*] Cross-layer threat detection complete.")
    print(combined[['protocol', 'threat_score', 'threat_flag']].head())

# =========================
# Section 6: Main Execution
# =========================
if __name__ == "__main__":
    # stats = capture_network_traffic('wlo1')
    nmap_df = detect_active_recon(None)
    # burp_df = burp_application_scan()
    # sample_features = [stats['mean'].mean(), nmap_df['open_ports'].mean(), burp_df['high_severity_issues'].mean()]
    # ciphertext, HE = encrypt_features(sample_features)
    # correlate_and_flag_threats()

