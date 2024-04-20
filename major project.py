from scapy.all import *
import subprocess

messages =[]
port_scan_detected = False
ftp_activity_detected = False
arp_detect =False
arpscan_detected = False
ping_ping = False
def detect_port_scan(packet):
    global port_scan_detected
    if not port_scan_detected and TCP in packet and packet[TCP].flags == "S" and packet[TCP].flags != "A":
        print(f"Port scan detected! Source IP: {packet[IP].src}")
        message = f"Port scan detected! Source IP: {packet[IP].src}"
        messages.append(message)
        port_scan_detected = True

def detect_ftp_activity(packet):
    global ftp_activity_detected
    if not ftp_activity_detected and TCP in packet and packet[TCP].dport == 21 and packet[TCP].flags == 2:
        print("Port 21 scan detected! Source IP:", packet[IP].src)
        message = f"Port 21 scan detected! Source IP: {packet[IP].src}"
        messages.append(message)
        ftp_activity_detected = True
    elif not ftp_activity_detected and TCP in packet and packet[TCP].dport == 21 and packet[TCP].flags == 18:
        print("FTP connection attempt detected! Source IP:", packet[IP].src)
        message = f"FTP connection attempt detected! Source IP: {packet[IP].src}"
        messages.append(message)

        ftp_activity_detected = True
def arpspoof_detecter(packet):
    global arp_detect
    if not arp_detect and ARP in packet and packet[ARP].op == 2:  # ARP response
        # Extract IP and MAC addresses from the ARP response
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        # Check if the IP-MAC mapping is consistent with previous observations
        if src_ip in ip_mac_mapping:
            if ip_mac_mapping[src_ip] != src_mac:
                print(
                    f"Potential ARP spoofing detected! IP: {src_ip}, Original MAC: {ip_mac_mapping[src_ip]}, New MAC: {src_mac}")
                message = f"Potential ARP spoofing detected! IP: {src_ip}, Original MAC: {ip_mac_mapping[src_ip]}, New MAC: {src_mac}"
                messages.append(message)
        else:
            # Add the new IP-MAC mapping to the dictionary
            ip_mac_mapping[src_ip] = src_mac
ip_mac_mapping = {}

def detect_arp_scan(packet):
    global arpscan_detected
    if not arpscan_detected and ARP in packet and packet[ARP].op == 1:  # ARP request
        print(f"ARP scan detected! Source IP: {packet[ARP].psrc} and Source MAC address: {packet[ARP].hwsrc}")
        message = f"ARP scan detected! Source IP: {packet[ARP].psrc}and Source MAC address: {packet[ARP].hwsrc}"
        messages.append(message)
        arpscan_detected = True

def ping_detect(packet):
    global ping_ping
    if not ping_ping and ICMP in packet and packet[ICMP].type == 8:
        print(f"Ping detected! Source IP: {packet[IP].src}")
        message = f"Ping detected! Source IP {packet[IP].src}"
        messages.append(message)
        ping_ping = True


# def notification(messages):
#     command = f'echo "{messages}"| notify'
#     subprocess.run(command,shell=True, check=True)
def notification(messages):
    if messages:
        command = f'echo "{messages}" | notify'
        subprocess.run(command, shell=True, check=True)
        messages.clear()  # Clear the messages list after sending the notification

def packet_handler(packet):
    detect_port_scan(packet)
    detect_ftp_activity(packet)
    arpspoof_detecter(packet)
    detect_arp_scan(packet)
    ping_detect(packet)
    notification(messages)



# Sniff network traffic and call packet_handler for each captured packet
sniff(prn=packet_handler, store=0)
