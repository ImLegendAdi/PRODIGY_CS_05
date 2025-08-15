from scapy.all import sniff, IP, IPv6, ICMP, TCP, Raw
from flask import Flask, send_from_directory
from flask_socketio import SocketIO
import os
import datetime
import threading
import time

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')  # Use threading mode explicitly

sniffing = False
delay_seconds = 0

@app.route('/')
def index():
    # Serve index.html from current folder
    return send_from_directory(os.getcwd(), 'index.html')

@socketio.on('start_sniff')
def start_sniff():
    global sniffing
    sniffing = True
    socketio.emit('sniffer_status', {'status': 'started'})

@socketio.on('stop_sniff')
def stop_sniff():
    global sniffing
    sniffing = False
    socketio.emit('sniffer_status', {'status': 'stopped'})

@socketio.on('set_delay')
def set_delay(data):
    global delay_seconds
    try:
        delay_seconds = float(data.get('delay', 0))
    except:
        delay_seconds = 0
    socketio.emit('sniffer_status', {'status': f'delay set to {delay_seconds} sec'})


def parse_packet(pkt):
    packet_info = {}
    packet_info['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in pkt:
        ip_layer = pkt[IP]
        packet_info['src_ip'] = ip_layer.src
        packet_info['dst_ip'] = ip_layer.dst
        proto_num = ip_layer.proto
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        packet_info['protocol'] = proto_map.get(proto_num, str(proto_num))
    elif IPv6 in pkt:
        ip6_layer = pkt[IPv6]
        packet_info['src_ip'] = ip6_layer.src
        packet_info['dst_ip'] = ip6_layer.dst
        nh = ip6_layer.nh
        proto_map = {58: "ICMPv6", 6: "TCP", 17: "UDP"}
        packet_info['protocol'] = proto_map.get(nh, str(nh))
    else:
        return None

    if ICMP in pkt:
        packet_info['protocol'] = "ICMP"

    # Extract payload if present
    payload_text = ""
    if Raw in pkt:
        raw_bytes = pkt[Raw].load
        try:
            payload_text = raw_bytes.decode('utf-8', errors='ignore')
            payload_text = payload_text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
            if len(payload_text) > 200:
                payload_text = payload_text[:200] + "..."
        except Exception:
            payload_text = "[binary data]"

    packet_info['payload'] = payload_text

    # Mark HTTP if TCP port 80 or 443 and payload exists
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if (sport == 80 or dport == 80 or sport == 443 or dport == 443) and payload_text:
            packet_info['protocol'] = "HTTP"

    return packet_info


def packet_callback(pkt):
    global sniffing, delay_seconds
    if not sniffing:
        return  # Ignore packets if not sniffing

    info = parse_packet(pkt)
    if info:
        socketio.emit('new_packet', info)
        if delay_seconds > 0:
            time.sleep(delay_seconds)

def sniff_packets():
    sniff(prn=packet_callback, store=False)

if __name__ == '__main__':
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()
    socketio.run(app, host='0.0.0.0', port=5000)
