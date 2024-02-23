from scapy.all import IP, TCP, send

def send_tcp_packet(destination_ip, destination_port):
    ip_packet = IP(dst=destination_ip)
    tcp_packet = TCP(dport=destination_port, sport=12345, flags="A", seq=12345, ack=67890,options=[('NOP', None), ('NOP', None), ('Timestamp', (12345, 90909090))])
    packet = ip_packet / tcp_packet
    send(packet)

if __name__ == "__main__":
    destination_ip = "172.19.0.3"
    destination_port = 80

    send_tcp_packet(destination_ip, destination_port)
