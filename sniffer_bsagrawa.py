import struct
import socket
import time
import csv

def get_ethernet_proto_data(packet):
    ethernet_header_len = 14
    ethernet_header = packet[:ethernet_header_len]
    dmac,smac,proto_field = struct.unpack('!6s6sH' , ethernet_header)    
    return packet[ethernet_header_len:],socket.htons(proto_field)


def get_ip_proto_data(packet):
    ip_head_size=20
    ip_header = packet[:ip_head_size] 
    ip_header_list = struct.unpack('!BBHHHBBH4s4s' , ip_header)
    version_ihl = ip_header_list[0]
    ip_header_len = (version_ihl & 0xF) * 4
    ip_protocol = ip_header_list[6]
    return packet[ip_header_len:], ip_protocol
    
    
    

def get_upd_port_addr(packet):
    udp_len = 6
    udp_header = struct.unpack('!HHH',packet[:udp_len])
    return udp_header[0], udp_header[1]

def get_tcp_port_addr(packet):
    tcp_len = 14
    tcp_header = struct.unpack('!HHLLH',packet[:tcp_len])
    return tcp_header[0],tcp_header[1]

def main():
    
    listener_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(3))
    proto_counter = {}
    proto_counter['ip'] = 0
    proto_counter['tcp'] = 0
    proto_counter['udp'] = 0
    proto_counter['icmp'] = 0
    proto_counter['http'] = 0
    proto_counter['https'] = 0
    proto_counter['quic'] = 0
    proto_counter['dns'] = 0
    
    stoppage = time.time() + 30
    while time.time() < stoppage:
        
        packet,addr = listener_socket.recvfrom(65535)
        ethernet_packet,ethernet_protocol = get_ethernet_proto_data(packet)
        
        if ethernet_protocol == 8:
            proto_counter['ip'] = proto_counter['ip'] + 1 
            ip_packet, ip_protocol = get_ip_proto_data(ethernet_packet)
            
            if ip_protocol == 6:
                proto_counter['tcp'] = proto_counter['tcp'] + 1 
                src_port, dest_port = get_tcp_port_addr(ip_packet)
                
                if src_port == 80 or dest_port == 80:
                    proto_counter['http'] = proto_counter['http'] + 1
                elif src_port == 443 or dest_port == 443:
                    proto_counter['https'] = proto_counter['https'] + 1
            elif ip_protocol == 17:
                proto_counter['udp'] = proto_counter['udp'] + 1    
                src_port, dest_port = get_upd_port_addr(ip_packet)
                
                if src_port == 53 or dest_port == 53: 
                    proto_counter['dns'] = proto_counter['dns'] + 1
                elif src_port == 443 or src_port == 80 or dest_port == 443 or src_port == 80:
                    proto_counter['quic'] = proto_counter['quic'] + 1
            elif ip_protocol == 1:
                proto_counter['icmp'] = proto_counter['icmp'] + 1
            
    with open('sniffer_bsagrawa.csv', 'w') as file:
        for key in ['ip','tcp','udp','dns','icmp','http','https','quic']:
            file.write("{},{}\n".format(key, proto_counter[key]))
        

if __name__=="__main__":
    main()
