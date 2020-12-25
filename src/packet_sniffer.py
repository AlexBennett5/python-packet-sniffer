import socket
import protocols

def main():
    
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 

    while True:
        print("Starting loop")
        binarydata, address = conn.recvfrom(65536)
        print("Binary data received")
        etherframe = protocols.EthernetFrame(binarydata)
        etherframe.print_protocol()
        ippacket = etherframe.get_next_protocol()
        ippacket.print_protocol()
        transport_or_icmp = ippacket.get_next_protocol()
        transport_or_icmp.print_protocol()

if __name__ == "__main__":
    main()
