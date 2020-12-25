import socket
import struct
import binascii

### Helper Protocol ###

class NullProtocol:

    def print_protocol(self):
        print("*************************************")
        print("***********Unknown Protocol**********")
        print("*************************************")

    def get_next_protocol(self):
        return NullProtocol()

### Link Layer ###

class EthernetFrame:

    def __init__(self, frame):
        macDst, macSrc, ethertype = struct.unpack(">6s6sH", frame[:14])
        self.macDst = binascii.hexlify(macDst)
        self.macSrc = binascii.hexlify(macSrc)
        ethertype = hex(ethertype)
        
        if (ethertype == '0x0800'):
          self.ethertype = 'IPv4'
        elif (ethertype == '0x86DD'):
          self.ethertype = 'IPv6'
        
        self.payload = frame[14:]

    def print_protocol(self):
        print("===========Ethernet Frame===========")
        print("MAC Destination: {}\nMAC Source{}".format(self.macDst, self.macSrc))
        print("EtherType: {}".format(self.ethertype))

    def get_next_protocol(self):
        if (self.ethertype == 'IPv4'):
            return IPv4(self.payload)
        elif (self.ethertype == 'IPv6'):
            return IPv6(self.payload)
        else:
            return NullProtocol()

### Internet Layer ###

class IPv4:
 
    def __init__(self, packet):
        ttl, next_header, checksum, src_ip, dst_ip = struct.unpack(">8x2BH4s4s", packet[:20])
        self.ttl = ttl
        self.get_next_header(next_header)
        self.checksum = checksum
        self.src_ip = '.'.join(map(str, src_ip))
        self.dst_ip = '.'.join(map(str, dst_ip))
        self.payload = packet[20:]

    def get_next_header(self, next_header):
        next_header = int(next_header)
        if (next_header == 1):
            self.next_header = 'ICMP'
        elif (next_header == 6):
            self.next_header = 'TCP'
        elif (next_header == 17):
            self.next_header = 'UDP'

    def print_protocol(self):
        print("===========IPv4===========")
        print("Time To Live: {}\nNext Protocol: {}\nChecksum: {}".format(self.ttl, self.next_header, self.checksum))
        print("Source IP: {}\nDestination IP: {}\n".format(self.src_ip, self.dst_ip))

    def get_next_protocol(self):
        if (self.next_header == 'ICMP'):
            return ICMP(self.payload)
        elif (self.next_header == 'TCP'):
            return TCP(self.payload)
        elif (self.next_header == 'UDP'):
            return UDP(self.payload)
        else:
            return NullProtocol()

class IPv6:

    def __init__(self, packet):
        firstword, payload_len, next_header, hop_limit = struct.unpack(">IHBB", packet[:8])
        self.get_fields(firstword)
        self.payload_len = int(payload_len)
        self.get_next_header(next_header)
        self.hop_limit = int(hop_limit)
        self.src_ip = socket.inet_ntop(socket.AF_INET6, packet[8:24])
        self.dst_ip = socket.inet_ntop(socket.AF_INET6, packet[24:40])
        self.payload = packet[40:]

    def get_fields(self, firstword):
        firstword = int(firstword)
        self.version = firstword >> 28
        self.traffic_class = (firstword >> 20) & 255
        self.flow_label = firstword & 1048575

    def get_next_header(self, next_header):
        next_header = int(next_header)
        if (next_header == 1):
            self.next_header = 'ICMP'
        elif (next_header == 6):
            self.next_header = 'TCP'
        elif (next_header == 17):
            self.next_header = 'UDP'

    def print_protocol(self):
        print("===========IPv6===========")
        print("Ver: {}\nTraffic Class: {}\nFlow Label: {}".format(self.version, self.traffic_class, self.flow_label))
        print("Payload Length: {}\nNext Header: {}\nHop Limit: {}".format(self.payload_len, self.next_header, self.hop_limit))
        print("Source Address: {}\nDestination Address: {}".format(self.src_ip, self.dst_ip))

    def get_next_protocol(self):
        if (self.next_header == 'ICMP'):
            return ICMP(self.payload)
        elif (self.next_header == 'TCP'):
            return TCP(self.payload)
        elif (self.next_header == 'UDP'):
            return UDP(self.payload)
        else:
            return NullProtocol()

class ICMP:

    def __init__(self, packet):
        icmp_type, code, checksum, rest_of_header = struct.unpack(">BBHI", packet[:8])
        self.icmp_type = icmp_type
        self.code = code
        self.checksum = checksum
        self.rest_of_header = rest_of_header

    def print_protocol(self):
        print("===========ICMP===========")
        print("Type: {}\nCode: {}\nChecksum: {}".format(self.icmp_type, self.code, self.checksum))

### Transport Layer ###

class TCP:

    def __init__(self, segment):
        segment_info = struct.unpack(">2H2I4H", segment[:20])
        self.src_port = segment_info[0]
        self.dst_port = segment_info[1]
        self.seq_num = segment_info[2]
        self.ack_num = segment_info[3]
        self.get_flags(segment_info[4])
        self.window_size = segment_info[5]
        self.checksum = segment_info[6]
        self.urg_pointer = segment_info[7]

    def get_flags(self, data):
        self.data_offset = data >> 12
        flags = data & 0x01FF
        self.fin_flag = flags & 0x0001
        self.syn_flag = flags & 0x0002
        self.rst_flag = flags & 0x0004
        self.psh_flag = flags & 0x0008
        self.ack_flag = flags & 0x0010
        self.urg_flag = flags & 0x0020
        self.ece_flag = flags & 0x0040
        self.cwr_flag = flags & 0x0080
        self.ns_flag = flags & 0x0100

    def print_protocol(self):
        print("===========TCP===========")
        print("Source Port: {}\nDestination Port: {}".format(self.src_port, self.dst_port))
        print("Sequence Number: {}\nACK Number: {}".format(self.seq_num, self.ack_num))
        print("Data Offset: {}".format(self.data_offset))
        print("NS: {}\tCWR: {}\tECE: {}\tURG: {}\tACK: {}".format(self.ns_flag, self.cwr_flag, self.ece_flag, self.urg_flag, self.ack_flag))
        print("PSH: {}\tRST: {}\tSYN: {}\tFIN: {}".format(self.psh_flag, self.rst_flag, self.syn_flag, self.fin_flag))
        print("Window Size: {}\nChecksum: {}\nUrgent Pointer: {}".format(self.window_size, self.checksum, self.urg_pointer))


class UDP:

    def __init__(self, datagram):
        src_port, dst_port, data_len, checksum = struct.unpack(">4H", datagram[:8])
        self.src_port = int(src_port)
        self.dst_port = int(dst_port)
        self.data_len = int(data_len)
        self.checksum = hex(checksum)

    def print_protocol(self):
        print("===========UDP===========")
        print("Source Port: {}\nDestination Port: {}".format(self.src_port, self.dst_port))
        print("Data Length (bytes): {}\nChecksum: {}".format(self.data_len, self.checksum))

