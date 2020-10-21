import sys
import json

# > 1500 == Ethernet II
# < 1500 && !IPX && !SNAP ==  IEEE 802.3 LLC
IPX = [0xff, 0xff]
SNAP = [0xaa, 0xaa]


class Packet:
    Headers = ""
    DestinationIPs = {}

    @staticmethod
    def GetMostDestination():
        most_ips = -1
        ip = ""
        for x in Packet.DestinationIPs.keys():
            if Packet.DestinationIPs[x] > most_ips:
                most_ips = Packet.DestinationIPs[x]
                ip = x
        return ip, most_ips

    def __init__(self, hex_packet: bytes, index: int, packet_header):
        self.index = index
        self.hex_raw = hex_packet
        self.destination_mac = self.get_destination_MAC(hex_packet)
        self.source_mac = self.get_source_MAC(hex_packet)
        self.type = self.get_type(hex_packet)
        self.transport_protocol = "none"
        self.syn = False
        self.finres = False

        self.ipv4_length = -1
        self.source_port = -1
        self.destination_port = -1

        self.icmp_type = -1
        self.icmp_id = -1
        self.icmp_seq = -1

        self.destination_mac_arp = -1
        self.source_mac_arp = -1
        self.arpcode = -1

        self.source_ip = -1
        self.destination_ip = -1
        self.frame_len = packet_header.wirelen
        self.data_len = 64 if packet_header.caplen < 60 else packet_header.caplen + 4
        # self.total_size = sys.getsizeof(self.data_len) + sys.getsizeof(self.frame_len) + sys.getsizeof(self.type) +
        # sys.getsizeof(self.source_mac) + sys.getsizeof(self.destination_mac) + sys.getsizeof(self.hex_raw) +
        # sys.getsizeof(self.index) self.data_len = len(hex_packet) + (22 if self.type[1] == "ARP" else 4)
        if self.type[1] == "IPV4":
            self.get_ipv4(hex_packet)
        elif self.type[1] == "ARP":
            self.get_arp(hex_packet)
        if self.transport_protocol == "TCP":
            self.get_tcp(hex_packet)
        elif self.transport_protocol == "UDP":
            self.get_udp(hex_packet)
        elif self.transport_protocol == "ICMP":
            self.get_icmp(hex_packet)

    def get_ipv4(self, hex_arr):
        ip_header_length = (hex_arr[14] & 0b00001111) * 4
        self.ipv4_length = ip_header_length
        #print(f'LEN: {ip_header_length}') # IP Header length debug
        transport_bytes = [hex_arr[23]]
        self.transport_protocol = find_match(transport_bytes, Packet.Headers["ip"]["protocol"])
        self.source_ip = f'{hex_arr[26]}.{hex_arr[27]}.{hex_arr[28]}.{hex_arr[29]}'
        self.destination_ip = f'{hex_arr[30]}.{hex_arr[31]}.{hex_arr[32]}.{hex_arr[33]}'
        if self.destination_ip in Packet.DestinationIPs:
            Packet.DestinationIPs[self.destination_ip] += 1
        else:
            Packet.DestinationIPs[self.destination_ip] = 1

    def get_icmp(self, hex_arr):
        type_bytes = [hex_arr[34 + self.ipv4_length - 20]]
        self.icmp_type = find_match(type_bytes, Packet.Headers["icmp_type"])
        self.icmp_id = hex_arr[38] * 256 + hex_arr[39]
        self.icmp_seq = hex_arr[40] * 256 + hex_arr[41]

    def get_tcp(self, hex_arr):
        source_port_bytes = [hex_arr[34 + self.ipv4_length - 20], hex_arr[35 + self.ipv4_length - 20]]
        source_port_number = source_port_bytes[0] * 256 + source_port_bytes[1]
        source_port = find_match(source_port_bytes, Packet.Headers["known_ports"])
        if not source_port:
            self.source_port = f'Unknown port ({source_port_bytes[0] * 256 + source_port_bytes[1]})'
        else:
            self.source_port = f'{source_port} (Port {source_port_number})'
        flag_bytes = hex_arr[47 + self.ipv4_length - 20]
        self.syn = flag_bytes & 2
        self.finres = flag_bytes & 1 or flag_bytes & 4

        destination_port_bytes = [hex_arr[36 + self.ipv4_length - 20], hex_arr[37 + self.ipv4_length - 20]]
        destination_port_number = destination_port_bytes[0] * 256 + destination_port_bytes[1]
        destination_port = find_match(destination_port_bytes, Packet.Headers["known_ports"])
        if not destination_port:
            self.destination_port = f'Unknown port ({destination_port_number})'
        else:
            self.destination_port = f'{destination_port} (Port {destination_port_number})'

    def get_udp(self, hex_arr):
        source_port_bytes = [hex_arr[34 + self.ipv4_length - 20], hex_arr[35 + self.ipv4_length - 20]]
        source_port_number = source_port_bytes[0] * 256 + source_port_bytes[1]
        source_port = find_match(source_port_bytes, Packet.Headers["known_ports"])
        if not source_port:
            self.source_port = f'Unknown port ({source_port_bytes[0] * 256 + source_port_bytes[1]})'
        else:
            self.source_port = f'{source_port} (Port {source_port_number})'

        destination_port_bytes = [hex_arr[36 + self.ipv4_length - 20], hex_arr[37 + self.ipv4_length - 20]]
        destination_port_number = destination_port_bytes[0] * 256 + destination_port_bytes[1]
        destination_port = find_match(destination_port_bytes, Packet.Headers["known_ports"])
        if not destination_port:
            self.destination_port = f'Unknown port ({destination_port_number})'
        else:
            self.destination_port = f'{destination_port} (Port {destination_port_number})'

    def print(self):
        byte_index = 1
        for byte in self.hex_raw:
            if byte_index % 16 == 0:
                end_char = "\n"
            elif byte_index % 8 == 0:
                end_char = " | "
            else:
                end_char = " "
            print(f'{byte:02x}', end=end_char)
            byte_index += 1
        print("\n")

    def format_hex(self):
        str = ""
        byte_index = 1
        for byte in self.hex_raw:
            if byte_index % 16 == 0:
                end_char = "\n"
            elif byte_index % 8 == 0:
                end_char = " | "
            else:
                end_char = " "
            str += f"{byte:02x}" + end_char
            byte_index += 1
        str += "\n"
        return str

    def to_string(self):
        res = ""
        res += str(self.index) + "\n"
        res += str(self.frame_len) + "\n"
        res += str(self.data_len) + "\n"
        res += str(self.type[0]) + "\n" + str(self.type[1]) + "\n"
        res += str(self.transport_protocol) + "\n"
        res += str(self.source_mac) + "\n"
        res += str(self.destination_mac) + "\n"
        res += str(self.format_hex())
        return res

    def pretty_print(self):
        print(f'frame {self.index}')
        print(f'frame length from pcap API {self.frame_len}')
        print(f'frame length in source {self.data_len}')
        print(f'frame type: {self.type[0]} \nlength/ethertype: {self.type[1]}')
        print(f'transport protocol: {self.transport_protocol}')
        if self.type[1] == "IPV4" or self.type[1] == "ARP":
            print(f'source ip: {self.source_ip}')
            print(f'destination ip: {self.destination_ip}')
        if self.type[1] == "ARP":
            print(f'source arp mac: {self.source_mac_arp}')
            print(f'destination arp mac: {self.destination_mac_arp}')
        if self.transport_protocol == "UDP" or self.transport_protocol == "TCP":
            print(f'Source port: {self.source_port}')
            print(f'Destination port: {self.destination_port}')
        if self.icmp_type != -1:
            print(f'ICMP Type: {self.icmp_type}')
        print(f'Source MAC address: {self.source_mac}')
        print(f'Destination MAC address: {self.destination_mac}')
        self.print()

    @staticmethod
    def get_destination_MAC(hex_arr):
        result = ""
        for hex_byte in hex_arr[0:6]:
            result += hex(hex_byte)[2:].zfill(2) + " "
        return result

    @staticmethod
    def get_source_MAC(hex_arr):
        result = ""
        for hex_byte in hex_arr[6:12]:
            result += hex(hex_byte)[2:].zfill(2) + " "
        return result

    @staticmethod
    def get_type(hex_arr):
        len_type_bytes = [hex_arr[12], hex_arr[13]]
        ieee_bytes = [hex_arr[14], hex_arr[15]]
        length = len_type_bytes[0] * 256 + len_type_bytes[1]
        if length <= 1500:
            return Packet.get_8023_type(ieee_bytes), "length: " + str(length)
        else:
            return "Ethernet II", Packet.get_ethertype(hex_arr)

    @staticmethod
    def get_ethertype(hex_arr):
        t = [hex_arr[12], hex_arr[13]]
        return find_match(t, Packet.Headers["ethertype"]) or "unknown"


    @staticmethod
    def get_8023_type(t):
        if match_bytes(t, IPX):
            return "IEEE 802.3 IPX RAW"
        elif match_bytes(t, SNAP):
            return "IEEE 802.3 LLC + SNAP"
        else:
            return "IEEE 802.3 LLC"

    def get_arp(self, hex_arr):
        src_mac = ""
        for hex_byte in hex_arr[22:28]:
            src_mac += hex(hex_byte)[2:].zfill(2) + " "
        self.source_mac_arp = src_mac
        dest_mac = ""
        for hex_byte in hex_arr[32:38]:
            dest_mac += hex(hex_byte)[2:].zfill(2) + " "
        self.destination_mac_arp = dest_mac
        self.source_ip = f'{hex_arr[28]}.{hex_arr[29]}.{hex_arr[30]}.{hex_arr[31]}'
        self.destination_ip = f'{hex_arr[38]}.{hex_arr[39]}.{hex_arr[40]}.{hex_arr[41]}'
        self.arpcode = int(hex_arr[21])


def find_match(t, match_dict):
    for x in match_dict.keys():
        if match_bytes(t, bytearray.fromhex(str(x))):
            return match_dict[x]
    return False


def match_bytes(x, y):
    # print(f'{x}\n{y}') #DEBUG
    if len(x) != len(y):
        return False
    else:
        for i in range(0, len(x)):
            if x[i] != y[i]:
                return False
        return True


def load_headers(filename):
    print("---Loading headers: ")
    Packet.Headers = json.load(open(filename))

    print("---Loaded: ")
    print(Packet.Headers)

