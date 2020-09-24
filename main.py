from scapy.all import *
from sys import getsizeof

IPv4 = [0x08, 0x00]
ARP = [0x08, 0x06]
IPv6 = [0x08, 0xdd]

class Packet:
    def __init__(self, hex_packet, index):
        self.index = index
        self.hex_raw = hex_packet
        self.destination_mac = get_destination_MAC(hex_packet)
        self.source_mac = get_source_MAC(hex_packet)
        self.type = get_type(hex_packet)
        self.frame_len = len(hex_packet)
        self.data_len = len(hex_packet) + 22 if self.type[1] == "ARP" else 4

    def print(self):
        byte_index = 1
        for byte in self.hex_raw:
            end_char = " "
            if byte_index != 0 and byte_index % 16 == 0:
                end_char = "\n"
            elif byte_index != 0 and byte_index % 8 == 0:
                end_char = " | "
            else:
                endchar = " "
            print(f'{byte:02x}', end=end_char)
            byte_index += 1
        print("\n")





def netAnalyzer(fileName):
    print(f'Opening: {fileName}')
    packets = rdpcap(fileName)
    i = 0
    packet_list = []
    for pkt in packets.res:
        i += 1
        print(f'{i}. packet: \n {pkt}')
        packet_list.append(Packet(bytes(pkt), i))
    for pkt in packet_list:
        print(f'ramec {pkt.index}')
        print(f'dlzka ramca poskytnuta pcap API {pkt.frame_len}')
        print(f'dlzka ramca prenasaneho po mediu {pkt.data_len}')
        print(f'{pkt.type[0]}\n{pkt.type[1]}')
        print(f'Zdrojova MAC adresa: {pkt.source_mac}')
        print(f'Cielova MAC adresa: {pkt.destination_mac}')
        pkt.print()


# def loadProtocols(fileName):

def get_destination_MAC(hex_arr):
    result = ""
    for hex_byte in hex_arr[0:6]:
        result += hex(hex_byte)[2:].zfill(2) + " "
    return result


def get_source_MAC(hex_arr):
    result = ""
    for hex_byte in hex_arr[6:12]:
        result += hex(hex_byte)[2:].zfill(2) + " "
    return result


def get_type(hex_arr):
    t = [hex_arr[12], hex_arr[13]]
    length = hex_arr[12] + 0xff * hex_arr[13]
    if 46 <= length <= 1500:
        return "IEEE 802.3", "dlzka: " + str(length)
    elif match_bytes(t, IPv4):
        return "Ethernet II", "IPv4"
    elif match_bytes(t, ARP):
        return "Ethernet II", "ARP"
    elif match_bytes(t, IPv6):
        return "Ethernet II", "IPv6"
    else:
        return "Unknown type", ""


def match_bytes(x, y):
    # print(f'{x}\n{y}') #DEBUG
    if len(x) != len(y):
        return False
    else:
        for i in range(0, len(x)):
            if x[i] != y[i]:
                return False
        return True



if __name__ == '__main__':
    netAnalyzer('inputs/spec.pcap')

