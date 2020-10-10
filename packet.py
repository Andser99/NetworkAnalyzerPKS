import sys
import json

# > 1500 == Ethernet II
# < 1500 && !IPX && !SNAP ==  IEEE 802.3 LLC
IPX = [0xff, 0xff]
SNAP = [0xaa, 0xaa]


class Packet:
    Headers = ""

    def __init__(self, hex_packet: bytes, index: int, packet_header):
        self.index = index
        self.hex_raw = hex_packet
        self.destination_mac = self.get_destination_MAC(hex_packet)
        self.source_mac = self.get_source_MAC(hex_packet)
        self.type = self.get_type(hex_packet)
        self.frame_len = packet_header.wirelen
        self.data_len = packet_header.caplen
        self.total_size = sys.getsizeof(self.data_len) + sys.getsizeof(self.frame_len) + sys.getsizeof(self.type) + sys.getsizeof(self.source_mac) + sys.getsizeof(self.destination_mac) + sys.getsizeof(self.hex_raw) + sys.getsizeof(self.index)
        # self.data_len = len(hex_packet) + (22 if self.type[1] == "ARP" else 4)

    def get_size(self):
        return sys.getsizeof(self)

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
        res += str(self.source_mac) + "\n"
        res += str(self.destination_mac) + "\n"
        res += str(self.format_hex())
        return res

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

        if 46 <= length <= 1500:
            return "IEEE 802.3" + Packet.get_8023_type(ieee_bytes), "length: " + str(length)
        elif match_bytes(len_type_bytes, IPX):
            return "Novell RAW", "length: " + str(length)
        elif match_bytes(len_type_bytes, SNAP):
            return "IEEE 802.3 LLC + SNAP" + str(length)
        else:
            return "Ethernet II", Packet.get_ethertype(hex_arr)

    @staticmethod
    def get_ethertype(hex_arr):
        t = [hex_arr[12], hex_arr[13]]
        return find_match(t, Packet.Headers["ethertype"])

    @staticmethod
    def get_8023_type(t):
        if match_bytes(t, IPX):
            return "Novell RAW"
        elif match_bytes(t, SNAP):
            return "IEEE 802.3 LLC + SNAP"
        else:
            return "IEEE 802.3 LLC"


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
    print(Packet.Headers)
    Packet.Headers = json.load(open(filename))

    print("---Loaded: ")
    print(Packet.Headers)

