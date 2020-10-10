from kivy.app import App
from scapy.all import *
from packet import *
from mainPage import MainPage
import json

main_page = MainPage()


def netAnalyzer(file_name):
    print(f'Opening: {file_name}')

    # scapy
    packets = rdpcap(file_name)
    packet_headers = []
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        packet_headers.append(pkt_metadata)

    i = 0
    packet_list = []

    for pkt in packets:
        i += 1
        print(f'{i}. packet: \n {pkt}')
        packet_list.append(Packet(bytes(pkt), i, packet_headers[i-1]))
    for pkt in packet_list:
        print(f'frame {pkt.index}')
        print(f'frame length from pcap API {pkt.frame_len}')
        print(f'frame length in source {pkt.data_len}')
        print(f'frame type: {pkt.type[0]} \nlength/ethertype: {pkt.type[1]}')
        print(f'Source MAC address: {pkt.source_mac}')
        print(f'Destination MAC address: {pkt.destination_mac}')
        pkt.print()
    main_page.populate_list(packet_list)


class MainApp(App):
    def build(self):
        return main_page

if __name__ == '__main__':
    # netAnalyzer('inputs/vzorky_pcap_na_analyzu/trace-4.pcap')
    load_headers("headers.json")
    netAnalyzer('inputs/vzorky_pcap_na_analyzu/trace-20.pcap')
    # MainApp().run()
