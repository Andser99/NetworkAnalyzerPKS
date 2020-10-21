from scapy.all import *
from packet import *
import json


def netAnalyzer(file_name):
    print(f'Opening file: {file_name}')
    print(f'...')

    # scapy
    packets = rdpcap(file_name)
    packet_headers = []
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        packet_headers.append(pkt_metadata)

    i = 0
    packet_list = []
    print("analyzing file...")
    for pkt in packets:
        i += 1
        packet_list.append(Packet(bytes(pkt), i, packet_headers[i - 1]))

    # Print all packets
    # for pkt in packet_list:
    #     pkt.pretty_print()
    print("Done")
    return packet_list


def printMostIPs():
    res = Packet.GetMostDestination()
    print(f'Most used destination ip:{res[0]} ({res[1]})')


def printDestinationIPs():
    i = 0
    print("--Destination IPs--")
    for ip in Packet.DestinationIPs:
        i += 1
        print(f'{i} -- {ip} ({Packet.DestinationIPs[ip]})')
    print("--------END--------\n")


def printAll(packet_list):
    for pkt in packet_list:
        pkt.pretty_print()


def printApplications(packet_list, port):
    application_list = []
    application_filtered_list = []
    for pkt in packet_list:
        if pkt.source_port == port or pkt.destination_port == port:
            application_list.append(pkt)
            application_filtered_list.append(pkt)
    index = 0
    all_comms = []
    for pkt in application_list:
        src_port = pkt.source_port
        dest_port = pkt.destination_port
        index += 1
        comm = []
        if pkt.destination_port == port and pkt.syn:
            comm.append(pkt)
            for n in application_list[index:]:
                if n.finres and n.source_port == port:
                    comm.append(n)
                    if n in application_filtered_list:
                        application_filtered_list.remove(n)
                    break
                elif (n.source_port == src_port and n.destination_port == dest_port) or (n.source_port == dest_port and n.destination_port == src_port):
                    comm.append(n)
                    if n in application_filtered_list:
                        application_filtered_list.remove(n)
        if len(comm) > 0:
            all_comms.append(comm)
    index = 0
    for comm in all_comms:
        index += 1
        print(f"---Communicaiton {index}---")
        for pkt in comm:
            pkt.pretty_print()
        print(f"---End Communicaiton {index}---")

    print(f'---Unfinished comms---')
    for pkt in application_filtered_list:
        pkt.pretty_print()
    print(f'---END Unfinished comms---')


def printARPs(packet_list):
    arp_packets = []
    arp_packets_other = []
    for pkt in packet_list:
        if pkt.type[1] == "ARP":
            arp_packets.append(pkt)
            arp_packets_other.append(pkt)
    requests = []
    replies = []
    for res in arp_packets:
        if res.arpcode == 2 and res.source_ip != res.destination_ip:
            replies.append(res)
            arp_packets_other.remove(res)

    for req in arp_packets:
        if req.arpcode == 1:
            index = 0
            for rep in replies:
                if rep.source_ip == req.destination_ip and rep.destination_ip == req.source_ip:
                    requests.append([index, req])
                    if req in arp_packets_other:
                        arp_packets_other.remove(req)
                index += 1

    index = 0
    for rep in replies:
        print(f"---ARP communication {index+1}---")
        for req in requests:
            if req[0] == index:
                req[1].pretty_print()
        rep.pretty_print()
        print(f"---END ARP {index+1}---\n")
        index += 1
    if len(replies) == 0:
        print("none")

    print("---OTHER ARPs---")
    for arp in arp_packets_other:
        arp.pretty_print()
    if len(arp_packets_other) == 0:
        print("none")
    print("")


def printTFTPs(packet_list):
    tftp_packets = []
    for pkt in packet_list:
        if pkt.transport_protocol == "UDP":
            tftp_packets.append(pkt)
    index = 0
    all_comms = []
    for pkt in tftp_packets:
        comm = []
        if pkt.destination_port == "tftp (Port 69)":
            comm.append(pkt)
            for tftp in tftp_packets[index+1:]:
                if tftp.destination_port == "tftp (Port 69)":
                    break
                elif tftp.source_port == pkt.source_port or tftp.destination_port == pkt.source_port:
                    comm.append(tftp)
            index += 1 + len(comm)
        else:
            index += 1
        if len(comm) > 0:
            all_comms.append(comm)
    index = 1
    print("---TFTP Communications---")
    for comm in all_comms:
        print(f"---Communication {index}---")
        if len(comm) > 20:
            for pkt in comm[:10]:
                pkt.pretty_print()
            for pkt in comm[len(comm) - 11:]:
                pkt.pretty_print()
        else:
            for pkt in comm:
                pkt.pretty_print()
        print(f"---END Communication {index}---")
        index += 1

    print("--------END TFTP--------")


def printICMPs(packet_list):
    print("-----ICMP Frames---")
    unpaired = []
    requests = []
    replies = []
    index = 0
    icmp_packets = []
    icmp_requestables = []
    for requestable in Packet.Headers["icmp_requestable"]:
        icmp_requestables.append(Packet.Headers["icmp_requestable"][requestable])
    for pkt in packet_list:
        if pkt.transport_protocol == "ICMP":
            icmp_packets.append(pkt)
    for request in icmp_packets:
        if request.transport_protocol == "ICMP" and request not in replies and request.icmp_type in icmp_requestables:
            found = False
            for reply in icmp_packets[index:]:
                if reply.transport_protocol == "ICMP" and request.source_mac == reply.destination_mac and request.destination_mac == reply.source_mac:
                    requests.append(request)
                    replies.append(reply)
                    found = True
                    break
            if not found:
                unpaired.append(request)
        index += 1

    for x in icmp_packets:
        if x not in requests and x not in replies:
            unpaired.append(x)

    for x in range(len(requests)):
        print(f'---Pair {x+1}---')
        requests[x].pretty_print()
        replies[x].pretty_print()
        print(f'---ENDPair {x+1}---\n')
    print('---other ICMPs---')
    for x in unpaired:
        x.pretty_print()
    print("------ENDICMPs------\n")


def loadFile():
    print("Relative file location:")
    return netAnalyzer(input())


def printHelp():
    print("load - waits for a relative file path")
    print("1 - Prints all frames with 3a and 3b")
    print("3a - Print all destination IPs")
    print("3b - Prints most frequent destination IP")
    print("4a - Prints HTTP communications")
    print("4b - Prints HTTPS communications")
    print("4c - Prints TELNET communications")
    print("4d - Prints SSH communications")
    print("4e - Prints FTP-Control communications")
    print("4f - Prints FTP-Data communications")
    print("4g - Prints TFTP communications")
    print("4h - Prints ICMP pairs and unpaired frames")
    print("4i - Prints ARP pairs and unpaired frames")
    print("q - exits")
    print("help - prints this")


if __name__ == '__main__':
    load_headers("headers.json")
    # netAnalyzer('inputs/vzorky_pcap_na_analyzu/trace-4.pcap')
    # default = 'inputs/vzorky_pcap_na_analyzu/trace-10.pcap'  # One ARP
    # default = 'inputs/vzorky_pcap_na_analyzu/trace-15.pcap'  # ICMP
    default = 'inputs/vzorky_pcap_na_analyzu/trace-18.pcap'  # ICMP
    # default = 'inputs/vzorky_pcap_na_analyzu/unpaired_reply.pcap'
    print(f'Loading default file: {default}')
    packet_list = netAnalyzer(default)
    # printICMPs(packet_list)
    # printMostIPs()
    print("Help menu:")
    print("")
    printHelp()
    inp = input()
    while inp != "q":
        if inp == "1":
            printAll(packet_list)
        elif inp == "4a":
            printApplications(packet_list, "http (Port 80)")
        elif inp == "4b":
            printApplications(packet_list, "https (Port 443)")
        elif inp == "4c":
            printApplications(packet_list, "telnet (Port 23)")
        elif inp == "4d":
            printApplications(packet_list, "ssh (Port 22)")
        elif inp == "4e":
            printApplications(packet_list, "ftp-control (Port 21)")
        elif inp == "4f":
            printApplications(packet_list, "ftp-data (Port 20)")
        elif inp == "4g":
            printTFTPs(packet_list)
        elif inp == "4h":
            printICMPs(packet_list)
        elif inp == "4i":
            printARPs(packet_list)
        elif inp == "3a":
            printDestinationIPs()
        elif inp == "3b":
            printMostIPs()
        elif inp == "load":
            packet_list = loadFile()
        elif inp == "help":
            printHelp()
        inp = input()
