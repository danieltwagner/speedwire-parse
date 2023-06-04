#!/usr/bin/env python3

import dpkt
import struct
import sys

from datetime import datetime
from dpkt.utils import inet_to_str

TAG_0 = b'\x02\xa0'
TAG_END = b'\x00\x00'
TAG_SMA_NET_2 = b'\x00\x10'
GROUP1 = b'\x00\x00\x00\x01'


def parse_sma_packet(ip):
    udp = ip.data
    # print(f'{inet_to_str(ip.src)}:{udp.sport} -> {inet_to_str(ip.dst)}:{udp.dport} length {udp.ulen} bytes')

    # ensure the packet has the SMA header
    if udp.data[:4] != b"SMA\x00":
        return None, None
    
    # parse tags
    read = 4
    content_by_tag = dict()
    while read < len(udp.data):
        length = int.from_bytes(udp.data[read:read+2])
        tag = udp.data[read+2:read+4]
        read += 4

        content = udp.data[read:read+length]
        read += length

        content_by_tag[tag] = content

    # ensure it's the right kind of packet
    assert TAG_END in content_by_tag, "Missing end tag"
    assert len(content_by_tag[TAG_END]) == 0, "Invalid end tag"
    
    assert TAG_0 in content_by_tag, "Missing Tag0"
    assert content_by_tag[TAG_0] == GROUP1, "Tag0 isn't Group 1"

    assert TAG_SMA_NET_2 in content_by_tag
    return content_by_tag[TAG_SMA_NET_2], parse_sma_net_packet(content_by_tag[TAG_SMA_NET_2])


def parse_sma_net_packet(data):
    protocol_id = data[:2]
    if protocol_id != b'\x60\x81':
        return None

    parsed = ""
    # The changing bytes
    parsed += data[11:14].hex() + " "
    parsed += data[40:42].hex() + " "
    parsed += data[51:54].hex() + " "
    parsed += data[60:62].hex() + " "
    parsed += data[72:74].hex() + " "
    parsed += data[80:82].hex() + " "
    parsed += data[92:94].hex() + " "
    parsed += data[120:122].hex() + " "
    parsed += data[131:134].hex() + " "
    parsed += data[148:150].hex() + " "
    parsed += data[176:178].hex() + " "
    parsed += data[187:190].hex() + " "
    parsed += data[196:198].hex() + " "
    parsed += data[207:210].hex() + " "
    parsed += data[256:258].hex() + " "
    parsed += data[267:270].hex() + " "
    parsed += data[276:278].hex() + " "
    parsed += data[284:286].hex() + " "
    parsed += data[293:294].hex() + " "
    parsed += data[320:322].hex() + " "
    parsed += data[331:334].hex() + " "
    parsed += data[341:342].hex() + " "
    parsed += data[360:362].hex() + " "
    parsed += data[372:374].hex() + " "
    parsed += data[400:402].hex() + " "
    parsed += data[411:414].hex() + " "
    parsed += data[420:422].hex() + " "
    parsed += data[428:430].hex() + " "
    parsed += data[437:438].hex() + " "
    parsed += data[464:466].hex() + " "
    parsed += data[475:478].hex() + " "
    parsed += data[504:506].hex() + " "
    parsed += data[515:518].hex() + " "
    parsed += data[544:546].hex() + " "
    parsed += data[555:558].hex() + " "
    parsed += data[564:566].hex() + " "
    parsed += data[572:574].hex() + " "
    return parsed


def find_constant_elements(all_packets):
    # start by assuming all bytes are the same, then mark changed ones as we read packets
    constant_bytes = all_packets[0]
    packet_length = len(all_packets[0])
    constant_byte_mask = list(range(packet_length))

    for p in all_packets:
        assert len(p) == packet_length, "Packet has length %d but expected %d from first packet" % (len(p), packet_length)
        constant_byte_mask = [x for x in constant_byte_mask if p[x] == constant_bytes[x]]

    print(f"The following {len(constant_byte_mask)} bytes are constant across all packages:")
    print("Position Content")
    for start, end in group_ranges(constant_byte_mask):
        if start == end:
            print(f"{start:8d} {constant_bytes[start].hex()}")
        else:
            print(f"{start:4d}-{end:3d} {constant_bytes[start:end+1].hex()}")

    print(f"Print/parse the {len(constant_byte_mask)} changing bytes like so:")
    changing_bytes = [x for x in range(packet_length) if x not in constant_byte_mask]
    for start, end in group_ranges(changing_bytes):
            print(f'parsed += data[{start}:{end+1}].hex() + " "')



def group_ranges(sorted_list):
    # e.g. 1,2,4,6,7,8 -> [(1,2), (4,4), (6,8)]
    ranges = []
    idx = 0
    while idx+1 < len(sorted_list):
        start = sorted_list[idx]

        while idx+1 < len(sorted_list) and sorted_list[idx+1] == sorted_list[idx]+1:
            idx += 1
        
        ranges.append((start, sorted_list[idx]))
        idx += 1

    return ranges


def main(path):
    print(f"Parsing {path}...")
    
    all_packets = []

    with open(path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)

            # find udp packets
            if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.udp.UDP):
                raw, parsed = parse_sma_packet(eth.data)
                if parsed:
                    all_packets.append(raw)
                    print(f"{datetime.utcfromtimestamp(ts)}: {parsed}")

    print(f"Found {len(all_packets)} packets")
    find_constant_elements(all_packets)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} pcap_file")
        sys.exit(1)
    
    main(sys.argv[1])
