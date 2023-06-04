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
    parsed += str(int.from_bytes(data[10:14])) + ","
    parsed += str(int.from_bytes(data[20:22])) + ","
    parsed += str(int.from_bytes(data[31:34])) + ","
    parsed += str(int.from_bytes(data[39:42])) + ","
    parsed += str(int.from_bytes(data[50:54])) + ","
    parsed += str(int.from_bytes(data[60:62])) + ","
    parsed += str(int.from_bytes(data[70:74])) + ","
    parsed += str(int.from_bytes(data[80:82])) + ","
    parsed += str(int.from_bytes(data[90:94])) + ","
    parsed += str(int.from_bytes(data[100:102])) + ","
    parsed += str(int.from_bytes(data[111:114])) + ","
    parsed += str(int.from_bytes(data[119:122])) + ","
    parsed += str(int.from_bytes(data[130:134])) + ","
    parsed += str(int.from_bytes(data[140:142])) + ","
    parsed += str(int.from_bytes(data[148:150])) + ","
    parsed += str(int.from_bytes(data[156:158])) + ","
    parsed += str(int.from_bytes(data[167:170])) + ","
    parsed += str(int.from_bytes(data[176:178])) + ","
    parsed += str(int.from_bytes(data[186:190])) + ","
    parsed += str(int.from_bytes(data[196:198])) + ","
    parsed += str(int.from_bytes(data[207:210])) + ","
    parsed += str(int.from_bytes(data[216:218])) + ","
    parsed += str(int.from_bytes(data[227:230])) + ","
    parsed += str(int.from_bytes(data[236:238])) + ","
    parsed += str(int.from_bytes(data[246:250])) + ","
    parsed += str(int.from_bytes(data[256:258])) + ","
    parsed += str(int.from_bytes(data[266:270])) + ","
    parsed += str(int.from_bytes(data[276:278])) + ","
    parsed += str(int.from_bytes(data[284:286])) + ","
    parsed += str(int.from_bytes(data[292:294])) + ","
    parsed += str(int.from_bytes(data[300:302])) + ","
    parsed += str(int.from_bytes(data[310:314])) + ","
    parsed += str(int.from_bytes(data[320:322])) + ","
    parsed += str(int.from_bytes(data[330:334])) + ","
    parsed += str(int.from_bytes(data[340:342])) + ","
    parsed += str(int.from_bytes(data[350:354])) + ","
    parsed += str(int.from_bytes(data[360:362])) + ","
    parsed += str(int.from_bytes(data[370:374])) + ","
    parsed += str(int.from_bytes(data[380:382])) + ","
    parsed += str(int.from_bytes(data[390:394])) + ","
    parsed += str(int.from_bytes(data[400:402])) + ","
    parsed += str(int.from_bytes(data[410:414])) + ","
    parsed += str(int.from_bytes(data[420:422])) + ","
    parsed += str(int.from_bytes(data[428:430])) + ","
    parsed += str(int.from_bytes(data[436:438])) + ","
    parsed += str(int.from_bytes(data[444:446])) + ","
    parsed += str(int.from_bytes(data[455:458])) + ","
    parsed += str(int.from_bytes(data[464:466])) + ","
    parsed += str(int.from_bytes(data[474:478])) + ","
    parsed += str(int.from_bytes(data[484:486])) + ","
    parsed += str(int.from_bytes(data[495:498])) + ","
    parsed += str(int.from_bytes(data[504:506])) + ","
    parsed += str(int.from_bytes(data[514:518])) + ","
    parsed += str(int.from_bytes(data[524:526])) + ","
    parsed += str(int.from_bytes(data[534:538])) + ","
    parsed += str(int.from_bytes(data[544:546])) + ","
    parsed += str(int.from_bytes(data[554:558])) + ","
    parsed += str(int.from_bytes(data[564:566])) + ","
    parsed += str(int.from_bytes(data[572:574])) + ","
    parsed += str(int.from_bytes(data[580:582])) + ","
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
            print(f'parsed += str(int.from_bytes([{start}:{end+1}])) + ","')



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


def parse_file(path):
    all_packets = []
    last_ts = 0

    with open(path, 'rb') as f:
        with open('out.csv', 'w') as csv:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)

                # find udp packets
                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.udp.UDP):
                    raw, parsed = parse_sma_packet(eth.data)
                    if parsed:
                        all_packets.append(raw)
                        print(f"{datetime.utcfromtimestamp(ts)}: {parsed}")
                        if ts%60 < last_ts%60:
                            csv.write(f"{datetime.utcfromtimestamp(ts)},{parsed}\n")
                        last_ts = ts

    return all_packets


def main(paths):
    
    all_packets = []

    for path in paths:
        print(f"Parsing {path}...")
        all_packets += parse_file(path)

    print(f"Found {len(all_packets)} packets")
    find_constant_elements(all_packets)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} pcap_file [pcap_file2, ...]")
        sys.exit(1)
    
    main(sys.argv[1:])
