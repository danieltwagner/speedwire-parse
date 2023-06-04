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

class UnkownProtocolException(Exception):
    pass

def parse_sma_packet(ip):
    udp = ip.data
    # print(f'{inet_to_str(ip.src)}:{udp.sport} -> {inet_to_str(ip.dst)}:{udp.dport} length {udp.ulen} bytes')

    # ensure the packet has the SMA header
    if udp.data[:4] != b"SMA\x00":
        raise UnkownProtocolException("First 4 UDP package bytes are " + str(udp.data[:4]))
    
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
        raise UnkownProtocolException("SMA Protocol ID is " + str(protocol_id))

    # The changing bytes
    parsed = dict()
    parsed["uptime_millis"] = int.from_bytes(data[10:14])
    
    parsed["column03"] = int.from_bytes(data[20:22])
    parsed["cumulative_column03"] = int.from_bytes(data[31:34])

    parsed["export_tenths_watt"] = int.from_bytes(data[39:42])
    parsed["cumulative_export"] = int.from_bytes(data[50:54])

    parsed["column07"] = int.from_bytes(data[60:62])
    parsed["cumulative_column07"] = int.from_bytes(data[70:74])

    parsed["column09"] = int.from_bytes(data[80:82])
    parsed["cumulative_column09"] = int.from_bytes(data[90:94])

    parsed["column11"] = int.from_bytes(data[100:102])
    parsed["cumulative_column11"] = int.from_bytes(data[111:114])

    parsed["column13"] = int.from_bytes(data[119:122])
    parsed["cumulative_column13"] = int.from_bytes(data[130:134])

    parsed["column15"] = int.from_bytes(data[140:142])
    parsed["column16"] = int.from_bytes(data[148:150])

    parsed["column17"] = int.from_bytes(data[156:158])
    parsed["cumulative_column17"] = int.from_bytes(data[167:170])

    parsed["column19"] = int.from_bytes(data[176:178])
    parsed["cumulative_column19"] = int.from_bytes(data[186:190])

    parsed["column21"] = int.from_bytes(data[196:198])
    parsed["cumulative_column21"] = int.from_bytes(data[207:210])

    parsed["column23"] = int.from_bytes(data[216:218])
    parsed["column24"] = int.from_bytes(data[227:230])

    parsed["column25"] = int.from_bytes(data[236:238])
    parsed["cumulative_column25"] = int.from_bytes(data[246:250])

    parsed["column27"] = int.from_bytes(data[256:258])
    parsed["cumulative_column27"] = int.from_bytes(data[266:270])

    parsed["column29"] = int.from_bytes(data[276:278])
    parsed["column30"] = int.from_bytes(data[284:286])
    parsed["column31"] = int.from_bytes(data[292:294])
    parsed["column32"] = int.from_bytes(data[300:302])
    parsed["column33"] = int.from_bytes(data[310:314])

    parsed["column34"] = int.from_bytes(data[320:322])
    parsed["cumulative_column34"] = int.from_bytes(data[330:334])

    parsed["column36"] = int.from_bytes(data[340:342])
    parsed["cumulative_column36"] = int.from_bytes(data[350:354])

    parsed["column38"] = int.from_bytes(data[360:362])
    parsed["cumulative_column38"] = int.from_bytes(data[370:374])

    parsed["column40"] = int.from_bytes(data[380:382])
    parsed["column41"] = int.from_bytes(data[390:394])

    parsed["column42"] = int.from_bytes(data[400:402])
    parsed["cumulative_column42"] = int.from_bytes(data[410:414])

    parsed["column44"] = int.from_bytes(data[420:422])
    parsed["column45"] = int.from_bytes(data[428:430])
    parsed["column46"] = int.from_bytes(data[436:438])

    parsed["column47"] = int.from_bytes(data[444:446])
    parsed["cumulative_column47"] = int.from_bytes(data[455:458])

    parsed["column49"] = int.from_bytes(data[464:466])
    parsed["cumulative_column49"] = int.from_bytes(data[474:478])

    parsed["column51"] = int.from_bytes(data[484:486])
    parsed["cumulative_column51"] = int.from_bytes(data[495:498])

    parsed["column53"] = int.from_bytes(data[504:506])
    parsed["cumulative_column53"] = int.from_bytes(data[514:518])

    parsed["column55"] = int.from_bytes(data[524:526])
    parsed["cumulative_column55"] = int.from_bytes(data[534:538])

    parsed["column57"] = int.from_bytes(data[544:546])
    parsed["cumulative_column57"] = int.from_bytes(data[554:558])

    parsed["column59"] = int.from_bytes(data[564:566])
    parsed["column60"] = int.from_bytes(data[572:574])
    parsed["column61"] = int.from_bytes(data[580:582])

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
    did_write_header = False

    with open(path, 'rb') as f:
        with open('out.csv', 'w') as csv:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)

                # find udp packets
                if isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.udp.UDP):
                    try:
                        raw, parsed = parse_sma_packet(eth.data)

                        # keep the raw packet data so we can find changing and fixed bytes
                        all_packets.append(raw)

                        # print each packet so we can inspect visually
                        print(f"{datetime.utcfromtimestamp(ts)}: {parsed}")

                        # Export the first datapoint each minute to "out.csv"
                        if not did_write_header:
                            did_write_header = True
                            csv.write("date," + ",".join(sorted(parsed.keys())) + "\n")

                        if ts%60 < last_ts%60:
                            to_write = ""
                            for k in sorted(parsed.keys()):
                                to_write += str(parsed[k]) + ","
                            
                            csv.write(f"{datetime.utcfromtimestamp(ts)},{to_write[:-1]}\n")

                        last_ts = ts

                    except UnkownProtocolException:
                        pass

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
