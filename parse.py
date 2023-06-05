#!/usr/bin/env python3

import dpkt
import struct
import sys

from collections import defaultdict
from datetime import datetime
from dpkt.utils import inet_to_str

TAG_0 = b'\x02\xa0'
TAG_END = b'\x00\x00'
TAG_SMA_NET_2 = b'\x00\x10'
GROUP1 = b'\x00\x00\x00\x01'

KNOWN_CHANNELS = {
    1: "power-drawn-tenths-watt",
    2: "grid-feed-in-tenths-watt",
    3: "negative-reactive-power-grid-feed-var",
    4: "reactive-power-grid-feed-var",
    9: "negative-apparent-power-tenths-VA",
    10: "apparent-power-tenths-VA",
    13: "power-factor",
    14: "grid-frequency-Hz",

    21: "power-drawn-L1-tenths-watt",
    22: "power-grid-feeding-L1-tenth-watts",
    23: "negative-reactive-power-grid-feed-L1-var",
    24: "reactive-power-grid-feed-L1-var",
    29: "negative-apparent-power-L1-tenths-VA",
    30: "apparent-power-L1-tenths-VA",
    31: "grid-current-phase-L1-mA",
    32: "grid-voltage-phase-L1-mV",
    33: "power-factor-L1",

    21: "power-drawn-L2-tenths-watt",
    42: "power-grid-feeding-L2-tenth-watts",
    43: "negative-reactive-power-grid-feed-L2-var",
    44: "reactive-power-grid-feed-L2-var",
    49: "negative-apparent-power-L2-tenths-VA",
    50: "apparent-power-L2-tenths-VA",
    51: "grid-current-phase-L2-mA",
    52: "grid-voltage-phase-L2-mV",
    53: "power-factor-L2",

    21: "power-drawn-L3-tenths-watt",
    62: "power-grid-feeding-L3-tenth-watts",
    63: "negative-reactive-power-grid-feed-L3-var",
    64: "reactive-power-grid-feed-L3-var",
    69: "negative-apparent-power-L3-tenths-VA",
    70: "apparent-power-L3-tenths-VA",
    71: "grid-current-phase-L3-mA",
    72: "grid-voltage-phase-L3-mV",
    73: "power-factor-L3",
}

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

    parsed = dict()
    # The packet starts with the protocol ID. 0x6069 is the energy meter, for example.
    # 0x6081 is what we're seeing at the SMA EV Charger.

    protocol_id = data[:2]
    if protocol_id != b'\x60\x81':
        raise UnkownProtocolException("SMA Protocol ID is " + str(protocol_id))

    # Next comes some unknown data, could be meter number? followed by uptime
    # bytes 2 - 3 = 0x0003
    parsed["meter-id"] = f"{data[4:6].hex()}-{int.from_bytes(data[6:10])}"
    parsed["uptime-millis"] = int.from_bytes(data[10:14])
    read = 14

    # Now parse the regular parts of the packet.
    # They are structured like so:
    # 0x0001 0400 xxxx xxxx
    # where the first 2 bytes appear to be the channel number,
    # the next byte is the length of the data, followed by a zero byte.
    # Next comes the actual value.

    reached_end = False
    while not reached_end:
        channel = int.from_bytes(data[read:read+2])
        length = data[read+2]
        assert data[read+3] == 0, "Found non-zero fourth byte at %d: %08x" % (read, int.from_bytes(data[read:read+4]))
        read += 4
        
        name = KNOWN_CHANNELS[channel] if channel in KNOWN_CHANNELS else "unknown"
        if length == 0x08:
            name += "-cumulative"

        parsed[f'{channel:02d}-{name}'] = int.from_bytes(data[read:read+length], signed=True)
        read += length

        reached_end = channel == 0x9000

    # Finally, we encounter this end marker
    # bytes 582-589 = 0x9000 0000 020b 0552

    return parsed


def main(path_pcap, path_csv):
    all_packets = []
    last_ts = 0
    did_write_header = False

    with open(path_pcap, 'rb') as f:
        with open(path_csv, 'w') as csv:
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


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} in.pcap out.csv")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2])
