Trying to make sense of the speedwire messages sent between the SMA Home Manager 2.0 and the SMA EV Charger 22.

See also https://github.com/RalfOGit/libspeedwire/blob/main/include/SpeedwireHeader.hpp for 0x6069 (emeter) and 0x6065 (inverter) protocol messages.

```
pip3 install -r requirements.txt
python3 parse.py 2023-06-03-capture-idle.cap out.csv
```

The Home Manager sends Speedwire messages to the EV Charger once a second.
Each message contains in order:
- The protocol ID `0x6081`
- `0x0003` followed by the meter id, itself formed of a hex value and then numeric serial number
- uptime in milliseconds
- 60 data channels containing data values of either 4 or 8 byte length. Instantaneous measurements are of length 4 bytes, cumulative measurements are 8 bytes. 
- what appears to be an end marker

Each channel looks like `0x0001 0400 xxxx xxxx` where the first 2 bytes appear to indicate the channel, followed by the data length and a zero byte. After that the actual data follows.

The channels were experimentally determined to be:
```
1: power-drawn-tenths-watt
2: grid-feed-in-tenths-watt
3: negative-reactive-power-grid-feed-var
4: reactive-power-grid-feed-var
9: negative-apparent-power-tenths-VA
10: apparent-power-tenths-VA
13: power-factor
14: grid-frequency-Hz

21: power-drawn-L1-tenths-watt
22: power-grid-feeding-L1-tenth-watts
23: negative-reactive-power-grid-feed-L1-var
24: reactive-power-grid-feed-L1-var
29: negative-apparent-power-L1-tenths-VA
30: apparent-power-L1-tenths-VA
31: grid-current-phase-L1-mA
32: grid-voltage-phase-L1-mV
33: power-factor-L1

21: power-drawn-L2-tenths-watt
42: power-grid-feeding-L2-tenth-watts
43: negative-reactive-power-grid-feed-L2-var
44: reactive-power-grid-feed-L2-var
49: negative-apparent-power-L2-tenths-VA
50: apparent-power-L2-tenths-VA
51: grid-current-phase-L2-mA
52: grid-voltage-phase-L2-mV
53: power-factor-L2

21: power-drawn-L3-tenths-watt
62: power-grid-feeding-L3-tenth-watts
63: negative-reactive-power-grid-feed-L3-var
64: reactive-power-grid-feed-L3-var
69: negative-apparent-power-L3-tenths-VA
70: apparent-power-L3-tenths-VA
71: grid-current-phase-L3-mA
72: grid-voltage-phase-L3-mV
73: power-factor-L3
```
