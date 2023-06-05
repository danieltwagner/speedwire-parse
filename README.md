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
 1: Power Drawn (1/10 Watt)
 2: Grid Feed-in (1/10 Watt)
 3: Reactive Power Grid-Feed (negative values only) (var)
 4: Reactive Power Grid-Feed (positive values only) (var)
 9: Apparent Power (negative values only) (1/10 VA)
10: Apparent Power (positive values only) (1/10 VA)
13: Power Factor (1/1000)
14: Grid Frequency (Hz)

21: Power Drawn Phase L1 (1/10 Watt)
22: Grid Feed-in Phase L1 (1/10 Watt)
23: Reactive Power Grid-Feed Phase L1 (negative values only) (var)
24: Reactive Power Grid-Feed Phase L1 (positive values only) (var)
29: Apparent Power Phase L1 (negative values only) (1/10 VA)
30: Apparent Power Phase L1 (positive values only) (1/10 VA)
31: Grid Current Phase L1 (mA)
32: Grid Voltage Phase L1 (mV)
33: Power Factor Phase L1 (1/1000)

41: Power Drawn Phase L2 (1/10 Watt)
42: Grid Feed-in Phase L2 (1/10 Watt)
43: Reactive Power Grid-Feed Phase L2 (negative values only) (var)
44: Reactive Power Grid-Feed Phase L2 (positive values only) (var)
49: Apparent Power Phase L2 (negative values only) (1/10 VA)
50: Apparent Power Phase L2 (positive values only) (1/10 VA)
51: Grid Current Phase L2 (mA)
52: Grid Voltage Phase L2 (mV)
53: Power Factor Phase L2 (1/1000)

61: Power Drawn Phase L3 (1/10 Watt)
62: Grid Feed-in Phase L3 (1/10 Watt)
63: Reactive Power Grid-Feed Phase L3 (negative values only) (var)
64: Reactive Power Grid-Feed Phase L3 (positive values only) (var)
69: Apparent Power Phase L3 (negative values only) (1/10 VA)
70: Apparent Power Phase L3 (positive values only) (1/10 VA)
71: Grid Current Phase L3 (mA)
72: Grid Voltage Phase L3 (mV)
73: Power Factor Phase L3 (1/1000)
```
