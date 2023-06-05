Trying to make sense of the speedwire messages sent between the SMA Home Manager 2.0 and the SMA EV Charger 22.

See also https://github.com/RalfOGit/libspeedwire/blob/main/include/SpeedwireHeader.hpp for 0x6069 (emeter) and 0x6065 (inverter) protocol messages.

```
pip3 install -r requirements.txt
python3 parse.py 2023-06-03-capture-idle.cap out.csv
```

The Home Manager sends Speedwire messages to the EV Charger once a second.
Each message contains in order:
- The protocol ID `0x6081`
- some unknown data, which could be the meter number
- uptime in milliseconds
- 60 dynamic data values of either 4 or 8 byte length. 4 byte length seems to indicate instantaneous measurement and 8 byte length a cumulative value.
- what appears to be an end marker
