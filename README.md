# NetPulse

A hybrid network monitor: a live **up/down board** for a list of IPs, plus a **PingPlotter-style plotter** with latency graphs and hop-by-hop route tracing.

![Monitor mode](NetPulse%20-%20screenshot.png)
![Plotter mode](NetPulse%20-%20plotter%20screenshot.png)

## Features
- **Import IP lists from Excel** (.xlsx), CSV, or pasted text. The IP/Host, Name and Group columns are detected automatically, each sheet becomes a group, and ranges like `10.0.0.1-50` or `10.0.0.0/24` are expanded
- **Monitor mode:** Up / Down / Degraded / Total counts, a live table with sparklines, an up/down event log, an alert beep, and CSV export
- **Plotter mode:** stacked latency-over-time graphs for every target, a detailed graph per target, traceroute with per-hop Avg/Min/Max/Jitter/PL%, packet-loss markers, and time windows from 1 min to 6 h
- Adjustable ping interval, timeout, down threshold, and slow/loss limits
- Your list and settings are saved between runs

## Run it
Requires **Python 3.8+**. No other packages are needed.

| System | How |
|---|---|
| Windows | Double-click `Start NetPulse (Windows).bat` |
| Mac | Double-click `Start NetPulse (Mac).command` |
| Linux / Raspberry Pi | `./start-netpulse.sh` |

The dashboard opens at http://127.0.0.1:8765.
Add `--lan` to open it from other devices on your network.

See `README.txt` for the full guide. `sample-ip-list.xlsx` shows the import layout.
