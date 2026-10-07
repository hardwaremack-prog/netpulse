# NetPulse

A hybrid network monitor: a live **up/down board** for a list of IPs, plus a **PingPlotter-style plotter** with latency graphs and hop-by-hop route tracing.

![Monitor mode](NetPulse%20-%20screenshot.png)
![Plotter mode](NetPulse%20-%20plotter%20screenshot.png)

## Features
- **Import IP lists from Excel** (.xlsx), CSV, or pasted text. The IP/Host, Name and Group columns are detected automatically, each sheet becomes a group, and ranges like `10.0.0.1-50` or `10.0.0.0/24` are expanded
- **Monitor mode:** Up / Down / Degraded / Total counts, a live table with sparklines, an up/down event log, an alert beep, and CSV export
- **Plotter mode:** stacked latency-over-time graphs for every target, a detailed graph per target, traceroute with per-hop Avg/Min/Max/Jitter/PL%, packet-loss markers, and time windows from 1 min to 6 h
- **TCP port pings** (`192.168.1.10:80`, or a Port column): checks a service even when ICMP is blocked
- **PingInfoView-style columns** (pick them from the Columns menu): succeeded/failed counts, failed %, fails in a row, most failed in a row, last succeeded/failed, TTL, reply IP, MAC address, min/max/jitter
- **Alert commands**: runs your own command or script when a device goes down or comes back up, with `{name} {addr} {ip} {status} {time}` fill-ins
- **Sounds**: a beep on down and a chime on recovery
- **Reports**: export to CSV, HTML, XML or tab-separated text, copy to the clipboard, or auto-save every N minutes
- **Collapsible groups** in the table
- **Command line**: `--load`, `--add`, and `--report status.html --rounds 3` for headless checks (Task Scheduler/cron)
- Packet size and Don't fragment options
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
Add `--lan` to open it from other devices on your network. Alert commands and the report folder can only be changed from the computer running NetPulse.

```
python netpulse.py --help
python netpulse.py --load hosts.xlsx --report status.html --rounds 3
```

See `README.txt` for the full guide. `sample-ip-list.xlsx` shows the import layout.
