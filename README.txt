NetPulse - network monitor
==========================

START IT
  Windows : double-click "Start NetPulse (Windows).bat" (or the NetPulse icon)
  Mac     : double-click "Start NetPulse (Mac).command"  (first time: right-click > Open)
  Linux / Raspberry Pi : ./start-netpulse.sh
  Your browser opens the dashboard. Keep the black window open while monitoring.
  Needs Python 3 (free from python.org). Nothing else to install.

LOAD YOUR IPs
  Click "Import Excel" and drop in an .xlsx or .csv file.
  - It finds the IP/Host column by itself. Name, Group and Port columns are optional.
  - Each sheet in the workbook becomes its own group.
  - Ranges work too: 192.168.1.1-50  or  192.168.1.0/24
  - Or paste IPs, or type one in the box at the top and press Enter.
  Try sample-ip-list.xlsx to see the layout.

TCP PORT PINGS
  Add :port to check a service instead of a normal ping, for example
     192.168.1.10:80     printer web page
     nas.local:445       file sharing
     example.com:443     a website
  This works even when a device ignores normal pings. "Port closed" means the
  device answered but nothing is listening on that port.

MONITOR MODE
  Up / Down / Degraded counts at the top (click a card to show only those).
  Degraded = answering but slow or dropping pings (limits in the gear menu).
  Columns button: add Succeeded / Failed counts, Fails in a row, Most in a row,
    Last succeeded / Last failed, TTL, Reply from, MAC address, Min / Max / Jitter.
  Groups button: shows devices under collapsible group headings.
  Right side logs every time something goes down or comes back.
  Export: CSV, HTML report, XML, text, or copy the table to paste into Excel.

PLOTTER MODE
  "All targets" = stacked latency graphs for every device.
  Click a device for the full graph, then "Trace route" to see every hop between you
  and it, each with its own stats. Click a hop to graph that hop.
  Red bars = lost pings. Hover the graph for details. Use the Window buttons (1m ... 6h, All).

SETTINGS (gear button)
  - Ping interval, timeout, packet size and Don't fragment
  - How many misses in a row mark a device DOWN
  - Beep on DOWN, chime when it comes back UP
  - Run a command when a device goes DOWN or comes back UP. Fill-ins:
      {name} {addr} {ip} {group} {status} {time} {duration}
    Example (Windows):  powershell -c "Add-Content alerts.log '{time} {name} {status}'"
    Use Test to try it. Only the computer running NetPulse can change these.
  - Auto-save a report every few minutes (HTML, CSV, XML or text) into the
    "reports" folder next to netpulse.py, or a folder you choose.
  - Reset all counts and graphs.

COMMAND LINE
  python netpulse.py --help                       every option
  python netpulse.py --load hosts.xlsx            start with this list
  python netpulse.py --load hosts.csv --report status.html --rounds 3
        pings everything 3 times, saves the report and exits (no window).
        Works with .html .csv .xml .txt. Handy for Task Scheduler / cron.
  python netpulse.py --lan                        open the dashboard from other PCs/phones
  Other options: --add FILE  --interval SEC  --timeout MS  --size BYTES  --port N

  Your list and settings are saved in netpulse_data.json next to the app.
  History is kept in memory while the app is running (up to 6-12 hours per device).
