NetPulse - network monitor
==========================

START IT
  Windows : double-click "Start NetPulse (Windows).bat"
  Mac     : double-click "Start NetPulse (Mac).command"  (first time: right-click > Open)
  Linux / Raspberry Pi : ./start-netpulse.sh
  Your browser opens the dashboard. Keep the black window open while monitoring.
  Needs Python 3 (free from python.org). Nothing else to install.

LOAD YOUR IPs
  Click "Import Excel" and drop in an .xlsx or .csv file.
  - It finds the IP/Host column by itself. Name and Group/Location columns are optional.
  - Each sheet in the workbook becomes its own group.
  - Ranges work too: 192.168.1.1-50  or  192.168.1.0/24
  - Or paste IPs, or type one in the box at the top and press Enter.
  Try sample-ip-list.xlsx to see the layout.

MONITOR MODE
  Up / Down / Degraded counts at the top (click a card to filter).
  Degraded = answering but slow or dropping pings (limits in the gear menu).
  Right side logs every time something goes down or comes back. A beep plays on a new outage.
  Export CSV saves a status report.

PLOTTER MODE
  "All targets" = stacked latency graphs for every device.
  Click a device for the full graph, then "Trace route" to see every hop between you
  and it, each with its own stats. Click a hop to graph that hop.
  Red bars = lost pings. Hover the graph for details. Use the Window buttons (1m ... 6h, All).

EXTRAS
  python netpulse.py --lan        open the dashboard from other PCs/phones on your network
  python netpulse.py --port 9000  use a different port
  Your list and settings are saved in netpulse_data.json next to the app.
  History is kept in memory while the app is running (up to 6-12 hours per device).
