# Connection monitor

A single PowerShell script that shows what your Windows PC is talking to on the network, live, in your browser.

- Maps every TCP connection to the app that owns it (including the Windows services inside `svchost`)
- Marks each connection **inbound or outbound**, and **internet or local network**
- Lists ports that are open to incoming connections, and whether other devices can reach them
- Flags **risky** items in red, with a hover tooltip explaining the problem and how to fix it
- Hover over any app name to see whether it's **built into Windows**, what it does, its risks, where the file lives, who signed it, and links to look it up
- Logs every new connection to a daily CSV file

No installs needed: it uses only what ships with Windows.

## Run it

Open PowerShell **as Administrator** (it works without, but some app details are hidden), go to this folder and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\NetMonitor.ps1
```

The dashboard opens in your browser and refreshes every 3 seconds. Press Ctrl+C in the PowerShell window to stop.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `-IntervalSeconds` | 3 | How often to refresh |
| `-OutDir` | `.\NetMonitorOutput` | Where the dashboard, data and CSV logs go |
| `-ClosedRetentionMinutes` | 10 | How long closed connections stay visible |
| `-NoBrowser` | off | Don't open the browser automatically |
| `-Once` | off | Take one snapshot and exit |

## What gets flagged

**Red (risky):**
- An internet computer connecting *into* an app
- An app running from Temp, Downloads, the Recycle Bin or the Public folder
- A broken digital signature (file may be tampered with)
- A Windows system name (svchost, lsass…) running from outside `C:\Windows`
- Connections to ports used by hacking tools, backdoors, botnets or Tor
- Remote Desktop, VNC or Telnet open to the network

**Amber (worth checking):**
- Apps not signed by a known publisher
- Windows scripting tools (PowerShell, cmd, mshta…) using the network
- SSH or FTP servers
- File sharing on a public network

These are simple heuristics, not antivirus. If something you don't recognise is flagged, run a full scan in Windows Security (Virus & threat protection > Scan options > Full scan).

## Limitations

- Shows connections, not how much data each app sends (Windows doesn't expose per-app byte counts without extra tooling). The header shows total download/upload speed.
- UDP traffic is listed under open ports only, since UDP has no connections to track.
- Very short-lived connections that open and close between refreshes can be missed.
