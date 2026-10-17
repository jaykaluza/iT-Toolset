# Connection monitor

A single PowerShell script that shows what your Windows PC is talking to on the network, live, in your browser.

- Maps every TCP connection to the app that owns it (including the Windows services inside `svchost`)
- Marks each connection **inbound or outbound**, and **internet or local network**
- Lists ports that are open to incoming connections, and whether other devices can reach them
- Flags **risky** items in red, with a hover tooltip explaining the problem and how to fix it
- Hover over any app name to see whether it's **built into Windows**, what it does, its risks, where the file lives, who signed it, and links to look it up
- Click a row and press **End process** to stop a program, with safety checks (see below)
- Logs every new connection to a daily CSV file

No installs needed: it uses only what ships with Windows.

## Run it

Open PowerShell **as Administrator** (it works without, but some app details are hidden), go to this folder and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\NetMonitor.ps1
```

The dashboard opens in your browser at `http://localhost:8765` and refreshes every 3 seconds. Keep the PowerShell window open while you use it, and press Ctrl+C there to stop.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `-IntervalSeconds` | 3 | How often to refresh |
| `-OutDir` | `.\NetMonitorOutput` | Where the dashboard, data and CSV logs go |
| `-ClosedRetentionMinutes` | 10 | How long closed connections stay visible |
| `-NoBrowser` | off | Don't open the browser automatically |
| `-Once` | off | Take one snapshot (saved as `data.json`) and exit |
| `-Port` | 8765 | Local port for the dashboard (the next free one is used if it's taken) |

## Ending a program

Click any row to select its program (click again or press Esc to clear), then click **End process**. You always get a confirmation prompt showing the program's name, PID and file location, and any unsaved work in it is lost.

Safety checks:
- The dashboard is served only to this PC (`localhost`), and every request needs a secret key created fresh each time the script starts, so other websites can't trigger it.
- Only programs currently shown in the dashboard can be ended, and the script checks the PID still belongs to the same program.
- It refuses to end core Windows processes (lsass, csrss, winlogon, svchost and others) and Microsoft Defender, since that would crash Windows or switch off your protection. For svchost, stop the specific service in `services.msc` instead.
- Programs running as Administrator can only be ended when NetMonitor itself runs as Administrator.
- Every attempt is logged to `NetMonitorOutput\ended-processes.csv`.

Ending a program is a quick fix, not a cure: if something suspicious comes back after a restart, uninstall it and run a full Microsoft Defender scan.

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
