# Connection monitor (Python version)

**New here? Start with the [quick guide](GUIDE.md)** (with screenshots).

The same live dashboard as the [PowerShell Connection monitor](../ConnectionMonitor/README.md), rewritten in Python. It looks and works the same: connections mapped to apps, risky items in red with fix-it tooltips, app details on hover, listening ports, and the **End process** button.

Pick whichever suits you:

| | PowerShell version | Python version |
| --- | --- | --- |
| Needs installing | Nothing | Python 3.9 or newer |
| Extra libraries | None | None (standard library only) |
| Start command | `powershell -ExecutionPolicy Bypass -File .\NetMonitor.ps1` | `py NetMonitor.py` |

## Easiest: the double-click app

**NetMonitor.exe** is this Python version packaged as a single app: nothing to install, not even Python. Download it from the Python release on the [Releases](../../releases) page.

1. Check its fingerprint first (see the release notes): in PowerShell, `Get-FileHash .\NetMonitor.exe -Algorithm SHA256`.
2. Double-click **NetMonitor.exe** and click **Yes** when Windows asks to allow it to make changes (it needs administrator rights to see every app and to end programs).
3. The dashboard opens in your browser.

The app isn't digitally signed, so the first time you run it Windows may show **"Windows protected your PC"**: click **More info**, check the publisher reads *Unknown publisher* and the file name is NetMonitor.exe, then click **Run anyway**.

There's no window to close: use the **Stop monitor** button on the dashboard, or just close the dashboard tab and the app stops itself after 3 minutes. Double-clicking it again while it's running simply reopens the dashboard. Logs are kept in `%LOCALAPPDATA%\MyNetworkMonitor`.

To build the app yourself from this folder: `py -m pip install pyinstaller`, then `py build_exe.py`. The result is `dist\NetMonitor.exe`.

## Install Python (once)

You need Python 3.9 or newer. No `pip install` is needed. Pick whichever option works on your PC.

**Option A: winget (quickest).** In PowerShell:

```powershell
winget install Python.Python.3.13
```

**Option B: installer from python.org (if winget isn't available or fails).**

1. Go to [python.org/downloads/windows](https://www.python.org/downloads/windows/) and click the latest **Python 3** release, then **Windows installer (64-bit)**.
2. Run the downloaded `python-3.x.x-amd64.exe`.
3. On the first screen, tick **Add python.exe to PATH** and leave **Use admin privileges when installing py.exe** as it is (untick it if you don't have admin rights).
4. Click **Install Now**. It installs for your user account only, so it works without administrator rights.

**Option C: Microsoft Store (if downloads from websites are blocked).**

1. Open the **Microsoft Store** app and search for **Python 3.13**. Pick the one published by **Python Software Foundation**.
2. Click **Get**.

With the Store version, use `python` instead of `py` in the commands below (for example `python NetMonitor.py`).

**Check it worked.** Open a **new** PowerShell window and run:

```powershell
py --version
```

It should print something like `Python 3.13.x`. If you get an error, try `python --version` instead. If typing `python` opens the Microsoft Store, Python isn't installed yet: that's a placeholder built into Windows, so use one of the options above.

## Run it

Open PowerShell **as Administrator** (it works without, but some app details are hidden and elevated programs can't be ended), go to this folder and run:

```powershell
py NetMonitor.py
```

The dashboard opens at `http://localhost:8765` and refreshes every 3 seconds. The first refresh takes 10 to 20 seconds while each program's digital signature is checked; after that it's quick. Keep the window open while you use it, and press **Ctrl+C** there to stop.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--interval` | 3 | Seconds between refreshes |
| `--outdir` | `.\NetMonitorOutput` | Where logs go |
| `--closed-retention` | 10 | Minutes closed connections stay visible |
| `--no-browser` | off | Don't open the browser automatically |
| `--once` | off | Take one snapshot (saved as `data.json`) and exit |
| `--port` | 8765 | Local port for the dashboard (the next free one is used if it's taken) |

## Start it from a web page (RUN button)

When NetMonitor.exe runs, it registers a `netmonitor://` link for the signed-in Windows user (no administrator rights needed for that part). After that, any web page with a RUN button pointing to `netmonitor://run` starts the app: the browser asks to open it, Windows asks for administrator rights as usual, and the dashboard opens. The link can only start the app; anything else in it is rejected.

- Try it on the [demo page](https://jaykaluza.github.io/iT-Toolset/) (proof of concept, demo sign-in only).
- Remove the link with the **"click here"** line in the demo page's setup steps (it sends `netmonitor://unregister`, the only other action a link can trigger) or `NetMonitor.exe --unregister-link`; add it again by starting the app, or with `NetMonitor.exe --register-link`.
- The demo page remembers, per browser, whether this PC has been set up: if not, RUN shows the setup steps instead of trying to start the app.

## Blocking apps

Select a row and click **Block app** to cut a program off from the network: NetMonitor adds two Windows Firewall rules (incoming and outgoing) for that program's file and closes the program, so connections it already had open end too. You always get a confirmation prompt first. If you start the program again, it stays blocked.

Blocked apps get a red **Blocked by you** tag and are listed under **Apps you blocked** in the Blocked tab, each with an **Unblock** button (or select the app and click **Unblock app**).

- The rules are named `NetMonitor block: <app>` and kept in their own **NetMonitor** group in Windows Defender Firewall, so you can also see or remove them there. Unblock only ever removes NetMonitor's own rules.
- Core Windows processes, Microsoft Defender and programs shared by many apps (PowerShell, Edge WebView2, dllhost and similar) can't be blocked, since that would cut off much more than one app.
- Blocking needs administrator rights (the app has them).
- Each blocked attempt in the Blocked tab shows the **Firewall rule** that stopped it (normally your NetMonitor rule; anything else means another rule or security product did the blocking).

## Activity log

Every **Block app**, **Unblock** and **End process** is written to `activity-log.txt` **next to NetMonitor.exe** (or next to NetMonitor.py when run as a script), one line each, with the time, app, process IDs, file location, the firewall rules added or removed, and the result. It keeps the last 10 days; older lines are removed automatically. The **Activity log** button at the top of the dashboard opens it in your text editor. If that folder can't be written to, the log goes to `%LOCALAPPDATA%\MyNetworkMonitor\NetMonitorOutput` instead.

```
2026-10-29 18:02:41  BLOCKED    iCloudHome (PID 10532)  C:\...\iCloudHome.exe  Blocked iCloudHome with Windows Firewall rules 'NetMonitor block: iCloudHome (outbound)' and ...
2026-10-29 18:02:46  ENDED      iCloudHome (PID 10532)  C:\...\iCloudHome.exe  Closed iCloudHome.
2026-10-29 18:05:12  UNBLOCKED  iCloudHome  C:\...\iCloudHome.exe  Unblocked iCloudHome: removed Windows Firewall rules ...
```

## Blocked connections

Below **Apps you blocked**, the **Blocked** tab lists each blocked app's attempts to connect in the last hour, grouped by address, with how many times Windows Firewall stopped each one. Connections the firewall blocks for other reasons aren't listed. It reads them from the Windows Security log, which needs administrator rights (the app has them).

Windows doesn't record blocked connections by default. The easiest way to turn recording on is the **Turn on recording** button in the Blocked tab (it asks you to confirm first); once it's on, a **Turn off recording** button appears there too. Or run this once in PowerShell **as Administrator**:

```powershell
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /failure:enable
```

and to turn it off again:

```powershell
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /failure:disable
```

A busy PC can record many blocks, and the Security log has a size limit, so older security records (such as sign-in history) are replaced sooner while recording is on.

## How it works

- Connections, processes, file locations and network counters are read straight from Windows using Python's built-in `ctypes`.
- Windows' built-in PowerShell is used only for three things Python can't read on its own: digital signatures, service details and the DNS cache. Data is passed to it as data, never as code.
- `dashboard.html` is the page served to your browser; it must stay next to `NetMonitor.py`.

Ending programs, risk flags and limitations are the same as the PowerShell version; see its [README](../ConnectionMonitor/README.md).
