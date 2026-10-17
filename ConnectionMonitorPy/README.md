# Connection monitor (Python version)

The same live dashboard as the [PowerShell Connection monitor](../ConnectionMonitor/README.md), rewritten in Python. It looks and works the same: connections mapped to apps, risky items in red with fix-it tooltips, app details on hover, listening ports, and the **End process** button.

Pick whichever suits you:

| | PowerShell version | Python version |
| --- | --- | --- |
| Needs installing | Nothing | Python 3.9 or newer |
| Extra libraries | None | None (standard library only) |
| Start command | `powershell -ExecutionPolicy Bypass -File .\NetMonitor.ps1` | `py NetMonitor.py` |

## Install Python (once)

Download it from [python.org](https://www.python.org/downloads/windows/) and run the installer, or in PowerShell:

```powershell
winget install Python.Python.3.13
```

No `pip install` is needed.

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

## How it works

- Connections, processes, file locations and network counters are read straight from Windows using Python's built-in `ctypes`.
- Windows' built-in PowerShell is used only for three things Python can't read on its own: digital signatures, service details and the DNS cache. Data is passed to it as data, never as code.
- `dashboard.html` is the page served to your browser; it must stay next to `NetMonitor.py`.

Ending programs, risk flags and limitations are the same as the PowerShell version; see its [README](../ConnectionMonitor/README.md).
