# My Connections for Mac (test version 0.1)

A live dashboard in your browser that shows every network connection your Mac is making, the app behind each one, which ports are open, and anything that looks risky.

**This first version only looks.** It never blocks, closes or changes anything. Blocking may come in a later version.

## Start it

You need Python 3.9 or newer. To check, open Terminal and run `python3 --version`. If macOS offers to install the developer tools, accept: that installs Python.

1. Copy this folder to your Mac, for example to `Downloads`.
2. In Terminal, run:

```bash
sudo python3 ~/Downloads/ConnectionMonitorMac/MyConnections.py
```

3. Enter your Mac password when asked. The dashboard opens in your browser.
4. To stop it, click **Stop monitor** on the page, or press **Ctrl+C** in Terminal.

Without `sudo` it still works, but macOS only shows your own apps, not system services or other users' apps. With `sudo` it can read more, but it still only reads.

## What's on the page

- **Connections:** every live connection, with app, remote host and address, port and state. Hover over a row for links that check its internet address: who owns it, blacklists, abuse reports, reputation and exposure. Each link sends the address to that site only when you click it.
- **By app:** one row per app, with its connection counts and the hosts it talks to.
- **Listening:** ports open for incoming connections, and whether other devices can reach them.
- **Risk column:** **red** rows need attention and **amber** rows are worth a look. Hover over a coloured row to see why and how to fix it.
- **App details:** hover over an app name to see whether it's built into macOS, who signed it, and where its file lives.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--interval` | 3 | Seconds between refreshes |
| `--port` | 8765 | Local port for the dashboard (the next free one is used if it's taken) |
| `--closed-retention` | 10 | Minutes closed connections stay visible |
| `--outdir` | see below | Where the daily logs go |
| `--no-browser` | off | Don't open the browser automatically |
| `--demo` | off | Show made-up data; works on any computer and reads nothing |

## What it keeps

A daily log of new connections, `connections-YYYYMMDD.csv`, in `~/Library/Application Support/MyConnections`. Everything stays on your Mac; the app sends nothing anywhere. Delete that folder to remove the logs.

## How it works

- It reads macOS's built-in tools: `lsof` for connections, `ps` for apps, `netstat` for speed and `codesign` for who signed each app. Names come from reverse DNS lookups.
- `dashboard.html` is the page served to your browser, and it must stay next to `MyConnections.py`.
- The page is only available on this Mac (`127.0.0.1`), and its data needs a secret key created at each start.

## Good to know

- **Names:** many remote hosts show a raw server name or nothing, because macOS doesn't offer a list of recent lookups the way Windows does.
- **Speed:** download and upload cover real network adapters (Wi-Fi and Ethernet).
- **Checks:** `python3 -m unittest` in this folder checks the parts that read each tool's output. It doesn't need a Mac.
