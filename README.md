# IT toolset

Handy tools that every admin/user should have access to. Small and dependency-free: they use only what ships with Windows (the Python version needs Python itself, nothing more).

| Tool | Folder | What it does |
| --- | --- | --- |
| [Connection monitor](ConnectionMonitor/README.md) | `ConnectionMonitor` | Live dashboard of every network connection, mapped to the app behind it, with risky items flagged in red |
| [Connection monitor (Python)](ConnectionMonitorPy/README.md) | `ConnectionMonitorPy` | The same dashboard rewritten in Python (standard library only, needs Python installed) |

Each tool lives in its own folder and is developed and released independently.

**Website demo (proof of concept):** [jaykaluza.github.io/iT-Toolset](https://jaykaluza.github.io/iT-Toolset/) shows how a website could start the monitor with a RUN button. Its source is in `docs/`.

## Versions

Each tool has its own version numbers and releases on the [Releases](../../releases) page:

| Tool | Release tags |
| --- | --- |
| Connection monitor (PowerShell) | `ps-v1.2`, `ps-v1.3`, … (earlier releases: `v1.0`, `v1.1`) |
| Connection monitor (Python) | `py-v1.0`, `py-v1.1`, … |

A release's notes give the master fingerprint for that tool.

## Verify your download

Every tool folder has its own `SHA256SUMS.txt` listing the SHA-256 fingerprint of each file in that folder. If even one byte of a file changes, its fingerprint changes completely.

Open PowerShell **in the folder of the tool you want to check** (for example `ConnectionMonitor`), then:

**Step 1: check that the fingerprint list is genuine.**

```powershell
Get-FileHash .\SHA256SUMS.txt -Algorithm SHA256
```

Compare the result with the master fingerprint in that tool's release notes, or one the author gave you directly. If they don't match, don't use the files.

**Step 2: check every file against the list:**

```powershell
Get-Content .\SHA256SUMS.txt | ForEach-Object {
  $hash, $file = $_ -split '\s+', 2
  $ok = (Test-Path $file) -and (Get-FileHash $file -Algorithm SHA256).Hash -eq $hash
  '{0}  {1}' -f $(if ($ok) { 'OK      ' } else { 'MISMATCH' }), $file
}
```

Every line should say `OK`. Any `MISMATCH` means that file differs from the published version.

These commands use only PowerShell's built-in `Get-FileHash`, so there's no extra script to trust. On macOS or Linux, `sha256sum -c SHA256SUMS.txt` does the same check.

Why step 1 matters: someone who could change a tool could also change its `SHA256SUMS.txt` in the same download. The fingerprint published separately is what ties the list to the author.

Releases `v1.0` and `v1.1` predate per-tool fingerprints: for those, the single `SHA256SUMS.txt` is in the top folder and the steps are run from there.
