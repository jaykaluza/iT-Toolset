# IT toolset

Handy tools that every admin/user should have access to. Small and dependency-free: they use only what ships with Windows.

| Tool | What it does |
| --- | --- |
| [Connection monitor](ConnectionMonitor/README.md) | Live dashboard of every network connection, mapped to the app behind it, with risky items flagged in red |

## Verify your download

Every file's SHA-256 fingerprint is listed in [`SHA256SUMS.txt`](SHA256SUMS.txt). If even one byte of a file changes, its fingerprint changes completely.

**Step 1: check that the fingerprint list is genuine.** Run this in PowerShell from the toolset folder:

```powershell
Get-FileHash .\SHA256SUMS.txt -Algorithm SHA256
```

Compare the result with the fingerprint published in this repository's
[Releases](../../releases) page, or one the author gave you directly. If they don't match, don't use the files.

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

Why step 1 matters: someone who could change a tool could also change `SHA256SUMS.txt` in the same download. The fingerprint published separately is what ties the list to the author.
