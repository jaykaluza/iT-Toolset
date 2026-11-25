# Notes for Claude

Rules for working on the Nesiam.com tools in this repo. They hold on any computer.

## Commits, PRs and releases
- Never add Claude attribution: no "Co-Authored-By: Claude", no "Generated with Claude Code", no Claude mention in commits, PR descriptions, release notes or files. Use plain messages.
- Never commit or push before the user says so.
- Release pattern: create the GitHub release before pushing main (the website download link points to `/releases/latest/download/<exe>`). Release notes give the exe fingerprint and the `SHA256SUMS.txt` fingerprint. Regenerate the tool's `SHA256SUMS.txt` at release.
- Never alter old tags/releases (web-v1.0/1.1, v1.0/1.1, py-v1.0/1.1). Claude can't force-push tags; give the user the command instead.
- Release notes link to the guide on `blob/main`.

## Naming (every tool, current and future)
- Tools are named "My X" (My Connections, My Network, My Disk, My Security), published by Nesiam.com.
- Each exe's version info must have CompanyName `Nesiam.com`, ProductName `My <Thing>` and the file name `My<Thing>.exe`. My Security (`is_nesiam_product` in `SecurityMonitorPy/scans_win.py`) and My Connections (`is_nesiam_app` in `ConnectionMonitorPy/NetMonitor.py`) use this to never alert on Nesiam apps, so a new tool's `build_exe.py` must keep the pattern.
- Each module works standalone; if another module is already installed, it joins that one's tools (one combined app, not separate windows).
- My Connections (web-v1.x) is finished. Don't propose changes to it unless asked.

## Look
- Logo: `docs/logo.png`, lowercase white `nesiam.com` on black #161617 with three 3D balls (blue dot of the i, green dot before com, red behind the right leg of the n). It's defined by the `header h1` CSS in `docs/index.html`. Don't restyle it unasked.
- Style: light grey #f5f5f7 page, white cards, black #161617 header, pill buttons, Stanford red #8c1515 for Block and RUN buttons.
- Screenshots and demo data must never show real PC details: use made-up data (`--demo`), PC name "Temp-PC", user "you".

## Website (`docs/`, served at nesiam.com via GitHub Pages)
- The landing page must fit one screen without scrolling (hide parts in short windows instead). Check 1280x720, 1280x560 and 376x560.
- RUN buttons: `openLink()` follows the `myconnections://` link in a throwaway tab (`window.open(link, '_blank')`, closed after `LAUNCH_WAIT_MS`). Don't switch to `location.href` or an iframe as the main way; Opera closes the landing tab. If RUN doesn't start the app, check that the registered link's exe still exists.
- Sign-in is a passwordless email code via the Cloudflare Worker in `AuthWorker/`. Secrets live only in Cloudflare (`wrangler secret put`), never in the repo or chat. Sign-in only controls what the page shows; the tools are public downloads.
- Privacy wording: say "scan results stay on your PC", not "nothing is sent outside" (some tools look up the public IP or download threat lists).
- Ask before any DNS or hosting change.

## Building
- Rebuild an exe with `py build_exe.py` only when that app isn't running (a running copy locks `dist/`).
- Don't use `explorer.exe <url>` (opens Documents) or a desktop-COM ShellExecute script (Defender blocks it) to open the browser.
- `ConnectionMonitorMac/` (My Connections for Mac 0.1) has never run on a real Mac. Don't release or build on it until the user reports back.
