# Microsoft Store listing: My Connections

**Name:** My Connections
**Publisher display name:** Nesiam.com
**Category:** Utilities & tools (or Security)
**Privacy policy URL:** https://nesiam.com/privacy.html  (after the page is published; see note below)

## Short description (up to 100 characters)
See which programs on your PC are talking to the internet, and block the ones you don't trust.

## Description
My Connections shows you, in plain English, every program on your PC that is connected to the internet right now, who it is talking to, and whether it looks safe.

- A live list of connections, with the program name and who made it
- Browser connections are matched to the website they belong to
- Warnings for programs that look unusual or risky
- One click to Block a program (Windows Firewall) or End it
- A log of what you blocked or ended

Everything stays on your PC. There are no accounts, no ads and no tracking, and nothing about your connections is sent to us.

Needs Administrator permission: Windows asks when you open the app, because blocking programs and seeing every connection require it.

Part of the My X tools from Nesiam.com.

## What's new (this version)
First Microsoft Store release.

## Search terms (up to 7)
network monitor, connections, firewall, netstat, block program, internet activity, security

## Notes for certification
IMPORTANT: this app requires Administrator rights, so it does not start until the Windows User Account Control (UAC) prompt is approved. If the prompt is not approved, or cannot be shown to the test account, nothing opens and it can look like a crash at launch. Please approve the prompt ("Yes") when it appears. The test account must be an administrator, or be able to enter an administrator's credentials.

Why: the app reads the network connections of every process (including system ones) and adds Windows Firewall block rules when the user presses Block (restricted capabilities runFullTrust and allowElevation, requireAdministrator).

How to test:
1. Launch My Connections from the Start menu.
2. Approve the Windows UAC prompt.
3. A dashboard opens in the default browser at http://localhost:8765 showing the live list of connections. No sign-in needed.

Privacy: the app sends no data to the publisher. It makes ordinary DNS lookups, and a GitHub version check only when the user hovers over the app's own name. Policy: https://nesiam.com/privacy.html

## Screenshots
Needed (at least 1, 1366x768 or larger PNG). Existing ones in docs/shots can be used if current.
