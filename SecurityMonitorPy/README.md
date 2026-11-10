# My Security

A local security assessment for Windows, part of the Nesiam.com tools. It runs on `127.0.0.1` only. Scans never change the PC. Every change is a button you press and confirm, and most can be undone from the Blocked tab.

## Run it

```bash
py MySecurity.py
```

Without Administrator rights some checks and all system fixes are unavailable. `MySecurity.exe` asks for them by itself.

```bash
py build_exe.py
```

The build writes `dist\MySecurity.exe`.

## What it checks

| Tab | Checks |
|---|---|
| Autopilot | Runs every scan and sorts the results into fix now, this week, and when you have time |
| Ports | Every listening port, with a hover explanation and a Block button |
| Shares, Protocols | Shares and SMB, LLMNR, NetBIOS, old TLS, NTLM, Remote Desktop |
| Accounts | Local admins, hidden accounts, weak admin setup, password rules, powerful groups |
| Services, System | Services and remote-control tools, antivirus, firewall, UAC, BitLocker, proxy, hosts |
| Firewall | Inbound rules that are too open, or point at temporary folders, script tools or missing programs |
| Hacker tricks | Port forwards, sign-in DLLs, admin-prompt bypass keys, hidden startup places, foreign drivers |
| Lateral | Live connections on control ports, remote-admin doors, PsExec traces, SSH keys, remote sign-ins |
| Pentest | Inside: paths to more privileges and what your network can reach. Outside: what the internet can see |
| Malware, Processes, Downloads | Malware signs, live watch of risky processes with end and block, risky downloads with quarantine |
| Apps, Patches, Threats | Outdated apps, apps installed only for this user, missing updates, CISA known-exploited list, attacks in the logs |
| Browsers | Live check of open tabs, and extensions against a published list of malicious ones |
| Events, Health | Event Viewer errors explained; bottlenecks, memory leaks, full or failing disks |

While the app is open, it also warns within a minute if an account gains admin rights or a suspicious new service appears, and the live process watcher recognises lateral-movement and privilege-escalation commands.

## What the pentest does and doesn't do

It only looks. It exploits nothing, attempts no sign-ins, and touches no device other than this PC and the router, where it tries eight common ports. Secrets are counted, never read out or stored.

The outside test finds your public address with ipify and asks Shodan's InternetDB what its internet-wide scans have recorded there. Those records can be some days old, and on a VPN they describe the VPN. A live attack from outside needs a machine outside your network.

## Online services

These receive a request when you scan: CISA (known-exploited list), GitHub (malicious-extension list), ipify (your public address), Shodan InternetDB (your public address). Open-tab checks fetch the site you're on, without cookies.

## Data sources

- Known-exploited vulnerabilities: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- Malicious browser extensions: [MalExt Sentry](https://github.com/toborrm9/malicious_extension_sentry), CC BY 4.0

## Files

- `MySecurity.py`: the app, local web server and live guards
- `scans_win.py`, `scans_deep.py`: the scans, which change nothing
- `fixes_win.py`: everything that changes the PC
- `knowledge.py`: ports, risky services and threat names
- `dashboard.html`: the page
