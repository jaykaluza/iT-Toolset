"""What My Security tells people about ports and risky behaviour. Plain data, no logic beyond look-ups."""

# port: (name, how it works, what can go wrong, what blocking it will break)
PORTS = {
    20: ('FTP data', 'Carries the files of an FTP transfer.', 'Nothing is encrypted, so files can be read on the network.', 'FTP transfers to this PC.'),
    21: ('FTP', 'Old file-transfer service. A client logs in and moves files.', 'User names and passwords travel unencrypted, and FTP servers are constantly probed by bots.', 'Other devices fetching files from this PC by FTP.'),
    22: ('SSH', 'Encrypted remote command line. Someone with a valid login gets a shell on this PC.', 'Password guessing from the network, and a stolen key gives full access.', 'Remote logins and file copies (SCP/SFTP) to this PC.'),
    23: ('Telnet', 'Remote command line from the 1970s.', 'Everything, including the password, is sent as plain text. It should never be on.', 'Nothing you should still be using.'),
    25: ('SMTP', 'Sends email between mail servers.', 'A home PC listening here is unusual. Malware uses it to send spam.', 'A mail server on this PC.'),
    53: ('DNS', 'Turns site names into addresses.', 'An open DNS server can be abused in attacks on others. Malware can use it to redirect sites.', 'Devices that use this PC as their DNS server.'),
    67: ('DHCP server', 'Hands out network addresses.', 'A rogue DHCP server can send every device on the network through an attacker.', 'Devices getting addresses from this PC.'),
    68: ('DHCP client', 'How this PC receives its own network address.', 'Normal and needed.', 'This PC could lose its network connection, so My Security will not block it.'),
    69: ('TFTP', 'Simple file transfer with no login at all.', 'Anyone who can reach it can read or write files.', 'Network boot or firmware tools that use TFTP.'),
    80: ('HTTP', 'Unencrypted web server.', 'Whatever web app is behind it is exposed to your network, unencrypted.', 'Other devices opening the web page this PC serves.'),
    88: ('Kerberos', 'Windows domain sign-in.', 'Normal on a domain controller. Unusual on a workstation.', 'Domain sign-ins if this PC is a domain controller.'),
    110: ('POP3', 'Old mail download protocol.', 'Often unencrypted.', 'A mail server on this PC.'),
    111: ('RPCbind', 'Directory of Unix network services.', 'Reveals what is running, and has been used in amplification attacks.', 'NFS shares on this PC.'),
    123: ('NTP', 'Keeps the clock correct.', 'Low risk as a client. A public NTP server can be abused in amplification attacks.', 'Other devices syncing time from this PC.'),
    135: ('Windows RPC', 'A directory that tells other computers which port each Windows service is on. WMI, DCOM and remote management start here.', 'A classic target. It should never be reachable from the internet, because worms like Blaster spread through it.', 'Remote management of this PC, and some printing and domain features.'),
    137: ('NetBIOS name', 'Old way for Windows PCs to find each other by name.', 'Reveals the PC and user name. It can be tricked into handing over password hashes.', 'Very old devices finding this PC by name.'),
    138: ('NetBIOS datagram', 'Old Windows network browsing.', 'Same as NetBIOS name: leaks information and is rarely needed.', 'Very old devices browsing the network.'),
    139: ('NetBIOS session', 'File sharing the old way, before port 445.', 'Exposes file sharing, with the same attacks as port 445.', 'File sharing with very old devices.'),
    143: ('IMAP', 'Mail access.', 'Often unencrypted.', 'A mail server on this PC.'),
    161: ('SNMP', 'Lets management tools read device information.', 'The default "public" password leaks a detailed picture of the PC.', 'Network monitoring tools.'),
    389: ('LDAP', 'Directory look-ups, as used by Windows domains.', 'Unencrypted, so it exposes account names.', 'Directory services on this PC.'),
    427: ('SLP', 'Service discovery.', 'Used in very large amplification attacks.', 'Printer or service discovery.'),
    443: ('HTTPS', 'Encrypted web server.', 'Depends entirely on the app behind it. Check that you know why this PC is serving web pages.', 'Other devices opening the page this PC serves.'),
    445: ('SMB file sharing', 'Windows file and printer sharing: network drives, shared folders and remote admin.', 'The most attacked Windows port. WannaCry and NotPetya spread through it, and it must never face the internet.', 'Shared folders and network printers on this PC, and remote admin. Reaching shares on other PCs still works.'),
    465: ('SMTPS', 'Encrypted mail sending.', 'Unusual on a PC.', 'A mail server on this PC.'),
    500: ('IKE (VPN)', 'Sets up IPsec VPN tunnels.', 'Low risk. Fine if you use a VPN.', 'IPsec VPN connections.'),
    514: ('Syslog', 'Receives log messages.', 'Unencrypted and unauthenticated.', 'Devices sending logs to this PC.'),
    515: ('LPD printing', 'Old printing service.', 'Rarely needed, and has a history of security bugs.', 'Printing to this PC with LPD.'),
    546: ('DHCPv6 client', 'How this PC receives an IPv6 address.', 'Normal and needed.', 'This PC could lose its IPv6 connection, so My Security will not block it.'),
    554: ('RTSP', 'Video streaming control.', 'Often has no password on cameras and media apps.', 'Video streams from this PC.'),
    623: ('Intel AMT / IPMI', 'Hardware-level remote management, separate from Windows.', 'Serious flaws have been published. It works even when the PC is off.', 'Remote hardware management.'),
    636: ('LDAPS', 'Encrypted directory look-ups.', 'Unusual on a PC that is not a server.', 'Directory services on this PC.'),
    902: ('VMware', 'VMware Workstation or ESXi remote console.', 'Keep VMware updated: it is often targeted by ransomware groups.', 'Remote access to virtual machines.'),
    912: ('VMware', 'VMware authorization service.', 'Keep VMware updated.', 'Remote access to virtual machines.'),
    993: ('IMAPS', 'Encrypted mail access.', 'Unusual on a PC.', 'A mail server on this PC.'),
    995: ('POP3S', 'Encrypted mail download.', 'Unusual on a PC.', 'A mail server on this PC.'),
    1080: ('SOCKS proxy', 'Relays network traffic for other computers.', 'Malware opens proxies so criminals can route attacks through your PC.', 'Whatever proxy software you run on purpose.'),
    1337: ('Backdoor (classic)', 'No standard service uses this. It is a favourite of hacking tools.', 'Treat as a possible backdoor until you know which app opened it.', 'Nothing legitimate in most cases.'),
    1433: ('Microsoft SQL Server', 'Database server.', 'Constantly targeted with password guessing, and databases hold valuable data.', 'Apps on other PCs using this database.'),
    1434: ('SQL Browser', 'Tells clients which SQL Server instances exist.', 'The Slammer worm spread through it.', 'Finding SQL instances by name.'),
    1521: ('Oracle database', 'Database server.', 'A target for password guessing.', 'Apps using this database.'),
    1723: ('PPTP VPN', 'An old VPN.', 'Its encryption is broken. Replace it with a modern VPN.', 'PPTP VPN connections.'),
    1900: ('SSDP / UPnP', 'Lets devices announce themselves on the network: printers, TVs, media players.', 'Reveals device details and has been used in amplification attacks.', 'Automatic discovery of media devices.'),
    2049: ('NFS', 'Unix-style file sharing.', 'Often relies only on the client address for security.', 'NFS shares on this PC.'),
    2179: ('Hyper-V console', 'Remote console for virtual machines.', 'Low risk on a trusted network.', 'Remote console access to virtual machines.'),
    3074: ('Xbox Live', 'Game traffic.', 'Low risk.', 'Online games using this port.'),
    3128: ('HTTP proxy', 'Relays web traffic.', 'An open proxy lets strangers use your connection.', 'Whatever proxy you run on purpose.'),
    3268: ('Global Catalog', 'Windows domain directory.', 'Normal on domain controllers only.', 'Domain look-ups if this is a domain controller.'),
    3306: ('MySQL / MariaDB', 'Database server.', 'A target for password guessing, and should normally listen on this PC only.', 'Apps on other PCs using this database.'),
    3389: ('Remote Desktop', 'Full remote control of this PC with its screen, keyboard and mouse.', 'The top way ransomware gets in. Bots guess passwords on it all day, and it has had critical flaws such as BlueKeep.', 'Remote Desktop connections to this PC.'),
    3702: ('WS-Discovery', 'Finds printers and other devices on the local network.', 'Low risk locally. It has been used in amplification attacks.', 'Automatic discovery of network printers.'),
    4444: ('Backdoor (Metasploit)', 'The default listening port of the Metasploit hacking tool.', 'A strong sign of a backdoor unless you run security tools yourself.', 'Nothing legitimate in most cases.'),
    4500: ('IPsec NAT-T', 'Carries VPN traffic through routers.', 'Low risk.', 'IPsec VPN connections.'),
    4899: ('Radmin', 'Remote-control software.', 'Often abused by attackers once they are inside.', 'Radmin remote control.'),
    5040: ('Connected Devices', 'Windows service that links your PC to phones and other devices.', 'Low risk. It belongs to Windows.', 'Nearby sharing and Phone Link features.'),
    5060: ('SIP', 'Internet phone calls.', 'Probed constantly by toll-fraud bots.', 'Internet phone software.'),
    5353: ('mDNS', 'Finds devices by name on the local network, such as printers and casting.', 'Low risk locally, and it reveals device names.', 'Finding printers and devices by name.'),
    5355: ('LLMNR', 'Windows asks everyone nearby "who is this name?" when DNS fails.', 'An attacker on the same network can answer "me" and capture a password hash.', 'Name look-ups on networks without DNS.'),
    5357: ('WSD HTTP', 'Windows device discovery, mostly for network printers.', 'Low risk on a trusted network.', 'Automatic discovery of network printers.'),
    5358: ('WSD HTTPS', 'Windows device discovery, encrypted.', 'Low risk on a trusted network.', 'Automatic discovery of network printers.'),
    5432: ('PostgreSQL', 'Database server.', 'Should normally listen on this PC only.', 'Apps on other PCs using this database.'),
    5500: ('VNC listener', 'Reverse VNC remote control.', 'A sign of remote-control software.', 'VNC reverse connections.'),
    5800: ('VNC web', 'VNC remote control through a browser.', 'VNC often has weak passwords and no encryption.', 'VNC access through a browser.'),
    5900: ('VNC', 'Remote control of this PC.', 'Often weakly protected, and has been used for silent takeovers.', 'VNC remote control.'),
    5938: ('TeamViewer', 'TeamViewer remote control.', 'Tech-support scammers use it to take over PCs.', 'TeamViewer direct connections.'),
    5985: ('WinRM (HTTP)', 'Lets an administrator run PowerShell on this PC from another computer.', 'A stolen admin password becomes full remote control.', 'Remote PowerShell management.'),
    5986: ('WinRM (HTTPS)', 'Encrypted remote PowerShell.', 'A stolen admin password becomes full remote control.', 'Remote PowerShell management.'),
    6379: ('Redis', 'In-memory database. Often has no password by default.', 'An exposed Redis server can be taken over completely.', 'Apps on other PCs using it.'),
    6666: ('IRC', 'Chat protocol.', 'Botnets use IRC to receive commands.', 'Nothing legitimate in most cases.'),
    6667: ('IRC', 'Chat protocol.', 'Botnets use IRC to receive commands.', 'Nothing legitimate in most cases.'),
    7070: ('AnyDesk / RTSP', 'Used by AnyDesk for direct connections, and by some media apps.', 'Scammers use AnyDesk to take over PCs.', 'AnyDesk direct connections.'),
    7680: ('Delivery Optimization', 'Windows Update shares update pieces with nearby PCs.', 'Low risk. It belongs to Windows.', 'Nothing important: updates still download from Microsoft.'),
    8000: ('Web (development)', 'Commonly a development web server or an app\'s own admin page.', 'Development servers are not hardened, and they should stay on this PC.', 'Other devices using that web app.'),
    8080: ('Web / proxy', 'A web app or proxy.', 'Admin pages often have weak or default passwords.', 'Other devices using that web app.'),
    8443: ('Web (HTTPS)', 'A web app or admin console.', 'Admin consoles are valuable targets.', 'Other devices using that web app.'),
    8888: ('Web (development)', 'Often Jupyter notebooks or a development server.', 'An exposed notebook is remote code execution by design.', 'Other devices using that web app.'),
    9001: ('Tor', 'Tor relay traffic.', 'Unless you run Tor, malware may be hiding its traffic.', 'A Tor relay you run on purpose.'),
    9050: ('Tor SOCKS', 'Local Tor proxy.', 'Unless you run Tor, malware may be hiding its traffic.', 'Tor Browser or similar tools.'),
    9100: ('Raw printing', 'Direct printing to a printer.', 'Unusual on a PC.', 'Printing directly to this PC.'),
    9200: ('Elasticsearch', 'Search database. Older setups have no password.', 'Exposed databases are a very common cause of data leaks.', 'Apps on other PCs using it.'),
    11211: ('Memcached', 'Cache server with no password.', 'Used in record-breaking amplification attacks.', 'Apps on other PCs using it.'),
    12345: ('NetBus trojan', 'No standard service uses this. It is the old NetBus trojan port.', 'Treat as a possible backdoor.', 'Nothing legitimate in most cases.'),
    16992: ('Intel AMT', 'Hardware-level remote management.', 'Serious flaws have been published. Keep the firmware updated.', 'Intel AMT remote management.'),
    16993: ('Intel AMT (TLS)', 'Hardware-level remote management.', 'Serious flaws have been published. Keep the firmware updated.', 'Intel AMT remote management.'),
    27017: ('MongoDB', 'Database server.', 'Exposed MongoDB servers are routinely wiped and ransomed.', 'Apps on other PCs using it.'),
    31337: ('Back Orifice', 'A classic hacker port.', 'Treat as a possible backdoor.', 'Nothing legitimate in most cases.'),
}

BACKDOOR_PORTS = {1337, 4444, 12345, 31337, 6666, 6667}
REMOTE_CONTROL_PORTS = {3389, 5900, 5800, 5500, 4899, 5938, 7070}
NEVER_BLOCK_PORTS = {('UDP', 68), ('UDP', 546)}


def port_info(port, proto='TCP'):
    """(name, how it works, risk, what blocking breaks) for any port number."""
    known = PORTS.get(port)
    if known:
        return known
    if port >= 49152:
        return ('Temporary port', 'Windows hands out ports in this range as needed. Windows services (RPC) and apps use them for their own traffic.',
                'Normally low. What matters is which program owns it, so check the app shown here.', 'Whatever this app uses it for. Often nothing you would notice.')
    if port >= 1024:
        return ('Application port', f'Port {port} is not a standard service. The app shown here chose it for its own use.',
                'Depends on the app. An app you do not recognise listening for connections deserves a look.', 'Whatever this app receives on the port.')
    return ('System port', f'Port {port} is in the range reserved for system services, but it is not one My Security has notes on.',
            'Unknown service. Find out what the app shown here does before leaving it open.', 'Whatever this app receives on the port.')


# Services that are worth turning off unless used on purpose: name -> (severity, plain name, why it matters)
RISKY_SERVICES = {
    'RemoteRegistry': ('high', 'Remote Registry', 'Lets other computers read and change this PC\'s settings database over the network.'),
    'TlntSvr': ('critical', 'Telnet Server', 'Remote login with no encryption.'),
    'SNMP': ('medium', 'SNMP', 'Reveals details about this PC to anyone who knows the community string, which is usually "public".'),
    'ftpsvc': ('high', 'IIS FTP Server', 'An FTP server sends passwords unencrypted.'),
    'W3SVC': ('medium', 'IIS Web Server', 'A web server on this PC is exposed to your network.'),
    'sshd': ('medium', 'OpenSSH Server', 'Accepts remote logins to this PC.'),
    'TermService': ('medium', 'Remote Desktop', 'Accepts remote logins to this PC.'),
    'WinRM': ('medium', 'Windows Remote Management', 'Allows remote PowerShell. A stolen admin password becomes full control.'),
    'RemoteAccess': ('medium', 'Routing and Remote Access', 'Turns this PC into a router or VPN server.'),
    'SSDPSRV': ('low', 'SSDP Discovery', 'Announces and finds UPnP devices on the network.'),
    'upnphost': ('low', 'UPnP Device Host', 'Lets this PC act as a UPnP device.'),
    'Fax': ('low', 'Fax', 'Rarely used, and the fax service has had critical flaws.'),
    'SharedAccess': ('medium', 'Internet Connection Sharing', 'Shares this PC\'s connection with other devices.'),
    'XblGameSave': ('info', 'Xbox Game Save', 'Harmless, but not needed unless you game on Xbox.'),
}

# Remote-control and remote-management tools: normal in IT, and a favourite of scammers and intruders.
REMOTE_TOOLS = {
    'anydesk': 'AnyDesk', 'teamviewer': 'TeamViewer', 'screenconnect': 'ConnectWise ScreenConnect', 'connectwisecontrol': 'ConnectWise ScreenConnect',
    'logmein': 'LogMeIn', 'gotoassist': 'GoTo Assist', 'splashtop': 'Splashtop', 'rustdesk': 'RustDesk', 'ultraviewer': 'UltraViewer',
    'supremo': 'Supremo', 'netsupport': 'NetSupport', 'client32': 'NetSupport', 'atera': 'Atera', 'ninjarmm': 'NinjaOne', 'tightvnc': 'TightVNC',
    'tvnserver': 'TightVNC', 'winvnc': 'VNC', 'uvnc': 'UltraVNC', 'radmin': 'Radmin', 'ammyy': 'Ammyy Admin', 'dwagent': 'DWService', 'meshagent': 'MeshCentral',
    'ngrok': 'ngrok tunnel', 'cloudflared': 'Cloudflare Tunnel', 'frpc': 'frp tunnel', 'plink': 'PuTTY Link tunnel', 'zerotier': 'ZeroTier', 'tailscale': 'Tailscale',
}

# Commercial keyloggers and stalkerware. Names seen as installed programs, processes or services.
SPYWARE_NAMES = {
    'ardamax': 'Ardamax Keylogger', 'refog': 'Refog', 'spyrix': 'Spyrix', 'revealer keylogger': 'Revealer Keylogger', 'actual keylogger': 'Actual Keylogger',
    'perfect keylogger': 'Perfect Keylogger', 'elite keylogger': 'Elite Keylogger', 'kidlogger': 'KidLogger', 'mspy': 'mSpy', 'flexispy': 'FlexiSPY',
    'webwatcher': 'WebWatcher', 'spyagent': 'SpyAgent', 'spector': 'Spector', 'hoverwatch': 'Hoverwatch', 'wolfeye': 'Wolfeye', 'best free keylogger': 'Best Free Keylogger',
    'all in one keylogger': 'All In One Keylogger', 'realtime spy': 'Realtime-Spy', 'iwantsoft': 'iWantSoft Keylogger',
}

LOGIN_BRANDS = {
    'microsoft': ('microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'microsoft365.com', 'outlook.com', 'windows.net', 'sharepoint.com', 'azure.com', 'msn.com', 'bing.com', 'skype.com', 'onedrive.com', 'msauth.net', 'msftauth.net', 'cloud.microsoft'),
    'office': ('microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'microsoft365.com', 'outlook.com', 'sharepoint.com', 'cloud.microsoft', 'officedepot.com', 'libreoffice.org'),
    'outlook': ('microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'microsoft365.com', 'outlook.com', 'cloud.microsoft'),
    'onedrive': ('microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'onedrive.com', 'sharepoint.com', 'cloud.microsoft'),
    'sharepoint': ('microsoft.com', 'microsoftonline.com', 'sharepoint.com', 'office.com', 'cloud.microsoft'),
    'paypal': ('paypal.com',), 'apple': ('apple.com', 'icloud.com'), 'icloud': ('apple.com', 'icloud.com'), 'google': ('google.com', 'gmail.com', 'youtube.com'), 'gmail': ('google.com', 'gmail.com'),
    'amazon': ('amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'aws.amazon.com'), 'facebook': ('facebook.com', 'meta.com'), 'instagram': ('instagram.com', 'facebook.com'),
    'netflix': ('netflix.com',), 'linkedin': ('linkedin.com',), 'dropbox': ('dropbox.com',), 'docusign': ('docusign.com', 'docusign.net'), 'adobe': ('adobe.com',),
    'chase': ('chase.com',), 'wellsfargo': ('wellsfargo.com',), 'bankofamerica': ('bankofamerica.com',), 'coinbase': ('coinbase.com',), 'binance': ('binance.com',), 'github': ('github.com', 'github.io'),
}
# Real site names that phishing domains imitate with one changed letter.
LOOKALIKE_TARGETS = ('microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'outlook.com', 'live.com', 'google.com', 'gmail.com', 'paypal.com', 'apple.com', 'icloud.com',
                     'amazon.com', 'facebook.com', 'instagram.com', 'netflix.com', 'linkedin.com', 'dropbox.com', 'docusign.com', 'adobe.com', 'chase.com', 'wellsfargo.com', 'coinbase.com', 'binance.com', 'github.com')
# Free hosting where anyone can put up a page in minutes. Not bad in itself, but real sign-in pages don't live here.
FREE_HOSTING = ('pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'r2.dev', 'netlify.app', 'vercel.app', 'github.io', 'glitch.me', 'weebly.com', 'wixsite.com', 'webflow.io',
                'blob.core.windows.net', 'web.core.windows.net', 'azurewebsites.net', 'amazonaws.com', 'appspot.com', 'ipfs.io', 'dweb.link', 'herokuapp.com', 'surge.sh', 'replit.dev', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com')
RISKY_TLDS = ('zip', 'mov', 'top', 'xyz', 'click', 'icu', 'rest', 'cfd', 'sbs', 'quest', 'cam', 'lol', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'monster', 'country', 'stream', 'loan', 'work')
# Sites too big and too widely used to be worth fetching a second time for the page check.
TRUSTED_SITES = ('google.com', 'youtube.com', 'microsoft.com', 'microsoftonline.com', 'office.com', 'live.com', 'outlook.com', 'bing.com', 'github.com', 'apple.com', 'amazon.com', 'wikipedia.org', 'anthropic.com', 'claude.ai',
                 'facebook.com', 'instagram.com', 'linkedin.com', 'x.com', 'reddit.com', 'yahoo.com', 'netflix.com', 'zoom.us', 'slack.com', 'dropbox.com', 'cloud.microsoft', 'sharepoint.com', 'gmail.com')
