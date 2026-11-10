r"""
My_network: a live 3D picture of the devices around this PC and the packets moving between them.

Standard library only, no capture driver to install. Windows 10/11.
    py My_network.py                 asks for Administrator rights (packet capture needs them), opens the view
    py My_network.py --no-elevate    no prompt; devices and open connections only, no packets
    py My_network.py --demo          made-up devices and traffic, to try the view

Packets are read with a Windows raw socket, so a capture starts at the IP layer. If Npcap and scapy are installed (the page
offers both), capture moves to them by itself and gains real Ethernet headers and ARP. On a switched network or Wi-Fi a PC
only receives its own traffic plus broadcasts and multicasts; traffic between two other devices never reaches it.
Packet contents stay in memory and are only served to this run's private local page. Nothing is written to disk.
"""

import argparse
import bisect
import collections
import concurrent.futures as cf
import ctypes
import http.client
import http.server
import importlib
import importlib.util
import ipaddress
import json
import os
import random
import re
import secrets
import site
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
import winreg

APP_NAME = 'My_network'
APP_VERSION = '0.1'
HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = getattr(sys, 'frozen', False)       # running as My_network.exe
RESOURCES = getattr(sys, '_MEIPASS', HERE)
WINDIR = os.environ.get('SystemRoot', r'C:\Windows')
APP_DIR = os.path.join(os.environ.get('LOCALAPPDATA', HERE), 'My_network')
SITE_ORIGINS = ('https://nesiam.com', 'https://www.nesiam.com', 'https://jaykaluza.github.io')
LINK_SCHEME = 'mynetwork'
LINK_PATTERN = re.compile(r'^mynetwork:(//)?(run|unregister)?/?$', re.I)
DASHBOARD_URL = re.compile(r'^http://localhost:\d{1,5}/\?k=[\w-]{20,}$')

SNAP = 1600            # bytes kept per packet for the detail view
RING = 24              # packets kept per connection
MAX_FLOWS = 1500       # connections remembered
MAX_DRAW = 400         # connections sent to the view
MAX_EXTERNAL = 60      # internet hosts drawn
FLOW_TTL = 300         # seconds an idle connection is remembered
EVENT_GAP = 0.04       # at most one animated packet per connection in this many seconds
SCAPY_VERSION = '2.8.0'
NPCAP_DLL = os.path.join(WINDIR, 'System32', 'Npcap', 'wpcap.dll')
NPCAP_PAGE = 'https://npcap.com/#download'
ARP = 0x0806           # used as the protocol number of ARP "connections"

PROTO = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP', ARP: 'ARP'}
SERVICES = {20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP server', 68: 'DHCP client',
            69: 'TFTP', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 123: 'NTP', 135: 'RPC', 137: 'NetBIOS name', 138: 'NetBIOS datagram',
            139: 'NetBIOS session', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            500: 'IKE', 514: 'Syslog', 515: 'LPD printing', 546: 'DHCPv6 client', 547: 'DHCPv6 server', 587: 'SMTP submission',
            631: 'IPP printing', 636: 'LDAPS', 853: 'DNS over TLS', 993: 'IMAPS', 995: 'POP3S', 1433: 'SQL Server', 1723: 'PPTP',
            1883: 'MQTT', 1900: 'SSDP', 3306: 'MySQL', 3389: 'Remote Desktop', 4500: 'IPsec NAT', 5040: 'Windows CDP', 5222: 'XMPP',
            5353: 'mDNS', 5355: 'LLMNR', 5432: 'PostgreSQL', 5900: 'VNC', 8008: 'HTTP alt', 8080: 'HTTP alt', 8443: 'HTTPS alt',
            8883: 'MQTT TLS', 9100: 'Raw printing', 32400: 'Plex'}
GROUPS = {'224.0.0.1': 'All hosts', '224.0.0.2': 'All routers', '224.0.0.22': 'IGMP report', '224.0.0.251': 'mDNS',
          '224.0.0.252': 'LLMNR', '239.255.255.250': 'SSDP', '255.255.255.255': 'Broadcast'}
TCP_STATES = {1: 'Closed', 2: 'Listening', 3: 'SYN sent', 4: 'SYN received', 5: 'Established', 6: 'FIN wait 1', 7: 'FIN wait 2',
              8: 'Close wait', 9: 'Closing', 10: 'Last ACK', 11: 'Time wait', 12: 'Deleting'}
ICMP_TYPES = {0: 'Echo reply', 3: 'Destination unreachable', 5: 'Redirect', 8: 'Echo request', 9: 'Router advertisement',
              10: 'Router solicitation', 11: 'Time exceeded', 12: 'Parameter problem', 13: 'Timestamp', 14: 'Timestamp reply'}
DNS_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 47: 'NSEC', 65: 'HTTPS', 255: 'ANY'}
DNS_RCODES = {0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'No such name', 4: 'Not implemented', 5: 'Refused'}
DHCP_TYPES = {1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform'}
TLS_RECORDS = {20: 'Change cipher spec', 21: 'Alert', 22: 'Handshake', 23: 'Application data (encrypted)'}
TLS_HANDSHAKES = {1: 'ClientHello', 2: 'ServerHello', 4: 'New session ticket', 8: 'Encrypted extensions', 11: 'Certificate',
                  12: 'Server key exchange', 13: 'Certificate request', 14: 'Server hello done', 15: 'Certificate verify',
                  16: 'Client key exchange', 20: 'Finished'}
TLS_VERSIONS = {0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'}
DSCP_NAMES = {0: 'Default', 8: 'CS1', 10: 'AF11', 18: 'AF21', 26: 'AF31', 34: 'AF41', 46: 'EF (voice)', 48: 'CS6', 56: 'CS7'}


def clean(text, limit=64):
    """Anything a device or packet calls itself is untrusted: printable characters only, and short."""
    return ''.join(c for c in str(text) if c.isprintable())[:limit]


def service_for(sport, dport):
    return SERVICES.get(dport) or SERVICES.get(sport) or ''


# ---------------------------------------------------------------- explaining a connection in plain words

DATA_TYPES = {20: 'A file transfer (FTP). It is not encrypted.', 21: 'A file transfer login (FTP). Passwords are not encrypted.', 22: 'An encrypted remote login (SSH).',
              23: 'A remote login (Telnet). Nothing is encrypted, including passwords.', 25: 'Email being sent (SMTP).', 53: 'A DNS lookup: asking for the address of a website or service.',
              67: 'A device asking for, or being given, a network address (DHCP).', 68: 'A device asking for, or being given, a network address (DHCP).',
              80: 'Ordinary web traffic (HTTP). It is not encrypted.', 110: 'Email being collected (POP3).', 123: 'A clock check (NTP), keeping the time correct.',
              135: 'Windows asking another PC for a service (RPC).', 137: 'Windows PCs announcing their names (NetBIOS).', 138: 'Windows network announcements (NetBIOS).',
              139: 'Windows file sharing (older NetBIOS form).', 143: 'Email being read (IMAP).', 161: 'Network equipment reporting its status (SNMP).',
              443: 'Encrypted web traffic (HTTPS). The contents cannot be read, only where it is going.', 445: 'Windows file sharing (SMB).', 465: 'Encrypted email being sent.',
              515: 'A document being printed.', 587: 'Email being sent.', 631: 'A document being printed, or a printer being checked (IPP).', 853: 'An encrypted DNS lookup.',
              993: 'Encrypted email being read (IMAP).', 995: 'Encrypted email being collected (POP3).', 1883: 'Smart-home device messages (MQTT).', 1900: 'Smart devices announcing themselves (SSDP).',
              3389: 'A remote-control session (Remote Desktop).', 5222: 'Chat messages (XMPP).', 5353: 'Devices on your network announcing themselves or looking for each other (mDNS).',
              5355: 'A Windows PC asking nearby PCs for a name (LLMNR).', 5900: 'A remote-control session (VNC).', 8008: 'Web traffic on a side port. It is usually not encrypted.',
              8080: 'Web traffic on a side port. It is usually not encrypted.', 8443: 'Encrypted web traffic on a side port.', 8883: 'Encrypted smart-home device messages (MQTT).',
              9100: 'A document being printed.', 32400: 'Media streaming (Plex).'}
BAD_PORTS = {4444: 'the default port of the Metasploit hacking tool', 1337: 'a classic backdoor port', 31337: 'a classic backdoor port', 12345: 'the NetBus trojan port',
             6666: 'IRC, used by botnets', 6667: 'IRC, used by botnets', 6697: 'IRC, used by botnets', 9001: 'the Tor network', 9030: 'the Tor network', 9050: 'the Tor network'}
INTERNET_UNWISE = {21: 'file transfers without encryption', 23: 'Telnet, which has no encryption', 135: 'Windows RPC', 139: 'Windows file sharing', 445: 'Windows file sharing', 3389: 'Remote Desktop', 5900: 'VNC remote control'}
LOOKALIKE_NAMES = {'svchost', 'lsass', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'spoolsv', 'taskhostw', 'dllhost', 'conhost', 'runtimebroker', 'rundll32', 'explorer', 'searchindexer', 'lsm'}
UNUSUAL_FOLDER = re.compile(r'\\(AppData\\Local\\Temp|Windows\\Temp|Temp)\\|\\Downloads\\|\\Users\\Public\\|\$Recycle\.Bin', re.I)
BIG_UPLOAD = 100 * 1000 * 1000


def describe_data(proto, server_port, client_port):
    if proto == 1:
        return 'A network test or error message (ICMP, the kind ping uses).'
    if proto == 2:
        return 'A device joining or leaving a broadcast group (IGMP).'
    if proto == ARP:
        return 'A device asking which hardware address belongs to an IP address (ARP).'
    if proto == 50 or proto == 47:
        return 'A VPN or tunnel carrying other traffic inside it.'
    if proto == 17 and 443 in (server_port, client_port):
        return 'Encrypted web traffic (QUIC). The contents cannot be read, only where it is going.'
    known = DATA_TYPES.get(server_port) or DATA_TYPES.get(client_port)
    if known:
        return known
    return f'Data on port {server_port}, which is not a well-known service, so the type cannot be told from outside.' if server_port else 'Data of a type that cannot be told from outside.'


def fmt_bytes(n):
    for size, unit in ((1e9, 'GB'), (1e6, 'MB'), (1e3, 'KB')):
        if n >= size:
            return f'{n / size:.1f} {unit}'
    return f'{n} B'


class Blocklists:
    """Public lists of known-dangerous addresses. Only the lists are downloaded; nothing about this PC or its connections is sent."""
    FEEDS = (('Feodo Tracker', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'a list of botnet control servers'),
             ('Spamhaus DROP', 'https://www.spamhaus.org/drop/drop.txt', 'a list of networks run by criminals'))
    ENTRY = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)(?:\s|$)')

    def __init__(self):
        self.meaning = {name: meaning for name, _url, meaning in self.FEEDS}
        self.feeds = {}     # name -> (exact addresses, sorted range starts, range ends)
        self.updated = 0.0

    def load(self, name, text):
        """Replaces one list. Lines that aren't public addresses are ignored, so a damaged file can't flag everything. Returns how many it kept."""
        exact, ranges = set(), []
        for line in text.splitlines()[:50000]:
            found = self.ENTRY.match(line.strip())
            if not found:
                continue
            try:
                net = ipaddress.ip_network(found.group(1), strict=False)
            except ValueError:
                continue
            if not net.is_global or net.prefixlen < 8:
                continue
            if net.prefixlen == 32:
                exact.add(int(net.network_address))
            else:
                ranges.append((int(net.network_address), int(net.broadcast_address)))
        if exact or ranges:
            ranges.sort()
            self.feeds[name] = (exact, [r[0] for r in ranges], [r[1] for r in ranges])
            self.updated = time.time()
        return len(exact) + len(ranges)

    def refresh(self):
        """True if every list was fetched."""
        complete = True
        for name, url, _meaning in self.FEEDS:
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'network-tool'}), timeout=20) as response:
                    text = response.read(4 * 1024 * 1024).decode('utf-8', 'replace')
                complete = bool(self.load(name, text)) and complete
            except (OSError, ValueError, http.client.HTTPException):
                complete = False
        return complete

    def lookup(self, ip):
        """The name of a list holding this address, or ''."""
        value = int(ipaddress.ip_address(ip))
        for name, (exact, starts, ends) in list(self.feeds.items()):
            if value in exact:
                return name
            i = bisect.bisect_right(starts, value) - 1
            if i >= 0 and value <= ends[i]:
                return name
        return ''

    def status(self):
        names = list(self.feeds)
        if not names:
            return 'Not checked: the blocklists could not be downloaded.'
        count = sum(len(e) + len(s) for e, s, _ in self.feeds.values())
        return f'Not on {" or ".join(names)} ({count:,} {"entry" if count == 1 else "entries"}, updated {time.strftime("%H:%M", time.localtime(self.updated))}).'


# ---------------------------------------------------------------- decoding a packet for the detail view

def dns_name(d, o):
    labels, end, hops = [], None, 0
    while True:
        n = d[o]
        if n == 0:
            o += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = o + 2
            o = ((n & 0x3F) << 8) | d[o + 1]
            hops += 1
            if hops > 32:
                raise ValueError('DNS name loops')
            continue
        o += 1
        labels.append(d[o:o + n].decode('latin-1'))
        o += n
        if len(labels) > 64:
            raise ValueError('DNS name too long')
    return clean('.'.join(labels), 255), (end if end is not None else o)


def parse_dns(d):
    ident, flags, qd, an, ns, ar = struct.unpack_from('!6H', d, 0)
    o, questions, answers = 12, [], []
    for _ in range(min(qd, 16)):
        name, o = dns_name(d, o)
        qtype, _qclass = struct.unpack_from('!HH', d, o)
        o += 4
        questions.append((name, DNS_TYPES.get(qtype, str(qtype))))
    for _ in range(min(an + ns + ar, 32)):
        name, o = dns_name(d, o)
        rtype, _rclass, ttl, rdlen = struct.unpack_from('!HHIH', d, o)
        o += 10
        value = f'{rdlen} bytes'
        if rtype == 1 and rdlen == 4:
            value = socket.inet_ntoa(d[o:o + 4])
        elif rtype == 28 and rdlen == 16:
            value = str(ipaddress.IPv6Address(bytes(d[o:o + 16])))
        elif rtype in (2, 5, 12):
            value = dns_name(d, o)[0]
        answers.append((name, DNS_TYPES.get(rtype, str(rtype)), ttl, value))
        o += rdlen
    return {'id': ident, 'response': bool(flags & 0x8000), 'opcode': (flags >> 11) & 15, 'rcode': flags & 15,
            'authoritative': bool(flags & 0x400), 'truncated': bool(flags & 0x200), 'counts': (qd, an, ns, ar),
            'questions': questions, 'answers': answers}


def dns_layer(p, title):
    info = parse_dns(p)
    fields = [['Transaction ID', f'0x{info["id"]:04x}'], ['Message', 'Response' if info['response'] else 'Query'],
              ['Result', DNS_RCODES.get(info['rcode'], str(info['rcode']))] if info['response'] else ['Opcode', str(info['opcode'])],
              ['Questions / answers / authority / extra', ' / '.join(map(str, info['counts']))]]
    fields += [['Question', f'{name} ({qtype})'] for name, qtype in info['questions']]
    fields += [['Answer', f'{name} {rtype} {value} (TTL {ttl})'] for name, rtype, ttl, value in info['answers']]
    subject = info['questions'][0] if info['questions'] else ('', '')
    if info['response']:
        first = next((a[3] for a in info['answers'] if a[1] in ('A', 'AAAA', 'PTR', 'CNAME')), DNS_RCODES.get(info['rcode'], ''))
        summary = f'{title} response {subject[0]} = {first}'
    else:
        summary = f'{title} query {subject[0]} {subject[1]}'
    return {'title': title, 'fields': fields}, summary, subject[0]


def parse_tls(p):
    """The TLS record at the start of p, or None if it isn't one."""
    if len(p) < 5 or p[0] not in TLS_RECORDS or p[1] != 3 or p[2] > 4:
        return None
    version, length = struct.unpack_from('!HH', p, 1)
    info = {'record': TLS_RECORDS[p[0]], 'version': TLS_VERSIONS.get(version, hex(version)), 'length': length, 'hello': None, 'sni': '', 'alpn': []}
    if p[0] == 22 and len(p) > 5:
        info['hello'] = TLS_HANDSHAKES.get(p[5], f'Type {p[5]}')
        if p[5] == 1:
            o = 9 + 2 + 32
            o += 1 + p[o]
            o += 2 + struct.unpack_from('!H', p, o)[0]
            o += 1 + p[o]
            ext_end = min(len(p), o + 2 + struct.unpack_from('!H', p, o)[0])
            o += 2
            while o + 4 <= ext_end:
                kind, size = struct.unpack_from('!HH', p, o)
                body = p[o + 4:o + 4 + size]
                if kind == 0 and len(body) > 5:
                    info['sni'] = clean(body[5:5 + struct.unpack_from('!H', body, 3)[0]].decode('latin-1'), 255)
                elif kind == 16 and len(body) > 2:
                    i = 2
                    while i < len(body):
                        info['alpn'].append(clean(body[i + 1:i + 1 + body[i]].decode('latin-1')))
                        i += 1 + body[i]
                o += 4 + size
    return info


def tls_layer(p):
    info = parse_tls(p)
    if not info:
        return None, ''
    fields = [['Record', info['record']], ['Record version', info['version']], ['Record length', f'{info["length"]} bytes']]
    if info['hello']:
        fields.append(['Handshake', info['hello']])
    if info['sni']:
        fields.append(['Server name (SNI)', info['sni']])
    if info['alpn']:
        fields.append(['Application protocols (ALPN)', ', '.join(info['alpn'])])
    summary = 'TLS ' + (info['hello'] or info['record'])
    return {'title': 'TLS', 'fields': fields}, summary + (f' {info["sni"]}' if info['sni'] else '')


HTTP_START = re.compile(rb'^(?:(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|NOTIFY|M-SEARCH) \S+ HTTP/\d\.\d|HTTP/\d\.\d \d{3}[^\r\n]*)\r\n')


def text_protocol_layer(p, title):
    if not HTTP_START.match(p):
        return None, ''
    head = p.split(b'\r\n\r\n', 1)[0].decode('latin-1').split('\r\n')
    fields = [['Start line', clean(head[0], 240)]]
    for line in head[1:40]:
        name, _, value = line.partition(':')
        fields.append([clean(name), clean(value.strip(), 240)])
    return {'title': title, 'fields': fields}, f'{title} {clean(head[0], 100)}'


def dhcp_layer(p):
    if len(p) < 240 or p[236:240] != b'\x63\x82\x53\x63':
        return None, ''
    fields = [['Message', 'Request from client' if p[0] == 1 else 'Reply from server'], ['Transaction ID', f'0x{p[4:8].hex()}'],
              ['Client IP', socket.inet_ntoa(p[12:16])], ['Offered IP', socket.inet_ntoa(p[16:20])],
              ['Client MAC', ':'.join(f'{b:02x}' for b in p[28:34])]]
    o, kind = 240, ''
    while o + 2 <= len(p) and p[o] != 255:
        if p[o] == 0:
            o += 1
            continue
        code, size = p[o], p[o + 1]
        body = p[o + 2:o + 2 + size]
        if code == 53 and body:
            kind = DHCP_TYPES.get(body[0], str(body[0]))
            fields.insert(0, ['DHCP type', kind])
        elif code == 12:
            fields.append(['Host name', clean(body.decode('latin-1'))])
        elif code == 50 and size == 4:
            fields.append(['Requested IP', socket.inet_ntoa(body)])
        elif code == 54 and size == 4:
            fields.append(['DHCP server', socket.inet_ntoa(body)])
        o += 2 + size
    return {'title': 'DHCP', 'fields': fields}, f'DHCP {kind}'.strip()


def application_layers(p, proto, sport, dport):
    """(layers, summary, a short name for the connection) for what's inside a TCP or UDP packet."""
    if not p:
        return [], '', ''
    ports = {sport, dport}
    if proto == 17 and ports & {53, 5353, 5355}:
        title = 'mDNS' if 5353 in ports else 'LLMNR' if 5355 in ports else 'DNS'
        layer, summary, name = dns_layer(p, title)
        return [layer], summary, name
    if proto == 17 and ports & {67, 68}:
        layer, summary = dhcp_layer(p)
        return ([layer] if layer else []), summary, ''
    if proto == 17 and 1900 in ports:
        layer, summary = text_protocol_layer(p, 'SSDP')
        return ([layer] if layer else []), summary, ''
    if proto == 17 and 123 in ports and len(p) >= 48:
        mode, stratum = p[0] & 7, p[1]
        names = {3: 'Client', 4: 'Server', 5: 'Broadcast'}
        return [{'title': 'NTP', 'fields': [['Version', str((p[0] >> 3) & 7)], ['Mode', names.get(mode, str(mode))], ['Stratum', str(stratum)]]}], f'NTP {names.get(mode, mode)}', ''
    if proto == 17 and 443 in ports:
        if p[0] & 0x80 and len(p) >= 5:
            version = struct.unpack_from('!I', p, 1)[0]
            return [{'title': 'QUIC', 'fields': [['Header', 'Long (connection setup)'], ['Version', hex(version)]]}], 'QUIC setup', ''
        return [{'title': 'QUIC', 'fields': [['Header', 'Short (encrypted data)']]}], 'QUIC data', ''
    if proto == 6:
        layer, summary = tls_layer(p)
        if layer:
            sni = next((v for k, v in layer['fields'] if k == 'Server name (SNI)'), '')
            return [layer], summary, sni
        layer, summary = text_protocol_layer(p, 'HTTP')
        if layer:
            return [layer], summary, ''
    return [], '', ''


def tcp_flags(flags):
    names = ((0x02, 'SYN'), (0x10, 'ACK'), (0x08, 'PSH'), (0x01, 'FIN'), (0x04, 'RST'), (0x20, 'URG'), (0x40, 'ECE'), (0x80, 'CWR'))
    return ' '.join(name for bit, name in names if flags & bit) or 'none'


def tcp_options(data):
    out, o = [], 0
    while o < len(data):
        kind = data[o]
        if kind == 0:
            break
        if kind == 1:
            o += 1
            continue
        if o + 1 >= len(data) or data[o + 1] < 2:
            break
        size = data[o + 1]
        body = data[o + 2:o + size]
        if kind == 2 and len(body) == 2:
            out.append(f'MSS {struct.unpack("!H", body)[0]}')
        elif kind == 3 and len(body) == 1:
            out.append(f'Window scale {body[0]}')
        elif kind == 4:
            out.append('SACK permitted')
        elif kind == 5:
            out.append(f'SACK {len(body) // 8} block(s)')
        elif kind == 8 and len(body) == 8:
            out.append('Timestamps %d, echo %d' % struct.unpack('!II', body))
        else:
            out.append(f'Option {kind}')
        o += size
    return ', '.join(out)


def ip_checksum_ok(header):
    total = sum(struct.unpack(f'!{len(header) // 2}H', header[:len(header) // 2 * 2]))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def hexdump(data):
    lines = []
    for o in range(0, len(data), 16):
        row = data[o:o + 16]
        lines.append(f'{o:04x}  {" ".join(f"{b:02x}" for b in row):<47}  {"".join(chr(b) if 32 <= b < 127 else "." for b in row)}')
    return '\n'.join(lines)


def decode_packet(raw, wire_len=None):
    """Every field worth showing, as {'summary', 'layers': [{'title', 'fields': [[name, value]]}], 'hex'}."""
    wire_len = wire_len or len(raw)
    if len(raw) < 20 or raw[0] >> 4 != 4:
        return {'summary': 'Not an IPv4 packet', 'layers': [], 'hex': hexdump(raw)}
    ihl = (raw[0] & 15) * 4
    tos, total, ident, frag, ttl, proto, checksum = struct.unpack_from('!BHHHBBH', raw, 1)
    src, dst = socket.inet_ntoa(raw[12:16]), socket.inet_ntoa(raw[16:20])
    offset = (frag & 0x1FFF) * 8
    flags = [n for bit, n in ((0x4000, "Don't fragment"), (0x2000, 'More fragments')) if frag & bit]
    dscp = tos >> 2
    valid = len(raw) >= ihl and ip_checksum_ok(raw[:ihl])
    fields = [['Version', '4'], ['Header length', f'{ihl} bytes'], ['Service class (DSCP)', f'{dscp} {DSCP_NAMES.get(dscp, "")}'.strip()],
              ['Congestion (ECN)', ('Not used', 'Capable', 'Capable', 'Congestion seen')[tos & 3]], ['Total length', f'{total} bytes'],
              ['Identification', f'0x{ident:04x} ({ident})'], ['Flags', ', '.join(flags) or 'none'], ['Fragment offset', f'{offset} bytes'],
              ['Time to live', str(ttl)], ['Protocol', f'{PROTO.get(proto, "Unknown")} ({proto})'],
              ['Header checksum', f'0x{checksum:04x} ' + ('(valid)' if valid else '(not valid here; normal on outgoing packets, the network card fills it in)')],
              ['Source', src], ['Destination', dst]]
    if ihl > 20:
        fields.append(['Options', raw[20:ihl].hex()])
    layers = [{'title': 'IPv4 header', 'fields': fields}]
    summary = PROTO.get(proto, f'IP protocol {proto}')
    body = raw[ihl:]
    if len(raw) < wire_len:
        layers[0]['fields'].append(['Captured', f'first {len(raw)} of {wire_len} bytes'])
    try:
        if offset:
            summary += f' fragment at {offset}'
        elif proto == 6 and len(body) >= 20:
            sport, dport, seq, ack, off, bits, window, tcsum, urgent = struct.unpack_from('!HHIIBBHHH', body)
            size = (off >> 4) * 4
            payload = body[size:]
            sent = max(0, total - ihl - size)
            f = [['Source port', f'{sport} {SERVICES.get(sport, "")}'.strip()], ['Destination port', f'{dport} {SERVICES.get(dport, "")}'.strip()],
                 ['Sequence number', str(seq)], ['Acknowledgment number', str(ack)], ['Header length', f'{size} bytes'], ['Flags', tcp_flags(bits)],
                 ['Window', str(window)], ['Checksum', f'0x{tcsum:04x}'], ['Urgent pointer', str(urgent)], ['Payload', f'{sent} bytes']]
            options = tcp_options(body[20:size])
            if options:
                f.append(['Options', options])
            layers.append({'title': 'TCP header', 'fields': f})
            summary = f'TCP {sport} → {dport} [{tcp_flags(bits)}]' + (f' {sent} B' if sent else '')
            app, text, _ = application_layers(payload, 6, sport, dport)
            layers += app
            summary = text or summary
        elif proto == 17 and len(body) >= 8:
            sport, dport, length, ucsum = struct.unpack_from('!HHHH', body)
            layers.append({'title': 'UDP header', 'fields': [['Source port', f'{sport} {SERVICES.get(sport, "")}'.strip()],
                                                             ['Destination port', f'{dport} {SERVICES.get(dport, "")}'.strip()],
                                                             ['Length', f'{length} bytes'], ['Checksum', f'0x{ucsum:04x}']]})
            summary = f'UDP {sport} → {dport} {max(0, length - 8)} B'
            app, text, _ = application_layers(body[8:], 17, sport, dport)
            layers += app
            summary = text or summary
        elif proto == 1 and len(body) >= 8:
            kind, code, icsum, a, b = struct.unpack_from('!BBHHH', body)
            name = ICMP_TYPES.get(kind, f'Type {kind}')
            f = [['Type', f'{kind} {name}'], ['Code', str(code)], ['Checksum', f'0x{icsum:04x}']]
            if kind in (0, 8):
                f += [['Identifier', str(a)], ['Sequence', str(b)]]
            layers.append({'title': 'ICMP', 'fields': f})
            summary = f'ICMP {name}'
        elif proto == 2 and len(body) >= 8:
            names = {0x11: 'Membership query', 0x16: 'Membership report v2', 0x17: 'Leave group', 0x22: 'Membership report v3'}
            layers.append({'title': 'IGMP', 'fields': [['Type', names.get(body[0], hex(body[0]))], ['Group', socket.inet_ntoa(body[4:8])]]})
            summary = 'IGMP ' + names.get(body[0], hex(body[0]))
    except (IndexError, ValueError, struct.error, OSError):
        layers.append({'title': 'Decoding stopped', 'fields': [['Reason', 'This packet is cut short or malformed']]})
    return {'summary': summary, 'layers': layers, 'hex': hexdump(raw)}


def decode_arp(raw):
    if len(raw) < 28:
        return {'summary': 'ARP (cut short)', 'layers': [], 'hex': hexdump(raw)}
    op = struct.unpack_from('!H', raw, 6)[0]
    smac, sip, tmac, tip = format_mac(raw[8:14]), socket.inet_ntoa(raw[14:18]), format_mac(raw[18:24]), socket.inet_ntoa(raw[24:28])
    summary = f'ARP who has {tip}? tell {sip}' if op == 1 else f'ARP {sip} is at {smac}' if op == 2 else f'ARP operation {op}'
    fields = [['Operation', {1: 'Request', 2: 'Reply'}.get(op, str(op))], ['Sender MAC', smac], ['Sender IP', sip], ['Target MAC', tmac], ['Target IP', tip]]
    return {'summary': summary, 'layers': [{'title': 'ARP', 'fields': fields}], 'hex': hexdump(raw)}


# ---------------------------------------------------------------- Windows network facts (no Administrator rights needed)

iphlp = ctypes.WinDLL(os.path.join(WINDIR, 'System32', 'iphlpapi.dll')) if os.name == 'nt' else None
if iphlp:
    kernel32 = ctypes.WinDLL(os.path.join(WINDIR, 'System32', 'kernel32.dll'), use_last_error=True)
    shell32 = ctypes.WinDLL(os.path.join(WINDIR, 'System32', 'shell32.dll'), use_last_error=True)
    iphlp.SendARP.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.c_void_p]
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    shell32.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]


def to_dword(ip):
    return struct.unpack('<I', socket.inet_aton(ip))[0]


def to_ip(value):
    return socket.inet_ntoa(struct.pack('<I', value))


def is_admin():
    try:
        return bool(shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def api_table(call, *args):
    """Calls a Windows table function that says how much room it needs; returns the bytes."""
    size = ctypes.c_ulong(0)
    call(None, ctypes.byref(size), *args)
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value + 4096)
        size = ctypes.c_ulong(len(buf))
        if call(buf, ctypes.byref(size), *args) == 0:
            return buf.raw
    return b'\0\0\0\0'


def local_network():
    """(this PC's IP, its netmask, the router's IP, the interface number) for the connection to the internet."""
    row = (ctypes.c_ulong * 14)()
    if iphlp.GetBestRoute(to_dword('8.8.8.8'), 0, ctypes.byref(row)):
        return None
    gateway, ifindex = to_ip(row[3]), row[4]
    data = api_table(iphlp.GetIpAddrTable, 0)
    for i in range(struct.unpack_from('<I', data)[0]):
        addr, index, mask = struct.unpack_from('<III', data, 4 + i * 24)
        ip = to_ip(addr)
        if index == ifindex and ip != '0.0.0.0' and not ip.startswith('169.254.'):
            return ip, to_ip(mask), gateway, ifindex
    return None


def arp_table(ifindex):
    data, found = api_table(iphlp.GetIpNetTable, 0), {}
    for i in range(struct.unpack_from('<I', data)[0]):
        index, size, mac, addr, kind = struct.unpack_from('<II8sII', data, 4 + i * 24)
        if index == ifindex and kind in (3, 4) and size == 6 and mac[:6] not in (b'\0' * 6, b'\xff' * 6):
            found[to_ip(addr)] = format_mac(mac[:6])
    return found


def format_mac(mac):
    return ':'.join(f'{b:02x}' for b in mac)


def arp_probe(ip, source):
    mac, size = ctypes.create_string_buffer(8), ctypes.c_ulong(8)
    if iphlp.SendARP(to_dword(ip), to_dword(source), mac, ctypes.byref(size)) == 0 and size.value == 6:
        return format_mac(mac.raw[:6])
    return None


def sweep_targets(ip, mask):
    network = ipaddress.ip_network(f'{ip}/{mask}', strict=False)
    if network.num_addresses > 1024:   # a very wide network: only this PC's neighbourhood
        network = ipaddress.ip_network(f'{ip}/24', strict=False)
    return [str(h) for h in network.hosts()]


def tcp_connections():
    data = api_table(lambda b, s, o: iphlp.GetExtendedTcpTable(b, s, o, socket.AF_INET, 5, 0), 0)   # owner-pid, all states
    rows = []
    for i in range(struct.unpack_from('<I', data)[0]):
        state, laddr, lport, raddr, rport, pid = struct.unpack_from('<6I', data, 4 + i * 24)
        rows.append((state, to_ip(laddr), socket.ntohs(lport & 0xFFFF), to_ip(raddr), socket.ntohs(rport & 0xFFFF), pid))
    return rows


def udp_owners():
    data = api_table(lambda b, s, o: iphlp.GetExtendedUdpTable(b, s, o, socket.AF_INET, 1, 0), 0)
    owners = {}
    for i in range(struct.unpack_from('<I', data)[0]):
        _addr, port, pid = struct.unpack_from('<3I', data, 4 + i * 12)
        owners[socket.ntohs(port & 0xFFFF)] = pid
    return owners


_process_names = {}


def process_info(pid):
    """(a label for people, the program's full path or '')."""
    if pid in (0, 4):
        return 'Windows system', ''
    cached = _process_names.get(pid)
    if cached and cached[2] > time.time():
        return cached[:2]
    name, path = f'Process {pid} (needs Administrator to name)', ''
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if handle:
        buf, size = ctypes.create_unicode_buffer(1024), ctypes.c_ulong(1024)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            path = buf.value
            name = f'{os.path.basename(path)} (PID {pid})'
        kernel32.CloseHandle(handle)
    _process_names[pid] = (name, path, time.time() + 30)
    return name, path


# ---------------------------------------------------------------- working out what a device is called

def netbios_name(ip):
    query = secrets.token_bytes(2) + b'\0\0\0\1\0\0\0\0\0\0\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0\x21\0\1'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.8)
        try:
            s.sendto(query, (ip, 137))
            data = s.recv(2048)
            for i in range(min(data[56], 64)):
                entry = data[57 + i * 18:57 + (i + 1) * 18]
                if entry[15] == 0 and not entry[16] & 0x80:
                    return clean(entry[:15].decode('latin-1').strip())
        except (OSError, IndexError):
            pass
    return ''


def mdns_name(ip):
    name = b''.join(bytes([len(part)]) + part.encode() for part in reversed(ip.split('.'))) + b'\7in-addr\4arpa\0'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.8)
        try:
            s.sendto(secrets.token_bytes(2) + b'\0\0\0\1\0\0\0\0\0\0' + name + b'\0\x0c\0\1', (ip, 5353))
            for answer in parse_dns(s.recv(4096))['answers']:
                if answer[1] == 'PTR':
                    return clean(answer[3].removesuffix('.local').removesuffix('.'))
        except (OSError, ValueError, IndexError, struct.error):
            pass
    return ''


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        return ''
    return clean(name, 96) if name != ip else ''


def ssdp_friendly_name(ip, location):
    """The name a smart device publishes about itself. Only asks the device that answered, and doesn't follow redirects."""
    try:
        url = urllib.parse.urlsplit(location)
        if url.scheme != 'http' or url.hostname != ip:
            return ''
        conn = http.client.HTTPConnection(ip, url.port or 80, timeout=2)
        conn.request('GET', url.path or '/')
        response = conn.getresponse()
        body = response.read(65536) if response.status == 200 else b''
        conn.close()
    except (OSError, ValueError, http.client.HTTPException):
        return ''
    found = re.search(rb'<friendlyName>([^<]{1,120})</friendlyName>', body)
    return clean(found.group(1).decode('utf-8', 'replace')) if found else ''


def ssdp_devices(local_ip, wait=3.0):
    found = {}
    message = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.settimeout(0.5)
            s.sendto(message, ('239.255.255.250', 1900))
        except OSError:
            return found
        deadline = time.time() + wait
        while time.time() < deadline and len(found) < 256:
            try:
                data, addr = s.recvfrom(4096)
            except OSError:
                continue
            match = re.search(rb'(?im)^location:\s*(\S+)', data)
            found.setdefault(addr[0], match.group(1).decode('latin-1') if match else '')
    return found


# ---------------------------------------------------------------- what's on the network and what's moving

class Flow:
    __slots__ = ('id', 'key', 'proto', 'proto_num', 'a', 'ap', 'b', 'bp', 'first', 'last', 'alive', 'pkts_ab', 'pkts_ba', 'bytes_ab', 'bytes_ba',
                 'state', 'info', 'process', 'path', 'ring', 'last_event', 'folded')

    def __init__(self, fid, key, proto, a, ap, b, bp, now):
        self.id, self.key, self.proto_num, self.a, self.ap, self.b, self.bp = fid, key, proto, a, ap, b, bp
        self.proto = PROTO.get(proto, f'IP {proto}')
        self.first, self.last, self.alive = now, 0.0, now
        self.pkts_ab = self.pkts_ba = self.bytes_ab = self.bytes_ba = 0
        self.state, self.info, self.process, self.path = '', '', '', ''
        self.ring = collections.deque(maxlen=RING)
        self.last_event, self.folded = 0.0, 0


class Network:
    def __init__(self, ip, mask, gateway, ifindex, mode, note=''):
        self.ip, self.mask, self.gateway, self.ifindex, self.mode, self.note = ip, mask, gateway, ifindex, mode, note
        self.net = ipaddress.ip_network(f'{ip}/{mask}', strict=False) if ip else None
        self.broadcast = str(self.net.broadcast_address) if self.net else ''
        self.lock = threading.Lock()
        self.nodes, self.flows = {}, {}
        self.flow_ids = {}
        self.next_flow = 1
        self.events = collections.deque(maxlen=4000)
        self.seq = 0
        self.packet_no = 0
        self.total = {'pkts': 0, 'bytes': 0, 'in': 0, 'out': 0}
        self.rate = {'pps': 0.0, 'bps': 0.0}
        self.last_total = (0, 0, time.time())
        self.started = time.time()
        self.scanning = False
        self.engine = ''
        self.npcap_error = ''
        self.scapy_install = {'state': 'idle', 'message': ''}
        self.last_client = 0.0
        self.stop = threading.Event()
        self.rdns = cf.ThreadPoolExecutor(8, thread_name_prefix='rdns')
        self.blocklists = Blocklists()
        if ip:
            self.node(ip, time.time())

    def kind(self, ip):
        if ip == self.ip:
            return 'me'
        if ip == self.gateway:
            return 'gateway'
        addr = ipaddress.ip_address(ip)
        if addr.is_multicast or ip == '255.255.255.255' or ip == self.broadcast:
            return 'group'
        return 'lan' if self.net and addr in self.net else 'external'

    def node(self, ip, now):
        n = self.nodes.get(ip)
        if n is None:
            kind = self.kind(ip)
            name = 'This PC' if kind == 'me' else GROUPS.get(ip, 'Subnet broadcast' if ip == self.broadcast else '')
            n = self.nodes[ip] = {'ip': ip, 'kind': kind, 'name': name, 'names': {}, 'mac': '', 'first': now, 'last': 0.0, 'seen': 0.0,
                                  'tx': 0, 'rx': 0, 'txb': 0, 'rxb': 0}
            if kind == 'external':
                self.rdns.submit(self._name_external, ip)
        return n

    def _name_external(self, ip):
        name = reverse_dns(ip)
        if name:
            with self.lock:
                if ip in self.nodes:
                    self.nodes[ip]['name'] = name
                    self.nodes[ip]['names']['Reverse DNS'] = name

    def flow(self, proto, src, sport, dst, dport, flags, now):
        ends = sorted(((src, sport), (dst, dport)))
        key = (proto, ends[0], ends[1])
        f = self.flows.get(key)
        if f is None:
            client_is_src = sport >= dport
            if proto == 6 and flags & 0x02:
                client_is_src = not flags & 0x10
            elif self.kind(dst) == 'group':
                client_is_src = True
            a, ap, b, bp = (src, sport, dst, dport) if client_is_src else (dst, dport, src, sport)
            f = Flow(self.next_flow, key, proto, a, ap, b, bp, now)
            self.next_flow += 1
            self.flows[key] = f
            self.flow_ids[f.id] = f
        return f

    def ingest_frame(self, frame, now=None):
        """One Ethernet frame, as captured by Npcap."""
        if len(frame) < 14:
            return
        kind, offset = struct.unpack_from('!H', frame, 12)[0], 14
        if kind == 0x8100 and len(frame) >= 18:   # a VLAN tag sits in front of the real type
            kind, offset = struct.unpack_from('!H', frame, 16)[0], 18
        eth = (format_mac(frame[6:12]), format_mac(frame[:6]), kind)
        if kind == 0x0800:
            self.ingest(frame[offset:], now, eth)
        elif kind == ARP:
            self.ingest_arp(frame[offset:], now or time.time(), eth)

    def ingest_arp(self, body, now, eth):
        if len(body) < 28 or body[:6] != b'\0\1\x08\0\6\4':
            return
        op = struct.unpack_from('!H', body, 6)[0]
        src, dst = socket.inet_ntoa(body[14:18]), socket.inet_ntoa(body[24:28])
        if src == '0.0.0.0' or not self.net or ipaddress.ip_address(src) not in self.net:
            return
        with self.lock:
            sender = self.node(src, now)
            sender['mac'], sender['seen'] = format_mac(body[8:14]), now
            # a request for an address nobody has must not draw a device that doesn't exist
            if src != dst and (op == 2 or dst in self.nodes):
                f = self.flow(ARP, src, 0, dst, 0, 0, now)
                self._record(f, src, 0, dst, 0, bytes(body), len(body) + 14, now, eth)

    def ingest(self, raw, now=None, eth=None):
        """One IPv4 packet, as captured."""
        if len(raw) < 20 or raw[0] >> 4 != 4:
            return
        now = now or time.time()
        ihl = (raw[0] & 15) * 4
        size = max(struct.unpack_from('!H', raw, 2)[0], len(raw))
        frag = struct.unpack_from('!H', raw, 6)[0] & 0x1FFF
        proto = raw[9]
        src, dst = socket.inet_ntoa(raw[12:16]), socket.inet_ntoa(raw[16:20])
        sport = dport = flags = 0
        payload = b''
        if not frag and proto in (6, 17) and len(raw) >= ihl + 8:
            sport, dport = struct.unpack_from('!HH', raw, ihl)
            if proto == 6 and len(raw) >= ihl + 20:
                flags = raw[ihl + 13]
                payload = raw[ihl + (raw[ihl + 12] >> 4) * 4:]
            elif proto == 17:
                payload = raw[ihl + 8:]
        with self.lock:
            f = self.flow(proto, src, sport, dst, dport, flags, now)
            if proto == 6:
                f.state = self._tcp_state(f.state, flags)
            if not f.info and payload and f.pkts_ab + f.pkts_ba < 24:
                try:
                    f.info = application_layers(payload, proto, sport, dport)[2]
                except (IndexError, ValueError, struct.error, OSError):
                    pass
            self._record(f, src, sport, dst, dport, bytes(raw[:SNAP]), size, now, eth)

    def _record(self, f, src, sport, dst, dport, kept, size, now, eth):
        """Counts one packet on its connection and devices, and queues its animation. Call with the lock held."""
        forward = src == f.a and sport == f.ap
        f.last = f.alive = now
        if forward:
            f.pkts_ab += 1
            f.bytes_ab += size
        else:
            f.pkts_ba += 1
            f.bytes_ba += size
        self.packet_no += 1
        f.ring.append((self.packet_no, now, kept, size, forward, eth))
        sender, receiver = self.node(src, now), self.node(dst, now)
        sender['last'] = receiver['last'] = now
        if eth and sender['kind'] in ('lan', 'gateway', 'me'):
            sender['mac'] = eth[0]
        sender['tx'] += 1
        sender['txb'] += size
        receiver['rx'] += 1
        receiver['rxb'] += size
        self.total['pkts'] += 1
        self.total['bytes'] += size
        self.total['out' if src == self.ip else 'in'] += 1
        if now - f.last_event >= EVENT_GAP:
            f.last_event = now
            self.seq += 1
            self.events.append([self.seq, round((now - self.started) * 1000), src, sport, dst, dport, f.proto, size, f.id, str(dport) if dport else f.proto])

    @staticmethod
    def _tcp_state(current, flags):
        if flags & 0x04:
            return 'Reset'
        if flags & 0x01:
            return 'Closing'
        if flags & 0x02:
            return 'SYN-ACK' if flags & 0x10 else 'SYN'
        return 'Established' if current in ('', 'SYN', 'SYN-ACK', 'Established') else current

    def add_device(self, ip, mac='', now=None):
        with self.lock:
            n = self.node(ip, now or time.time())
            if mac:
                n['mac'] = mac
            n['seen'] = time.time()

    def set_name(self, ip, source, name):
        if not name:
            return
        with self.lock:
            n = self.nodes.get(ip)
            if n is None or n['kind'] == 'me':
                return
            n['names'][source] = name
            for best in ('Device description', 'mDNS', 'NetBIOS', 'Reverse DNS'):
                if best in n['names']:
                    n['name'] = n['names'][best]
                    break

    def tick(self):
        """Once a second: rates and forgetting old things."""
        now = time.time()
        pkts, size, then = self.last_total
        with self.lock:
            elapsed = max(0.2, now - then)
            self.rate = {'pps': round((self.total['pkts'] - pkts) / elapsed, 1), 'bps': round((self.total['bytes'] - size) * 8 / elapsed)}
            self.last_total = (self.total['pkts'], self.total['bytes'], now)
            for key in [k for k, f in self.flows.items() if now - max(f.last, f.alive) > FLOW_TTL]:
                self.flow_ids.pop(self.flows.pop(key).id, None)
            if len(self.flows) > MAX_FLOWS:
                for f in sorted(self.flows.values(), key=lambda x: max(x.last, x.alive))[:len(self.flows) - MAX_FLOWS]:
                    del self.flows[f.key]
                    self.flow_ids.pop(f.id, None)
            used = {f.a for f in self.flows.values()} | {f.b for f in self.flows.values()}
            for ip in [ip for ip, n in self.nodes.items() if n['kind'] == 'external' and ip not in used]:
                del self.nodes[ip]
            if self.engine == 'raw' and not self.note and now - self.started > 20 and self.total['out'] > 50 and self.total['in'] == 0:
                self.note = 'Only outgoing packets are arriving. Windows Firewall may be hiding incoming ones; the Npcap upgrade avoids that.'

    def refresh_connections(self):
        tcp, udp = tcp_connections(), udp_owners()
        now = time.time()
        with self.lock:
            for state, laddr, lport, raddr, rport, pid in tcp:
                if state == 2 or raddr in ('0.0.0.0', '127.0.0.1') or laddr.startswith('127.') or laddr != self.ip:
                    continue
                f = self.flow(6, laddr, lport, raddr, rport, 0x02 if lport > rport else 0x12, now)
                f.alive = now
                f.state = TCP_STATES.get(state, f.state)
                f.process, f.path = process_info(pid)
                self.node(laddr, now)
                self.node(raddr, now)
            for f in self.flows.values():
                if f.proto_num == 17:
                    port = f.ap if f.a == self.ip else f.bp if f.b == self.ip else None
                    if port in udp:
                        f.process, f.path = process_info(udp[port])

    def state(self):
        now = time.time()
        with self.lock:
            flows = sorted(self.flows.values(), key=lambda f: max(f.last, f.alive), reverse=True)[:MAX_DRAW]
            drawn = {f.a for f in flows} | {f.b for f in flows}
            external = sorted((n for n in self.nodes.values() if n['kind'] == 'external' and n['ip'] in drawn), key=lambda n: max(n['last'], n['first']), reverse=True)
            keep = {n['ip'] for n in external[:MAX_EXTERNAL]}
            nodes = [self._node_view(n, now) for n in self.nodes.values() if (n['kind'] != 'external' and (n['kind'] != 'group' or n['ip'] in drawn)) or n['ip'] in keep]
            shown = {n['ip'] for n in nodes}
            flow_views = [self._flow_view(f, now) for f in flows if f.a in shown and f.b in shown]
            setup = {'npcap': npcap_installed(), 'scapy': scapy_installed(), 'install': dict(self.scapy_install), 'error': self.npcap_error, 'frozen': bool(FROZEN)}
            return {'mode': self.mode, 'engine': self.engine, 'setup': setup, 'admin': is_admin(), 'note': self.note, 'ip': self.ip, 'mask': self.mask, 'gateway': self.gateway, 'scanning': self.scanning,
                    'version': APP_VERSION, 'total': self.total, 'rate': self.rate, 'nodes': nodes, 'flows': flow_views,
                    'devices': sum(1 for n in nodes if n['kind'] in ('me', 'gateway', 'lan'))}

    @staticmethod
    def _node_view(n, now):
        return {'ip': n['ip'], 'kind': n['kind'], 'name': n['name'], 'names': n['names'], 'mac': n['mac'], 'online': now - max(n['seen'], n['last']) < 180,
                'age': round(now - n['first']), 'idle': round(now - n['last'], 1) if n['last'] else None, 'tx': n['tx'], 'rx': n['rx'], 'txb': n['txb'], 'rxb': n['rxb']}

    def _flow_view(self, f, now):
        return {'id': f.id, 'proto': f.proto, 'a': f.a, 'ap': f.ap, 'b': f.b, 'bp': f.bp, 'service': service_for(f.ap, f.bp), 'state': f.state, 'info': f.info,
                'pkts': f.pkts_ab + f.pkts_ba, 'bytes': f.bytes_ab + f.bytes_ba, 'idle': round(now - f.last, 1) if f.last else None, 'plain': self.explain(f)}

    def _who(self, ip, process=''):
        n = self.nodes.get(ip) or {'kind': self.kind(ip), 'name': ''}
        kind, name = n['kind'], n['name']
        if kind == 'me':
            program = process.split(' (')[0] if process and not process.startswith('Process ') else ''
            return f'{program} on This PC' if program else 'This PC'
        if kind == 'gateway':
            return f'your router ({name or ip})'
        if kind == 'group':
            return f'everyone nearby ({name or ip})'
        if kind == 'lan':
            return name or f'a device at {ip}'
        return name or ip

    def explain(self, f):
        """A plain description of one connection, and every warning sign the simple checks can find. Call with the lock held."""
        a_local, b_local = self.kind(f.a) != 'external', self.kind(f.b) != 'external'
        local_process = f.process if f.a == self.ip or f.b == self.ip else ''
        source, target = self._who(f.a, local_process if f.a == self.ip else ''), self._who(f.b, local_process if f.b == self.ip else '')
        port = f' on port {f.bp}' if f.bp else ''
        if f.bytes_ab and not f.bytes_ba:
            who = f'{source} is sending data to {target}{port}. Sent {fmt_bytes(f.bytes_ab)} so far.'
        elif f.bytes_ba and not f.bytes_ab:
            who = f'{target} is sending data to {source}. Sent {fmt_bytes(f.bytes_ba)} so far.'
        elif f.bytes_ab:
            who = f'{source} is sending data to {target}{port}. Sent {fmt_bytes(f.bytes_ab)}, received {fmt_bytes(f.bytes_ba)} back.'
        else:
            who = f'{source} has a connection open to {target}{port}. No packets captured yet.'
        if who.startswith(('a ', 'your ', 'everyone ')):
            who = who[0].upper() + who[1:]

        worst, reasons = 0, []

        def warn(level, text):
            nonlocal worst
            worst = max(worst, level)
            reasons.append(text)

        hits = [(ip, self.blocklists.lookup(ip)) for ip, local in ((f.a, a_local), (f.b, b_local)) if not local]
        hits = [(ip, name) for ip, name in hits if name]
        for ip, name in hits:
            warn(2, f'{ip} is on {name}, {self.blocklists.meaning.get(name, "a list of dangerous addresses")}.')
        if not a_local or not b_local:
            if f.bp in BAD_PORTS:
                warn(2, f'It uses port {f.bp}, which is {BAD_PORTS[f.bp]}.')
            if not a_local and f.b == self.ip and f.proto_num == 6 and f.bp in INTERNET_UNWISE:
                warn(2, f'A machine on the internet connected to {INTERNET_UNWISE[f.bp]} on this PC.')
            elif a_local and f.bp in INTERNET_UNWISE:
                warn(1, f'{INTERNET_UNWISE[f.bp]} is rarely meant to cross the internet.'.capitalize())
            sent = f.bytes_ab if a_local else f.bytes_ba
            received = f.bytes_ba if a_local else f.bytes_ab
            if sent >= BIG_UPLOAD and sent > received * 5:
                warn(1, f'A large one-way upload: {fmt_bytes(sent)} sent to the internet.')
        if local_process and f.path:
            stem = os.path.splitext(os.path.basename(f.path))[0].lower()
            if stem in LOOKALIKE_NAMES and not f.path.lower().startswith(WINDIR.lower() + '\\'):
                warn(2, f'{os.path.basename(f.path)} has the name of a Windows system file but runs from {f.path}, a common malware disguise.')
            elif UNUSUAL_FOLDER.search(f.path):
                warn(1, f'The program runs from an unusual folder: {f.path}.')
        if hits:
            listed = 'Yes. ' + ' '.join(f'{ip} is listed by {name}.' for ip, name in hits)
        elif a_local and b_local:
            listed = 'Does not apply: this stays on your own network.'
        else:
            listed = self.blocklists.status()
        return {'who': clean(who, 400), 'data': describe_data(f.proto_num, f.bp, f.ap), 'level': ('ok', 'watch', 'bad')[worst],
                'verdict': ('No warning signs found', 'Worth a look', 'Warning signs found')[worst], 'reasons': [clean(r, 400) for r in reasons], 'listed': clean(listed, 300)}

    def events_since(self, since):
        with self.lock:
            events = [e for e in self.events if e[0] > since][-150:]
            return {'seq': self.seq, 'events': events}

    def mac_for(self, ip):
        n = self.nodes.get(ip)
        if n and n['mac']:
            return n['mac']
        if n and n['kind'] == 'external' and self.gateway in self.nodes:
            mac = self.nodes[self.gateway]['mac']
            return f'{mac} (the router, the next hop)' if mac else ''
        return ''

    def flow_detail(self, fid):
        with self.lock:
            f = self.flow_ids.get(fid)
            if f is None:
                return None
            now = time.time()
            detail = self._flow_view(f, now)
            ring = list(f.ring)
            detail.update({'pkts_ab': f.pkts_ab, 'pkts_ba': f.pkts_ba, 'bytes_ab': f.bytes_ab, 'bytes_ba': f.bytes_ba, 'process': f.process, 'age': round(now - f.first),
                           'a_name': self.nodes[f.a]['name'] if f.a in self.nodes else '', 'b_name': self.nodes[f.b]['name'] if f.b in self.nodes else '',
                           'a_mac': self.mac_for(f.a), 'b_mac': self.mac_for(f.b), 'a_service': SERVICES.get(f.ap, ''), 'b_service': SERVICES.get(f.bp, '')})
        packets = []
        for no, ts, raw, size, forward, eth in ring:
            info = decode_arp(raw) if f.proto_num == ARP else decode_packet(raw, size)
            src, dst = (f.a, f.b) if forward else (f.b, f.a)
            if eth:
                link = [['Source MAC', eth[0]], ['Destination MAC', eth[1]], ['EtherType', f'0x{eth[2]:04x} ' + {0x0800: 'IPv4', ARP: 'ARP'}.get(eth[2], '')]]
            else:
                link = [['Visible in this capture', 'No. Windows raw sockets start at the IP layer'], ['Source MAC (ARP table)', self.mac_for(src) or 'Unknown'], ['Destination MAC (ARP table)', self.mac_for(dst) or 'Unknown']]
            info['layers'].insert(0, {'title': 'Ethernet', 'fields': link})
            info.update({'no': no, 'ago': round(time.time() - ts, 2), 'clock': time.strftime('%H:%M:%S', time.localtime(ts)) + f'.{int(ts * 1000) % 1000:03d}', 'len': size, 'forward': forward})
            packets.append(info)
        detail['packets'] = packets
        return detail


def npcap_installed():
    return os.path.exists(NPCAP_DLL)


def scapy_installed():
    if FROZEN:   # the exe reads Npcap itself; a packaged app can't install Python libraries
        return True
    if importlib.util.find_spec('scapy') is not None:
        return True
    importlib.invalidate_caches()
    user_site = site.getusersitepackages()
    if user_site not in sys.path and os.path.isdir(user_site):   # the folder may only exist since the install a moment ago
        site.addsitedir(user_site)
    return importlib.util.find_spec('scapy') is not None


def install_scapy(net):
    """Runs pip for the exact version this app was checked against. Runs once at a time, reports through net.scapy_install."""
    with net.lock:
        if net.scapy_install['state'] == 'running':
            return
        net.scapy_install = {'state': 'running', 'message': f'Installing scapy {SCAPY_VERSION}…'}

    def work():
        command = [sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check', '--no-input']
        if sys.prefix == sys.base_prefix:
            command.append('--user')
        try:
            done = subprocess.run(command + [f'scapy=={SCAPY_VERSION}'], capture_output=True, text=True, timeout=300, creationflags=subprocess.CREATE_NO_WINDOW)
            ok, text = done.returncode == 0, (done.stderr or done.stdout).strip()
        except (OSError, subprocess.SubprocessError) as e:
            ok, text = False, str(e)
        last = text.splitlines()[-1] if text else ''
        net.scapy_install = {'state': 'done', 'message': f'scapy {SCAPY_VERSION} is installed.'} if ok else {'state': 'failed', 'message': clean(last, 240) or 'pip failed.'}
    threading.Thread(target=work, daemon=True, name='install-scapy').start()


class SockAddr(ctypes.Structure):
    _fields_ = [('family', ctypes.c_ushort), ('data', ctypes.c_ubyte * 14)]   # bytes, not c_char: a c_char field is cut at the first zero


class PcapAddr(ctypes.Structure):
    pass


PcapAddr._fields_ = [('next', ctypes.POINTER(PcapAddr)), ('addr', ctypes.POINTER(SockAddr)), ('netmask', ctypes.POINTER(SockAddr)),
                     ('broadaddr', ctypes.POINTER(SockAddr)), ('dstaddr', ctypes.POINTER(SockAddr))]


class PcapIf(ctypes.Structure):
    pass


PcapIf._fields_ = [('next', ctypes.POINTER(PcapIf)), ('name', ctypes.c_char_p), ('description', ctypes.c_char_p), ('addresses', ctypes.POINTER(PcapAddr)), ('flags', ctypes.c_uint)]


class PcapHeader(ctypes.Structure):
    _fields_ = [('sec', ctypes.c_long), ('usec', ctypes.c_long), ('caplen', ctypes.c_uint), ('len', ctypes.c_uint)]


def wpcap_reader(local_ip):
    """Opens Npcap's own library directly, for the exe. Returns (read, close); read gives (frame, time) or (None, None)."""
    dll = ctypes.CDLL(NPCAP_DLL, winmode=0x8)   # also finds its helper Packet.dll in Npcap's folder, never beside this app
    dll.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(PcapIf)), ctypes.c_char_p]
    dll.pcap_freealldevs.argtypes = [ctypes.POINTER(PcapIf)]
    dll.pcap_open_live.restype = ctypes.c_void_p
    dll.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    dll.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(PcapHeader)), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    dll.pcap_close.argtypes = [ctypes.c_void_p]
    errors = ctypes.create_string_buffer(512)
    devices = ctypes.POINTER(PcapIf)()
    if dll.pcap_findalldevs(ctypes.byref(devices), errors) != 0:
        raise OSError(errors.value.decode('latin-1'))
    wanted, name, device = socket.inet_aton(local_ip), None, devices
    while device and name is None:
        address = device.contents.addresses
        while address:
            sock = address.contents.addr
            if sock and sock.contents.family == socket.AF_INET and bytes(sock.contents.data)[2:6] == wanted:
                name = device.contents.name
                break
            address = address.contents.next
        device = device.contents.next
    handle = dll.pcap_open_live(name, 65535, 1, 100, errors) if name else None
    dll.pcap_freealldevs(devices)
    if not handle:
        raise OSError(errors.value.decode('latin-1') or 'This network connection was not found in Npcap.')

    header, data = ctypes.POINTER(PcapHeader)(), ctypes.POINTER(ctypes.c_ubyte)()

    def read():
        result = dll.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(data))
        if result < 0:
            raise OSError('Npcap stopped reading this connection.')
        if result == 0:
            return None, None
        info = header.contents
        return ctypes.string_at(data, info.caplen), info.sec + info.usec / 1e6

    return read, lambda: dll.pcap_close(handle)


def scapy_reader(local_ip):
    import scapy.all as scapy
    iface = next(i for i in scapy.conf.ifaces.values() if i.ip == local_ip)
    s = scapy.conf.L2listen(iface=iface, promisc=True)

    def read():
        _cls, frame, ts = s.recv_raw(65535)
        return (bytes(frame), float(ts) if ts else None) if frame else (None, None)

    return read, s.close


def capture_with_npcap(net):
    """Reads frames through Npcap until told to stop. Returning with net.npcap_error set means it could not work."""
    try:
        read, close = (wpcap_reader if FROZEN else scapy_reader)(net.ip)
    except Exception as e:   # third-party code on a driver: whatever goes wrong, the raw socket is still there
        net.npcap_error = f'Npcap could not start: {clean(e, 160)}'
        return
    net.mode, net.engine, net.note = 'capture', 'npcap', ''
    try:
        while not net.stop.is_set():
            frame, ts = read()
            if frame:
                net.ingest_frame(frame, ts)
    except Exception as e:
        net.npcap_error = f'Npcap stopped: {clean(e, 160)}'
    finally:
        try:
            close()
        except Exception:
            pass


def run_capture(net):
    """Prefers Npcap, and moves to it as soon as it and scapy are both installed; otherwise the raw socket if allowed."""
    raw_failed = False
    while not net.stop.is_set():
        if not net.npcap_error and npcap_installed() and scapy_installed():
            capture_with_npcap(net)
        elif is_admin() and not raw_failed:
            raw_failed = not capture_with_raw_socket(net)
        else:
            if net.engine or net.mode == 'capture':
                net.mode, net.engine = 'connections', ''
            if not net.note:
                net.note = net.npcap_error or 'No packet capture: start My_network as Administrator, or use the Npcap upgrade.'
            net.stop.wait(3)


def capture_with_raw_socket(net):
    """Returns False if it could not start, True once it has been stopped or Npcap has become available."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
        s.bind((net.ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except OSError as e:
        net.mode, net.engine, net.note = 'connections', '', f'Packet capture could not start: {clean(e, 160)}'
        return False
    net.mode, net.engine = 'capture', 'raw'
    if net.note.startswith('Not running'):
        net.note = ''
    s.settimeout(1)
    checked = time.time()
    while not net.stop.is_set():
        if time.time() - checked > 3:
            checked = time.time()
            if not net.npcap_error and npcap_installed() and scapy_installed():
                break
        try:
            raw, _ = s.recvfrom(65535)
        except TimeoutError:
            continue
        except OSError:
            if net.stop.is_set():
                break
            time.sleep(0.05)   # a raw socket reports oversized packets and resets as errors; keep going
            continue
        net.ingest(raw)
    try:
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except OSError:
        pass
    s.close()
    return True


def run_discovery(net):
    pool = cf.ThreadPoolExecutor(64, thread_name_prefix='arp')
    names = cf.ThreadPoolExecutor(16, thread_name_prefix='names')
    named_at = {}

    def name_device(ip):
        for source, finder in (('Reverse DNS', reverse_dns), ('NetBIOS', netbios_name), ('mDNS', mdns_name)):
            net.set_name(ip, source, finder(ip))

    def describe(ip, location):
        net.add_device(ip)
        net.set_name(ip, 'Device description', ssdp_friendly_name(ip, location) if location else '')

    while not net.stop.is_set():
        net.scanning = True
        targets = sweep_targets(net.ip, net.mask)
        found = {}
        for ip, mac in zip(targets, pool.map(lambda t: arp_probe(t, net.ip), targets)):
            if mac:
                found[ip] = mac
        found.update({ip: mac for ip, mac in arp_table(net.ifindex).items() if net.kind(ip) in ('lan', 'gateway', 'me')})
        for ip, mac in found.items():
            net.add_device(ip, mac)
        net.add_device(net.ip)
        now = time.time()
        for ip in found:
            if ip != net.ip and now - named_at.get(ip, 0) > 300:
                named_at[ip] = now
                names.submit(name_device, ip)
        for ip, location in ssdp_devices(net.ip).items():
            if net.net and ipaddress.ip_address(ip) in net.net:
                names.submit(describe, ip, location)
        net.scanning = False
        net.stop.wait(60)


def run_blocklists(net):
    while not net.stop.is_set():
        net.stop.wait(6 * 3600 if net.blocklists.refresh() else 900)


def run_connections(net):
    while not net.stop.is_set():
        try:
            net.refresh_connections()
        except (OSError, struct.error):
            pass
        net.stop.wait(3)


# ---------------------------------------------------------------- made-up traffic for trying the view (--demo)

def build_packet(src, dst, proto, sport=0, dport=0, payload=b'', flags=0x18, ttl=64, seq=1000, ack=2000):
    if proto == 6:
        l4 = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
    elif proto == 17:
        l4 = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    else:
        l4 = payload
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), random.randrange(65536), 0x4000, ttl, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    total = sum(struct.unpack('!10H', header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return header[:10] + struct.pack('!H', ~total & 0xFFFF) + header[12:] + l4


def build_dns_query(name, qtype=1):
    return b'\x12\x34\x01\0\0\1\0\0\0\0\0\0' + b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0' + struct.pack('!HH', qtype, 1)


def build_client_hello(server):
    name = server.encode()
    sni = struct.pack('!HH', 0, len(name) + 5) + struct.pack('!HBH', len(name) + 3, 0, len(name)) + name
    alpn = struct.pack('!HHHB', 16, 5, 3, 2) + b'h2'
    extensions = sni + alpn
    body = b'\x03\x03' + bytes(32) + b'\0' + struct.pack('!H', 2) + b'\x13\x01' + b'\1\0' + struct.pack('!H', len(extensions)) + extensions
    handshake = b'\1' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\1' + struct.pack('!H', len(handshake)) + handshake


DEMO_ME, DEMO_ROUTER = '10.20.30.5', '10.20.30.1'
DEMO_DEVICES = [('10.20.30.11', 'Living Room TV', 'a4:83:e7:10:22:01'), ('10.20.30.12', 'Office Printer', '00:1b:a9:44:51:02'), ('10.20.30.17', 'Kitchen Speaker', 'f4:f5:d8:90:13:03'),
                ('10.20.30.23', 'Sam-Laptop', 'dc:a6:32:01:77:04'), ('10.20.30.31', 'NAS', '00:11:32:aa:bc:05'), ('10.20.30.40', 'Doorbell Camera', '2c:aa:8e:31:6e:06'),
                ('10.20.30.52', 'Phone', '7a:12:9c:55:ee:07'), ('10.20.30.77', '', 'b8:27:eb:6c:09:08')]
DEMO_SITES = [('203.0.113.10', 'www.example.com'), ('203.0.113.45', 'cdn.example.net'), ('198.51.100.7', 'mail.example.org'), ('198.51.100.92', 'video.example.tv'), ('192.0.2.33', 'updates.example.com')]


def run_demo(net):
    me, router = DEMO_ME, DEMO_ROUTER
    net.add_device(router, 'c8:3a:35:21:00:01')
    net.set_name(router, 'Reverse DNS', 'router.demo')
    for ip, name, mac in DEMO_DEVICES:
        net.add_device(ip, mac)
        net.set_name(ip, 'mDNS', name)
    for ip, name in DEMO_SITES:
        with net.lock:
            net.node(ip, time.time())['name'] = name

    def browse():
        ip, name = random.choice(DEMO_SITES)
        port = random.randint(49152, 65000)
        net.ingest(build_packet(me, ip, 6, port, 443, flags=0x02))
        time.sleep(0.05)
        net.ingest(build_packet(ip, me, 6, 443, port, flags=0x12))
        net.ingest(build_packet(me, ip, 6, port, 443, flags=0x10))
        net.ingest(build_packet(me, ip, 6, port, 443, build_client_hello(name)))
        for _ in range(random.randint(3, 8)):
            time.sleep(random.uniform(0.04, 0.2))
            net.ingest(build_packet(ip, me, 6, 443, port, b'\x17\x03\x03\x05\xb4' + os.urandom(1200)))
            net.ingest(build_packet(me, ip, 6, port, 443, flags=0x10))

    def web_lan():
        ip = random.choice(DEMO_DEVICES)[0]
        port = random.randint(49152, 65000)
        net.ingest(build_packet(me, ip, 6, port, 80, b'GET /status HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\nUser-Agent: demo\r\n\r\n'))
        time.sleep(0.1)
        net.ingest(build_packet(ip, me, 6, 80, port, b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok'))

    def file_share():
        port = 50500
        for _ in range(10):
            net.ingest(build_packet('10.20.30.31', me, 6, 445, port, os.urandom(1300)))
            time.sleep(0.05)

    def dns():
        name = random.choice(DEMO_SITES)[1]
        port = random.randint(49152, 65000)
        net.ingest(build_packet(me, router, 17, port, 53, build_dns_query(name)))
        time.sleep(0.05)
        net.ingest(build_packet(router, me, 17, 53, port, os.urandom(40)))

    def discovery():
        ip = random.choice(DEMO_DEVICES)[0]
        net.ingest(build_packet(ip, '224.0.0.251', 17, 5353, 5353, build_dns_query('_airplay._tcp.local', 12), ttl=255))
        net.ingest(build_packet(ip, '239.255.255.250', 17, 49999, 1900, b'NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\r\n'))

    def ping():
        net.ingest(build_packet(me, router, 1, payload=struct.pack('!BBHHH', 8, 0, 0, 1, 7) + bytes(32)))
        time.sleep(0.03)
        net.ingest(build_packet(router, me, 1, payload=struct.pack('!BBHHH', 0, 0, 0, 1, 7) + bytes(32)))

    def backdoor():
        net.ingest(build_packet(me, '198.51.100.7', 6, 51000, 4444, os.urandom(300)))

    net.blocklists.feeds['Feodo Tracker'] = ({int(ipaddress.ip_address('192.0.2.33'))}, [], [])   # made up, like everything in the demo
    net.blocklists.updated = time.time()
    jobs = [browse, browse, browse, web_lan, file_share, dns, dns, discovery, ping, backdoor]
    workers = cf.ThreadPoolExecutor(8)
    while not net.stop.is_set():
        workers.submit(random.choice(jobs))
        with net.lock:
            for ip, name in DEMO_SITES:   # internet hosts are forgotten when idle, so keep naming them
                if ip in net.nodes:
                    net.nodes[ip]['name'] = name
        net.stop.wait(random.uniform(0.15, 0.45))


# ---------------------------------------------------------------- the local page

CSP = "default-src 'none'; script-src 'nonce-{}'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


def make_handler(net, page, token, port, launch_key, nonce):
    csp = CSP.format(nonce)
    page_path = f'/?k={launch_key}'.encode()
    origins = (f'http://localhost:{port}', f'http://127.0.0.1:{port}')

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'My_network'
        sys_version = ''

        def log_message(self, *args):
            pass

        def send(self, status, ctype, body, extra=None):
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', csp)
            self.send_header('Referrer-Policy', 'no-referrer')
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status, obj, extra=None):
            self.send(status, 'application/json; charset=utf-8', json.dumps(obj).encode('utf-8'), extra)

        def site_headers(self):
            """Lets the Nesiam.com website, and only it, ask whether the app is running."""
            origin = self.headers.get('Origin')
            return {'Access-Control-Allow-Origin': origin, 'Vary': 'Origin'} if origin in SITE_ORIGINS else None

        def do_OPTIONS(self):
            headers = self.site_headers()
            if not self.host_ok() or not headers or self.path not in ('/status', '/site-stop'):
                return self.send_json(403, {'ok': False})
            self.send(204, 'text/plain', b'', {**headers, 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'Content-Type',
                                               'Access-Control-Allow-Private-Network': 'true', 'Access-Control-Max-Age': '600'})

        def host_ok(self):
            return self.headers.get('Host') in (f'localhost:{port}', f'127.0.0.1:{port}')

        def token_ok(self):
            origin = self.headers.get('Origin')
            return secrets.compare_digest(self.headers.get('X-Net-Token', '').encode('utf-8', 'replace'), token.encode()) and (not origin or origin in origins)

        def do_GET(self):
            if not self.host_ok():
                return self.send_json(403, {'ok': False})
            url = urllib.parse.urlsplit(self.path)
            if url.path == '/':
                if secrets.compare_digest(self.path.encode('utf-8', 'replace'), page_path):
                    return self.send(200, 'text/html; charset=utf-8', page)
                return self.send(403, 'text/plain; charset=utf-8', b'This address has expired. Start My_network again.')
            if url.path == '/status':   # only "it's running" and the version, and only for the website
                headers = self.site_headers()
                if not headers:
                    return self.send_json(403, {'ok': False})
                return self.send_json(200, {'app': 'My_network', 'version': APP_VERSION, 'stopping': net.stop.is_set()}, headers)
            if not self.token_ok():
                return self.send_json(403, {'ok': False})
            net.last_client = time.time()
            query = urllib.parse.parse_qs(url.query)
            try:
                if url.path == '/state':
                    return self.send_json(200, net.state())
                if url.path == '/events':
                    return self.send_json(200, net.events_since(int(query.get('since', ['0'])[0])))
                if url.path == '/flow':
                    detail = net.flow_detail(int(query.get('id', ['0'])[0]))
                    return self.send_json(200 if detail else 404, detail or {'gone': True})
            except ValueError:
                return self.send_json(400, {'ok': False})
            self.send_json(404, {'ok': False})

        def do_POST(self):
            if self.path == '/site-stop':   # the website's STOP button
                headers = self.site_headers()
                if not self.host_ok() or not headers:
                    return self.send_json(403, {'ok': False})
                self.send_json(200, {'ok': True}, headers)
                net.stop.set()
                return
            if not (self.host_ok() and self.token_ok()):
                return self.send_json(403, {'ok': False})
            if self.path == '/quit':
                self.send_json(200, {'ok': True})
                net.stop.set()
            elif self.path == '/install-scapy' and net.mode != 'demo' and not FROZEN:
                install_scapy(net)
                self.send_json(200, {'ok': True})
            elif self.path == '/open-npcap-page' and net.mode != 'demo':
                self.send_json(200, {'ok': bool(open_view(NPCAP_PAGE))})
            else:
                self.send_json(404, {'ok': False})

    return Handler


class LocalServer(http.server.ThreadingHTTPServer):
    """Refuses a port another program holds. Python's default on Windows would share it, and requests would reach the wrong app."""
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self):
        if os.name == 'nt':
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def start_server(net, first_port):
    with open(os.path.join(RESOURCES, 'my_network.html'), encoding='utf-8') as f:
        page = f.read()
    token, launch_key, nonce = secrets.token_hex(32), secrets.token_urlsafe(24), secrets.token_urlsafe(18)
    body = page.replace('__NET_TOKEN__', token).replace('<script>', f'<script nonce="{nonce}">').encode('utf-8')
    for port in range(first_port, first_port + 3):   # the website looks for the app on these three
        try:
            server = LocalServer(('127.0.0.1', port), make_handler(net, body, token, port, launch_key, nonce))
        except OSError:
            continue
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f'http://localhost:{port}/?k={launch_key}'
    sys.exit(f"Couldn't open a local port for My_network (tried {first_port} to {first_port + 2}). Close another program using them and try again.")


def open_view(url):
    """A browser started from an elevated app would be elevated too, so Explorer opens it as the signed-in user, via a short-lived forwarding page."""
    if not is_admin():
        return webbrowser.open(url)
    try:
        handle, path = tempfile.mkstemp(prefix='my_network_', suffix='.html')
        with os.fdopen(handle, 'w', encoding='utf-8') as f:
            f.write(f'<!doctype html><meta charset=utf-8><meta http-equiv=refresh content="0;url={url}"><a href="{url}">Open My_network</a>')
        subprocess.Popen([os.path.join(WINDIR, 'explorer.exe'), path])
    except OSError:
        return False

    def remove():
        try:
            os.remove(path)
        except OSError:
            pass
    threading.Timer(20, remove).start()
    return True


def relaunch_as_admin():
    """True if Windows started an elevated copy (the person clicked Yes)."""
    args = subprocess.list2cmdline([os.path.abspath(__file__), *sys.argv[1:], '--no-elevate'])
    return (shell32.ShellExecuteW(None, 'runas', sys.executable, args, None, 1) or 0) > 32


def show_error(message):
    ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x10)


_instance_mutex = None


def another_copy_running():
    global _instance_mutex
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    _instance_mutex = kernel32.CreateMutexW(None, False, 'Local\\My_network')
    return ctypes.get_last_error() == 183   # ERROR_ALREADY_EXISTS


def is_redirected(path):
    """True if this folder is a junction or symbolic link, which could send the app's files somewhere else."""
    try:
        return os.lstat(path).st_reparse_tag in (0xA0000003, 0xA000000C)
    except OSError:
        return False


def link_target():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf'Software\Classes\{LINK_SCHEME}\shell\open\command') as k:
            found = re.match(r'^"([^"]+)"', winreg.QueryValueEx(k, '')[0])
            return found.group(1) if found else ''
    except OSError:
        return ''


def register_link(exe):
    """Lets a website's RUN button start this app, for this Windows user."""
    base = rf'Software\Classes\{LINK_SCHEME}'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'URL:{APP_NAME}')
        winreg.SetValueEx(k, 'URL Protocol', 0, winreg.REG_SZ, '')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r'\DefaultIcon') as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'"{exe}",0')
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r'\shell\open\command') as k:
        winreg.SetValueEx(k, '', 0, winreg.REG_SZ, f'"{exe}" "%1"')


def unregister_link():
    base = rf'Software\Classes\{LINK_SCHEME}'
    for sub in (r'\shell\open\command', r'\shell\open', r'\shell', r'\DefaultIcon', ''):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + sub)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description='A live 3D view of the devices around this PC and their traffic.')
    ap.add_argument('--demo', action='store_true', help='made-up devices and traffic, to try the view')
    ap.add_argument('--no-elevate', action='store_true', help="don't ask for Administrator rights (no packet capture without them)")
    ap.add_argument('--no-browser', action='store_true', help="don't open the browser")
    ap.add_argument('--port', type=int, default=8801, help='local port (default 8801; My Connections and My Security use 8765 to 8795)')
    ap.add_argument('--idle-exit', type=int, default=3, help='minutes without an open page before stopping (0 = never)')
    ap.add_argument('--app', action='store_true', default=FROZEN, help='one copy only (default for the exe)')
    ap.add_argument('link', nargs='?', help=argparse.SUPPRESS)   # mynetwork://run, passed by Windows
    args = ap.parse_args()

    exe = sys.executable if FROZEN else os.path.abspath(__file__)
    if args.link and not LINK_PATTERN.match(args.link):
        sys.exit('The app was started from an unsupported link. Links can only start the app or remove the link.')
    if args.link and (LINK_PATTERN.match(args.link).group(2) or '').lower() == 'unregister':
        unregister_link()
        if FROZEN:
            ctypes.windll.user32.MessageBoxW(None, 'The RUN button link was removed. Running My_network.exe again sets it up again.', APP_NAME, 0x40)
        return
    if FROZEN and args.app and (not link_target() or not os.path.isfile(link_target())):
        try:
            register_link(exe)
        except OSError:
            pass
    url_file = os.path.join(APP_DIR, 'running.url')
    if args.app:
        os.makedirs(APP_DIR, exist_ok=True)
        if is_admin() and is_redirected(APP_DIR):
            sys.exit(f"The app's folder ({APP_DIR}) points somewhere else, so it won't write there with Administrator rights. Delete that folder and start the app again.")
        if another_copy_running():
            try:
                with open(url_file, encoding='utf-8') as f:
                    saved = f.read().strip()
                if not DASHBOARD_URL.match(saved) or not open_view(saved):
                    show_error('The saved address is not valid. Stop My_network and start it again.')
            except OSError:
                show_error('My_network is already running, but its address could not be found. Wait a minute and try again.')
            return

    upgraded = npcap_installed() and scapy_installed()   # Npcap normally works without Administrator rights
    if not args.demo and not args.no_elevate and not upgraded and not is_admin() and relaunch_as_admin():
        return

    if args.demo:
        net = Network(DEMO_ME, '255.255.255.0', DEMO_ROUTER, 0, 'demo', 'Demo: these devices and packets are made up.')
        workers = [run_demo]
    else:
        local = local_network()
        if not local:
            sys.exit('This PC does not seem to be on a network right now.')
        mode, note = ('capture', '') if is_admin() or upgraded else ('connections', 'Not running as Administrator: devices and connections only, no packets.')
        net = Network(*local, mode, note)
        workers = [run_discovery, run_connections, run_capture, run_blocklists]
    for worker in workers:
        threading.Thread(target=worker, args=(net,), daemon=True, name=worker.__name__).start()

    server, url = start_server(net, args.port)
    if args.app:
        with open(url_file, 'w', encoding='utf-8') as f:
            f.write(url)
    print(f'{APP_NAME} is running: {url}')
    print('Close with the Stop button on the page, or Ctrl+C here.')
    if not args.no_browser:
        open_view(url)
    net.last_client = time.time()
    try:
        while not net.stop.wait(1):
            net.tick()
            if args.idle_exit and time.time() - net.last_client > args.idle_exit * 60:
                print('The page has been closed for a while, stopping.')
                break
    except KeyboardInterrupt:
        pass
    net.stop.set()
    server.shutdown()
    if args.app:
        try:
            os.remove(url_file)
        except OSError:
            pass
    os._exit(0)


if __name__ == '__main__':
    try:
        main()
    except SystemExit as e:
        if FROZEN and isinstance(e.code, str):
            show_error(e.code)
        raise
    except Exception:
        if not FROZEN:
            raise
        import traceback
        os.makedirs(APP_DIR, exist_ok=True)
        with open(os.path.join(APP_DIR, 'error.log'), 'a', encoding='utf-8') as f:
            f.write(f'{time.ctime()}\n{traceback.format_exc()}\n')
        show_error(f'My_network stopped because of an unexpected problem. Details are in {APP_DIR}\\error.log')
