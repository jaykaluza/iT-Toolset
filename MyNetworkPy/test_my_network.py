"""Tests for My_network that need no Administrator rights.  Run:  py -m unittest test_my_network  (from this folder)"""

import http.client
import os
import random
import socket
import struct
import threading
import unittest

import My_network as m

ME, ROUTER, TV, SITE = '192.168.1.5', '192.168.1.1', '192.168.1.40', '203.0.113.10'


def network():
    return m.Network(ME, '255.255.255.0', ROUTER, 1, 'demo')


def layer(info, title):
    return dict(next(x for x in info['layers'] if x['title'] == title)['fields'])


class Decoding(unittest.TestCase):
    def test_tcp_syn_fields(self):
        info = m.decode_packet(m.build_packet(ME, SITE, 6, 50000, 443, flags=0x02, ttl=61, seq=77))
        ip, tcp = layer(info, 'IPv4 header'), layer(info, 'TCP header')
        self.assertEqual((ip['Source'], ip['Destination'], ip['Time to live']), (ME, SITE, '61'))
        self.assertIn('(valid)', ip['Header checksum'])
        self.assertEqual((tcp['Source port'], tcp['Destination port'], tcp['Flags'], tcp['Sequence number']), ('50000', '443 HTTPS', 'SYN', '77'))
        self.assertIn('[SYN]', info['summary'])

    def test_tls_server_name(self):
        info = m.decode_packet(m.build_packet(ME, SITE, 6, 50000, 443, m.build_client_hello('www.example.com')))
        tls = layer(info, 'TLS')
        self.assertEqual((tls['Handshake'], tls['Server name (SNI)'], tls['Application protocols (ALPN)']), ('ClientHello', 'www.example.com', 'h2'))
        self.assertEqual(info['summary'], 'TLS ClientHello www.example.com')

    def test_dns_query(self):
        info = m.decode_packet(m.build_packet(ME, ROUTER, 17, 50000, 53, m.build_dns_query('example.com', 28)))
        self.assertEqual(layer(info, 'DNS')['Question'], 'example.com (AAAA)')
        self.assertEqual(info['summary'], 'DNS query example.com AAAA')

    def test_dns_answer_with_name_pointer(self):
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(SITE)
        reply = b'\x12\x34\x81\x80\0\1\0\1\0\0\0\0\7example\3com\0\0\1\0\1' + answer
        info = m.decode_packet(m.build_packet(ROUTER, ME, 17, 53, 50000, reply))
        self.assertEqual(info['summary'], f'DNS response example.com = {SITE}')

    def test_dns_pointer_loop_stops(self):
        with self.assertRaises(ValueError):
            m.dns_name(b'\xc0\x00', 0)

    def test_http_request_line(self):
        info = m.decode_packet(m.build_packet(ME, TV, 6, 50000, 80, b'GET /a HTTP/1.1\r\nHost: tv\r\n\r\n'))
        self.assertEqual(layer(info, 'HTTP')['Host'], 'tv')

    def test_icmp_echo(self):
        info = m.decode_packet(m.build_packet(ME, ROUTER, 1, payload=struct.pack('!BBHHH', 8, 0, 0, 1, 9)))
        self.assertEqual(layer(info, 'ICMP')['Sequence'], '9')
        self.assertEqual(info['summary'], 'ICMP Echo request')

    def test_hexdump_shape(self):
        self.assertEqual(m.hexdump(b'AB'), '0000  41 42' + ' ' * 42 + '  AB')

    def test_control_characters_are_removed_from_names(self):
        self.assertEqual(m.clean('tv\r\n\x1b[31m'), 'tv[31m')

    def test_garbage_and_truncation_never_raise(self):
        rng = random.Random(4)
        good = m.build_packet(ME, SITE, 6, 50000, 443, m.build_client_hello('x.example'))
        dns = m.build_packet(ME, ROUTER, 17, 5, 53, m.build_dns_query('a.example'))
        for packet in (good, dns):
            for cut in range(len(packet)):
                m.decode_packet(packet[:cut])
        for _ in range(4000):
            raw = bytearray(rng.randbytes(rng.randrange(0, 200)))
            if len(raw) > 20:
                raw[0], raw[9] = 0x45, rng.choice((1, 2, 6, 17))
                raw[20:24] = struct.pack('!HH', rng.choice((53, 443, 67, 123, 1900, 80)), rng.randrange(65536))
            m.decode_packet(bytes(raw))


class Tracking(unittest.TestCase):
    def test_syn_decides_the_client_even_with_a_high_server_port(self):
        net = network()
        net.ingest(m.build_packet(ME, TV, 6, 2000, 50000, flags=0x02), 100.0)
        net.ingest(m.build_packet(TV, ME, 6, 50000, 2000, flags=0x12), 100.1)
        flow = next(iter(net.flows.values()))
        self.assertEqual((flow.a, flow.ap, flow.b, flow.bp), (ME, 2000, TV, 50000))
        self.assertEqual((flow.pkts_ab, flow.pkts_ba, len(net.flows)), (1, 1, 1))
        self.assertEqual(flow.state, 'SYN-ACK')

    def test_event_has_the_receiving_port(self):
        net = network()
        net.ingest(m.build_packet(TV, ME, 6, 80, 50000, b'x'), 100.0)
        event = net.events[-1]
        self.assertEqual((event[2], event[4], event[9]), (TV, ME, '50000'))

    def test_portless_protocol_is_labelled(self):
        net = network()
        net.ingest(m.build_packet(ME, ROUTER, 1, payload=bytes(8)), 100.0)
        self.assertEqual(net.events[-1][9], 'ICMP')

    def test_fast_packets_are_counted_but_animated_sparingly(self):
        net = network()
        for i in range(50):
            net.ingest(m.build_packet(ME, SITE, 6, 50000, 443, b'x'), 100.0 + i * 0.001)
        self.assertEqual(net.total['pkts'], 50)
        self.assertEqual(len(net.events), 2)

    def test_ring_keeps_only_the_latest(self):
        net = network()
        for _ in range(m.RING + 10):
            net.ingest(m.build_packet(ME, SITE, 6, 50000, 443, b'x'))
        self.assertEqual(len(next(iter(net.flows.values())).ring), m.RING)

    def test_kinds(self):
        net = network()
        self.assertEqual([net.kind(i) for i in (ME, ROUTER, TV, SITE, '224.0.0.251', '192.168.1.255', '255.255.255.255')],
                         ['me', 'gateway', 'lan', 'external', 'group', 'group', 'group'])

    def test_flow_detail_shows_direction_and_layers(self):
        net = network()
        net.add_device(TV, 'aa:bb:cc:dd:ee:ff')
        net.ingest(m.build_packet(ME, TV, 6, 50000, 80, flags=0x02))
        net.ingest(m.build_packet(TV, ME, 6, 80, 50000, flags=0x12))
        fid = next(iter(net.flows.values())).id
        detail = net.flow_detail(fid)
        self.assertEqual([p['forward'] for p in detail['packets']], [True, False])
        self.assertEqual(detail['b_mac'], 'aa:bb:cc:dd:ee:ff')
        self.assertEqual([x['title'] for x in detail['packets'][0]['layers']], ['Ethernet', 'IPv4 header', 'TCP header'])
        self.assertIsNone(net.flow_detail(fid + 1))

    def frame(self, kind, body, src_mac=b'\xaa\xbb\xcc\0\0\1', dst_mac=b'\xaa\xbb\xcc\0\0\2'):
        return dst_mac + src_mac + struct.pack('!H', kind) + body

    def arp(self, op, sender, target, mac=b'\xaa\xbb\xcc\0\0\1'):
        return b'\0\1\x08\0\6\4' + struct.pack('!H', op) + mac + socket.inet_aton(sender) + bytes(6) + socket.inet_aton(target)

    def test_ethernet_frame_shows_real_macs(self):
        net = network()
        net.add_device(TV)
        net.ingest_frame(self.frame(0x0800, m.build_packet(TV, ME, 6, 80, 50000, b'x')))
        detail = net.flow_detail(next(iter(net.flows.values())).id)
        fields = dict(detail['packets'][0]['layers'][0]['fields'])
        self.assertEqual((fields['Source MAC'], fields['Destination MAC']), ('aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:02'))
        self.assertEqual(net.nodes[TV]['mac'], 'aa:bb:cc:00:00:01')

    def test_vlan_tag_is_skipped(self):
        net = network()
        net.ingest_frame(self.frame(0x8100, struct.pack('!HH', 5, 0x0800) + m.build_packet(TV, ME, 6, 80, 50000, b'x')))
        self.assertEqual(net.total['pkts'], 1)

    def test_arp_reply_finds_a_device_and_decodes(self):
        net = network()
        net.ingest_frame(self.frame(m.ARP, self.arp(2, TV, ME)))
        self.assertEqual(net.nodes[TV]['mac'], 'aa:bb:cc:00:00:01')
        self.assertEqual(net.events[-1][9], 'ARP')
        detail = net.flow_detail(next(iter(net.flows.values())).id)
        self.assertEqual(detail['packets'][0]['summary'], f'ARP {TV} is at aa:bb:cc:00:00:01')

    def test_arp_request_for_nobody_does_not_invent_a_device(self):
        net = network()
        net.ingest_frame(self.frame(m.ARP, self.arp(1, ME, '192.168.1.200')))
        self.assertNotIn('192.168.1.200', net.nodes)
        self.assertEqual(len(net.flows), 0)

    def test_arp_from_outside_the_network_is_ignored(self):
        net = network()
        net.ingest_frame(self.frame(m.ARP, self.arp(2, '10.9.9.9', ME)))
        self.assertNotIn('10.9.9.9', net.nodes)

    def test_short_frames_are_ignored(self):
        net = network()
        net.ingest_frame(b'\0' * 13)
        net.ingest_frame(self.frame(m.ARP, b'\0' * 5))
        self.assertEqual(net.total['pkts'], 0)

    def test_scapy_install_pins_the_version_and_runs_once(self):
        net = network()
        calls, release = [], threading.Event()

        class Done:
            returncode, stdout, stderr = 0, 'Successfully installed', ''

        def fake_run(command, **kwargs):
            calls.append(command)
            release.wait(5)
            return Done()
        original, m.subprocess.run = m.subprocess.run, fake_run
        try:
            m.install_scapy(net)
            m.install_scapy(net)
            self.assertEqual(net.scapy_install['state'], 'running')
            release.set()
            for t in threading.enumerate():
                if t.name == 'install-scapy':
                    t.join(5)
        finally:
            m.subprocess.run = original
        self.assertEqual(len(calls), 1)
        self.assertIn(f'scapy=={m.SCAPY_VERSION}', calls[0])
        self.assertEqual(net.scapy_install['state'], 'done')

    def test_name_priority(self):
        net = network()
        net.add_device(TV)
        net.set_name(TV, 'Reverse DNS', 'host-40.lan')
        net.set_name(TV, 'Device description', 'Living Room TV')
        net.set_name(TV, 'NetBIOS', 'SOMETHING')
        self.assertEqual(net.nodes[TV]['name'], 'Living Room TV')

    def test_idle_connections_are_forgotten(self):
        net = network()
        net.ingest(m.build_packet(ME, SITE, 6, 50000, 443, b'x'), 1.0)
        net.tick()
        self.assertEqual((len(net.flows), len(net.flow_ids)), (0, 0))
        self.assertNotIn(SITE, net.nodes)


@unittest.skipUnless(os.name == 'nt', 'Windows only')
class WindowsFacts(unittest.TestCase):
    def test_local_network_and_tables_can_be_read(self):
        local = m.local_network()
        self.assertIsNotNone(local)
        self.assertIsInstance(m.arp_table(local[3]), dict)
        self.assertTrue(all(len(row) == 6 for row in m.tcp_connections()))
        self.assertIsInstance(m.udp_owners(), dict)


class Explaining(unittest.TestCase):
    def flow(self, net):
        return next(iter(net.flows.values()))

    def test_plain_sentence_and_no_warnings(self):
        net = network()
        net.ingest(m.build_packet(ME, SITE, 6, 50000, 443, b'x' * 100, flags=0x02))
        net.ingest(m.build_packet(SITE, ME, 6, 443, 50000, b'x' * 900, flags=0x12))
        plain = net.explain(self.flow(net))
        self.assertEqual(plain['who'], f'This PC is sending data to {SITE} on port 443. Sent 140 B, received 940 B back.')
        self.assertIn('Encrypted web traffic (HTTPS)', plain['data'])
        self.assertEqual((plain['level'], plain['reasons']), ('ok', []))

    def test_only_incoming_says_who_is_actually_sending(self):
        net = network()
        flow = net.flow(6, ME, 50000, SITE, 443, 0x02, 1.0)
        flow.bytes_ba = 5000
        self.assertEqual(net.explain(flow)['who'], f'{SITE} is sending data to This PC. Sent 5.0 KB so far.')

    def test_program_is_named(self):
        net = network()
        net.ingest(m.build_packet(ME, SITE, 6, 50000, 443, b'x'))
        flow = self.flow(net)
        flow.process, flow.path = 'opera.exe (PID 9)', r'C:\Program Files\Opera\opera.exe'
        self.assertTrue(net.explain(flow)['who'].startswith('opera.exe on This PC is sending'))

    def test_listed_target_is_a_warning(self):
        net = network()
        net.blocklists.load('Feodo Tracker', '# comment\n8.8.4.4\n')
        net.ingest(m.build_packet(ME, '8.8.4.4', 6, 50000, 443, b'x'))
        plain = net.explain(self.flow(net))
        self.assertEqual(plain['level'], 'bad')
        self.assertTrue(plain['listed'].startswith('Yes.'))

    def test_range_lists_match_only_inside_the_range(self):
        lists = m.Blocklists()
        self.assertEqual(lists.load('Spamhaus DROP', '8.8.8.0/24 ; SBL2\n'), 1)
        self.assertEqual(lists.lookup('8.8.8.200'), 'Spamhaus DROP')
        self.assertEqual(lists.lookup('8.8.9.1'), '')

    def test_damaged_list_flags_nothing(self):
        lists = m.Blocklists()
        self.assertEqual(lists.load('Feodo Tracker', '<html>error</html>\n0.0.0.0/0\n192.168.0.0/16\n1.0.0.0/2\n999.1.1.1\n'), 0)
        self.assertEqual(lists.lookup('8.8.8.8'), '')
        self.assertIn('Not checked', lists.status())

    def test_unavailable_lists_are_not_reported_as_clean(self):
        net = network()
        net.ingest(m.build_packet(ME, SITE, 6, 50000, 443, b'x'))
        self.assertIn('Not checked', net.explain(self.flow(net))['listed'])

    def test_backdoor_port_is_a_warning(self):
        net = network()
        net.ingest(m.build_packet(ME, SITE, 6, 50000, 4444, b'x', flags=0x02))
        plain = net.explain(self.flow(net))
        self.assertEqual(plain['level'], 'bad')
        self.assertIn('Metasploit', plain['reasons'][0])

    def test_inbound_remote_desktop_from_the_internet_is_a_warning(self):
        net = network()
        net.ingest(m.build_packet(SITE, ME, 6, 50000, 3389, b'x', flags=0x02))
        self.assertEqual(net.explain(self.flow(net))['level'], 'bad')

    def test_file_sharing_inside_the_network_is_fine(self):
        net = network()
        net.ingest(m.build_packet(ME, TV, 6, 50000, 445, b'x', flags=0x02))
        plain = net.explain(self.flow(net))
        self.assertEqual(plain['level'], 'ok')
        self.assertIn('own network', plain['listed'])

    def test_program_in_a_temp_folder_is_worth_a_look(self):
        net = network()
        net.ingest(m.build_packet(ME, SITE, 6, 50000, 443, b'x'))
        flow = self.flow(net)
        flow.process, flow.path = 'x.exe (PID 9)', r'C:\Users\a\AppData\Local\Temp\x.exe'
        self.assertEqual(net.explain(flow)['level'], 'watch')

    def test_fake_system_program_is_a_warning(self):
        net = network()
        net.ingest(m.build_packet(ME, SITE, 6, 50000, 443, b'x'))
        flow = self.flow(net)
        flow.process, flow.path = 'svchost.exe (PID 9)', r'C:\Users\a\svchost.exe'
        self.assertEqual(net.explain(flow)['level'], 'bad')

    def test_every_flow_view_can_be_explained(self):
        net = network()
        net.ingest(m.build_packet(TV, '224.0.0.251', 17, 5353, 5353, b'x'))
        net.ingest(m.build_packet(ME, ROUTER, 1, payload=bytes(8)))
        for view in net.state()['flows']:
            self.assertTrue(view['plain']['who'] and view['plain']['data'])


class PortClaim(unittest.TestCase):
    def test_a_port_in_use_is_skipped_for_the_next_one(self):
        other_app = m.http.server.ThreadingHTTPServer(('127.0.0.1', 18990), m.http.server.BaseHTTPRequestHandler)   # bound the way the other Nesiam apps bind
        server = None
        try:
            server, url = m.start_server(network(), 18990)
            self.assertIn('localhost:18991/', url)
        finally:
            other_app.server_close()
            if server:
                server.shutdown()
                server.server_close()


class PageAccess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.net = network()
        token, cls.key, cls.token = 't' * 64, 'launchkey', 't' * 64
        handler = m.make_handler(cls.net, b'<html>', token, 18999, cls.key, 'nonce')
        cls.server = m.http.server.ThreadingHTTPServer(('127.0.0.1', 18999), handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def status(self, path, headers=None, method='GET'):
        c = http.client.HTTPConnection('127.0.0.1', 18999, timeout=5)
        c.request(method, path, headers={'Host': 'localhost:18999', **(headers or {})})
        response = c.getresponse()
        response.read()
        c.close()
        return response.status

    def test_page_needs_the_private_address(self):
        self.assertEqual(self.status('/?k=launchkey'), 200)
        self.assertEqual(self.status('/'), 403)
        self.assertEqual(self.status('/?k=wrong'), 403)

    def test_data_needs_the_token(self):
        self.assertEqual(self.status('/state'), 403)
        self.assertEqual(self.status('/state', {'X-Net-Token': 'nope'}), 403)
        self.assertEqual(self.status('/state', {'X-Net-Token': self.token}), 200)

    def test_other_sites_and_addresses_are_refused(self):
        self.assertEqual(self.status('/state', {'X-Net-Token': self.token, 'Origin': 'https://evil.example'}), 403)
        self.assertEqual(self.status('/state', {'X-Net-Token': self.token, 'Host': 'evil.example:18999'}), 403)

    def test_website_can_only_see_that_it_is_running(self):
        site = {'Origin': 'https://jaykaluza.github.io'}
        self.assertEqual(self.status('/status', site), 200)
        self.assertEqual(self.status('/status'), 403)
        self.assertEqual(self.status('/status', {'Origin': 'https://evil.example'}), 403)
        self.assertEqual(self.status('/state', site), 403)

    def test_only_the_website_can_press_stop(self):
        self.assertEqual(self.status('/site-stop', {'Origin': 'https://evil.example'}, 'POST'), 403)
        self.assertEqual(self.status('/site-stop', method='POST'), 403)
        self.assertFalse(self.net.stop.is_set())

    def test_links_only_start_or_remove(self):
        for good in ('mynetwork://run', 'mynetwork://run/', 'mynetwork://unregister', 'mynetwork:'):
            self.assertTrue(m.LINK_PATTERN.match(good), good)
        for bad in ('mynetwork://run --demo', 'mynetwork://evil', 'http://x'):
            self.assertIsNone(m.LINK_PATTERN.match(bad), bad)

    def test_install_is_off_in_demo_and_needs_the_token(self):
        self.assertEqual(self.status('/install-scapy', method='POST'), 403)
        self.assertEqual(self.status('/open-npcap-page', method='POST'), 403)
        self.assertEqual(self.status('/install-scapy', {'X-Net-Token': self.token}, 'POST'), 404)
        self.assertEqual(self.net.scapy_install['state'], 'idle')

    def test_stop_needs_the_token(self):
        self.assertEqual(self.status('/quit', method='POST'), 403)
        self.assertFalse(self.net.stop.is_set())

    def test_bad_number_is_a_clean_error(self):
        self.assertEqual(self.status('/flow?id=abc', {'X-Net-Token': self.token}), 400)


if __name__ == '__main__':
    unittest.main()
