"""Checks that don't need a Mac: run with  python3 -m unittest  in this folder."""
import argparse
import json
import unittest

import MyConnections as app


class Parsing(unittest.TestCase):
    def test_endpoints(self):
        self.assertEqual(app.parse_endpoint('10.0.0.2:5000'), ('10.0.0.2', 5000))
        self.assertEqual(app.parse_endpoint('[::1]:631', 'IPv6'), ('::1', 631))
        self.assertEqual(app.parse_endpoint('[fe80::1%en0]:49152', 'IPv6'), ('fe80::1', 49152))
        self.assertEqual(app.parse_endpoint('*:5353'), ('0.0.0.0', 5353))
        self.assertEqual(app.parse_endpoint('*:5353', 'IPv6'), ('::', 5353))
        self.assertEqual(app.parse_endpoint('*:*'), ('0.0.0.0', 0))

    def test_lsof(self):
        tcp, udp, conn = app.parse_lsof(app.DEMO_LSOF)
        self.assertIn(('Listen', '0.0.0.0', 5000, '0.0.0.0', 0, 340), tcp)
        self.assertIn(('Listen', '::', 7000, '0.0.0.0', 0, 340), tcp)
        self.assertIn(('Established', '192.168.1.20', 50112, '17.57.146.68', 5223, 512), tcp)
        self.assertIn(('CloseWait', '192.168.1.20', 50302, '151.101.1.140', 443, 1204), tcp)
        self.assertIn(('Established', '2600:1f18:24e6:b900::10', 50231, '2606:4700::6810:84e5', 443, 902), tcp)
        self.assertEqual(sorted(udp), [('0.0.0.0', 5353, 212), ('::', 5353, 212)])
        self.assertEqual(conn, [('192.168.1.20', 58911, '142.250.72.14', 443, 1204)])

    def test_lsof_state_only_in_name(self):
        tcp, _, _ = app.parse_lsof('p7\nf1\ntIPv4\nPTCP\nn1.2.3.4:5->8.8.8.8:443 (ESTABLISHED)\n')
        self.assertEqual(tcp, [('Established', '1.2.3.4', 5, '8.8.8.8', 443, 7)])

    def test_same_socket_in_two_descriptors_counts_once(self):
        tcp, _, _ = app.parse_lsof('p7\nf1\ntIPv4\nPTCP\nn1.2.3.4:5->8.8.8.8:443\nTST=ESTABLISHED\nf2\ntIPv4\nPTCP\nn1.2.3.4:5->8.8.8.8:443\nTST=ESTABLISHED\n')
        self.assertEqual(len(tcp), 1)

    def test_ps(self):
        procs = app.parse_ps(app.DEMO_PS)
        self.assertEqual(procs[0], ('kernel_task', ''))
        self.assertEqual(procs[1310], ('Slack', '/Applications/Slack.app/Contents/MacOS/Slack'))
        self.assertEqual(procs[1204][0], 'Google Chrome Helper')

    def test_netstat_counts_real_adapters_once(self):
        got = app.parse_netstat(app.DEMO_NETSTAT.format(rx=1000, tx=2000))
        self.assertEqual(got, {'en0': (1000, 2000)})

    def test_netstat_adapter_without_hardware_address(self):
        text = 'en5   1500  <Link#9>     100     0   5000   200     0   6000     0\n'
        self.assertEqual(app.parse_netstat(text), {'en5': (5000, 6000)})

    def test_external(self):
        self.assertTrue(app.is_external('17.57.146.68'))
        self.assertTrue(app.is_external('2606:4700::6810:84e5'))
        for ip in ('192.168.1.20', '127.0.0.1', '::1', 'fe80::1', '224.0.0.251', 'not-an-address'):
            self.assertFalse(app.is_external(ip), ip)


class Signatures(unittest.TestCase):
    def test_kinds(self):
        apple = 'Identifier=x\nAuthority=Software Signing\nAuthority=Apple Code Signing Certification Authority\nAuthority=Apple Root CA\n'
        self.assertEqual(app.parse_codesign(apple, False), {'Publisher': 'Apple', 'Kind': 'apple', 'Status': 'Valid'})
        dev = 'Authority=Developer ID Application: Google LLC (EQHXZ8M8AV)\nAuthority=Developer ID Certification Authority\n'
        self.assertEqual(app.parse_codesign(dev, False), {'Publisher': 'Google LLC', 'Kind': 'developer', 'Status': 'Valid'})
        self.assertEqual(app.parse_codesign('Authority=Apple Mac OS Application Signing\n', False)['Kind'], 'appstore')
        self.assertEqual(app.parse_codesign('x: code object is not signed at all\n', True)['Status'], 'NotSigned')
        self.assertEqual(app.parse_codesign('Signature=adhoc\nTeamIdentifier=not set\n', False)['Status'], 'AdHoc')
        broken = app.parse_codesign(dev, True)
        self.assertEqual((broken['Status'], broken['Publisher']), ('Invalid', ''))
        self.assertEqual(app.parse_codesign('', True)['Status'], 'Unknown')

    def test_origin(self):
        info = {'Path': '/x', 'Name': 'x'}
        self.assertEqual(app.origin_of(info, {'Status': 'Valid', 'Kind': 'apple'}), 'macos')
        self.assertEqual(app.origin_of(info, {'Status': 'Valid', 'Kind': 'developer'}), 'thirdparty')
        self.assertEqual(app.origin_of(info, {'Status': 'Invalid', 'Kind': 'developer'}), 'unsigned')
        self.assertEqual(app.origin_of({'Path': '', 'Name': 'kernel_task'}, {}), 'macos')


class Risks(unittest.TestCase):
    def info(self, name, path, sig='Valid'):
        return {'Name': name, 'Path': path, 'Signature': sig}

    def test_normal_app_is_ok(self):
        self.assertEqual(app.app_issues(self.info('Slack', '/Applications/Slack.app/Contents/MacOS/Slack')), [])

    def test_downloads_folder(self):
        self.assertEqual(app.risk_level(app.app_issues(self.info('tool', '/Users/demo/Downloads/tool'))), 'high')

    def test_lookalike(self):
        self.assertEqual(app.risk_level(app.app_issues(self.info('launchd', '/Users/demo/launchd'))), 'high')
        self.assertEqual(app.app_issues(self.info('launchd', '/sbin/launchd')), [])

    def test_unsigned_is_only_worth_checking(self):
        self.assertEqual(app.risk_level(app.app_issues(self.info('brewtool', '/opt/homebrew/bin/brewtool', 'AdHoc'))), 'medium')


class WholeRefresh(unittest.TestCase):
    def run_monitor(self, polls=2):
        args = argparse.Namespace(outdir=None, demo=True, interval=3, closed_retention=10, static_dns=app.DEMO_DNS, force_admin=True)
        m = app.Monitor(args, app.demo_sources())
        for _ in range(polls):
            m.poll()
        m.sig_pool.shutdown(wait=True)
        m.poll()
        return json.loads(m.latest_json)

    def test_payload(self):
        d = self.run_monitor()
        by_port = {c['LocalPort']: c for c in d['connections']}
        self.assertEqual(by_port[50112]['RemoteHost'], 'courier.push.apple.com')
        self.assertEqual(by_port[50112]['Risk'], '')
        self.assertEqual(by_port[50112]['Direction'], 'Outbound')
        self.assertEqual(by_port[58911]['Protocol'], 'UDP')
        self.assertEqual(by_port[50500]['Risk'], 'high')          # Downloads folder and a Tor port
        self.assertEqual(by_port[50600]['Risk'], 'medium')        # curl
        self.assertFalse(by_port[50411]['External'])
        self.assertEqual(by_port[50301]['Description'], 'Google Chrome')
        self.assertEqual(d['apps']['Google Chrome Helper']['Publisher'], 'Google LLC')
        self.assertEqual(d['apps']['Google Chrome Helper']['Origin'], 'thirdparty')
        self.assertEqual(d['apps']['apsd']['Origin'], 'macos')
        ssh = next(l for l in d['listeners'] if l['LocalPort'] == 22)
        self.assertEqual((ssh['Exposed'], ssh['Risk']), (True, 'medium'))
        self.assertIsNotNone(d['rxRate'])

    def test_closed_connections_stay_listed(self):
        args = argparse.Namespace(outdir=None, demo=True, interval=3, closed_retention=10, static_dns=app.DEMO_DNS, force_admin=True)
        src = app.demo_sources()
        m = app.Monitor(args, src)
        m.poll()
        src['lsof'] = lambda: ''
        m.poll()
        d = json.loads(m.latest_json)
        self.assertTrue(d['connections'] and all(c['Closed'] for c in d['connections']))


if __name__ == '__main__':
    unittest.main()
