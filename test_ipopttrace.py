import socket
import struct
import unittest
import contextlib
import io
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import ipopttrace as t


class PacketTests(unittest.TestCase):
    def probe(self, mode='tcp', profile='rr'):
        return dict(src='192.0.2.1', dst='198.51.100.1', ttl=5, id=1234,
                    sport=40000, dport=443, seq=123456, mode=mode, profile=profile)

    def wire(self, p):
        return t.packet(p['src'], p['dst'], p['ttl'], p['id'], p['sport'],
                        p['dport'], p['seq'], p['mode'], t.PROFILES[p['profile']])

    def icmp(self, quote, typ=11, code=0):
        body = bytes([typ, code, 0, 0, 0, 0, 0, 0]) + quote
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 7, 0,
                             64, 1, 0, socket.inet_aton('203.0.113.9'),
                             socket.inet_aton('192.0.2.1'))
        return header + body

    def test_all_wire_checksums(self):
        for mode in ('tcp', 'udp'):
            for profile in t.PROFILES:
                p = self.probe(mode, profile)
                wire = self.wire(p)
                ip = t.ipv4(wire)
                self.assertEqual(t.checksum(wire[:ip['ihl']]), 0)
                pseudo = wire[12:20] + struct.pack('!BBH', 0, ip['proto'], len(ip['body']))
                self.assertEqual(t.checksum(pseudo + ip['body']), 0)
                self.assertEqual(struct.unpack_from('!H', wire, 2)[0], len(wire))
                self.assertLessEqual(ip['ihl'], 60)

    def test_minimum_quote_with_options(self):
        p = self.probe()
        wire = self.wire(p)
        quote = wire[:t.ipv4(wire)['ihl'] + 8]
        r = t.decode_reply(self.icmp(quote), p)
        self.assertEqual(r['status'], 'ttl_exceeded')
        self.assertEqual(r['quoted_ihl'], 60)
        self.assertEqual(r['option_state'], 'same')
        wrong = dict(p, seq=p['seq'] + 1)
        self.assertIsNone(t.decode_reply(self.icmp(quote), wrong))
        self.assertIsNone(t.decode_reply(self.icmp(quote[:-1]), p))

    def test_nat_quote_and_stripped_options(self):
        p = self.probe()
        wire = self.wire(p)
        ip = t.ipv4(wire)
        quote = bytearray(wire[:20] + ip['body'][:8])
        quote[0] = 0x45
        quote[12:16] = socket.inet_aton('203.0.113.1')
        quote[20:22] = struct.pack('!H', 50000)
        r = t.decode_reply(self.icmp(bytes(quote)), p)
        self.assertEqual(r['option_state'], 'absent')
        self.assertEqual(r['quoted_source_port'], 50000)

    def test_explicit_rejection(self):
        p = self.probe()
        r = t.decode_reply(self.icmp(self.wire(p), 3, 13), p)
        self.assertEqual(r['status'], 'admin_prohibited')
        self.assertFalse(r['terminal'])

    def test_direct_tcp_reply_and_wrong_ack(self):
        p = self.probe()
        incoming = bytearray(t.packet(p['dst'], p['src'], 64, 7, p['dport'],
                                     p['sport'], 42, 'tcp', b''))
        incoming[33] = 0x12
        incoming[28:32] = struct.pack('!I', p['seq'] + 1)
        self.assertEqual(t.decode_reply(bytes(incoming), p)['status'], 'tcp_synack')
        incoming[31] ^= 1
        self.assertIsNone(t.decode_reply(bytes(incoming), p))

    def test_udp_destination(self):
        p = self.probe('udp')
        reply = bytearray(self.icmp(self.wire(p), 3, 3))
        reply[12:16] = socket.inet_aton(p['dst'])
        self.assertTrue(t.decode_reply(bytes(reply), p)['terminal'])

    def test_candidate_requires_controls_and_no_later_success(self):
        rows = []
        for ttl in range(1, 5):
            for _ in range(3):
                rows.append(dict(profile='none', ttl=ttl, status='ttl_exceeded'))
                rows.append(dict(profile='rr', ttl=ttl, status='ttl_exceeded' if ttl == 1 else 'timeout'))
        summary = t.summarize(rows, ['none', 'rr'])[0]
        self.assertEqual(summary['possible_silent_boundary'],
                         dict(after_observed_ttl=1, by_tested_ttl=2))
        rows.append(dict(profile='rr', ttl=4, status='ttl_exceeded'))
        self.assertIsNone(t.summarize(rows, ['none', 'rr'])[0]['possible_silent_boundary'])

    def test_parallel_out_of_order_and_individual_timeout(self):
        engine = t.Engine.__new__(t.Engine)
        engine.src, engine.dst, engine.mode = '192.0.2.1', '198.51.100.1', 'udp'
        engine.interval, engine.next_send, engine.ident = 0.05, 0, 1
        clock, queued, sends = [0.0], [], []

        class UDP:
            def getsockname(self):
                return ('192.0.2.1', 40000)

        class TX:
            def sendto(inner, wire, address):
                sends.append(clock[0])
                if t.ipv4(wire)['options'] != t.PROFILES['ts']:
                    queued.insert(0, self.icmp(wire))

        class RX:
            def recv(self, size):
                return queued.pop(0)

        engine.udp, engine.tx, engine.rx = UDP(), TX(), [RX()]

        def select_fn(read, write, error, timeout):
            if queued:
                clock[0] = min(clock[0] + timeout, max(clock[0], 0.2))
                return (read if clock[0] >= 0.2 else [], [], [])
            clock[0] += timeout
            return [], [], []

        with patch.object(t.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(t.time, 'time', side_effect=lambda: clock[0]), \
                patch.object(t.select, 'select', side_effect=select_fn):
            rows = list(engine.probe_many(3, ['none', 'nop4', 'rr', 'ts'], 443, 1, 1))
        self.assertEqual([r['profile'] for r in rows], ['rr', 'nop4', 'none', 'ts'])
        self.assertEqual(rows[-1]['status'], 'timeout')
        self.assertAlmostEqual(sends[-1], 0.15)
        self.assertAlmostEqual(clock[0], 1.15)

    def run_cycles(self, options, terminal_ttl, interrupt_second=False):
        calls = []

        class FakeEngine:
            def __init__(self, *args):
                pass

            def probe_many(self, ttl, profiles, port, attempt, timeout, observer=None):
                if interrupt_second and len(calls) >= terminal_ttl:
                    raise KeyboardInterrupt
                calls.append(ttl)
                for name in profiles:
                    terminal = ttl == terminal_ttl and name == 'none'
                    row = dict(profile=name, ttl=ttl, attempt=attempt,
                               status='tcp_rst' if terminal else 'ttl_exceeded',
                               reply='198.51.100.1' if terminal else '192.0.2.2',
                               rtt_ms=0.2, terminal=terminal)
                    if observer:
                        observer('sent', row)
                    yield row

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'trace.jsonl'
            argv = ['ipopttrace.py', '198.51.100.1', '--source', '192.0.2.1',
                    '--parallel', '--profiles', 'none,nop4', '--no-dns', '-q', '1',
                    '-m', '5', '--interval', '0', '--jsonl', str(output), *options]
            with patch.object(t, 'Engine', FakeEngine), patch.object(t.sys, 'argv', argv), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                t.main()
            records = [json.loads(line) for line in output.read_text().splitlines()]
        return calls, records

    def test_target_restarts_prior_hops_and_never_tests_later_hops(self):
        calls, records = self.run_cycles(['--cycles', '2'], 3)
        self.assertEqual(calls, [1, 2, 3, 1, 2, 3])
        probes = [r for r in records if r['type'] == 'probe']
        self.assertEqual(len(probes), 12)
        self.assertEqual({r['cycle'] for r in probes}, {1, 2})
        cycles = [r for r in records if r['type'] == 'cycle_summary']
        self.assertEqual([r['target_ttl'] for r in cycles], [3, 3])
        self.assertEqual(records[-1]['type'], 'summary')

    def test_once_and_unreachable_max_ttl(self):
        calls, _ = self.run_cycles(['--once'], 2)
        self.assertEqual(calls, [1, 2])
        calls, records = self.run_cycles(['--cycles', '2'], 99)
        self.assertEqual(calls, [1, 2, 3, 4, 5] * 2)
        self.assertTrue(all(r['target_ttl'] is None for r in records if r['type'] == 'cycle_summary'))

    def test_default_loops_until_interrupt_and_retains_completed_pass(self):
        calls, records = self.run_cycles([], 2, interrupt_second=True)
        self.assertEqual(calls, [1, 2])
        self.assertEqual(records[-1]['type'], 'summary')
        self.assertEqual(records[-1]['profiles'][0]['last_forwarding_response_ttl'], 2)


if __name__ == '__main__':
    unittest.main()
