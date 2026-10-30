#!/usr/bin/env python3
"""Linux IPv4 option path diagnostics. Python 3.10+, standard library only."""
import argparse
import contextlib
import ipaddress
import json
import math
import os
import queue
import random
import secrets
import select
import shutil
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque

PROFILES = {
    'none': b'',
    'eol4': b'\x00' * 4,
    'nop4': b'\x01' * 4,
    'nop40': b'\x01' * 40,
    # RR: length 39, pointer 4, nine empty IPv4 address slots, EOL padding.
    'rr': bytes([7, 39, 4]) + bytes(36) + b'\x00',
    # Timestamp: length 36, pointer 5, overflow=0, flag=0, eight time slots.
    'ts': bytes([68, 36, 5, 0]) + bytes(32),
}


def checksum(data):
    data += b'\x00' * (len(data) % 2)
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(src, dst, ttl, ident, sport, dport, seq, mode, options):
    proto = 6 if mode == 'tcp' else 17
    srcb, dstb = socket.inet_aton(src), socket.inet_aton(dst)
    if mode == 'tcp':
        transport = struct.pack('!HHIIBBHHH', sport, dport, seq, 0,
                                0x50, 0x02, 64240, 0, 0)
        check_offset = 16
    else:
        transport = struct.pack('!HHHH', sport, dport, 16, 0) + struct.pack('!II', seq, 0)
        check_offset = 6
    pseudo = srcb + dstb + struct.pack('!BBH', 0, proto, len(transport))
    check = checksum(pseudo + transport)
    if mode == 'udp' and check == 0:
        check = 65535
    transport = (transport[:check_offset] + struct.pack('!H', check)
                 + transport[check_offset + 2:])
    ihl = 20 + len(options)
    header = struct.pack('!BBHHHBBH4s4s', 0x40 | (ihl // 4), 0,
                         ihl + len(transport), ident, 0, ttl, proto, 0, srcb, dstb) + options
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return header + transport


def ipv4(data):
    # Also accepts ICMP quotes: their declared total length exceeds captured bytes.
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 15) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    return {'ihl': ihl, 'id': struct.unpack_from('!H', data, 4)[0],
            'proto': data[9], 'src': socket.inet_ntoa(data[12:16]),
            'dst': socket.inet_ntoa(data[16:20]), 'options': data[20:ihl],
            'body': data[ihl:]}


def decode_reply(data, probe):
    outer = ipv4(data)
    if not outer:
        return None
    body = outer['body']
    if outer['proto'] == 6 and probe['mode'] == 'tcp':
        if (len(body) < 20 or outer['src'] != probe['dst']
                or outer['dst'] != probe['src']):
            return None
        sp, dp, _, ack = struct.unpack_from('!HHII', body)
        flags = body[13]
        if (sp != probe['dport'] or dp != probe['sport'] or not flags & 0x10
                or ack != (probe['seq'] + 1) & 0xffffffff):
            return None
        if flags & 4:
            status = 'tcp_rst'
        elif flags & 0x12 == 0x12:
            status = 'tcp_synack'
        else:
            return None
        return {'reply': outer['src'], 'status': status, 'terminal': True}
    if outer['proto'] != 1 or len(body) < 8 or body[0] not in (3, 11, 12):
        return None
    typ, code = body[:2]
    quoted = ipv4(body[8:])
    if (not quoted or len(quoted['body']) < 8 or quoted['dst'] != probe['dst']
            or quoted['id'] != probe['id']
            or quoted['proto'] != (6 if probe['mode'] == 'tcp' else 17)):
        return None
    # Do not require quoted source address/port: NAT can rewrite them. TCP's
    # sequence number provides another independent correlation key.
    sp, dp = struct.unpack_from('!HH', quoted['body'])
    if dp != probe['dport']:
        return None
    if probe['mode'] == 'tcp' and struct.unpack_from('!I', quoted['body'], 4)[0] != probe['seq']:
        return None
    if typ == 11:
        status = 'ttl_exceeded' if code == 0 else 'reassembly_timeout'
    elif typ == 12:
        status = 'parameter_problem'
    elif code in (9, 10, 13):
        status = 'admin_prohibited'
    elif code == 3 and outer['src'] == probe['dst'] and probe['mode'] == 'udp':
        status = 'udp_port_unreachable'
    else:
        status = 'unreachable'
    opts = quoted['options']
    expected = PROFILES[probe['profile']]
    option_state = ('same' if opts == expected else
                    'absent' if expected and not opts else 'changed')
    result = {'reply': outer['src'], 'status': status, 'icmp_type': typ,
              'icmp_code': code, 'quoted_ihl': quoted['ihl'],
              'quoted_options_hex': opts.hex(), 'option_state': option_state,
              'quoted_source': quoted['src'], 'quoted_source_port': sp,
              'terminal': status == 'udp_port_unreachable'}
    if typ == 12 and code == 0:
        result['parameter_pointer'] = body[4]
    return result


class Engine:
    def __init__(self, src, dst, mode, pps, stack):
        self.src, self.dst, self.mode = src, dst, mode
        self.interval, self.next_send = 1 / pps, 0
        self.used_ports = set()
        self.port_history = deque()
        self.stack = stack
        self.tx = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW))
        self.rx = [stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP))]
        if mode == 'tcp':
            self.rx.append(stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)))
        for sock in self.rx:
            sock.setblocking(False)
        self.udp = None
        if mode == 'udp':
            self.udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            self.udp.bind((src, 0))
        self.ident = secrets.randbelow(65535) + 1

    def reserve(self):
        # Retire ports after a two-minute holdoff so continuous runs cannot
        # exhaust the port space. Never deliberately retransmit a TCP request.
        now = time.monotonic()
        while self.port_history and now - self.port_history[0][0] > 120:
            self.used_ports.discard(self.port_history.popleft()[1])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for _ in range(1000):
            port = 1024 + secrets.randbelow(64512)
            if port in self.used_ports:
                continue
            try:
                sock.bind((self.src, port))
                self.used_ports.add(port)
                self.port_history.append((now, port))
                return sock, port
            except OSError:
                continue
        sock.close()
        raise OSError('Could not reserve a fresh TCP source port')

    def probe_many(self, ttl, profiles, dport, attempt, timeout, observer=None):
        """Multiplex one TTL/attempt batch; each probe has its own deadline."""
        pending = list(profiles)
        active = []
        reservations = []
        try:
            while pending or active:
                if observer:
                    observer('tick', None)
                now = time.monotonic()
                if pending and now >= self.next_send:
                    name = pending.pop(0)
                    if self.mode == 'tcp':
                        reservation, sport = self.reserve()
                        reservations.append(reservation)
                    else:
                        sport = self.udp.getsockname()[1]
                    self.ident = self.ident % 65535 + 1
                    p = {'src': self.src, 'dst': self.dst, 'ttl': ttl, 'profile': name,
                         'dport': dport, 'sport': sport, 'id': self.ident,
                         'seq': secrets.randbits(32), 'mode': self.mode, 'attempt': attempt,
                         'sent_ihl': 20 + len(PROFILES[name]),
                         'sent_options_hex': PROFILES[name].hex()}
                    wire = packet(self.src, self.dst, ttl, p['id'], sport, dport,
                                  p['seq'], self.mode, PROFILES[name])
                    start = time.monotonic()
                    self.tx.sendto(wire, (self.dst, 0))
                    self.next_send = start + self.interval
                    p['sent_unix'] = time.time()
                    active.append((p, start, start + timeout))
                    if observer:
                        observer('sent', p)
                now = time.monotonic()
                for item in active.copy():
                    p, start, deadline = item
                    if now >= deadline:
                        active.remove(item)
                        p.update(status='timeout', reply=None, terminal=False)
                        yield p
                if not pending and not active:
                    break
                wake = min([item[2] for item in active] +
                           ([self.next_send] if pending else []))
                wait = max(0, wake - time.monotonic())
                ready, _, _ = select.select(self.rx, [], [], min(wait, 0.1) if observer else wait)
                for sock in ready:
                    try:
                        data = sock.recv(65535)
                    except BlockingIOError:
                        continue
                    received = time.monotonic()
                    for item in active.copy():
                        p, start, deadline = item
                        if received > deadline:
                            continue
                        result = decode_reply(data, p)
                        if result:
                            active.remove(item)
                            p.update(result)
                            p['rtt_ms'] = round((received - start) * 1000, 3)
                            yield p
                            break
        finally:
            for reservation in reservations:
                reservation.close()


def summarize(rows, profiles):
    groups = defaultdict(list)
    for r in rows:
        groups[r['profile'], r['ttl']].append(r)
    forward = {'ttl_exceeded', 'tcp_synack', 'tcp_rst', 'udp_port_unreachable'}
    baseline = {ttl for (name, ttl), rs in groups.items()
                if name == 'none' and sum(r['status'] in forward for r in rs) >= 2}
    summaries = []
    for name in profiles:
        if name == 'none':
            continue
        rs = [r for r in rows if r['profile'] == name]
        reached = [r for r in rs if r.get('terminal')]
        alive = [r['ttl'] for r in rs if r['status'] in forward]
        last = max(alive, default=None)
        explicit = [{'ttl': r['ttl'], 'reply': r['reply'], 'status': r['status'],
                     'code': r.get('icmp_code')} for r in rs
                    if r['status'] in ('admin_prohibited', 'parameter_problem')]
        silent = sorted(ttl for ttl in baseline if (name, ttl) in groups
                        and all(r['status'] == 'timeout' for r in groups[name, ttl])
                        and (last is None or ttl > last))
        # Require two consecutive TTLs with repeated successful controls. A
        # candidate is an observation interval, never identification of a router.
        sustained = next((ttl for ttl in silent if ttl + 1 in silent), None)
        summaries.append({'profile': name, 'destination_response': bool(reached),
                          'last_forwarding_response_ttl': last,
                          'explicit_rejections': explicit,
                          'possible_silent_boundary':
                          {'after_observed_ttl': last, 'by_tested_ttl': sustained}
                          if sustained is not None and not reached else None})
    return summaries


class ReverseDNS:
    """Cached PTR lookups on bounded daemon workers; never block packet timing."""
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.cache = {}
        self.lock = threading.Lock()
        self.work = queue.Queue(maxsize=512)
        self.stopped = threading.Event()
        self.workers = []
        if enabled:
            for _ in range(2):
                worker = threading.Thread(target=self.run, daemon=True)
                worker.start()
                self.workers.append(worker)

    def run(self):
        while not self.stopped.is_set():
            try:
                address = self.work.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                name = socket.gethostbyaddr(address)[0]
                name = ''.join(c if 32 <= ord(c) < 127 else '?' for c in name)
            except (OSError, UnicodeError):
                name = '-'
            with self.lock:
                self.cache[address] = name

    def request(self, address):
        if not self.enabled:
            return
        with self.lock:
            if address in self.cache:
                return
            if len(self.cache) >= 512:
                return
            self.cache[address] = None
        try:
            self.work.put_nowait(address)
        except queue.Full:
            with self.lock:
                self.cache[address] = '-'

    def label(self, address):
        if not self.enabled:
            return '-'
        with self.lock:
            return (self.cache[address] or 'resolving...') if address in self.cache else '-'

    def close(self):
        # A system resolver call can block. Daemon workers are deliberately not
        # joined; DNS must not delay completion, interruption, or process exit.
        self.stopped.set()


class TraceDisplay:
    """Small dependency-free terminal dashboard; packet results stay in JSONL."""
    def __init__(self, title, profiles, first, last, repeat, live, stream=None, dns=True):
        self.title, self.profiles = title, profiles
        self.first, self.last, self.repeat = first, last, repeat
        self.live, self.stream = live, stream or sys.stdout
        self.rows = defaultdict(lambda: deque(maxlen=20))
        self.totals = defaultdict(lambda: [0, 0, 0.0])
        self.sent = defaultdict(int)
        self.cycle_completed = defaultdict(int)
        self.cycle, self.cycle_done = 1, 0
        self.target_hop = None
        self.hop, self.done = first, 0
        self.started, self.last_draw = time.monotonic(), 0
        self.events = deque(maxlen=4)
        self.state = 'Scanning'
        self.color = live and 'NO_COLOR' not in os.environ
        self.dns = ReverseDNS(dns)

    def __enter__(self):
        if self.live:
            self.stream.write('\033[?1049h\033[?25l')
            self.render(force=True)
        return self

    def __exit__(self, typ, value, traceback):
        self.dns.close()
        if self.live:
            try:
                self.stream.write('\033[0m\033[?25h\033[?1049l')
                # Leave a readable final snapshot in normal scrollback.
                self.stream.write('\n'.join(self.frame(colored=False)) + '\n')
                self.stream.flush()
            finally:
                self.live = False

    def paint(self, text, code, enabled):
        return f'\033[{code}m{text}\033[0m' if enabled else text

    def begin_cycle(self, cycle):
        self.cycle, self.cycle_done = cycle, 0
        self.cycle_completed.clear()
        self.hop = self.first
        self.state = 'Scanning'
        self.render(force=True)

    def observe(self, event, row):
        if event == 'sent':
            self.sent[row['profile'], row['ttl']] += 1
        self.render()

    def record(self, row):
        self.rows[row['profile'], row['ttl']].append(row)
        self.done += 1
        self.cycle_done += 1
        key = row['profile'], row['ttl']
        self.cycle_completed[key] += 1
        totals = self.totals[key]
        totals[0] += 1
        if row['status'] != 'timeout':
            totals[1] += 1
            totals[2] += row['rtt_ms']
        if row.get('reply'):
            self.dns.request(row['reply'])
        status = row['status']
        detail = '*' if status == 'timeout' else f"{row['reply']}  {status}  {row['rtt_ms']:.2f} ms"
        if 'icmp_type' in row:
            detail += f"  ICMP {row['icmp_type']}:{row['icmp_code']}"
        if 'option_state' in row:
            detail += f"  quote:{row['option_state']}"
        self.events.append(f"TTL {row['ttl']:>3}  {row['profile']:<5}  {detail}")
        self.render()

    def cell(self, name, ttl, colored, width=12):
        rows = self.rows[name, ttl]
        good = [r for r in rows if r['status'] != 'timeout']
        completed, replied, rtt_sum = self.totals[name, ttl]
        sent = self.sent[name, ttl]
        pending = sent > completed
        if not rows:
            return self.paint(('~' if pending else '.').center(width), '2', colored)
        statuses = {r['status'] for r in good}
        if 'admin_prohibited' in statuses:
            symbol, color = 'A', '31;1'
        elif 'parameter_problem' in statuses:
            symbol, color = 'P', '31;1'
        elif any(r.get('terminal') for r in good):
            symbol, color = 'D', '36;1'
        elif 'ttl_exceeded' in statuses:
            symbol, color = 'T', '32'
        elif good:
            symbol, color = 'U', '33'
        else:
            symbol, color = '*', '33'
        rtt = rtt_sum / replied if replied else None
        def count_label(number):
            return str(number) if number < 1000 else f'{number / 1000:.0f}k'
        count = f'{count_label(replied)}/{count_label(completed)}'
        latency = (f'{rtt:.1f}' if rtt < 100 else f'{rtt:.0f}') if rtt is not None and rtt < 999.5 else ('>999' if rtt is not None else '-')
        text = f'{symbol}{count} {latency}' if width >= 12 else f'{symbol}{count}'
        if pending or (ttl == self.hop and self.cycle_completed[name, ttl] < self.repeat):
            text += '~'
        if len(text) > width:
            text = text[:width - 1] + '+'
        return self.paint(text.center(width), color, colored)

    def frame(self, colored=None):
        colored = self.color if colored is None else colored
        width, height = shutil.get_terminal_size((100, 28))
        width = max(1, width - 1)  # Avoid autowrap when writing at the last column.
        # Keep all test columns visible at ordinary 80-column terminal widths.
        cell_width = 12 if width >= 4 + 18 + 16 + 12 * len(self.profiles) else 7
        dns_width = max(8, min(32, width - 4 - 18 - cell_width * len(self.profiles)))
        left_width = 4 + 18 + dns_width
        colored = colored and width >= left_width + cell_width * len(self.profiles)
        capacity = max(1, height - 14)
        visible_end = max(self.hop, self.target_hop or self.first)
        end = min(self.last, visible_end)
        begin = max(self.first, end - capacity + 1)
        hops = range(begin, end + 1)
        elapsed = time.monotonic() - self.started
        limit = max(self.hop, self.target_hop or self.last)
        total = (limit - self.first + 1) * self.repeat * len(self.profiles)
        lines = [self.title,
                 f'{self.state} | pass {self.cycle} | hop {self.hop}/{limit} | pass {self.cycle_done}/{total} | total {self.done} | {elapsed:.1f}s',
                 '', f"{'TTL':<4}{'IP ADDRESS':<18}{'REVERSE DNS':<{dns_width}}" +
                 ''.join(name.center(cell_width) for name in self.profiles)]
        for ttl in hops:
            # Prefer the plain control responder; retain all ECMP/profile
            # responders in detailed records and report their count here.
            addresses = list(dict.fromkeys(r['reply'] for name in self.profiles
                             for r in self.rows[name, ttl] if r.get('reply')))
            address = addresses[0] if addresses else '*'
            ip_label = address + (f'+{len(addresses) - 1}' if len(addresses) > 1 else '')
            dns_label = self.dns.label(address) if addresses else '-'
            dns_label = dns_label if len(dns_label) < dns_width else dns_label[:dns_width - 2] + '~'
            left = f'{ttl:<4}{ip_label:<18}{dns_label:<{dns_width}}'
            lines.append(left + ''.join(self.cell(name, ttl, colored, cell_width) for name in self.profiles))
        cells = 'status replies/completed mean-ms' if cell_width == 12 else 'status replies/completed (RTT below/JSONL)'
        lines.extend(['', f'Hops {begin}-{end} of {self.first}-{self.last}; cells: {cells}',
                      'T=TTL expired  D=destination  A=admin denied  P=bad header  U=other ICMP',
                      '*=no reply  ~=pending/truncated  .=not tested  IP+N=additional responders'])
        addresses = sorted({r['reply'] for name in self.profiles
                            for r in self.rows[name, self.hop] if r.get('reply')})
        lines.append(f"Hop {self.hop}: " + ('; '.join(f'{a} ({self.dns.label(a)})' for a in addresses) or 'no replies yet'))
        remaining = height - len(lines) - 2
        if remaining > 1:
            lines.append('Recent results:')
            lines.extend(list(self.events)[-min(4, remaining - 1):])
        # Strip control characters supplied by the environment/title, and fit the
        # physical screen. Colored matrix rows are already sized by cell count.
        result = []
        for line in lines[:max(1, height - 1)]:
            if '\033[' in line and colored:
                result.append(line)
            else:
                result.append(''.join(c if c.isprintable() else ' ' for c in line)[:width])
        return result

    def render(self, force=False):
        if not self.live:
            return
        now = time.monotonic()
        if not force and now - self.last_draw < 0.1:
            return
        self.last_draw = now
        self.stream.write('\033[H' + '\n'.join(line + '\033[K' for line in self.frame()) + '\033[J')
        self.stream.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('target', help='one IPv4 address or DNS name')
    parser.add_argument('-p', '--port', type=int, default=443)
    parser.add_argument('--mode', choices=['tcp', 'udp'], default='tcp')
    parser.add_argument('--profiles', default='none,nop4,rr,ts', help='comma list: ' + ','.join(PROFILES))
    parser.add_argument('-m', '--max-ttl', type=int, default=30)
    parser.add_argument('-f', '--first-ttl', type=int, default=1)
    parser.add_argument('-q', '--repeat', type=int, default=3)
    parser.add_argument('-w', '--timeout', type=float, default=1)
    parser.add_argument('--pps', type=float, default=5, help='maximum total send rate, including parallel mode')
    parser.add_argument('--parallel', action='store_true', help='overlap profiles at each TTL/attempt, with paced sends')
    parser.add_argument('--display', choices=['auto', 'live', 'plain'], default='auto',
                        help='live matrix on a terminal; plain logs when redirected')
    parser.add_argument('--no-dns', action='store_true', help='disable background reverse DNS lookups')
    loops = parser.add_mutually_exclusive_group()
    loops.add_argument('--cycles', type=int, default=0, help='number of passes; 0 loops until Ctrl-C')
    loops.add_argument('--once', action='store_const', const=1, dest='cycles', help='run a single pass')
    parser.add_argument('--interval', type=float, default=1, help='seconds between passes')
    parser.add_argument('--source', help='local IPv4 source address; default follows routing table')
    parser.add_argument('--jsonl', help='write probe records and final summary to this file')
    parser.add_argument('--dry-run', action='store_true', help='show generated packets without raw sockets or sending probes')
    args = parser.parse_args()
    if args.cycles < 0 or not math.isfinite(args.interval) or not 0 <= args.interval <= 3600:
        parser.error('cycles must be >= 0 and interval must be between 0 and 3600 seconds')
    profiles = list(dict.fromkeys(args.profiles.split(',')))
    if any(p not in PROFILES for p in profiles):
        parser.error('unknown profile')
    if 'none' not in profiles:
        profiles.insert(0, 'none')
    if not (1 <= args.first_ttl <= args.max_ttl <= 255 and 1 <= args.port <= 65535
            and 1 <= args.repeat <= 20 and math.isfinite(args.timeout)
            and 0 < args.timeout <= 60 and math.isfinite(args.pps) and 0 < args.pps <= 100):
        parser.error('invalid TTL, port, repeat (1..20), timeout (0..60), or pps (0..100)')
    if sys.platform != 'linux' and not args.dry_run:
        parser.error('raw-packet backend requires Linux (use a Linux host or VM)')
    dst = socket.gethostbyname(args.target)
    if args.source:
        src = str(ipaddress.IPv4Address(args.source))
    elif args.dry_run:
        src = '192.0.2.1'
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect((dst, args.port))  # Routing lookup only; sends no datagram.
            src = route.getsockname()[0]
    if args.dry_run:
        for name in profiles:
            wire = packet(src, dst, args.first_ttl, 1234, 40000, args.port, 123456, args.mode, PROFILES[name])
            print(json.dumps({'profile': name, 'ihl': 20 + len(PROFILES[name]),
                              'bytes': len(wire), 'packet_hex': wire.hex()}))
        return
    live = args.display == 'live' or (args.display == 'auto' and sys.stdout.isatty()
                                        and os.environ.get('TERM', '') != 'dumb')
    if args.display == 'live' and not sys.stdout.isatty():
        parser.error('--display live requires a terminal; use --display plain for redirected output')
    title = f'{src} -> {dst}:{args.port} {args.mode.upper()}'
    if not live:
        print(title)
        for name in profiles:
            print(f"{name}: IHL={20 + len(PROFILES[name])} options={PROFILES[name].hex() or '-'}")
        print('TTL PROFILE IHL REPLIES  ADDRESSES / STATUS / ICMP TYPE:CODE / RTT (ms)')
    rows = []
    with contextlib.ExitStack() as stack:
        output = stack.enter_context(open(args.jsonl, 'w', encoding='utf-8')) if args.jsonl else None
        engine = Engine(src, dst, args.mode, args.pps, stack)
        with TraceDisplay(title, profiles, args.first_ttl, args.max_ttl, args.repeat, live,
                          dns=not args.no_dns) as display:
            try:
                cycle = 0
                previous_rows = []
                while args.cycles == 0 or cycle < args.cycles:
                    cycle += 1
                    rows = []
                    target_ttl = None
                    display.begin_cycle(cycle)
                    if not live:
                        print(f'Pass {cycle}', flush=True)
                    for ttl in range(args.first_ttl, args.max_ttl + 1):
                        display.hop = ttl
                        display.render(force=True)
                        current = defaultdict(list)
                        reached = False
                        for attempt in range(1, args.repeat + 1):
                            order = profiles.copy()
                            random.SystemRandom().shuffle(order)
                            batches = [order] if args.parallel else [[name] for name in order]
                            for batch in batches:
                                with contextlib.closing(engine.probe_many(ttl, batch, args.port, attempt, args.timeout,
                                                                         display.observe if live else None)) as replies:
                                    for row in replies:
                                        row['cycle'] = cycle
                                        rows.append(row)
                                        reached = reached or bool(row.get('terminal'))
                                        if row.get('terminal'):
                                            display.target_hop = ttl
                                        display.record(row)
                                        current[row['profile']].append(row)
                                        if output:
                                            output.write(json.dumps({'type': 'probe', **row}) + '\n')
                                            output.flush()
                        if not live:
                            for name in profiles:
                                rs = current[name]
                                count = sum(r['status'] != 'timeout' for r in rs)
                                details = []
                                for r in rs:
                                    if r['status'] == 'timeout':
                                        details.append('*')
                                    else:
                                        text = f"{r['reply']} {r['status']} {r['rtt_ms']:.2f}"
                                        if 'icmp_type' in r:
                                            text += f" ICMP={r['icmp_type']}:{r['icmp_code']}"
                                        if 'option_state' in r:
                                            text += f" [quote:{r['option_state']}]"
                                        details.append(text)
                                print(f'{ttl:3} {name:7} {20 + len(PROFILES[name]):3} {count}/{len(rs):<6} ' + ' | '.join(details), flush=True)
                        if reached:
                            target_ttl = ttl
                            break
                    previous_rows = rows
                    if output:
                        output.write(json.dumps({'type': 'cycle_summary', 'cycle': cycle,
                                                 'target_ttl': target_ttl,
                                                 'profiles': summarize(rows, profiles)}) + '\n')
                        output.flush()
                    if args.cycles and cycle >= args.cycles:
                        break
                    display.state = 'Next pass'
                    until = time.monotonic() + args.interval
                    while time.monotonic() < until:
                        display.render()
                        time.sleep(min(0.1, max(0, until - time.monotonic())))
            except KeyboardInterrupt:
                rows = rows or previous_rows
                display.state = 'Interrupted'
                if not live:
                    print('\nInterrupted; summarizing completed probes.', file=sys.stderr)
            else:
                display.state = 'Complete'
            display.render(force=True)
        summary = summarize(rows, profiles)
        if output:
            output.write(json.dumps({'type': 'summary', 'profiles': summary}) + '\n')
        print('\nEvidence summary (silence alone does not prove filtering):')
        for item in summary:
            name = item['profile']
            boundary = item['possible_silent_boundary']
            if item['destination_response']:
                message = 'destination responded'
            elif boundary:
                after = boundary['after_observed_ttl']
                message = (f"possible filtering after observed TTL {after}, by tested TTL "
                           f"{boundary['by_tested_ttl']} (inconclusive)")
            else:
                message = f"last forwarding response TTL {item['last_forwarding_response_ttl']}; no conclusive boundary"
            rejects = item['explicit_rejections']
            if rejects:
                message += f"; {len(rejects)} explicit rejection(s)"
            print(f'  {name:<7} {message}')
        if args.jsonl:
            print(f'Detailed probe records and summary: {args.jsonl}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        sys.exit(1)
