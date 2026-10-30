# ipopttrace

IPv4-options traceroute for Linux, Python 3.10+, no third-party dependencies.
Run on a Linux host or Linux VM, with root or CAP_NET_RAW. A container's bridge,
host, NAT, and firewall are part of its measured path. macOS raw-IP conventions
are different; this backend intentionally requires Linux.

## Run

```sh
sudo python3 ipopttrace.py 203.0.113.10 -p 443
sudo python3 ipopttrace.py YOUR_TARGET -p 80 --profiles none,eol4,nop4,nop40,rr,ts --jsonl trace.jsonl
sudo python3 ipopttrace.py YOUR_TARGET -p 443 --parallel --pps 10 --jsonl parallel.jsonl
sudo python3 ipopttrace.py YOUR_TARGET --mode udp -p 33434 --pps 2 -w 2
python3 ipopttrace.py 203.0.113.10 --dry-run
python3 -m unittest -v
```

## Live terminal display

On an interactive terminal, the default display is a live colored matrix:
**one row per TTL hop**, with responder IP and reverse DNS on the left, and one
column per option profile across the right. Each test cell shows status,
cumulative successful replies/completed probes, and cumulative mean RTT in milliseconds when the
terminal is wide enough. Compact cells omit RTT; recent details and JSONL retain it.
A trailing `~` indicates a test still in progress; `.` means not tested yet.
The header shows completed probe count, elapsed time and current hop.

Reverse DNS is enabled by default, cached per responder, and performed on two
background daemon workers. Pending lookups show `resolving...`; missing PTR
records show `-`. Slow or unresponsive DNS does not block probing or process
exit. Use `--no-dns` to disable PTR queries. Hostnames are display information;
JSONL probe records retain numeric addresses; each probe also has a pass number in `cycle`.

When a hop has several responders (ECMP or different option paths), the left
column prefers a plain-control responder and adds `+N` for the additional unique
addresses. The current-hop detail line lists its responder addresses and names;
every individual probe's IP remains in JSONL. Long hostnames are truncated with
`~` to preserve the test columns.

Status markers: `T` = ICMP TTL expired; `D` = destination response;
`A` = administrative rejection; `P` = ICMP Parameter Problem;
`U` = other ICMP response; `*` = no response. If a cell has mixed reply types,
explicit administrative/header rejection takes precedence, then destination
response, then TTL expiry, based on up to 20 recent results per cell. Counts and
mean RTT accumulate for the whole run. Silence alone does not prove filtering.

The dashboard adapts to terminal size. For long traces it follows the current
hop with a vertical window of recent hop rows; the displayed range is labeled.
An 80-column terminal uses compact cells to fit all six test columns; a wider
terminal also shows RTT within the cells. Very narrow terminals clip the table:
widen the terminal or use plain output. The display restores the cursor and
screen on completion or Ctrl-C and leaves a final snapshot plus a concise
evidence summary in scrollback. No extra packages are required. `NO_COLOR=1`
disables color while retaining the live display.

Use `--display plain` for the original detailed scrolling rows. Redirected
output automatically uses plain mode. `--display live` explicitly requests the
matrix and requires an interactive terminal. `--jsonl PATH` retains the same
probe records and final summary, and is flushed during scanning so interrupted
runs retain their completed results.

Replace example addresses with your target. `--dry-run` uses documentation
source address 192.0.2.1 unless `--source` is supplied, and sends nothing.
Hostnames resolve once to IPv4. One target and one destination port per run.
`--source` must be a local address; it does not select an interface or source
route. There is no source spoofing or source-route option profile.

Default: TTL 1..30, three probes per TTL/profile, TCP SYN to 443, at most five
probes/second, one second response timeout. Probes run sequentially by default;
`--parallel` overlaps profile response windows within each TTL/repetition while
still pacing sends at `--pps` total, not per profile. Each probe has its own timeout
starting when sent. This is close-in-time comparison, not an atomic burst. Loss reduces
the actual rate. Profiles are shuffled within each repetition to reduce ordering
bias and ICMP rate-limit bias. `none` controls are always included. A confirmed destination response from any profile ends the pass after all tests
and repetitions at that TTL finish. The next pass restarts at `--first-ttl`;
higher TTLs are not probed after the target is reached. TCP SYN-ACK, ACK-bearing
RST from the destination, or destination UDP Port Unreachable counts as reaching
the target. An intermediate ICMP rejection does not end the pass.

The default is continuous scanning until Ctrl-C, with a one-second pause between
passes. If there is no target response, the pass ends at `--max-ttl` and restarts.
Routes are rediscovered each pass, so a later pass may continue beyond a prior
pass's destination TTL when necessary. Use `--once` for one pass, `--cycles N` for
N passes, and `--interval SECONDS` to change the pause. The live display retains
cumulative per-cell counts and mean RTT; the pass counter advances on restart.
Detailed in-memory history is bounded for continuous operation. JSONL on disk
continues to grow for the duration of the run.

```sh
sudo python3 ipopttrace.py YOUR_TARGET --parallel --jsonl trace.jsonl
sudo python3 ipopttrace.py YOUR_TARGET --parallel --once
sudo python3 ipopttrace.py YOUR_TARGET --parallel --cycles 10 --interval 2
```

A complete pass to maximum TTL at the defaults sends up to 360 probes and can
take several minutes. Ctrl-C retains and summarizes completed probe records.

## What the probes do

Every packet has the selected IPv4 options and a varying TTL, with valid IP and
transport checksums. A router that expires the TTL may send ICMP Time Exceeded
(type 11/code 0). The tool matches its quoted original header and transport
bytes to the probe, and displays the responding address and RTT.

TCP SYN-ACK and ACK-bearing RST responses are recognized. TCP probes reserve source ports with a two-minute reuse holdoff and random
initial sequence numbers: they do not complete
handshakes or deliberately retransmit the same TCP request. Linux normally
resets unsolicited SYN-ACKs; local firewall policy can affect that cleanup.
The tool does not implement race timing, socket migration, or a vulnerability
test. A TCP response establishes reachability, not kernel patch status or
proof that the options arrived intact.

UDP mode keeps its source/destination ports fixed. It recognizes destination
ICMP Port Unreachable as endpoint reachability, but does not interpret application
UDP replies. Use an unused destination port if appropriate. ICMP Time Exceeded,
Destination Unreachable, and Parameter Problem are decoded in both modes.

| Profile | IPv4 header bytes | Contents |
|---|---:|---|
| none | 20 | No options; control |
| eol4 | 24 | End-of-list and zero padding |
| nop4 | 24 | Four NOP bytes |
| nop40 | 60 | Forty NOP bytes |
| rr | 60 | Valid Record Route, nine empty address slots |
| ts | 56 | Valid Timestamp, eight empty timestamp slots, flag 0 |

These are distinct tests. A NOP-only header is not equivalent to a processed RR
or Timestamp option, and no profile's success proves all other options pass.
There are no malformed option or exploitation payloads.

## Interpreting evidence

* `ttl_exceeded`: positive evidence that the probe reached the responder's
  expiration point. The source address can be a different interface, tunnel
  endpoint, or firewall; it is not necessarily the forwarding interface.
* `admin_prohibited`: an explicit ICMP administrative rejection (type 3 codes
  9, 10, 13). The reporter is evidence of policy rejection, not necessarily the
  physical location of the actual rule.
* `parameter_problem`: explicit header rejection; JSON includes the pointer
  for code 0. It does not automatically mean an ACL.
* `*`: no correlated response before timeout. This is inconclusive by itself.
* `[quote:same]`: the quoted options equal the sent bytes. `[quote:changed]`
  is normal for RR/TS because routers may update addresses, timestamps, and
  pointers. JSON retains `quoted_options_hex` for inspection.
* `[quote:absent]`: options were absent in the returned quote. That could be
  stripping on the forward path or reconstruction/sanitization of the ICMP
  quote. Confirm with packet captures before declaring stripping.

The summary flags a **possible silent boundary** only after the last forwarding
response for that profile, if at least two consecutive later TTLs are silent
while the plain controls each receive at least two responses. A later forwarding
response moves that boundary; a destination response suppresses the silent-boundary
claim. With `-q 1`, silent-boundary inference is disabled by lack of repeat controls.
`after_observed_ttl: null` means no positive forwarding evidence for that profile:
even local output filtering is possible. The interval is an observation bracket,
not a proven drop hop. Explicit rejections are retained separately.

Even an interleaved comparison cannot distinguish forward filtering from
suppressed ICMP, reverse-path filtering, ICMP rate limits, asymmetric routing,
ECMP, tunnels, or transient loss. TCP's varying source ports can select different
ECMP paths; UDP keeps ports fixed but is not a complete Paris traceroute and
other fields can still affect hashing. Option length also changes packet length.
NAT rewriting the quoted IP ID, destination port, or TCP sequence number can
prevent matching. UDP uses IP ID, protocol and destination port correlation;
TCP also checks its quoted sequence number. Late replies after a timeout are
not credited to another TCP probe. Reverse DNS runs separately from packet scheduling and RTT measurement.

To narrow a suspected boundary: repeat at 1–2 pps with a longer timeout, compare
TCP and UDP and several option profiles, and compare multiple destinations that
share the suspected segment. On equipment you control, capture both sides:

```sh
sudo tcpdump -ni any -s0 -vvv 'icmp or (host YOUR_TARGET and tcp port 443)'
```

An endpoint-side capture is the strongest check that options survived the path.
The remote service can answer even when an intermediary removed them.

## CVE context

CVE-2026-98432 concerns lifetime management of IPv4 socket options during
concurrent TCP request processing. `inet_opt` and `ireq_opt` are kernel fields,
not wire option types. This tool measures ordinary option-bearing packet
reachability. It cannot identify vulnerable kernels or certify a CVE mitigation.

References:
* https://access.redhat.com/security/cve/cve-2026-98432
* https://lists.openwall.net/linux-cve-announce/2026/10/15/1

## Output and tests

Plain console mode: the profile legend shows exact sent option hex and header lengths.
Each scrolling row includes TTL, profile, header length, reply count, and every attempt's
address, status, ICMP type/code when present, RTT and
quoted-option comparison. `--jsonl PATH` overwrites PATH and flushes one JSON
record per probe. Each completed pass adds a `type: cycle_summary` record with
its pass number, destination TTL (or null), and evidence summary. On exit,
`type: summary` describes the latest pass with completed probe records (including
a partially completed pass on Ctrl-C). Probe records include the
tuple, IP ID, TCP sequence/token, send time, response type/code, and quoted
options when available. Partial files remain useful after interruption.

Tests cover checksums for all profiles/transports, minimal ICMP quotes with
options, wrong/truncated quotations, NAT source rewrites, absent quoted options,
administrative rejections, TCP ACK matching, UDP endpoint responses, and
conservative summary logic, plus paced parallel sends, out-of-order replies,
independent timeouts, destination-triggered restart, finite passes, unreachable
paths, and interruption. Internet paths are not validated by these tests.
