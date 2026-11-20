# Security Center log fixtures

Example lines for `security_logfmt.py` and `security_logsrc.py` (plan
`docs/plans/2026-11-17-security-center.md`, 4.9). All addresses, MACs and
names are invented placeholders: IPv4 from RFC 5737 (`192.0.2.x`,
`198.51.100.x`, `203.0.113.x`), IPv6 from RFC 3849 (`2001:db8::/32`), MACs
`02:00:00:…` (locally administered), domains below `example.org`/`example.com`,
host name `ap-test`. No line was copied from a real router.

Lines starting with `#` in the `.txt` files are comments and are skipped by
the tests. The message fixtures (`fw4_kernel.txt`, `dnsmasq_query.txt`,
`dropbear_*.txt`) hold the message part as logd stores it (`proc[pid]: body`
or `kernel: body`); the tests put a remote head in front.

| File | Format | Evidence |
|---|---|---|
| `logd_remote_udp.txt` | `<PRI>Mmm dd hh:mm:ss HOST [PREFIX: ][kernel: ]MSG`, one datagram per line, no line end | **belegt aus Upstream-Quelle**: ubox `log/logread.c` (`log_notify`, branch `LOG_NET`); not seen live. Day padded with a space (`Nov  7`) follows from the `asctime` format: assumption, both forms are tested. The message parts are the confirmed hostapd / dnsmasq-dhcp / dropbear success lines of `tests/test_log_parser.py:59-75, :105` |
| `logd_remote_tcp.bin` | the same lines as a TCP stream, terminated by `\n` or NUL (`log_trailer_null`), one terminator per line, mixed | **belegt aus Upstream-Quelle**: `logread.c`, `log.init` (`-0`); not seen live |
| `fw4_kernel.txt` | `kernel: [<sec>] reject <zone> forward: IN=<if> OUT=<if> MAC=… SRC= DST= LEN= TOS= PREC= TTL= ID= PROTO=UDP SPT= DPT= LEN=` and `kernel: [<sec>] reject <zone> in: IN=<if> OUT= MAC=… SRC= DST= LEN= … PROTO=ICMP TYPE= CODE= …` | **belegt (1.46.2)**: both line shapes seen live (verdict `reject`, chains `forward` and `in`, IPv4, UDP and ICMP). Structure only: zones, interfaces, addresses, IDs and the elided middle fields are invented or filled in kernel field order. Shown by the live lines: the `[<sec>]` uptime stamp, an empty `OUT=` in the chain `in`, the second `LEN=` of UDP, ICMP without `SPT=`/`DPT=` |
| `fw4_kernel_unbelegt.txt` | the other fw4 shapes: verdicts `drop`/`accept`, chain `out`, TCP with flags, IPv6 | **nicht belegt, nach Upstream-Doku konstruiert** (fw4 `zone-verdict.uc`, `rule.uc`, kernel `nf_log_syslog`). They parse with the same rules; the format flag is per format, so they count as confirmed with it |
| `dnsmasq_query.txt` | `--log-queries=extra` lines: `<id> <addr>/<port> query[A] <name> from <client>`, `… reply <name> is <answer>`, `… forwarded …`, plus one line without `extra` | switch **belegt** (`dnsmasq.init`); line form **nicht belegt, nach Upstream-Doku konstruiert** (dnsmasq `cache.c`, `log_query`) |
| `dropbear_fail.txt` | `Bad password attempt for '<user>' from <ip>:<port>`, `Login attempt for nonexistent user from <ip>:<port>` (and the older form with the user name) | **nicht belegt, nach Upstream-Doku konstruiert** (dropbear `svr-authpasswd.c`, `svr-auth.c`). The live check of 2026-11-18 read only the last 5 dropbear lines per router; none was a failure |
| `dropbear_ok.txt` | `Password auth succeeded for '<user>' from <ip>:<port>` / `Pubkey auth succeeded for '<user>' with <type> key SHA256:<fingerprint> from <ip>:<port>` | both lines **belegt am 2026-11-18** auf gateway (WR3000, 25.12.1), ap2 (WR3000, 25.12.1), ap5 (FRITZ!Repeater 3000, 25.12.6), ap6 (1750E, 25.12.2); facility/severity `authpriv.notice` (PRI 85). The older repo form `… with key from …` (`tests/test_net_wifi.py:254`) is **widerlegt**: the live line names key type and fingerprint |
| `dropbear_session.txt` | `Child connection from <ip>:<port>`, auth line, `Exit (<user>) from <<ip>:<port>>: Disconnect received` | **belegt am 2026-11-18** on the same four routers; `Child connection` and `Exit` are `authpriv.info` (PRI 86). They stay unparsed (`kind` None) |

### Live check 2026-11-18 (read only, done by another session)

What the outputs show, per router: gateway (Cudy WR3000, 25.12.1), ap2
(WR3000, 25.12.1), ap5 (FRITZ!Repeater 3000, 25.12.6), ap6 (FRITZ!WLAN
Repeater 1750E, 25.12.2).

- The dropbear lines were read with `logread` (local form
  `<date> authpriv.notice dropbear[<pid>]: <body>`, addresses masked to `IP`
  before hand-over). The message part after `dropbear[<pid>]: ` is what logd
  also sends remotely; the remote head itself was **not** seen, because no
  router has `log_ip` set (only `log_proto='udp'` and `log_size='64'`), and
  only `logd -S 64` runs, no `logread -r` instance.
- Every source address was IPv4. The IPv6 form of the dropbear address is
  **nicht belegt** (`dropbear_fail.txt` line 3 stays a guess).
- No router set a firewall `log`/`log_limit` option or dnsmasq
  `logqueries` on that day. So there were no fw4 log lines and no query
  lines to copy; `dnsmasq_query.txt` stays **nicht belegt**. fw4: see
  1.46.2 below.
- `logread -e 'uhttpd|rpcd'` gave no line on any router. Whether a failed
  LuCI/rpcd login writes a line is **nicht belegt**.

### fw4 lines 1.46.2

Two real line shapes were handed over (values elided by the hand-over):
a `reject <zone> forward:` line with `IN=` and `OUT=` set, UDP and two
`LEN=` fields, and a `reject <zone> in:` line with an empty `OUT=` and ICMP
(`TYPE= CODE=`, no ports). `fw4_kernel.txt` follows that structure with
invented values; `FORMAT_CONFIRMED["fw4_nflog"]` is True since 1.46.2.
Still **nicht belegt**: the chain `out`, the verdicts `drop` and `accept`,
TCP flags and the IPv6 field order (`fw4_kernel_unbelegt.txt`).

Values copied into the fixtures: none. PIDs, addresses, ports and the key
fingerprint are invented; only field order, separators, quotes, brackets
and spaces follow the seen lines.

In the records, every unconfirmed format is marked with
`fields["unconfirmed"] = True` and its format id in `fields["fmt"]`
(`security_logfmt.FORMAT_CONFIRMED`). When a line is seen live, replace the
fixture line with one of the same structure and flip the flag.

`logd_remote_tcp.bin` is generated from `logd_remote_udp.txt` (non-comment
lines; odd lines end in `\n`, even lines in NUL). Regenerate with:

```sh
python - <<'EOF'
from pathlib import Path
d = Path("tests/fixtures/security")
lines = [l for l in d.joinpath("logd_remote_udp.txt").read_text("utf-8").splitlines()
         if l and not l.startswith("#")]
d.joinpath("logd_remote_tcp.bin").write_bytes(
    b"".join(l.encode() + (b"\n" if i % 2 == 0 else b"\x00") for i, l in enumerate(lines)))
EOF
```
