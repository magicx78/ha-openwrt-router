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
| `fw4_kernel.txt` | `kernel: [<sec>] <verdict> <zone> in\|out: …` / `<policy> <zone> forward: …` followed by netfilter fields `IN= OUT= MAC= SRC= DST= … PROTO= SPT= DPT= …` | prefix **belegt** (fw4 `zone-verdict.uc`, `rule.uc`, per plan 4.9); `[<sec>]` from the repo fixture `tests/test_net_infra.py:253` (origin **nicht belegt**); netfilter fields **nicht belegt, nach Upstream-Doku konstruiert** (kernel `nf_log_syslog` field names) |
| `dnsmasq_query.txt` | `--log-queries=extra` lines: `<id> <addr>/<port> query[A] <name> from <client>`, `… reply <name> is <answer>`, `… forwarded …`, plus one line without `extra` | switch **belegt** (`dnsmasq.init`); line form **nicht belegt, nach Upstream-Doku konstruiert** (dnsmasq `cache.c`, `log_query`) |
| `dropbear_fail.txt` | `Bad password attempt for '<user>' from <ip>:<port>`, `Login attempt for nonexistent user from <ip>:<port>` (and the older form with the user name) | **nicht belegt, nach Upstream-Doku konstruiert** (dropbear `svr-authpasswd.c`, `svr-auth.c`) |
| `dropbear_ok.txt` | `Password auth succeeded for '<user>' from <ip>:<port>` / `Pubkey auth succeeded for '<user>' with key … from <ip>:<port>` | password line **belegt** (live seen, `tests/test_log_parser.py:3-4, :105`); pubkey line **nicht belegt** (repo fixture `tests/test_net_wifi.py:254`, origin not stated) |

In the records, every unconfirmed format is marked with
`fields["unconfirmed"] = True` and its format id in `fields["fmt"]`
(`security_logfmt.FORMAT_CONFIRMED`). After the live check (plan Q-LIVE)
replace the lines here with seen lines and flip the flag.

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
