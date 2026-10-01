# Reverse Shell

A Pentest-tab card that generates connect-back reverse-shell one-liners and
catches them with a built-in listener. For authorised testing of systems you own
or have explicit permission to test.

> Gated by Pentest Mode (the tab is hidden otherwise), like the other manual
> tools.

## Generate

Enter **LHOST** (auto-filled with the box's primary LAN IP), **LPORT**, and the
target **shell**, then **Generate**. You get the usual copy-paste payloads —
Bash (`/dev/tcp`), `nc` (mkfifo and `-e`), Python3 (PTY), PowerShell, Perl, PHP —
each with a **Copy** button. Nothing runs on generation; these are strings to
deliver however you like (including via a [Rubber Ducky](rubber-ducky.md)
payload that types the one-liner into the target).

## Catch listener

**Start** opens a TCP listener on the chosen port (`0.0.0.0:LPORT`) and shows a
live console. When a target connects back, the console shows the session output;
type a command and **Send** (or press Enter) to drive it. **Stop** closes the
listener. One session at a time; extra connect-backs are refused while a session
is live.

The listener is a straightforward catch-and-interact (netcat-style), not an
interactive PTY — line-oriented commands work; full-screen TUI programs on the
target will not render. The console polls while the Pentest tab is open.

## Typical flow

1. **Start** the listener on, say, `4444`.
2. **Generate** with that port; **Copy** a one-liner that matches the target OS.
3. Deliver it (paste in an existing session, or a Rubber Ducky payload).
4. Watch the connect-back appear; drive it from the command box.

## Files

| Path | Role |
| --- | --- |
| `python/revshell.py` | Payload generator + single-session catch listener |
| `/api/revshell/generate` | Build one-liners for an LHOST/LPORT/shell |
| `/api/revshell/lan-ip` | Default LHOST (box LAN IP) |
| `/api/revshell/listener/{start,status,send,stop}` | Listener control |

---

## Related

- [Rubber Ducky](rubber-ducky.md) — can type a generated one-liner into a target
- [Scanning & Attacks](scanning-and-attacks.md) — the core manual-attack loop
