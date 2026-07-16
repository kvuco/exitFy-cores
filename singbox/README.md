# exitFy SB core adapter

This module builds a minimal Android C-shared core for exitFy from a pinned
SagerNet upstream revision. It deliberately does not use gomobile, `libbox.aar`
or an Android platform interface: exitFy supplies a loopback SOCKS inbound and
calls only the process-global `StartCore`/`StopCore` ABI.

Build tags are fixed to:

    with_quic,with_utls,badlinkname,tfogo_checklinkname0

The adapter and combined shared library are distributed under
GPL-3.0-or-later. See `COPYING`. This independent build is not affiliated with
or endorsed by SagerNet.
