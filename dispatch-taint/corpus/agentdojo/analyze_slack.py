#!/usr/bin/env python3
"""AgentDojo slack suite — cross-tool implicit-flow audit (Stage-4, M2).

Same enumeration approach as the other suites (see README). The slack suite has
11 tools across Slack messaging + web. Attacker-injection vectors are Slack
messages (read_channel_messages, read_inbox) and web-page content (get_webpage);
the channel list and user list are not injection vectors (role prune).

Note: get_webpage is BOTH a source (attacker-controlled page content) AND a sink
(fetching an attacker URL = SSRF). It appears in both tables, so the enumeration
includes flows into it (e.g. a malicious message → SSRF) and out of it (a
malicious page → another sink).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import analyze  # noqa: E402

SOURCES = {
    "read_channel_messages": dict(capacity="string", attacker=True,  reachable=True),  # a posted message = injection vector
    "read_inbox":            dict(capacity="string", attacker=True,  reachable=True),  # a DM = injection vector
    "get_webpage":           dict(capacity="string", attacker=True,  reachable=True),  # attacker-controlled page content
    "get_channels":          dict(capacity="string", attacker=False, reachable=True),  # channel list (not an injection vector)
    "get_users_in_channel":  dict(capacity="string", attacker=False, reachable=True),  # user list (not an injection vector)
}
SINKS = {
    "send_direct_message":    dict(arg="recipient", capacity="string", sensitive=True, category="exfiltration", reachable=True),
    "send_channel_message":   dict(arg="channel",   capacity="string", sensitive=True, category="messaging",    reachable=True),
    "post_webpage":           dict(arg="content",   capacity="string", sensitive=True, category="exfiltration", reachable=True),
    "get_webpage":            dict(arg="url",        capacity="string", sensitive=True, category="ssrf",         reachable=True),
    "invite_user_to_slack":   dict(arg="user_email", capacity="string", sensitive=True, category="membership",   reachable=True),
    "add_user_to_channel":    dict(arg="user",       capacity="enum",   sensitive=True, category="membership",   reachable=True),
    "remove_user_from_slack": dict(arg="user",       capacity="enum",   sensitive=True, category="destructive",  reachable=True),
}

if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    labels = sys.argv[1] if len(sys.argv) > 1 else here / "labels_slack.csv"
    raise SystemExit(analyze("slack", SOURCES, SINKS, labels))
