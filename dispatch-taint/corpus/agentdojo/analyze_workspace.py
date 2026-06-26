#!/usr/bin/env python3
"""AgentDojo workspace suite — cross-tool implicit-flow audit (Stage-4, M2).

The workspace suite is AgentDojo's largest (24 tools across email / calendar /
cloud-drive). Same enumeration approach as banking (see README): the cross-tool
implicit flow is a property of the tool registry + join-at-LLM (§4.2/§4.4), not a
code dataflow — so we enumerate co-registered (source, sink) pairs, prune with
§4.5, and score against the 6 workspace injection tasks.

Source/sink metadata is read off the real signatures in tools/email_client.py,
calendar_client.py, cloud_drive_client.py. Attacker-injection vectors in
workspace are received-email bodies, calendar-event descriptions, and cloud-drive
file contents; the user's own sent/draft mail and the contact list are NOT
injection vectors (role prune), and get_current_day returns a date that cannot
carry an instruction (schema prune).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import analyze  # noqa: E402

SOURCES = {
    # --- email reads -------------------------------------------------------- #
    "get_received_emails":       dict(capacity="string", attacker=True,  reachable=True),  # prime injection vector
    "get_unread_emails":         dict(capacity="string", attacker=True,  reachable=True),
    "search_emails":             dict(capacity="string", attacker=True,  reachable=True),
    "get_sent_emails":           dict(capacity="string", attacker=False, reachable=True),  # user's own outgoing mail
    "get_draft_emails":          dict(capacity="string", attacker=False, reachable=True),  # user's own drafts
    "search_contacts_by_name":   dict(capacity="string", attacker=False, reachable=True),  # user's contact list
    "search_contacts_by_email":  dict(capacity="string", attacker=False, reachable=True),
    # --- calendar reads ----------------------------------------------------- #
    "search_calendar_events":    dict(capacity="string", attacker=True,  reachable=True),  # event description = injection vector
    "get_day_calendar_events":   dict(capacity="string", attacker=True,  reachable=True),
    "get_current_day":           dict(capacity="date",   attacker=False, reachable=True),  # a date: can't carry an instruction
    # --- cloud-drive reads -------------------------------------------------- #
    "list_files":                dict(capacity="string", attacker=True,  reachable=True),  # file content = injection vector
    "get_file_by_id":            dict(capacity="string", attacker=True,  reachable=True),
    "search_files":              dict(capacity="string", attacker=True,  reachable=True),
    "search_files_by_filename":  dict(capacity="string", attacker=True,  reachable=True),
}
SINKS = {
    # --- email actions ------------------------------------------------------ #
    "send_email":                      dict(arg="recipients",     capacity="string", sensitive=True, category="exfiltration",        reachable=True),
    "delete_email":                    dict(arg="email_id",       capacity="enum",   sensitive=True, category="destructive",         reachable=True),
    # --- calendar actions --------------------------------------------------- #
    "create_calendar_event":           dict(arg="participants",   capacity="string", sensitive=True, category="exfiltration_inject", reachable=True),
    "add_calendar_event_participants": dict(arg="participants",   capacity="string", sensitive=True, category="exfiltration",        reachable=True),
    "cancel_calendar_event":           dict(arg="event_id",       capacity="enum",   sensitive=True, category="destructive",         reachable=True),
    "reschedule_calendar_event":       dict(arg="new_start_time", capacity="date",   sensitive=True, category="disruption",          reachable=True),
    # --- cloud-drive actions ------------------------------------------------ #
    "share_file":                      dict(arg="email",          capacity="string", sensitive=True, category="exfiltration",        reachable=True),
    "delete_file":                     dict(arg="file_id",        capacity="enum",   sensitive=True, category="destructive",         reachable=True),
    "create_file":                     dict(arg="content",        capacity="string", sensitive=True, category="data_write",          reachable=True),
    "append_to_file":                  dict(arg="content",        capacity="string", sensitive=True, category="data_write",          reachable=True),
}

if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    labels = sys.argv[1] if len(sys.argv) > 1 else here / "labels_workspace.csv"
    raise SystemExit(analyze("workspace", SOURCES, SINKS, labels))
