#!/usr/bin/env python3
"""AgentDojo banking suite — cross-tool implicit-flow audit (Stage-4, M2).

WHY ENUMERATION, NOT THE PYSA PORT (see README): AgentDojo's tools are isolated
functions registered in a suite's TOOLS list. There is no code dataflow between
a source tool (e.g. get_most_recent_transactions, whose returned transaction
`subject` carries attacker text) and a sink tool (e.g. send_money) — only the
LLM links them. So the cross-tool flow is a property of the tool registry +
join-at-LLM (§4.2/§4.4), and we enumerate co-registered (source, sink) pairs and
prune with §4.5, then score against the suite's injection-task labels.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import analyze  # noqa: E402

# banking TOOLS (default_suites/v1/banking/task_suite.py), with metadata read
# off the real signatures in tools/banking_client.py + user_account.py.
SOURCES = {
    "get_most_recent_transactions": dict(capacity="string",  attacker=True,  reachable=True),  # txn.subject = injection vector
    "get_scheduled_transactions":   dict(capacity="string",  attacker=True,  reachable=True),
    "read_file":                    dict(capacity="string",  attacker=True,  reachable=True),
    "get_user_info":                dict(capacity="string",  attacker=True,  reachable=True),
    "get_balance":                  dict(capacity="numeric", attacker=False, reachable=True),  # a number: can't carry an instruction
    "get_iban":                     dict(capacity="string",  attacker=False, reachable=True),  # the user's OWN iban: not attacker-set
}
SINKS = {
    "send_money":                   dict(arg="recipient", capacity="string", sensitive=True, category="money_transfer",   reachable=True),
    "schedule_transaction":         dict(arg="recipient", capacity="string", sensitive=True, category="money_transfer",   reachable=True),
    "update_scheduled_transaction": dict(arg="recipient", capacity="string", sensitive=True, category="money_transfer",   reachable=True),
    "update_password":              dict(arg="password",  capacity="string", sensitive=True, category="account_takeover", reachable=True),
    "update_user_info":             dict(arg="street",    capacity="string", sensitive=True, category="account_modify",   reachable=True),
}

if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    labels = sys.argv[1] if len(sys.argv) > 1 else here / "labels_banking.csv"
    raise SystemExit(analyze("banking", SOURCES, SINKS, labels))
