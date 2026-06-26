"""Sink catalog.

A representative, data-driven subset of the 236 sink implementations reused
from TaintP2X (§2.1).  The list is intentionally a *catalog* (plain data) so it
extends to the full set by appending rows — no engine changes required.

Each sink records which parameter is dangerous and that parameter's expected
type, so the channel-capacity heuristic (§4.6) and schema pruner (§4.5(2)) can
reason about it.  Note that almost every high-severity sink's dangerous
parameter is a *free-form string*, which is exactly why the constrained-decoding
channel-capacity argument does not help the most dangerous cases (§4.6).
"""

from __future__ import annotations

from typing import List

from .base import CalleePattern as P
from .base import SinkSpec


def sink_models() -> List[SinkSpec]:
    return [
        # -- command / code execution --------------------------------------- #
        SinkSpec(P("run", recv_contains="subprocess"), "subprocess.run", "exec"),
        SinkSpec(P("Popen", recv_contains="subprocess"), "subprocess.Popen", "exec"),
        SinkSpec(P("call", recv_contains="subprocess"), "subprocess.call", "exec"),
        SinkSpec(P("check_output", recv_contains="subprocess"), "subprocess.check_output", "exec"),
        SinkSpec(P("check_call", recv_contains="subprocess"), "subprocess.check_call", "exec"),
        SinkSpec(P("system", recv_contains="os"), "os.system", "exec"),
        SinkSpec(P("popen", recv_contains="os"), "os.popen", "exec"),
        SinkSpec(P("eval", bare=True), "eval", "exec"),
        SinkSpec(P("exec", bare=True), "exec", "exec"),
        SinkSpec(P("getoutput", recv_contains="commands"), "commands.getoutput", "exec"),
        # sandboxed / container command execution: a `.exec([...])` on a sandbox
        # handle runs a command in a container. General pattern used by inspect_ai
        # (sandbox().exec(["bash","-c",cmd])), Docker SDK, and similar runners —
        # not specific to any one agent framework.
        SinkSpec(P("exec", recv_contains="sandbox"), "sandbox.exec", "exec"),

        # -- file system ---------------------------------------------------- #
        SinkSpec(P("open", bare=True), "open", "file", severity="medium"),
        SinkSpec(P("rmtree", recv_contains="shutil"), "shutil.rmtree", "file"),
        SinkSpec(P("remove", recv_contains="os"), "os.remove", "file"),
        SinkSpec(P("unlink", recv_contains="os"), "os.unlink", "file"),
        SinkSpec(P("write_text", recv_contains=""), "Path.write_text", "file", severity="medium"),
        SinkSpec(P("write_bytes", recv_contains=""), "Path.write_bytes", "file", severity="medium"),

        # -- SQL ------------------------------------------------------------ #
        SinkSpec(P("execute", recv_contains=""), "cursor.execute", "sql"),
        SinkSpec(P("executemany", recv_contains=""), "cursor.executemany", "sql"),
        SinkSpec(P("executescript", recv_contains=""), "cursor.executescript", "sql"),

        # -- network / SSRF ------------------------------------------------- #
        SinkSpec(P("get", recv_contains="requests"), "requests.get", "network"),
        SinkSpec(P("post", recv_contains="requests"), "requests.post", "network"),
        SinkSpec(P("request", recv_contains="requests"), "requests.request", "network"),
        SinkSpec(P("urlopen", recv_contains=""), "urllib.urlopen", "network"),
        SinkSpec(P("get", recv_contains="httpx"), "httpx.get", "network"),

        # -- deserialization ------------------------------------------------ #
        SinkSpec(P("loads", recv_contains="pickle"), "pickle.loads", "deserialize"),
        SinkSpec(P("load", recv_contains="yaml"), "yaml.load", "deserialize"),
        SinkSpec(P("loads", recv_contains="marshal"), "marshal.loads", "deserialize"),
    ]
