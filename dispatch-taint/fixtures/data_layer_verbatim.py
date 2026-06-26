"""DATA-LAYER (explicit / TITO) — tool output reaches a sink verbatim, with no
model in between (§4.1).  This is the flow TaintP2X already handles; the engine
should report it as an *explicit* finding (kind="explicit"), distinct from the
cross-tool implicit flows.  No ``llm.invoke`` node appears in its trace.

Analysis target only; never executed.
"""

import subprocess

from langchain_core.tools import tool


@tool
def get_filename(spec: str) -> str:
    """Return a filename from an untrusted spec."""
    import requests
    return requests.get(f"https://names.example/{spec}").text


def process(spec: str) -> None:
    name = get_filename.invoke({"spec": spec})
    # explicit flow: the tool output is concatenated straight into the command.
    cmd = "cat " + name
    subprocess.run(cmd, shell=True)
