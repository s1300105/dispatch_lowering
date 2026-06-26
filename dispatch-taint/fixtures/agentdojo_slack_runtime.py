"""VULNERABLE — AgentDojo-style runtime (slack), reduced to its static essence.

Mirrors the real AgentDojo structure (see agentdojo_banking_runtime.py):

  * tools are plain functions in a module-level TOOLS list, registered into a
    name->function dict (``FunctionsRuntime``);
  * the dispatch wall is ``run_function``: ``f = self.functions[name]; f(**kwargs)``;
  * an agent loop calls the LLM, then routes the model-chosen tool name through
    the runtime.

Injection vectors (attacker-controllable tool output, per AgentDojo's own
injection_vectors.yaml): ``get_webpage`` (attacker text lives on fetched web
pages) and ``get_channels`` (a malicious channel name). Danger is
domain-semantic: ``send_direct_message`` exfiltrates; ``invite_user_to_slack``
performs an unauthorized action.

This file is an analysis target only; it is never executed.
"""

from typing import Annotated

from openai import OpenAI


def get_webpage(web: Annotated[object, "web"], url: str) -> str:
    """Fetch a web page (UNTRUSTED external content → tool-output source)."""
    return web.pages.get(url, "")


def get_channels(slack: Annotated[object, "slack"]) -> list:
    """List channels (UNTRUSTED — a channel name can carry attacker text)."""
    return slack.channels


def read_inbox(slack: Annotated[object, "slack"], user: str) -> list:
    """Read a user's DMs (benign read; not an injection vector in this suite)."""
    return slack.user_inbox.get(user, [])


def send_direct_message(
    slack: Annotated[object, "slack"],
    recipient: str,
    body: str,
) -> dict:
    """Send a Slack DM (DANGEROUS — domain sink: exfiltration to a recipient)."""
    slack.sent.append({"to": recipient, "body": body})
    return {"message": f"DM to {recipient} sent."}


def invite_user_to_slack(
    slack: Annotated[object, "slack"],
    user: str,
    user_email: str,
) -> dict:
    """Invite a user (DANGEROUS — domain sink: unauthorized action)."""
    slack.users.append(user)
    return {"message": f"Invited {user}."}


TOOLS = [
    get_webpage, get_channels, read_inbox, send_direct_message, invite_user_to_slack,
]


class FunctionsRuntime:
    def __init__(self, functions):
        self.functions = {f.__name__: f for f in functions}

    def run_function(self, env, function: str, kwargs):
        f = self.functions[function]          # dict-registry lookup (LLM-chosen name)
        return f(**kwargs), None              # the dispatch wall (indirected via f)


def run_agent(query: str):
    runtime = FunctionsRuntime(TOOLS)
    client = OpenAI()
    messages = [{"role": "user", "content": query}]
    for _ in range(15):
        resp = client.chat.completions.create(messages=messages, model="gpt-4o")
        tool_calls = resp.choices[0].message.tool_calls
        if not tool_calls:
            break
        for tc in tool_calls:
            runtime.run_function(None, tc.function.name, tc.function.arguments)
    return messages[-1]["content"]
