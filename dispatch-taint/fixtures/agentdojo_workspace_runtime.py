"""VULNERABLE — AgentDojo-style runtime (workspace), reduced to its static essence.

Mirrors the real AgentDojo structure (see agentdojo_banking_runtime.py):

  * tools are plain functions in a module-level TOOLS list, registered into a
    name->function dict (``FunctionsRuntime``);
  * the dispatch wall is ``run_function``: ``f = self.functions[name]; f(**kwargs)``
    — a dict-registry lookup indirected through a local, in the runtime;
  * an agent loop calls the LLM, then routes the model-chosen tool name through
    the runtime.

Injection vectors (attacker-controllable tool output, per AgentDojo's own
injection_vectors.yaml): calendar/email/drive readers. Danger is domain-semantic:
``send_email`` exfiltrates, ``delete_email`` destroys.

This file is an analysis target only; it is never executed.
"""

from typing import Annotated

from openai import OpenAI


def get_received_emails(inbox: Annotated[object, "inbox"]) -> list:
    """Return received emails (UNTRUSTED env data → tool-output source)."""
    return inbox.received


def search_emails(inbox: Annotated[object, "inbox"], query: str) -> list:
    """Search emails (UNTRUSTED env data → tool-output source)."""
    return [m for m in inbox.received if query in m.body]


def get_day_calendar_events(calendar: Annotated[object, "calendar"], day: str) -> list:
    """Return events for a day (UNTRUSTED env data → tool-output source)."""
    return calendar.events.get(day, [])


def search_files(drive: Annotated[object, "drive"], query: str) -> list:
    """Search files (UNTRUSTED env data → tool-output source)."""
    return [f for f in drive.files if query in f.content]


def send_email(
    inbox: Annotated[object, "inbox"],
    recipients: str,
    subject: str,
    body: str,
) -> dict:
    """Send an email (DANGEROUS — domain sink: exfiltration to a recipient)."""
    inbox.sent.append({"to": recipients, "subject": subject, "body": body})
    return {"message": f"Email to {recipients} sent."}


def delete_email(inbox: Annotated[object, "inbox"], email_id: str) -> dict:
    """Delete an email (DANGEROUS — domain sink: destruction)."""
    inbox.received = [m for m in inbox.received if m.id != email_id]
    return {"message": f"Email {email_id} deleted."}


TOOLS = [
    get_received_emails, search_emails, get_day_calendar_events, search_files,
    send_email, delete_email,
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
