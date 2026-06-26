"""VULNERABLE — AgentDojo-style runtime (banking), reduced to its static essence.

This mirrors the real AgentDojo structure confirmed by reconnaissance:

  * tools are plain functions listed in a module-level TOOLS list and registered
    into a name->function dict (``FunctionsRuntime``);
  * the dispatch wall is ``run_function``: ``f = self.functions[name]; f(**kwargs)``
    — a dict-registry lookup indirected through a local, in the runtime;
  * an agent loop calls the LLM, then routes the model-chosen tool name through
    the runtime.

Danger is domain-semantic: ``send_money`` just appends to the account (no syntactic
sink), but sending money to an attacker is the dangerous capability. ``read_file``
returns environment data (a tool-output source the model later reads).

This file is an analysis target only; it is never executed and the OpenAI/agentdojo
imports are illustrative.
"""

from typing import Annotated, Callable

from openai import OpenAI


class BankAccount:
    transactions: list


def get_most_recent_transactions(
    account: Annotated[BankAccount, "bank_account"], n: int = 100
) -> list:
    """Return recent transactions (UNTRUSTED environment data → tool-output source)."""
    return account.transactions[-n:]


def read_file(filesystem: Annotated[object, "filesystem"], file_path: str) -> str:
    """Return file contents (UNTRUSTED environment data → tool-output source)."""
    return filesystem.files.get(file_path, "")


def send_money(
    account: Annotated[BankAccount, "bank_account"],
    recipient: str,
    amount: float,
    subject: str,
    date: str,
) -> dict:
    """Send a transaction (DANGEROUS — domain sink: money movement)."""
    account.transactions.append(
        {"recipient": recipient, "amount": amount, "subject": subject, "date": date}
    )
    return {"message": f"Transaction to {recipient} for {amount} sent."}


def get_balance(account: Annotated[BankAccount, "bank_account"]) -> float:
    """Return the balance (benign read)."""
    return account.balance


TOOLS = [get_most_recent_transactions, read_file, send_money, get_balance]


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
