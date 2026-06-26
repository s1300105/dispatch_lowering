"""VULNERABLE — technical-sink dynamic-dispatch agent (FULL registry, 第一の選択).

A technical-sink analogue of the AgentDojo full fixtures, built on a REAL generic
framework (LangChain ``create_react_agent``) so the generic dispatch engine — not
any AgentDojo-specific declaration — resolves the wall. Every source and every
technical sink is registered, so resolving the framework-managed dispatch yields
the full source × sink candidate space (including over-flags), letting one run
show resolution -> over-flag -> pruning on TECHNICAL sinks.

Sinks are TECHNICAL (command execution / SSRF / file write): danger is the
capability itself, recognised syntactically — exactly as TaintP2X's sink model
and classic taint analysis do. No domain-semantic sink is declared.

Source roles:
  * attacker-influenced — untrusted external data the attacker can seed
    (web fetch, uploaded file, incoming message).
  * trusted-readonly    — data the app controls (own config, version constant).

Recall-first: resolve to ALL technical sinks for ALL sources, then role pruning
drops (trusted-readonly source -> technical sink) over-flags.

Analysis target only; never executed.
"""

import subprocess
import os

import requests
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent


# ---- SOURCES (attacker-influenced) -------------------------------------- #
@tool
def fetch_webpage(url: str) -> str:
    """attacker-influenced: remote content the attacker can control."""
    return requests.get(url).text


@tool
def read_uploaded_file(path: str) -> str:
    """attacker-influenced: a file the user/attacker supplied."""
    with open(path) as f:
        return f.read()


@tool
def read_incoming_message(message_url: str) -> str:
    """attacker-influenced: fetches a message from an attacker-supplied URL."""
    return requests.get(message_url).text


# ---- SOURCES (trusted-readonly) ----------------------------------------- #
@tool
def read_own_config(key: str) -> str:
    """trusted-readonly: reads the app's OWN config file (the attacker cannot
    write to it), so it is a source but not attacker-influenceable."""
    with open("/etc/myapp/config.ini") as f:
        return f.read()


@tool
def read_internal_db(table: str) -> str:
    """trusted-readonly: reads first-party data from the app's own internal DB
    over an authenticated channel the attacker cannot seed."""
    return requests.get("https://internal.myapp.local/db", params={"t": table}).text


# ---- TECHNICAL SINKS ----------------------------------------------------- #
@tool
def run_cmd(cmd: str) -> str:
    """technical sink: command execution."""
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@tool
def run_shell(script: str) -> int:
    """technical sink: command execution."""
    return os.system(script)


@tool
def fetch_url(url: str) -> str:
    """technical sink: network request (SSRF)."""
    return requests.get(url).text


@tool
def write_file(path: str, data: str) -> str:
    """technical sink: file write."""
    with open(path, "w") as f:
        f.write(data)
    return "ok"


def run_agent(user_goal: str):
    llm = ChatOpenAI(model="gpt-4o")
    agent = create_react_agent(llm, tools=[
        fetch_webpage, read_uploaded_file, read_incoming_message,   # attacker-influenced
        read_own_config, read_internal_db,                         # trusted-readonly
        run_cmd, run_shell, fetch_url, write_file,                  # technical sinks
    ])
    return agent.invoke({"messages": [("user", user_goal)]})
