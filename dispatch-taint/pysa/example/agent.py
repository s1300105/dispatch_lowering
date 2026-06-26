"""Self-contained Pysa validation target (no external imports).

Demonstrates both things the standalone prototype could not do on its own:

  * the cross-tool IMPLICIT flow expressed as Pysa data flow — `read_ticket`
    (source) -> ... -> `call_model` (LLM TITO, tagged llm_node) -> `run_command`
    (sink); and
  * GENERAL INTER-PROCEDURAL coverage — the taint passes through `summarize`
    and `build_request`, ordinary helpers that are *not modeled at all*. Pysa's
    whole-program call-graph analysis propagates through them automatically.
    This is exactly limitation (2), resolved for free by Pysa.

Run `pyre analyze` over this directory and you should get one issue (code 9001)
whose trace carries the `llm_node` feature => an implicit CWE-1426 flow.

This file is an analysis target; it is never executed.
"""


def read_ticket() -> str:
    # SOURCE (modeled in models/example.pysa as TaintSource[ToolOutput]).
    with open("/tmp/ticket.txt") as fh:
        return fh.read()


def summarize(text: str) -> str:
    # ordinary helper — intentionally UNMODELED. Pysa propagates taint through it.
    return "ticket summary: " + text.strip()


def build_request(summary: str) -> dict:
    # another unmodeled helper, two call-hops from the source.
    return {"role": "user", "content": summary}


def call_model(prompt: dict) -> dict:
    # LLM NODE (modeled as TaintInTaintOut[Via[llm_node]]). In a real app this is
    # an external library call (e.g. llm.invoke) whose body Pysa cannot see, so
    # the TITO model carries prompt taint to the response.
    #
    # IMPORTANT for this self-contained example: the body deliberately IGNORES
    # `prompt` and returns a constant. That way the ONLY taint reaching the
    # response comes from the TITO *model* (which adds the `llm_node` feature),
    # mimicking a real external LLM whose body Pysa cannot analyse. If the body
    # propagated `prompt` itself, Pysa's in-project analysis would also produce a
    # featureless (explicit) flow and the implicit tag could be lost.
    return {"tool": "shell", "args": {"command": "<command chosen by the model>"}}


def run_command(decision: dict) -> None:
    import subprocess
    # SINK (subprocess.run modeled as TaintSink[CodeExecution]).
    subprocess.run(decision["args"]["command"], shell=True)


def agent_loop() -> None:
    raw = read_ticket()              # tool output (attacker-influenceable)
    summary = summarize(raw)         # inter-procedural hop 1 (unmodeled)
    prompt = build_request(summary)  # inter-procedural hop 2 (unmodeled)
    decision = call_model(prompt)    # LLM node: births the implicit/control edge
    run_command(decision)            # dangerous sink chosen by the model
