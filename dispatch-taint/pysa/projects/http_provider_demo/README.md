# HTTP-provider exit model (b/(2)) — for agents that call the LLM over raw HTTP

Many real agents (e.g. termwise) don't use an SDK; the LLM call is a **raw HTTP
POST inside a provider abstraction**:

```python
class OpenAIProvider:
    def complete_with_tools(self, messages):
        return self._client.post("/chat/completions", json={"messages": messages}).json()
```

So `chat.completions.create` is never called — the join@LLM is the HTTP POST.
This is a distinct exit surface (RQ4). It is modeled in one line: the prompt rides
in the POST body, so tag taint through `httpx.Client.post`'s `json=` as the LLM node:

```
def httpx.Client.post(self, url, json: TaintInTaintOut[Via[llm_node]], **kwargs): ...
```

## Demo (this project) — proven end-to-end
`src/app/agent.py` is a minimal HTTP-provider loop: a tool output (source) flows
into the history, the agent calls `provider.complete_with_tools(messages)` which
POSTs to `/chat/completions`, and the model's chosen tool is run (sink). Run:

```
cd pysa/projects/http_provider_demo && pyre analyze --save-results-to ./res
python ../../postprocess.py ./res --implicit-only
```

Result: **1 CROSS-TOOL IMPLICIT FLOW (CWE-1426)**. Pysa threads it
inter-procedurally *through the provider abstraction* (agent → complete_with_tools
→ httpx.post → response → tool dispatch → sink), and the structural implicit
classifier tags it correctly even though the LLM node is two call-hops from the
recorded flow callables.

### Supporting fix
The structural implicit detector (`postprocess._flow_traverses_llm_node`) now
walks the flow's **bounded call-closure** (issue callables + their same-file
callees, a few hops) and matches both alias-resolved and raw-dotted call targets
(so `self._client.post` matches the `httpx.Client.post` model). This keeps the
provider-abstraction case implicit without over-tagging (a no-LLM verbatim flow
stays explicit — verified).

## Literal termwise — honest outcome
* The HTTP-provider exit model is the right surface for termwise (its
  `BaseProvider.complete_with_tools` / `complete` POST to `/chat/completions`).
* **Pyre's analyzer CRASHES on the full termwise repo** (OCaml
  `Base__Sys0.getenv`, non-zero exit) — a real RQ3 *tooling-robustness* data
  point: Pyre can abort on real-world code and needs scoping/triage. An empty
  model still crashes (it's the code, not the model); a 5-module base slice and a
  10-module flow slice (agent/core + providers/base + tools/base + conversation +
  cost_tracker) analyze cleanly.
* On the clean 10-module flow slice, Pysa returns **0**: termwise's history bridge
  (a `ConversationManager` method, cross-object state) and its **dict-of-`BaseTool`-
  subclass dispatch** (`self.tools[name].execute`) are the same walls as shell_gpt
  — pure data-flow reaches the provider call and the dispatch site but not the
  concrete `ShellTool.execute` (`subprocess.run`). So termwise's concrete sinks +
  its `_check_safety` guard are surfaced by the **enumeration leg**
  (`corpus/termwise_enum.py`), not the data-flow leg.

## Net
The HTTP-provider exit model is a few-line, reusable addition that lets Pysa see
provider-abstracted LLM calls (proven on the demo). On the literal repo, Pyre
robustness (RQ3) and the dict-of-subclass tool dispatch push the concrete-sink job
onto the enumeration leg (b) + guard-aware ranking — the hybrid split holds.
