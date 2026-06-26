# Faithful STRUCTURAL reproduction of semantic-kernel 1.39.3 CVE-2026-26030:
# the LLM-controlled name-keyed dispatch wall + the InMemory eval filter sink.
# STATIC ANALYSIS ONLY (never executed).
#
# Real file:line correspondence (semantic-kernel python @ python-1.39.3):
#   kernel.py:350                         -> get_function(fc.plugin_name, fc.function_name)
#   functions/kernel_function_extension.py:300 -> return self.plugins[plugin_name][function_name]   (WALL)
#   data/vector.py  (search_wrapper)      -> the tool body the model selects
#   data/_shared.py:171                   -> f"lambda x: x.{p.name} == '{kwargs[p.name]}'"  (interp)
#   connectors/in_memory.py:384           -> func = eval(code, {"__builtins__": {}}, {})    (SINK)

import ast
from typing import Any, Callable


# ---- SINK: connectors/in_memory.py:384 -------------------------------------
def parse_filter(filter_str: str) -> Callable:
    tree = ast.parse(filter_str, mode="eval")
    code = compile(tree, filename="<filter>", mode="eval")
    func = eval(code, {"__builtins__": {}}, {})   # <-- SINK (CodeExecution)
    return func


def collection_search(filter: str) -> Any:
    return parse_filter(filter)        # filter string flows into eval


# ---- interpolation: data/_shared.py:171 ------------------------------------
class Param:
    name: str


def default_dynamic_filter_function(parameters, **kwargs) -> Any:
    filter = None
    for param in parameters:
        if param.name in kwargs:
            # unsanitised interpolation of the model-controlled tool argument
            filter = f"lambda x: x.{param.name} == '{kwargs[param.name]}'"
    return filter


def _p(n: str) -> "Param":
    p = Param()
    p.name = n
    return p


# ---- the tool body the LLM selects: data/vector.py search_wrapper ----------
def search_wrapper(**kwargs) -> Any:
    parameters = [_p("city")]
    flt = default_dynamic_filter_function(parameters, **kwargs)
    return collection_search(filter=flt)


# ---- the dispatch wall: kernel.py / kernel_function_extension.py ------------
class FunctionCall:
    plugin_name: str
    function_name: str
    arguments: dict


class Kernel:
    def __init__(self) -> None:
        # plugins[plugin_name][function_name] -> the registered tool callable.
        # Populated like SK's KernelPlugin registration; the registry is a
        # name-keyed table, not a static call edge.
        self.plugins: dict = {}

    def add_function(self, plugin_name: str, function_name: str, fn: Callable) -> None:
        self.plugins.setdefault(plugin_name, {})[function_name] = fn

    def get_function(self, plugin_name: str, function_name: str) -> Callable:
        # name-keyed dynamic dispatch — opaque to the static call graph
        return self.plugins[plugin_name][function_name]

    def invoke_function_call(self, function_call: "FunctionCall") -> Any:
        # function_call is the model's chosen tool call (name + args) = LLM output.
        fn = self.get_function(function_call.plugin_name, function_call.function_name)
        # === ctaudit dispatch lowering: wall resolved to concrete candidate(s) ===
        # The name-keyed dispatch is lowered to explicit calls to the resolved
        # reachable tools, restoring the static edge taint propagation needs.
        if function_call.function_name == "search_hotels":
            return search_wrapper(**function_call.arguments)
        # === end ctaudit dispatch lowering ===
        return fn(**function_call.arguments)


def build_agent() -> "Kernel":
    k = Kernel()
    k.add_function("hotels", "search_hotels", search_wrapper)
    return k
