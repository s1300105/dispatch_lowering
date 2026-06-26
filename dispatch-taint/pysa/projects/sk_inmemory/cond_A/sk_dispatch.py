# Faithful STRUCTURAL reproduction of semantic-kernel 1.39.3 CVE-2026-26030:
# the LLM-controlled name-keyed dispatch wall + the InMemory eval filter sink.
# STATIC ANALYSIS ONLY (never executed).
#
# Real file:line correspondence (semantic-kernel python @ python-1.39.3):
#   functions/kernel_function_extension.py:300 -> return self.plugins[plugin_name][function_name]   (WALL)
#   kernel.py:350                              -> get_function(fc.plugin_name, fc.function_name)
#   data/vector.py search_wrapper              -> the tool body the model selects
#                                                 (declared params via KernelParameterMetadata: query, city)
#   data/_shared.py:171                        -> f"lambda x: x.{p.name} == '{kwargs[p.name]}'"  (interp)
#   connectors/in_memory.py:382-384            -> eval(compile(ast.parse(filter_str)))            (SINK)
#   registration                               -> KernelPlugin(name=..., functions=[create_search_function(...)])

import ast
from typing import Any, Callable


# ---- SINK: connectors/in_memory.py:382-384 ---------------------------------
def parse_filter(filter_str: str) -> Callable:
    tree = ast.parse(filter_str, mode="eval")
    code = compile(tree, filename="<filter>", mode="eval")
    func = eval(code, {"__builtins__": {}}, {})   # <-- SINK (CodeExecution)
    return func


def collection_search(filter: str) -> Any:
    return parse_filter(filter)


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


# ---- tool body the LLM selects: data/vector.py search_wrapper --------------
# Declared parameters mirror the KernelParameterMetadata schema (query, city).
def search_wrapper(query: str = "", city: str = "") -> Any:
    parameters = [_p("city")]
    flt = default_dynamic_filter_function(parameters, query=query, city=city)
    return collection_search(filter=flt)


# ---- registration: KernelPlugin(functions=[...]) (real SK API) -------------
class KernelPlugin:
    def __init__(self, name: str, functions: list) -> None:
        self.name = name
        self.functions = functions


# ---- dispatch wall: kernel.py / kernel_function_extension.py ----------------
class FunctionCall:
    plugin_name: str
    function_name: str
    arguments: dict


class Kernel:
    def __init__(self, plugins=None) -> None:
        self.plugins: dict = {}
        for p in (plugins or []):
            self.plugins[p.name] = {f.__name__: f for f in p.functions}

    def get_function(self, plugin_name: str, function_name: str) -> Callable:
        # name-keyed dynamic dispatch — opaque to the static call graph
        return self.plugins[plugin_name][function_name]

    def invoke_function_call(self, function_call: "FunctionCall") -> Any:
        # function_call is the model's chosen tool call (name + args) = LLM output.
        fn = self.get_function(function_call.plugin_name, function_call.function_name)
        # WALL: fn == plugins[name][fname]; no static edge to search_wrapper.
        return fn(**function_call.arguments)


search_plugin = KernelPlugin(name="hotels", functions=[search_wrapper])


def build_agent() -> "Kernel":
    return Kernel(plugins=[search_plugin])
