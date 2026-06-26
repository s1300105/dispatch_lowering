# Faithful transcription of the Semantic Kernel CVE-2026-26030 "hotel finder"
# shape, for STATIC ANALYSIS ONLY (never executed). Boilerplate (prompt text,
# embeddings wiring) trimmed; the tool construction + agent registration +
# launch are kept as published.
#
# Vulnerable chain in semantic-kernel < 1.39.4 (Python):
#   search_hotels(city=...)            # model-controlled tool arg  (source)
#     -> default_dynamic_filter_function (semantic_kernel/data/_shared.py:171)
#          new_filter = f"lambda x: x.{param.name} == '{kwargs[param.name]}'"   # unsanitized interpolation
#     -> InMemoryCollection._parse_filter (semantic_kernel/connectors/in_memory.py:384)
#          func = eval(code, {"__builtins__": {}}, {})                          # SINK (code_execution)
#
# The dispatch wall: the LLM selects which KernelFunction to call via
# ChatCompletionAgent(function_choice_behavior=FunctionChoiceBehavior.Auto()).
# The edge from the model's tool-choice into search_wrapper does not exist in
# the static call graph -> taint stops at the wall.

from dataclasses import dataclass
from typing import Annotated

from semantic_kernel.agents import ChatCompletionAgent
from semantic_kernel.connectors.ai import FunctionChoiceBehavior
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion
from semantic_kernel.connectors.in_memory import InMemoryCollection
from semantic_kernel.data.vector import VectorStoreField, vectorstoremodel
from semantic_kernel.functions import KernelParameterMetadata, KernelPlugin


@vectorstoremodel(collection_name="hotels")
@dataclass
class Hotel:
    hotel_id: Annotated[str, VectorStoreField("key")]
    city: Annotated[str, VectorStoreField("data")]
    name: Annotated[str, VectorStoreField("data")]
    embedding: Annotated[list[float] | str | None, VectorStoreField("vector", dimensions=1536)] = None


# Default in-memory store -> uses the eval-backed lambda filter path.
collection = InMemoryCollection(record_type=Hotel)

# The search tool exposed to the model. The `city` parameter is model-controlled
# and flows, unsanitised, into the lambda filter string that the store eval()s.
search_hotels = collection.create_search_function(
    function_name="search_hotels",
    description="Search for hotels in a specific city.",
    parameters=[
        KernelParameterMetadata(name="query", description="What to search for.", type="str", is_required=True, type_object=str),
        KernelParameterMetadata(name="city", description="The city to search in.", type="str", type_object=str),
    ],
)

search_plugin = KernelPlugin(name="hotels", functions=[search_hotels])

# The dispatch wall: Auto function-choice means the framework selects+invokes
# the chosen tool internally.
travel_agent = ChatCompletionAgent(
    name="TravelAgent",
    service=OpenAIChatCompletion(),
    instructions="You are a travel agent. Help the user find a hotel.",
    function_choice_behavior=FunctionChoiceBehavior.Auto(),
    plugins=[search_plugin],
)


async def main(user_message: str) -> str:
    # Launch: triggers auto function calling -> search_hotels(city=...) -> eval
    response = await travel_agent.get_response(messages=user_message)
    return str(response)
