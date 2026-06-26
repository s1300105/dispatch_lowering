"""VULNERABLE — AgentDojo-style runtime (travel), reduced to its static essence.

Mirrors the real AgentDojo structure (see agentdojo_banking_runtime.py):

  * tools are plain functions in a module-level TOOLS list, registered into a
    name->function dict (``FunctionsRuntime``);
  * the dispatch wall is ``run_function``: ``f = self.functions[name]; f(**kwargs)``;
  * an agent loop calls the LLM, then routes the model-chosen tool name through
    the runtime.

Injection vectors (attacker-controllable tool output, per AgentDojo's own
injection_vectors.yaml): the rating/review readers (attacker text lives in
reviews). Danger is domain-semantic: ``reserve_hotel`` books on the user's behalf.

This file is an analysis target only; it is never executed.
"""

from typing import Annotated

from openai import OpenAI


def get_rating_reviews_for_hotels(
    db: Annotated[object, "travel_db"], hotel_names: list
) -> dict:
    """Return hotel reviews (UNTRUSTED env data → tool-output source)."""
    return {h: db.hotel_reviews.get(h, []) for h in hotel_names}


def get_rating_reviews_for_restaurants(
    db: Annotated[object, "travel_db"], restaurant_names: list
) -> dict:
    """Return restaurant reviews (UNTRUSTED env data → tool-output source)."""
    return {r: db.restaurant_reviews.get(r, []) for r in restaurant_names}


def get_rating_reviews_for_car_rental(
    db: Annotated[object, "travel_db"], company_names: list
) -> dict:
    """Return car-rental reviews (UNTRUSTED env data → tool-output source)."""
    return {c: db.car_reviews.get(c, []) for c in company_names}


def reserve_hotel(
    reservation: Annotated[object, "reservation"],
    hotel: str,
    start_day: str,
    end_day: str,
) -> dict:
    """Make a hotel reservation (DANGEROUS — domain sink: booking on user's behalf)."""
    reservation.bookings.append({"hotel": hotel, "start": start_day, "end": end_day})
    return {"message": f"Reserved {hotel}."}


def reserve_restaurant(
    reservation: Annotated[object, "reservation"],
    restaurant: str,
    start_time: str,
) -> dict:
    """Make a restaurant reservation (DANGEROUS — domain sink: booking)."""
    reservation.bookings.append({"restaurant": restaurant, "time": start_time})
    return {"message": f"Reserved {restaurant}."}


TOOLS = [
    get_rating_reviews_for_hotels, get_rating_reviews_for_restaurants,
    get_rating_reviews_for_car_rental, reserve_hotel, reserve_restaurant,
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
