#!/usr/bin/env python3
"""AgentDojo travel suite — cross-tool implicit-flow audit (Stage-4, M2).

Same enumeration approach as the other suites (see README). The travel suite has
28 tools across hotels / restaurants / car-rental / flights + calendar + email.
The attacker-injection vector in travel is the rating/review text returned by
get_rating_reviews_for_* (a planted review); factual lookups (names, addresses,
prices, cuisines, hours) and the user's own PII (get_user_information) are NOT
injection vectors. The 7th injection task (InjectionTask6) has no tool call — it
only biases the agent's free-text recommendation — so it contributes no
(source, sink) pair and is not labelled.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import analyze  # noqa: E402

SOURCES = {
    # --- attacker-injection vectors: review text + calendar descriptions ---- #
    "get_rating_reviews_for_hotels":      dict(capacity="string",  attacker=True,  reachable=True),
    "get_rating_reviews_for_restaurants": dict(capacity="string",  attacker=True,  reachable=True),
    "get_rating_reviews_for_car_rental":  dict(capacity="string",  attacker=True,  reachable=True),
    "search_calendar_events":             dict(capacity="string",  attacker=True,  reachable=True),
    "get_day_calendar_events":            dict(capacity="string",  attacker=True,  reachable=True),
    # --- user PII + factual string lookups (not injection vectors → role) ---- #
    "get_user_information":               dict(capacity="string",  attacker=False, reachable=True),  # the user's OWN PII (the exfil target, not the injection)
    "get_all_hotels_in_city":             dict(capacity="string",  attacker=False, reachable=True),
    "get_hotels_address":                 dict(capacity="string",  attacker=False, reachable=True),
    "get_all_restaurants_in_city":        dict(capacity="string",  attacker=False, reachable=True),
    "get_restaurants_address":            dict(capacity="string",  attacker=False, reachable=True),
    "get_contact_information_for_restaurants": dict(capacity="string", attacker=False, reachable=True),
    "get_all_car_rental_companies_in_city":    dict(capacity="string", attacker=False, reachable=True),
    "get_car_rental_address":             dict(capacity="string",  attacker=False, reachable=True),
    # --- numeric / enum lookups (cannot carry an instruction → schema) ------- #
    "get_hotels_prices":                  dict(capacity="numeric", attacker=False, reachable=True),
    "get_price_for_restaurants":          dict(capacity="numeric", attacker=False, reachable=True),
    "get_car_price_per_day":              dict(capacity="numeric", attacker=False, reachable=True),
    "get_cuisine_type_for_restaurants":   dict(capacity="enum",    attacker=False, reachable=True),
    "get_dietary_restrictions_for_all_restaurants": dict(capacity="enum", attacker=False, reachable=True),
    "check_restaurant_opening_hours":     dict(capacity="enum",    attacker=False, reachable=True),
    "get_car_types_available":            dict(capacity="enum",    attacker=False, reachable=True),
    "get_car_fuel_options":               dict(capacity="enum",    attacker=False, reachable=True),
    "get_flight_information":             dict(capacity="enum",    attacker=False, reachable=True),
}
SINKS = {
    "reserve_hotel":          dict(arg="hotel",        capacity="string", sensitive=True, category="booking",             reachable=True),
    "reserve_restaurant":     dict(arg="restaurant",   capacity="string", sensitive=True, category="booking",             reachable=True),
    "reserve_car_rental":     dict(arg="company",      capacity="string", sensitive=True, category="booking",             reachable=True),
    "create_calendar_event":  dict(arg="participants", capacity="string", sensitive=True, category="exfiltration_inject", reachable=True),
    "cancel_calendar_event":  dict(arg="event_id",     capacity="enum",   sensitive=True, category="destructive",         reachable=True),
    "send_email":             dict(arg="recipients",   capacity="string", sensitive=True, category="exfiltration",        reachable=True),
}

if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    labels = sys.argv[1] if len(sys.argv) > 1 else here / "labels_travel.csv"
    raise SystemExit(analyze("travel", SOURCES, SINKS, labels))
