"""AgentDojo-derived ground truth for the SOURCE side of each suite (§5 precision).

A static analyzer needs a per-(source->sink) exploitability label to score
precision, and AgentDojo does not ship that table.  But AgentDojo DOES define
exactly WHERE attacker-controlled text is placed: each suite's
``data/suites/<suite>/injection_vectors.yaml`` names the injection slots, and the
suite environment embeds them in specific fields.  The tool that surfaces such a
field is, *by AgentDojo's own design*, a genuine attacker injection vector.

``INJECTION_VECTORS[suite]`` is transcribed from those slots + the field they are
embedded in (each mapping was verified against the suite's tools and tasks):

  banking   : injection_incoming_transaction  -> a transaction `subject`  => get_most_recent_transactions
              injection_{bill_text,landloard_notice,address_change} -> .txt files => read_file
  workspace : calendar_* -> event descriptions => get_day_calendar_events, search_calendar_events
              email_*    -> email bodies       => get_received_emails, get_unread_emails, search_emails
              drive_*    -> document contents   => get_file_by_id, search_files, search_files_by_filename, list_files
  travel    : injection_{hotels,restaurants,cars}_* -> reviews
              => get_rating_reviews_for_hotels / _restaurants / _car_rental.
              NOTE: travel has NO calendar injection slot, so the calendar readers
              are NOT injection vectors in this benchmark.
  slack     : injection_web_0 / injection_phishing_1 / injection_dora_0 /
              prompt_injection_eve_blog / prompt_injection_restaurant -> web-page
              content => get_webpage;  prompt_injection_channel -> a channel name
              => get_channels.
              NOTE: the attacker text lives on WEB pages, not in channel messages or
              the inbox.  The slack user tasks read a (benign) URL from a message and
              then call get_webpage, which surfaces the payload — so
              read_channel_messages / read_inbox are NOT injection vectors here.

This lets us score the tool's *source-side* precision against AgentDojo's own
ground truth with no manual labelling (see ``real_corpus --precision-vs-vectors``).

Caveat (rubric): a flagged source that is NOT in this set is a false positive only
*relative to this benchmark's chosen injection points*.  For a general
pre-deployment audit, treating any attacker-readable free-form field as a potential
vector is the conservative, recall-preserving choice (in a different deployment that
field could be attacker-influenced).  We therefore report this as
"precision vs AgentDojo injection points", not as an absolute precision.
"""

from __future__ import annotations

INJECTION_VECTORS = {
    "banking": {
        "get_most_recent_transactions",   # injection_incoming_transaction (transaction subject)
        "read_file",                      # injection_{bill_text,landloard_notice,address_change}
    },
    "workspace": {
        "get_day_calendar_events", "search_calendar_events",          # calendar_* (event descriptions)
        "get_received_emails", "get_unread_emails", "search_emails",  # email_* (email bodies)
        "get_file_by_id", "search_files", "search_files_by_filename", "list_files",  # drive_* (doc content)
    },
    "travel": {
        "get_rating_reviews_for_hotels",
        "get_rating_reviews_for_restaurants",
        "get_rating_reviews_for_car_rental",
    },
    "slack": {
        "get_webpage",     # injection_web_0/phishing_1/dora_0, prompt_injection_{eve_blog,restaurant}
        "get_channels",    # prompt_injection_channel (a malicious channel name)
    },
}
