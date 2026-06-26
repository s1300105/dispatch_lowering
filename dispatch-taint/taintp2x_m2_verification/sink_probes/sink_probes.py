"""sink_probes.py — minimal per-class sink confirmation target for TaintP2X.

Each function takes ONE (or two) parameter that sink_probes.pysa marks as
TaintSource[LLMControlled], and pipes it directly into one dangerous sink.
Run via run_sink_probes.sh and check that each expected rule code fires.

Expected codes (source kind = LLMControlled):
    probe_rce_eval        -> 5001  (RemoteCodeExecution)   [positive control: known to fire]
    probe_ssrf_requests   -> 5015  (SSRFSink)              [base model: requests.api.get]
    probe_ssrf_urllib     -> 5015  (SSRFSink)              [needs ssrf_sinks_ext.pysa]
    probe_deser_pickle    -> 5003  (ExecDeserializationSink)
    probe_deser_yaml      -> 5003  (ExecDeserializationSink)
    probe_filewrite_open  -> 5010  (FileSystem_ReadWrite, mode=w)
    probe_filewrite_path  -> 5010  (FileSystem_ReadWrite)
    probe_sql             -> 5008  (SQL)
"""
import pickle
import sqlite3
import urllib.request
from pathlib import Path

import requests
import yaml


# ---- positive control: we already validated RCE fires; if this is MISSING the harness is broken ----
def probe_rce_eval(expr: str):
    return eval(expr)                               # 5001

# ---- SSRF ----
def probe_ssrf_requests(u: str):
    return requests.get(u)                          # 5015 (base http_server.pysa)

def probe_ssrf_urllib(u: str):
    return urllib.request.urlopen(u)                # 5015 (needs ssrf_sinks_ext.pysa)

# ---- deserialization ----
def probe_deser_pickle(data: bytes):
    return pickle.loads(data)                       # 5003

def probe_deser_yaml(text: str):
    return yaml.load(text, Loader=yaml.Loader)      # 5003

# ---- file write / path traversal ----
def probe_filewrite_open(path: str, content: str) -> None:
    with open(path, "w") as f:                      # 5010 (mode tag = "w")
        f.write(content)

def probe_filewrite_path(path: str, content: str) -> None:
    Path(path).write_text(content)                  # 5010

# ---- SQL ----
def probe_sql(cur: sqlite3.Cursor, query: str):
    cur.execute(query)                              # 5008
    return cur.fetchall()
