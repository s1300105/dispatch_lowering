"""Hand-labelled ground truth for the tool-classifier benchmark (proposal RQ4).

Each repo is labelled by reading its actual tool registry / executors. We record,
per repo: the registration *idiom*, whether it was used while tuning the heuristic
(so we can report held-out metrics separately), and the gold set of
source/sink/guard tools that the enumeration leg should recover.

Only LLM-exposed / registry tools count (that is what cross-tool implicit flow is
about). Pure control-flow tools (e.g. codecli's report_*), chat services, and
verbatim-exec apps (the model's text is run directly, with no named tool registry)
have an empty gold set — they test the classifier's PRECISION (it must not invent
tools), not its recall.

`roles`    : subset of {"source","sink"}
`category` : sink category for sinks (code_execution|file_write|sql|network|deserialize), else None
`guard`    : in-/cross-layer guard name if the dangerous call is mitigated, else None
"""

import os

# Where the corpus repos live. Override on another machine, e.g.
#   export CTAUDIT_CORPUS_BASE=/path/to/your/agent/repos
CORPUS_BASE = os.environ.get("CTAUDIT_CORPUS_BASE", "/home/claude/cand")

# repo_key -> spec
GOLD = {
    # ----- tuning repos (class-based tools; the heuristic was iterated on these) -----
    "shellgpt": {
        "rel": "shellgpt", "src_rel": "shellgpt", "idiom": "class+schema-method",
        "tuning": True,
        "tools": {
            "execute_shell_command": {"roles": ["source", "sink"], "category": "code_execution", "guard": None},
            "execute_apple_script":  {"roles": ["source", "sink"], "category": "code_execution", "guard": None},
        },
        "note": "Function(BaseModel) classes with execute() + openai_schema()",
    },
    "termwise": {
        "rel": "termwise", "src_rel": "termwise", "idiom": "class+BaseTool+name-property",
        "tuning": True,
        "tools": {
            "shell":      {"roles": ["source", "sink"], "category": "code_execution", "guard": "_check_safety"},
            "write_file": {"roles": ["sink"],           "category": "file_write",     "guard": None},
            "read_file":  {"roles": ["source"],         "category": None,             "guard": None},
            "search":     {"roles": ["source"],         "category": None,             "guard": None},
        },
        "note": "BaseTool subclasses; search's file-read lives in a helper method",
    },

    # ----- held-out repos (NOT used while tuning) -----
    "codecli": {
        "rel": "codecli", "src_rel": "codecli/app", "idiom": "dict-registry+dispatcher",
        "tuning": False,
        "tools": {
            "list_files":  {"roles": ["source"], "category": None,         "guard": None},
            "read_file":   {"roles": ["source"], "category": None,         "guard": None},
            "search_text": {"roles": ["source"], "category": None,         "guard": None},
            "write_file":  {"roles": ["sink"],   "category": "file_write", "guard": "confirm_action"},
            "apply_diff":  {"roles": ["sink"],   "category": "file_write", "guard": "confirm_action"},
            # report_findings/plan/blocked/done = control-flow tools (no fs) -> excluded
        },
        "note": ("TOOL_SCHEMAS dict + _ALL_TOOLS + central run_tool() dispatcher; "
                 "sink bodies live in files.py/diff.py; the confirm guard is in the "
                 "dispatcher (run_tool), a DIFFERENT layer than the sink"),
    },
    "aicmd": {
        "rel": "aicmd", "src_rel": "aicmd/src", "idiom": "verbatim-exec",
        "tuning": False, "tools": {},
        "note": "execute_command() runs the model's suggested command directly; no tool registry",
    },
    "shelloracle": {
        "rel": "shelloracle", "src_rel": "shelloracle/src", "idiom": "verbatim-exec",
        "tuning": False, "tools": {},
        "note": "suggests a shell command executed by shell integration; no tool registry",
    },
    "incognito": {
        "rel": "incognito", "src_rel": "incognito", "idiom": "chat-service",
        "tuning": False, "tools": {},
        "note": "LLM chat service (llama via TGI/Replicate); no executable tools",
    },
    "haseeb_ci": {
        "rel": "haseeb_ci", "src_rel": "haseeb_ci", "idiom": "code-interpreter",
        "tuning": False, "tools": {},
        "note": ("code interpreter exec's model-generated code (single sink, verbatim-ish); "
                 "no multi-tool registry. Borderline: the interpreter is itself a code-exec sink"),
    },
}

# A synthetic repo reproducing the dict-registry idiom, so the recall hole is
# demonstrable WITHOUT the private corpus. Written to a temp dir by the harness.
SYNTHETIC_DICT_REGISTRY = {
    "files.py": (
        "from pathlib import Path\n"
        "def read_file(root, rel):\n"
        "    return Path(root, rel).read_text()\n"
        "def write_file(root, rel, content):\n"
        "    Path(root, rel).write_text(content)\n"
        "    return 'ok'\n"
    ),
    "safety.py": (
        "def confirm_action(prompt):\n"
        "    return input(prompt).strip().lower() == 'y'\n"
    ),
    "tools.py": (
        "import files, safety\n"
        "TOOL_SCHEMAS = {'read_file': {}, 'write_file': {}}\n"
        "_ALL_TOOLS = {'read_file', 'write_file'}\n"
        "def run_tool(name, args, settings):\n"
        "    if name == 'read_file':\n"
        "        return files.read_file(settings['root'], args.get('path',''))\n"
        "    if name == 'write_file':\n"
        "        if not safety.confirm_action('write? [y/N] '):\n"
        "            return {'ok': False}\n"
        "        return files.write_file(settings['root'], args.get('path',''), args.get('content',''))\n"
    ),
    "agent.py": (
        "import openai\n"
        "client = openai.OpenAI()\n"
        "completion = client.chat.completions.create\n"
        "def step(msgs):\n"
        "    return completion(model='x', messages=msgs)\n"
    ),
}
SYNTHETIC_GOLD = {
    "idiom": "dict-registry+dispatcher (synthetic)",
    "tuning": False,
    "tools": {
        "read_file":  {"roles": ["source"], "category": None,         "guard": None},
        "write_file": {"roles": ["sink"],   "category": "file_write", "guard": "confirm_action"},
    },
    "note": "portable reproduction of the codecli idiom",
}
