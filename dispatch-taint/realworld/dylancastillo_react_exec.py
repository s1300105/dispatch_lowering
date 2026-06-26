"""REAL-REPO analysis target A — create_react_agent with a USER-CODE exec sink.

Source: dylancastillo.co "Building ReAct agents with (and without) LangGraph"
(public tutorial).  Transcribed for STATIC ANALYSIS ONLY (never executed).  This
is the contrasting case to ``botextract_react_agent.py``: here the dangerous
operation (``exec``) lives in the agent's OWN tool body (user code), not inside a
library tool, so the per-tool sink judgement CAN ground it.

Pattern exercised (different from the botextract case):
  * ``@tool``-decorated function with the sink (``exec``) IN user code.
  * tool list bound to a variable, then ``create_react_agent(model, tools)``.
  * launched via ``.invoke({"messages": ...})``.

Expected: the framework wall resolves to ``run_python_code`` (code_execution),
because the classifier finds the ``exec`` in the tool body.
"""

from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI


@tool
def run_python_code(code: str) -> str:
    """Run arbitrary Python code. Save results as a variable."""
    import sys
    from io import StringIO

    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    namespace = {}
    try:
        exec(code, namespace)            # <-- code-execution sink, in USER code
        output = captured_output.getvalue()
        return output.strip() if output.strip() else "Code executed successfully"
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        sys.stdout = old_stdout


model = ChatOpenAI(model="gpt-4o", temperature=0)
tools = [run_python_code]
graph = create_react_agent(model, tools)


def main(question: str):
    return graph.invoke({"messages": [("user", question)]})
