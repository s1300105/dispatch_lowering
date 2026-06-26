"""REAL-REPO analysis target — transcribed from a PUBLIC LangChain ReAct agent.

Source: github.com/botextractai/ai-langchain-react-agent  (public, MIT-style template,
"Create a LangChain ReAct agent with multiple tools: Python REPL and DuckDuckGo
Search").  This file is a faithful transcription of that repository's single-file
agent for STATIC ANALYSIS ONLY (it is never executed here).  Some boilerplate
(prompt text, comments) is trimmed; the tool definitions and the agent
construction/launch — the parts ctaudit reasons about — are kept as published.

Why it is a relevant real-world case for 項目1:
  * DuckDuckGoSearchRun is an attacker-influenceable SOURCE (returns text fetched
    from the open web).
  * PythonAstREPLTool.run executes arbitrary Python — a code-execution SINK.
  * Both are registered with create_react_agent + AgentExecutor, and the agent is
    launched with .invoke(...).  The dispatch to the chosen tool happens INSIDE the
    framework (AgentExecutor's loop), so the wall is invisible to a syntactic scan
    of this file — exactly the framework-managed pattern 項目1 targets.

The judgement criterion is FLOW REACHABILITY (does source -> LLM -> dangerous tool
connect in the code?), not whether the template is an exploitable vulnerability.
"""

from langchain import hub
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_community.tools import DuckDuckGoSearchRun
from langchain_experimental.tools.python.tool import PythonAstREPLTool
from langchain_openai import ChatOpenAI

# LLM
llm = ChatOpenAI(openai_api_key="REPLACE_ME", temperature=0, model="gpt-3.5-turbo")

prompt = hub.pull("hwchase17/react")

# Python REPL tool — executes arbitrary Python (code-execution sink).
python_repl = PythonAstREPLTool()
python_repl_tool = Tool(
    name="Python REPL",
    func=python_repl.run,
    description="A Python shell. Use this to execute python commands.",
)

# DuckDuckGo search tool — returns text fetched from the open web (untrusted source).
search = DuckDuckGoSearchRun()
duckduckgo_tool = Tool(
    name="DuckDuckGo Search",
    func=search.run,
    description="Use this to search the internet for current information.",
)

tools = [python_repl_tool, duckduckgo_tool]

agent = create_react_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)


def main(question: str):
    return agent_executor.invoke({"input": question})
