"""REAL-REPO analysis target — class-based BaseTool with an ``eval`` sink.

Source: python-a2a documentation, "LangChain Agents with Tools Examples" (public).
Transcribed for STATIC ANALYSIS ONLY (never executed); the A2A server wiring and
agent-card boilerplate are trimmed, the tool class and agent construction/launch
are kept as published.

New pattern (not covered by the earlier three real targets):
  * the dangerous tool is a CLASS that subclasses ``BaseTool`` and puts the sink
    (``eval(query)``) in its ``_run`` method (user code), not a ``@tool`` function,
    an undecorated function, or a ``Tool(...)`` wrapper.
  * a benign source tool (``DuckDuckGoSearchRun``) is registered alongside.
  * registered with a LITERAL list via ``AgentExecutor`` + create_openai_functions_agent.

Expected: the wall is detected with candidates {calculator_tool, search_tool}, and
the class tool resolves to ``calculator`` (code_execution) because the classifier
recognises a BaseTool subclass whose ``_run`` body contains ``eval`` — and 方向C
should mark the argument as reaching (``eval(query)`` passes the parameter directly).
"""

from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.tools import BaseTool
from langchain_community.tools import DuckDuckGoSearchRun
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI


class CalculatorTool(BaseTool):
    name = "calculator"
    description = "Useful for performing mathematical calculations."

    def _run(self, query: str) -> str:
        """Calculate the result of a mathematical expression."""
        try:
            return str(eval(query))                  # <-- code-execution sink, user code
        except Exception as e:
            return f"Error evaluating expression: {str(e)}"

    async def _arun(self, query: str) -> str:
        return self._run(query)


search_tool = DuckDuckGoSearchRun()
calculator_tool = CalculatorTool()

tools = [calculator_tool, search_tool]

llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant with tools."),
    ("human", "{input}"),
    ("ai", "{agent_scratchpad}"),
])

agent = create_openai_functions_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)


def main(question: str):
    return agent_executor.invoke({"input": question})
