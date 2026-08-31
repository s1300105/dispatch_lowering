from tools import REGISTRY, BaseParser


def llm_decide(prompt):
    return prompt, prompt


class Agent:
    def __init__(self, parser: BaseParser):
        self.parser = parser

    def step(self, prompt):
        name, args = llm_decide(prompt)
        result = REGISTRY[name](args)
        self.parser.parse(args)
        return result
