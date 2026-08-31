from tools import REGISTRY, resolve


def llm_decide(prompt):
    return prompt, prompt


class Agent:
    def __init__(self, tools):
        self.tools = tools

    def step(self, prompt):
        name, args = llm_decide(prompt)
        t = self.tools[name]
        t.run(args)
        names = [t.name for t in self.tools]
        return names


def resolved_then_comprehension(prompt, tools):
    name, args = llm_decide(prompt)
    handler = resolve(name)
    handler(args)
    return [handler(args) for handler in tools]


def lambda_call(prompt):
    name, args = llm_decide(prompt)
    return list(map(lambda h: h(args), REGISTRY.values()))
