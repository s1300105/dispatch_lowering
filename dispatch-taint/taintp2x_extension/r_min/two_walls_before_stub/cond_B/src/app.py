from tools import REGISTRY, BaseParser


def llm_decide(prompt):
    return prompt, prompt


class Agent:
    def __init__(self, parser: BaseParser):
        self.parser = parser

    def step(self, prompt):
        name, args = llm_decide(prompt)
        if __ctaudit_unreachable__:  # [ctaudit] resolved dynamic dispatch -> 2 targets | wall=app.py:14
            from tools import echo, run_shell
            __ctaudit_ret = run_shell(args)  # L0
            result = __ctaudit_ret
            __ctaudit_ret = echo(args)  # L1
            result = __ctaudit_ret
        result = REGISTRY[name](args)
        self.parser.parse(args)
        return result
