import subprocess


def run_shell(cmd):
    subprocess.run(cmd, shell=True)


def echo(msg):
    return msg


REGISTRY = {"shell": run_shell, "echo": echo}


class BaseParser:
    def parse(self, text):
        raise NotImplementedError


class ShellParser(BaseParser):
    def parse(self, text):
        subprocess.run(text, shell=True)
