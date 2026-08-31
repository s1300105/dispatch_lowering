import subprocess


def run_shell(cmd):
    subprocess.run(cmd, shell=True)


def echo(msg):
    return msg


REGISTRY = {"shell": run_shell, "echo": echo}


def resolve(name):
    return REGISTRY[name]
