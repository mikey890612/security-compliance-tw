"""Intentional insecure snippets for open-source scanner fixture verification (bandit)."""

import os
import subprocess


def bad_sql(user_input: str) -> str:
    # bandit B608: hardcoded_sql_expressions
    return "SELECT * FROM users WHERE name = '%s'" % user_input


def bad_shell(user_input: str) -> None:
    # bandit B602: subprocess_popen_with_shell_equals_true
    subprocess.call("echo " + user_input, shell=True)


def bad_chmod(path: str) -> None:
    # bandit B103: set_bad_file_permissions
    os.chmod(path, 0o777)
