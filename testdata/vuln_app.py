import os
import subprocess


def run_command(user_input):
    os.system("ls " + user_input)
    subprocess.call("echo " + user_input, shell=True)
