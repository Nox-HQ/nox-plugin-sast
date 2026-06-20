import os
import subprocess


def run_command(user_input):
    os.system("ls " + user_input)
    subprocess.call("echo " + user_input, shell=True)


import hashlib
import requests
from flask import redirect, request
from jinja2 import Template


def fetch(part):
    requests.get("http://internal/" + part)              # SSRF (SAST-006)


def weak_hash(data):
    return hashlib.md5(data).hexdigest()                 # weak crypto (SAST-007)


def go_next():
    return redirect(request.args.get("next"))            # open redirect (SAST-008)


def render_name():
    return Template("Hello " + request.args.get("x")).render()  # SSTI (SAST-009)


def unsafe_query(cursor, val):
    cursor.execute("SELECT * FROM t WHERE x = '%s'" % val)  # SQLi via % operator (SAST-001)
