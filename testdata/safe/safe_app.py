import hashlib
import requests
from flask import redirect

ALLOWED = {"reports": "http://internal/reports"}


def fetch(key):
    # Allow-listed URL, no user concatenation — not SSRF.
    return requests.get(ALLOWED[key])


def strong_hash(data):
    return hashlib.sha256(data).hexdigest()  # not weak crypto


def go_home():
    return redirect("/home")  # constant target — not an open redirect


def safe_query(db, name):
    db.execute("SELECT * FROM users WHERE name = %s", (name,))  # parameterized
