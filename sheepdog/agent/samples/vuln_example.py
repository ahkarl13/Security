#!/usr/bin/env python3
"""A deliberately vulnerable sample for the Sheepdog code-review agent (authorized lab)."""
import hashlib
import os
import sqlite3
import subprocess

API_KEY = "sk-live-9f2c11a7b3e4"  # hardcoded secret


def get_user(db, username):
    cur = db.cursor()
    # user input concatenated into SQL
    cur.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cur.fetchall()


def ping(host):
    # user input passed to a shell
    return subprocess.check_output("ping -c 1 " + host, shell=True)


def read_report(name):
    # user-controlled path
    path = "/var/reports/" + name
    with open(path) as f:
        return f.read()


def store_password(pw):
    # fast unsalted hash for a password
    return hashlib.md5(pw.encode()).hexdigest()


def render(comment):
    # reflected user input into HTML without escaping
    return "<div>" + comment + "</div>"
