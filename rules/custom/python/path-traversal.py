import os
import shutil
from pathlib import Path

from flask import request, send_file, send_from_directory
from werkzeug.utils import secure_filename

BASE = "/srv/uploads"


def bad_open():
    name = request.args.get("file")
    # ruleid: sast.python.path-traversal
    with open(name) as fh:
        return fh.read()


def bad_join_open():
    name = request.form["name"]
    # ruleid: sast.python.path-traversal
    return open(os.path.join(BASE, name), "rb").read()


def bad_pathlib():
    # ruleid: sast.python.path-traversal
    return Path(request.args.get("doc")).read_text()


def bad_send_file():
    # ruleid: sast.python.path-traversal
    return send_file(os.path.join(BASE, request.args["f"]))


def bad_copy():
    # ruleid: sast.python.path-traversal
    shutil.copy(request.json["src"], "/tmp/out")


def bad_remove():
    victim = request.values.get("path")
    # ruleid: sast.python.path-traversal
    os.remove(victim)


def ok_secure_filename():
    name = secure_filename(request.args.get("file"))
    # ok: sast.python.path-traversal
    return open(os.path.join(BASE, name), "rb").read()


def ok_basename():
    # ok: sast.python.path-traversal
    return open(os.path.join(BASE, os.path.basename(request.args["f"])), "rb").read()


def ok_send_from_directory():
    # ok: sast.python.path-traversal
    return send_from_directory(BASE, request.args["f"])


def ok_constant_path():
    # ok: sast.python.path-traversal
    return open("/etc/app/config.ini").read()


def ok_unrelated_value():
    flag = request.args.get("verbose")
    # ok: sast.python.path-traversal
    return open("/var/log/app.log").read() if flag else ""
