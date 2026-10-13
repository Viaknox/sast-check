import os
import shutil
from pathlib import Path, PurePosixPath

from flask import request, send_file, send_from_directory
from werkzeug.utils import secure_filename

from uploads import Upload

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


def bad_path_div():
    # ruleid: sast.python.path-traversal
    return (Path(BASE) / request.args['f']).read_text()


def bad_div_bytes():
    # ruleid: sast.python.path-traversal
    return (BASE_DIR / request.args['f']).read_bytes()


def bad_joinpath():
    # ruleid: sast.python.path-traversal
    return Path(BASE).joinpath(request.args['f']).open()


def bad_rmtree():
    # ruleid: sast.python.path-traversal
    shutil.rmtree(request.args['d'])


def bad_listdir():
    # ruleid: sast.python.path-traversal
    return os.listdir(request.args['d'])


def bad_makedirs_rename():
    # ruleid: sast.python.path-traversal
    os.makedirs(request.form['d'])
    # ruleid: sast.python.path-traversal
    os.rename(request.form['a'], "/tmp/b")


def ok_path_div_secure():
    # ok: sast.python.path-traversal
    return (Path(BASE) / secure_filename(request.args['f'])).read_text()


def ok_listdir_const():
    # ok: sast.python.path-traversal
    return os.listdir(BASE)


def ok_rmtree_const():
    # ok: sast.python.path-traversal
    shutil.rmtree("/tmp/cache")


def bad_custom_name_attr():
    up = Upload(request.args["f"])
    # ruleid: sast.python.path-traversal
    return open(up.name).read()


def bad_custom_name_direct():
    # ruleid: sast.python.path-traversal
    return open(Upload(request.args["f"]).name).read()


def ok_path_name_direct():
    # ok: sast.python.path-traversal
    return open(os.path.join(BASE, Path(request.args["f"]).name)).read()


def ok_path_name_variable():
    p = Path(request.args["f"])
    # ok: sast.python.path-traversal
    return open(os.path.join(BASE, p.name)).read()


def ok_purepath_name():
    # ok: sast.python.path-traversal
    return open(os.path.join(BASE, PurePosixPath(request.form["f"]).name)).read()


def bad_path_object_unreduced():
    p = Path(request.args["f"])
    # ruleid: sast.python.path-traversal
    return open(p).read()


def bad_path_parent_not_name():
    p = Path(request.args["f"])
    # ruleid: sast.python.path-traversal
    return open(p.parent).read()
