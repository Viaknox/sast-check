import glob
import os
import pathlib
import shutil
import pathlib as pl
from pathlib import Path, PurePosixPath
from pathlib import Path as FilePath
from pathlib import PurePosixPath as PosixFile

from flask import request, send_file, send_from_directory
from werkzeug.utils import secure_filename

from uploads import Upload
from uploads import Upload as OtherFile

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


def ok_aliased_path_name_variable():
    p = FilePath(request.args["f"])
    # ok: sast.python.path-traversal
    return open(os.path.join(BASE, p.name)).read()


def ok_aliased_path_name_direct():
    # ok: sast.python.path-traversal
    return open(os.path.join(BASE, PosixFile(request.form["f"]).name)).read()


def ok_module_aliased_path_name_variable():
    p = pl.Path(request.args["f"])
    # ok: sast.python.path-traversal
    return open(os.path.join(BASE, p.name)).read()


def bad_aliased_path_name_listdir():
    p = FilePath(request.args["f"])
    # ruleid: sast.python.path-traversal
    return os.listdir(os.path.join(BASE, p.name))


def bad_aliased_path_unreduced():
    p = FilePath(request.args["f"])
    # ruleid: sast.python.path-traversal
    return open(p).read()


def bad_module_alias_non_path_name_direct():
    # ruleid: sast.python.path-traversal
    return open(os.path.join(BASE, pl.load_name(request.args["f"]).name)).read()


def bad_module_alias_non_path_name_variable():
    p = pl.load_name(request.args["f"])
    # ruleid: sast.python.path-traversal
    return open(os.path.join(BASE, p.name)).read()


def bad_other_alias_name_variable():
    p = OtherFile(request.args["f"])
    # ruleid: sast.python.path-traversal
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


# a basename can still be "..": for a directory sink that climbs out of BASE
def bad_listdir_path_name():
    # ruleid: sast.python.path-traversal
    return os.listdir(os.path.join(BASE, Path(request.args["f"]).name))


def bad_listdir_path_name_variable():
    p = Path(request.args["f"])
    # ruleid: sast.python.path-traversal
    return os.listdir(os.path.join(BASE, p.name))


def bad_listdir_basename():
    # ruleid: sast.python.path-traversal
    return os.listdir(os.path.join(BASE, os.path.basename(request.args["f"])))


def bad_listdir_bare_basename():
    # ruleid: sast.python.path-traversal
    return os.listdir(os.path.join(BASE, basename(request.args["f"])))


def bad_rmtree_basename():
    # ruleid: sast.python.path-traversal
    shutil.rmtree(os.path.join(BASE, os.path.basename(request.form["d"])))


def bad_rmtree_path_name():
    # ruleid: sast.python.path-traversal
    shutil.rmtree(os.path.join(BASE, PurePosixPath(request.form["d"]).name))


def bad_copytree_basename():
    # ruleid: sast.python.path-traversal
    shutil.copytree(os.path.join(BASE, os.path.basename(request.args["d"])), "/tmp/out")


def bad_scandir_basename():
    # ruleid: sast.python.path-traversal
    return list(os.scandir(os.path.join(BASE, os.path.basename(request.args["d"]))))


def bad_walk_path_name():
    # ruleid: sast.python.path-traversal
    return list(os.walk(os.path.join(BASE, Path(request.args["d"]).name)))


def bad_rmdir_basename():
    # ruleid: sast.python.path-traversal
    os.rmdir(os.path.join(BASE, os.path.basename(request.form["d"])))


def bad_glob_basename():
    # ruleid: sast.python.path-traversal
    return glob.glob(os.path.join(BASE, os.path.basename(request.args["d"]), "*"))


def bad_iterdir_path_name():
    # ruleid: sast.python.path-traversal
    return list((Path(BASE) / Path(request.args["d"]).name).iterdir())


def bad_scandir_raw():
    # ruleid: sast.python.path-traversal
    return list(os.scandir(request.args["d"]))


def bad_walk_raw():
    # ruleid: sast.python.path-traversal
    return list(os.walk(request.args["d"]))


def bad_rmdir_raw():
    # ruleid: sast.python.path-traversal
    os.rmdir(request.form["d"])


def bad_glob_raw():
    # ruleid: sast.python.path-traversal
    return glob.glob(os.path.join(BASE, request.args["d"], "*"))


def bad_iterdir_raw():
    # ruleid: sast.python.path-traversal
    return list(Path(request.args["d"]).iterdir())


# file sinks fail on ".." (it is a directory), so a basename stays a valid sanitizer there
def ok_remove_basename():
    # ok: sast.python.path-traversal
    os.remove(os.path.join(BASE, os.path.basename(request.form["f"])))


def ok_read_text_path_name():
    # ok: sast.python.path-traversal
    return (Path(BASE) / Path(request.args["f"]).name).read_text()


def ok_listdir_secure_filename():
    # ok: sast.python.path-traversal
    return os.listdir(os.path.join(BASE, secure_filename(request.args["d"])))


def ok_iterdir_secure_filename():
    # ok: sast.python.path-traversal
    return list((Path(BASE) / secure_filename(request.args["d"])).iterdir())


def ok_scandir_const():
    # ok: sast.python.path-traversal
    return list(os.scandir(BASE))


def bad_iterdir_qualified_raw():
    # ruleid: sast.python.path-traversal
    return list(pathlib.Path(request.args["d"]).iterdir())


def bad_iterdir_basename():
    # ruleid: sast.python.path-traversal
    return list((Path(BASE) / os.path.basename(request.args["d"])).iterdir())


def bad_iterdir_path_name_variable():
    p = Path(request.args["d"])
    # ruleid: sast.python.path-traversal
    return list((Path(BASE) / p.name).iterdir())


def ok_open_bare_basename():
    # ok: sast.python.path-traversal
    return open(os.path.join(BASE, basename(request.args["f"]))).read()


def ok_path_exists_not_a_sink():
    # ok: sast.python.path-traversal
    return (Path(BASE) / request.args["f"]).exists()
