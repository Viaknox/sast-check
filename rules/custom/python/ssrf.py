from flask import request
import httpx
import requests
import urllib.request


def bad_requests_get():
    # ruleid: sast.python.ssrf
    return requests.get(request.args.get("url"))


def bad_requests_post_form():
    target = request.form["callback"]
    # ruleid: sast.python.ssrf
    return requests.post(target, json={"ok": 1})


def bad_requests_request():
    data = request.get_json()
    # ruleid: sast.python.ssrf
    return requests.request("GET", data["endpoint"])


def bad_httpx():
    # ruleid: sast.python.ssrf
    return httpx.get(request.values.get("u"))


def bad_urlopen():
    # ruleid: sast.python.ssrf
    return urllib.request.urlopen(request.args["feed"])


def bad_concat_host():
    host = request.args.get("host")
    # ruleid: sast.python.ssrf
    return requests.get("http://" + host + "/status")


async def bad_aiohttp(session):
    # ruleid: sast.python.ssrf
    return await session.get(request.json["url"])


def ok_constant_url():
    # ok: sast.python.ssrf
    return requests.get("https://api.example.com/v1/ping")


def ok_param_only():
    q = request.args.get("q")
    # ok: sast.python.ssrf
    return requests.get("https://api.example.com/search", params={"q": q})


def ok_fixed_host_fstring():
    item = request.args.get("id")
    # ok: sast.python.ssrf
    return requests.get(f"https://api.example.com/items/{item}")


def ok_int_cast():
    n = int(request.args.get("n"))
    # ok: sast.python.ssrf
    return requests.get("https://api.example.com/items/" + str(n))


def ok_header_only():
    # ok: sast.python.ssrf
    return requests.get("https://api.example.com/", headers={"X-Q": request.args.get("q")})


def ok_cache_lookup(cache):
    # ok: sast.python.ssrf
    return cache.get(request.args["key"])


def ok_dict_get(table):
    # ok: sast.python.ssrf
    return table.get(request.args.get("k"))
