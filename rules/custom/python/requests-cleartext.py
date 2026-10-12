import httpx
import requests
import urllib.request


def bad_requests():
    # ruleid: sast.python.requests-cleartext
    return requests.get("http://api.example.com/v1/items")


def bad_post_with_keyword():
    # ruleid: sast.python.requests-cleartext
    return requests.post(url="http://payments.example.org/charge", data={"a": 1})


def bad_httpx():
    # ruleid: sast.python.requests-cleartext
    return httpx.get("http://example.com:8080/status")


def bad_urlopen():
    # ruleid: sast.python.requests-cleartext
    return urllib.request.urlopen("http://downloads.example.net/file.zip")


def ok_https():
    # ok: sast.python.requests-cleartext
    return requests.get("https://api.example.com/v1/items")


def ok_localhost():
    # ok: sast.python.requests-cleartext
    return requests.get("http://localhost:8000/health")


def ok_loopback():
    # ok: sast.python.requests-cleartext
    return httpx.get("http://127.0.0.1:9000/")


def ok_any_addr():
    # ok: sast.python.requests-cleartext
    return requests.get("http://0.0.0.0:5000/ping")


def ok_mdns():
    # ok: sast.python.requests-cleartext
    return requests.get("http://printer.local/status")


def ok_internal_suffix():
    # ok: sast.python.requests-cleartext
    return requests.get("http://billing.internal:8080/api")


def ok_ipv6_loopback():
    # ok: sast.python.requests-cleartext
    return requests.get("http://[::1]:8000/")


def ok_variable(url):
    # ok: sast.python.requests-cleartext
    return requests.get(url)
