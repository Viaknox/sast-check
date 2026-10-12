import aiohttp
import httpx
import urllib3


def bad_client():
    # ruleid: sast.python.httpx-verify-false
    return httpx.Client(verify=False)


def bad_async_client():
    # ruleid: sast.python.httpx-verify-false
    return httpx.AsyncClient(timeout=5, verify=False)


def bad_get():
    # ruleid: sast.python.httpx-verify-false
    return httpx.get("https://example.com", verify=False)


async def bad_aiohttp_connector():
    # ruleid: sast.python.httpx-verify-false
    return aiohttp.TCPConnector(ssl=False)


async def bad_aiohttp_request(session):
    # ruleid: sast.python.httpx-verify-false
    return await session.get("https://example.com", ssl=False)


def bad_urllib3():
    # ruleid: sast.python.httpx-verify-false
    return urllib3.PoolManager(cert_reqs="CERT_NONE")


def ok_default_client():
    # ok: sast.python.httpx-verify-false
    return httpx.Client()


def ok_ca_bundle():
    # ok: sast.python.httpx-verify-false
    return httpx.Client(verify="/etc/ssl/internal-ca.pem")


def ok_verify_true():
    # ok: sast.python.httpx-verify-false
    return httpx.get("https://example.com", verify=True)


def ok_urllib3_required():
    # ok: sast.python.httpx-verify-false
    return urllib3.PoolManager(cert_reqs="CERT_REQUIRED")


async def ok_aiohttp_default():
    # ok: sast.python.httpx-verify-false
    return aiohttp.TCPConnector(limit=10)


def ok_redis_plain():
    # ok: sast.python.httpx-verify-false
    return redis.Redis(host, ssl=False)
