"""Loads rdock's admin API while the proxy carries traffic (H-ENG-04). Runs in rdock's network
namespace, so the admin listener is on loopback. Standard library only.

    python3 attack.py login|sse|apply SECONDS

- login: failed logins from many threads; Argon2 runs for each attempt the rate limit lets in.
- sse: 10,000 log streams that send a request and never read; most are refused (4 per token).
- apply: configuration writes through the API, with a rollback every fifth write.
"""
import asyncio
import http.client
import json
import os
import sys
import threading
import time

ADMIN = ("127.0.0.1", 2080)
TOKEN = open("/work/token").read().strip() if os.path.exists("/work/token") else ""
HEADERS = {"Host": "localhost", "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
counts = {}
lock = threading.Lock()


def count(key):
    with lock:
        counts[key] = counts.get(key, 0) + 1


def call(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(*ADMIN, timeout=30)
    try:
        conn.request(method, path, body=body, headers={**HEADERS, **(headers or {})})
        reply = conn.getresponse()
        return reply.status, dict(reply.getheaders()), reply.read()
    finally:
        conn.close()


def login(deadline):
    body = json.dumps({"name": "admin", "password": "not-the-password-0"})
    while time.time() < deadline:
        try:
            status, _, _ = call("POST", "/api/v1/auth/login", body, {"Authorization": ""})
            count(status)
        except OSError as err:
            count(type(err).__name__)


def document(n):
    return json.dumps({
        "routes": {f"api-{n % 2}": {"match": f"Host(`api{n % 2}.test`)", "service": "api"}},
        "services": {"api": {"backends": [{"address": "backend:80"}]}},
    })


def apply(deadline):
    n = 0
    while time.time() < deadline:
        n += 1
        try:
            _, head, _ = call("GET", "/api/v1/config/api")
            tag = head.get("ETag", head.get("etag", ""))
            if n % 5 == 0:
                _, _, body = call("GET", "/api/v1/config/history")
                entries = json.loads(body)
                target = entries[1]["id"] if len(entries) > 1 else entries[0]["id"]
                status, _, _ = call("POST", "/api/v1/config/rollback", json.dumps({"id": target}), {"If-Match": tag})
                count(f"rollback {status}")
            else:
                status, _, _ = call("PUT", "/api/v1/config/api", document(n), {"If-Match": tag})
                count(f"apply {status}")
        except (OSError, ValueError, KeyError, IndexError) as err:
            count(type(err).__name__)


async def silent_stream(deadline):
    try:
        reader, writer = await asyncio.open_connection(*ADMIN)
        writer.write(
            f"GET /api/v1/logs/stream HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\n\r\n".encode()
        )
        await writer.drain()
        count("opened")
        # Never read: the server's buffers fill and it must drop, not wait.
        await asyncio.sleep(max(0, deadline - time.time()))
        writer.close()
    except OSError as err:
        count(type(err).__name__)


async def sse(deadline, streams=10_000):
    await asyncio.gather(*(silent_stream(deadline) for _ in range(streams)))


def main():
    mode, seconds = sys.argv[1], int(sys.argv[2])
    deadline = time.time() + seconds
    if mode == "sse":
        asyncio.run(sse(deadline))
    else:
        work = {"login": login, "apply": apply}[mode]
        threads = [threading.Thread(target=work, args=(deadline,)) for _ in range(32 if mode == "login" else 4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    print(json.dumps({"mode": mode, "counts": {str(k): v for k, v in sorted(counts.items(), key=str)}}))


main()
