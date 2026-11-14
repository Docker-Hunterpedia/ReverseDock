#!/usr/bin/env python3
"""Backends of the hosted soak (benchmarks/soak/hosted, standard library only).

    python3 -I backend.py PORT [PORT ...]

One asyncio process listens on every PORT on 127.0.0.1 and answers HTTP/1.1 with keep-alive:

    /cached/<k>   2 KiB, `Cache-Control: public, max-age=30`, so the proxy's cache can store it
    /stream/sse   a server-sent event stream, one event per second until the peer closes
    /stream/ws    a WebSocket that echoes every text or binary frame (RFC 6455)
    anything else 1 KiB, no caching headers

It is a load-bearing part of the soak only as a steady, boring origin: it holds no state that
grows, so memory growth seen in the soak is the proxy's.
"""
import asyncio
import base64
import hashlib
import struct
import sys

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PLAIN = b"x" * 1024
HEAD = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {n}\r\n{extra}\r\n"


def response(body, extra=""):
    return HEAD.format(n=len(body), extra=extra).encode() + body


async def read_head(reader):
    raw = await reader.readuntil(b"\r\n\r\n")
    lines = raw.decode("latin-1").split("\r\n")
    method, target, _ = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return method, target, headers


async def sse(writer):
    writer.write(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
    )
    n = 0
    while True:
        event = f"data: {n}\n\n".encode()
        writer.write(b"%x\r\n%s\r\n" % (len(event), event))
        await writer.drain()
        n += 1
        await asyncio.sleep(1)


def frame(opcode, payload):
    """A server frame: FIN set, never masked."""
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack(">H", n)
    else:
        head += bytes([127]) + struct.pack(">Q", n)
    return head + payload


async def websocket(reader, writer, key):
    accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()  # RFC 6455 4.2.2, not a security use
    writer.write(
        (
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode()
    )
    await writer.drain()
    while True:
        b0, b1 = await reader.readexactly(2)
        opcode, masked, n = b0 & 0x0F, b1 & 0x80, b1 & 0x7F
        if n == 126:
            (n,) = struct.unpack(">H", await reader.readexactly(2))
        elif n == 127:
            (n,) = struct.unpack(">Q", await reader.readexactly(8))
        mask = await reader.readexactly(4) if masked else b"\0\0\0\0"
        data = bytearray(await reader.readexactly(n))
        for i in range(n):
            data[i] ^= mask[i % 4]
        if opcode == 0x8:
            writer.write(frame(0x8, bytes(data[:2])))
            await writer.drain()
            return
        if opcode == 0x9:
            writer.write(frame(0xA, bytes(data)))
        elif opcode in (0x1, 0x2):
            writer.write(frame(opcode, bytes(data)))
        await writer.drain()


async def handle(reader, writer):
    try:
        while True:
            _, target, headers = await read_head(reader)
            length = int(headers.get("content-length", "0") or 0)
            if length:
                await reader.readexactly(length)
            path = target.split("?", 1)[0]
            if path.startswith("/stream/sse"):
                await sse(writer)
                return
            if path.startswith("/stream/ws") and "sec-websocket-key" in headers:
                await websocket(reader, writer, headers["sec-websocket-key"])
                return
            if path.startswith("/cached/"):
                body = (path.encode() + b" ").ljust(2048, b".")
                writer.write(response(body, "Cache-Control: public, max-age=30\r\n"))
            else:
                writer.write(response(PLAIN))
            await writer.drain()
            if headers.get("connection", "").lower() == "close":
                return
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def main(ports):
    servers = [await asyncio.start_server(handle, "127.0.0.1", port, backlog=1024) for port in ports]
    print("ready", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main([int(p) for p in sys.argv[1:]]))
    except KeyboardInterrupt:
        pass
