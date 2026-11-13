#!/usr/bin/env python3
"""Open-model load generator of the hosted soak (standard library only).

    python3 -I load.py --http-port P --https-port Q --out DIR [--rate 400] [--duration SECONDS]

Requests start at a fixed rate whatever the latency (an open model: a stalled proxy shows up as
latency and failures, it does not slow the load down; see benchmarks/README.md). Request i is
due at start + i / rate; latency counts from that due time, so the generator's own scheduling
delay is included, not hidden.

The mix (a fraction of the rate each):
    35 %  plain HTTP, GET /                      kept-alive connections
    30 %  HTTPS,      GET /                      kept-alive connections
    20 %  plain HTTP, GET /cached/<0..199>       the cache route
    10 %  HTTPS,      GET /cached/<0..199>
     5 %  HTTPS,      GET /                      `Connection: close`: a new TLS handshake each
Every request carries `X-Client-Id` from 5,000 values, the key of the rate limit, so its bucket
table is exercised.

A response counts when it is 200 with exactly the bytes its Content-Length announces. An idle
kept-alive connection that the server closed before it sent anything is a stale connection:
the request is repeated once on a new connection and counted in `stale`, as any HTTP client
does for an idempotent GET (RFC 9110 section 9.2.2); every other failure is a failure.

Output in DIR: load.csv (one row per window: counts and latency percentiles) and failures.csv
(one row per failed request: when, what, why). SIGTERM or SIGINT stops it cleanly.
"""
import argparse
import asyncio
import csv
import random
import signal
import ssl
import time

MIX = [
    (0.35, "http", "/", False),
    (0.30, "https", "/", False),
    (0.20, "http", "/cached/", False),
    (0.10, "https", "/cached/", False),
    (0.05, "https", "/", True),
]
CLIENT_IDS = 5000
IDLE_MAX = 20.0  # drop a pooled connection idle for longer than this (the server may have closed it)
POOL_MAX = 256


class Stale(Exception):
    """The server closed an idle connection before answering."""


class Conn:
    __slots__ = ("reader", "writer", "used")

    def __init__(self, reader, writer):
        self.reader, self.writer, self.used = reader, writer, time.monotonic()

    def close(self):
        try:
            self.writer.close()
        except OSError:
            pass


async def exchange(conn, request, timeout, expect):
    """Sends one request on `conn`; returns (status, keep_alive). Raises Stale for a dead idle connection."""
    try:
        conn.writer.write(request)
        await conn.writer.drain()
        head = await asyncio.wait_for(conn.reader.readuntil(b"\r\n\r\n"), timeout)
    except ConnectionError as err:  # reset or broken pipe before one byte of the answer
        raise Stale from err
    except asyncio.IncompleteReadError as err:
        if not err.partial:
            raise Stale from err
        raise
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    length, close = 0, False
    for line in lines[1:]:
        name, _, value = line.partition(":")
        name = name.strip().lower()
        if name == "content-length":
            length = int(value)
        elif name == "connection" and "close" in value.lower():
            close = True
    body = await asyncio.wait_for(conn.reader.readexactly(length), timeout)
    if status == 200 and len(body) != expect:
        raise ValueError(f"body of {len(body)} bytes, expected {expect}")
    return status, not close


class Generator:
    def __init__(self, args):
        self.args = args
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.pools = {"http": [], "https": []}
        self.rng = random.Random(1)
        self.sent = self.ok = self.failed = self.stale = 0
        self.latencies = []
        self.lag_max = 0.0
        self.inflight = 0
        self.failures = []
        self.stop = False

    async def open(self, scheme):
        port = self.args.http_port if scheme == "http" else self.args.https_port
        ctx = self.ctx if scheme == "https" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname="localhost" if ctx else None),
            self.args.timeout,
        )
        return Conn(reader, writer)

    def take(self, scheme):
        pool = self.pools[scheme]
        now = time.monotonic()
        while pool:
            conn = pool.pop()
            if now - conn.used < IDLE_MAX and not conn.writer.is_closing():
                return conn
            conn.close()
        return None

    def give(self, scheme, conn):
        conn.used = time.monotonic()
        pool = self.pools[scheme]
        if len(pool) < POOL_MAX:
            pool.append(conn)
        else:
            conn.close()

    async def one(self, due, scheme, path, close):
        client = self.rng.randrange(CLIENT_IDS)
        if path == "/cached/":
            path = f"/cached/{self.rng.randrange(200)}"
            expect = 2048
        else:
            expect = 1024
        request = (
            f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: rdock-soak/1\r\nAccept: */*\r\n"
            f"X-Client-Id: c{client}\r\n{'Connection: close' + chr(13) + chr(10) if close else ''}\r\n"
        ).encode()
        self.inflight += 1
        error = None
        try:
            conn = None if close else self.take(scheme)
            for attempt in (0, 1):
                reused = conn is not None
                try:
                    if conn is None:
                        conn = await self.open(scheme)
                    status, keep = await exchange(conn, request, self.args.timeout, expect)
                    if status != 200:
                        error = f"status {status}"
                    if keep and not close:
                        self.give(scheme, conn)
                    else:
                        conn.close()
                    break
                except Stale:
                    conn.close()
                    conn = None
                    if reused and attempt == 0:
                        self.stale += 1
                        continue
                    error = "closed before any answer"
                    break
        except Exception as err:  # noqa: BLE001 - every failure is data here
            error = f"{type(err).__name__}: {err}" if str(err) else type(err).__name__
            if conn is not None:
                conn.close()
        finally:
            self.inflight -= 1
        done = time.monotonic()
        if error:
            self.failed += 1
            self.failures.append((int(time.time()), scheme + path.split("/")[1] if path != "/" else scheme, error))
        else:
            self.ok += 1
            self.latencies.append(done - due)

    def pick(self):
        r = self.rng.random()
        for share, scheme, path, close in MIX:
            r -= share
            if r < 0:
                return scheme, path, close
        return MIX[-1][1:]


def percentile(sorted_values, q):
    if not sorted_values:
        return 0.0
    return sorted_values[min(len(sorted_values) - 1, int(q * len(sorted_values)))]


async def run(args):
    gen = Generator(args)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: setattr(gen, "stop", True))
    out_csv = open(f"{args.out}/load.csv", "w", newline="")
    out_fail = open(f"{args.out}/failures.csv", "w", newline="")
    writer, fail_writer = csv.writer(out_csv), csv.writer(out_fail)
    writer.writerow(["time", "sent", "ok", "failed", "stale", "p50_ms", "p99_ms", "p999_ms", "max_ms", "lag_ms", "inflight"])
    fail_writer.writerow(["time", "target", "error"])

    def flush():
        lat = sorted(gen.latencies)
        writer.writerow([
            int(time.time()), gen.sent, gen.ok, gen.failed, gen.stale,
            f"{percentile(lat, 0.5) * 1000:.2f}", f"{percentile(lat, 0.99) * 1000:.2f}",
            f"{percentile(lat, 0.999) * 1000:.2f}", f"{(lat[-1] if lat else 0) * 1000:.2f}",
            f"{gen.lag_max * 1000:.1f}", gen.inflight,
        ])
        out_csv.flush()
        for row in gen.failures:
            fail_writer.writerow(row)
        out_fail.flush()
        gen.sent = gen.ok = gen.failed = gen.stale = 0
        gen.latencies, gen.failures, gen.lag_max = [], [], 0.0

    start = time.monotonic()
    next_flush = start + args.window
    tasks = set()
    n = 0
    interval = 1.0 / args.rate
    while not gen.stop:
        now = time.monotonic()
        if args.duration and now - start >= args.duration:
            break
        due = start + n * interval
        if due > now:
            await asyncio.sleep(min(due - now, 0.05))
        else:
            # Everything that is due, at once: an open model catches up, it does not skip.
            while start + n * interval <= time.monotonic():
                due = start + n * interval
                gen.lag_max = max(gen.lag_max, time.monotonic() - due)
                scheme, path, close = gen.pick()
                gen.sent += 1
                task = asyncio.create_task(gen.one(due, scheme, path, close))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
                n += 1
                if n % 64 == 0:
                    await asyncio.sleep(0)
        if time.monotonic() >= next_flush:
            flush()
            next_flush += args.window
    # Let the requests in flight finish (each ends within the timeout).
    if tasks:
        await asyncio.wait(tasks, timeout=args.timeout + 2)
    flush()
    out_csv.close()
    out_fail.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--http-port", type=int, required=True)
    parser.add_argument("--https-port", type=int, required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--rate", type=float, default=400.0, help="requests per second (default 400)")
    parser.add_argument("--duration", type=float, default=0, help="seconds; 0 runs until SIGTERM")
    parser.add_argument("--window", type=float, default=10.0, help="seconds per row of load.csv")
    parser.add_argument("--timeout", type=float, default=10.0, help="per request, in seconds")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
