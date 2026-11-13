#!/usr/bin/env python3
"""The hosted soak (benchmarks/soak/hosted): rdock under steady load, reloads and binary upgrades.

    python3 -I soak.py --rdock target/release/rdock --duration 5h20m --out work

Standard library only. It starts two backends (backend.py), one rdock built from the given
binary with HTTP and HTTPS listeners, three routes, a rate limit, the cache, JSON access logging
and the admin API, and the open-model generator (load.py). Then, until the duration ends:

  - every `--sample-every` seconds it samples the serving process (RSS and PSS from
    /proc/<pid>/smaps_rollup, open file descriptors, threads, the data directory's size) and the
    counters of rdock's own /metrics, into samples.csv;
  - every `--reload-every` seconds it rewrites the configuration and reloads, then checks that
    the new generation answers;
  - every `--upgrade-every` seconds (until `--upgrade-until` of the run) it replaces the binary
    by peer handover (`POST /api/v1/upgrade` over the admin socket, the same file to itself),
    follows the handover to the new pid so sampling goes on, and checks what the upgrade guide
    promises about a WebSocket and an event stream held open across it: both keep working while
    the old process drains, and both are closed when the drain ends.

It writes events.csv, samples.csv, load.csv, failures.csv, meta.json and rdock.log into `--out`;
analyze.py reads them. Exit code: 0 when the run completed, 2 when rdock died or could not be
started (the analysis then fails too).
"""
import argparse
import base64
import csv
import hashlib
import http.client
import json
import os
import platform
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def parse_duration(text):
    """'5h20m', '90m', '30s' or plain seconds, as seconds."""
    total, number = 0, ""
    for ch in text.strip():
        if ch.isdigit():
            number += ch
        elif ch in "hms" and number:
            total += int(number) * {"h": 3600, "m": 60, "s": 1}[ch]
            number = ""
        else:
            raise argparse.ArgumentTypeError(f"not a duration: {text!r}")
    return total + (int(number) if number else 0)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


class Soak:
    def __init__(self, args):
        self.args = args
        self.out = os.path.abspath(args.out)
        self.stop = threading.Event()
        self.failed = None  # a reason, when the run must end early
        self.lock = threading.Lock()
        self.pid = None
        self.pids = []  # every generation seen
        self.generation_file = 0
        self.children = []
        self.ports = {k: free_port() for k in ("http", "https", "admin", "b1", "b2")}
        # The admin socket lives in the data directory and a Unix socket path is limited to 107
        # bytes: from a long output path the data directory goes to a short one under /tmp.
        self.data_dir = os.path.join(self.out, "data")
        self.short_data = False
        if len(os.path.join(self.data_dir, "admin.sock")) > 100:
            self.data_dir = tempfile.mkdtemp(prefix="rdsoak-", dir="/tmp")
            self.short_data = True
        self.admin_sock = os.path.join(self.data_dir, "admin.sock")
        self.binary = os.path.join(self.out, "bin", "rdock")
        self.config_path = os.path.join(self.out, "rdock.yaml")
        self.events = None

    # -- recording ---------------------------------------------------------------------------

    def event(self, kind, start, end, ok, detail=""):
        with self.lock:
            self.events.writerow([kind, f"{start:.1f}", f"{end:.1f}", int(bool(ok)), detail])
            self.events_file.flush()
        print(f"[{time.strftime('%H:%M:%S')}] {kind} {'ok' if ok else 'FAILED'} {detail}", flush=True)

    # -- admin socket ------------------------------------------------------------------------

    def admin(self, method, path, body=None, timeout=10):
        conn = UnixConnection(self.admin_sock, timeout)
        try:
            headers = {"Content-Type": "application/json"} if body is not None else {}
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def serving_pid(self):
        try:
            status, body = self.admin("GET", "/api/v1/status")
            if status == 200:
                return int(json.loads(body)["pid"])
        except (OSError, ValueError, KeyError, http.client.HTTPException):
            pass
        return None

    def set_pid(self, pid):
        with self.lock:
            self.pid = pid
            if pid not in self.pids:
                self.pids.append(pid)

    # -- set-up ------------------------------------------------------------------------------

    def write_config(self, generation):
        text = open(os.path.join(HERE, "rdock.yaml")).read()
        values = {
            "HTTP": self.ports["http"], "HTTPS": self.ports["https"], "ADMIN": self.ports["admin"],
            "B1": self.ports["b1"], "B2": self.ports["b2"], "GENERATION": generation,
            "CERT": os.path.join(self.out, "tls", "soak.pem"), "KEY": os.path.join(self.out, "tls", "soak.key"),
            "BINARY": self.binary, "DRAIN": f"{self.args.drain}s",
        }
        for name, value in values.items():
            text = text.replace(f"@{name}@", str(value))
        tmp = self.config_path + ".new"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, self.config_path)

    def prepare(self):
        for sub in ("data", "bin", "tls"):
            os.makedirs(os.path.join(self.out, sub), mode=0o700, exist_ok=True)
        os.makedirs(self.data_dir, mode=0o700, exist_ok=True)
        os.chmod(os.path.join(self.out, "bin"), 0o700)
        shutil.copyfile(self.args.rdock, self.binary)
        os.chmod(self.binary, 0o755)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-days", "3", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
             "-keyout", os.path.join(self.out, "tls", "soak.key"), "-out", os.path.join(self.out, "tls", "soak.pem")],
            check=True, capture_output=True,
        )
        self.write_config(0)
        check = subprocess.run([self.binary, "validate", self.config_path], capture_output=True, text=True)
        if check.returncode != 0:
            sys.exit(f"rdock validate refused the soak configuration:\n{check.stdout}{check.stderr}")

    def spawn(self, argv, **kwargs):
        child = subprocess.Popen(argv, **kwargs)
        self.children.append(child)
        return child

    def start_all(self):
        backend = self.spawn(
            [sys.executable, "-I", os.path.join(HERE, "backend.py"), str(self.ports["b1"]), str(self.ports["b2"])],
            stdout=subprocess.PIPE, text=True,
        )
        if backend.stdout.readline().strip() != "ready":
            sys.exit("the backends did not start")
        log = open(os.path.join(self.out, "rdock.log"), "ab")
        rdock = self.spawn(
            [self.binary, "run", "--log-format", "json", "--log", "info", "-c", self.config_path,
             "--data-dir", self.data_dir],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
        )
        self.rdock_child = rdock
        deadline = time.time() + 90
        while time.time() < deadline:
            if rdock.poll() is not None:
                sys.exit(f"rdock exited at start ({rdock.returncode}); see {self.out}/rdock.log")
            if b"cannot create the admin socket" in open(os.path.join(self.out, "rdock.log"), "rb").read():
                sys.exit(f"rdock cannot create its admin socket in {self.data_dir}; see {self.out}/rdock.log")
            pid = self.serving_pid()
            if pid and self.get_generation() is not None:
                self.set_pid(pid)
                return
            time.sleep(0.3)
        sys.exit("rdock did not become ready in 90 s")

    def get_generation(self, timeout=3):
        """The X-Soak-Generation that `/` answers with on the plain listener, or None."""
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.ports["http"], timeout=timeout)
            conn.request("GET", "/", headers={"Connection": "close", "X-Client-Id": "probe"})
            response = conn.getresponse()
            response.read()
            conn.close()
            return response.getheader("X-Soak-Generation") if response.status == 200 else None
        except (OSError, http.client.HTTPException):
            return None

    # -- sampling ----------------------------------------------------------------------------

    CSV_HEADER = [
        "time", "pid", "generation", "rss_kib", "pss_kib", "fds", "threads", "data_kib", "requests",
        "errors_5xx", "upstream_errors", "connections_total", "connections_open", "cache_objects", "cache_bytes",
    ]

    @staticmethod
    def read_proc(pid):
        rss = pss = None
        with open(f"/proc/{pid}/smaps_rollup") as f:
            for line in f:
                if line.startswith("Rss:"):
                    rss = int(line.split()[1])
                elif line.startswith("Pss:"):
                    pss = int(line.split()[1])
        threads = None
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Threads:"):
                    threads = int(line.split()[1])
        return rss, pss, len(os.listdir(f"/proc/{pid}/fd")), threads

    def data_kib(self):
        total = 0
        for root, _, files in os.walk(self.data_dir):
            for name in files:
                try:
                    total += os.lstat(os.path.join(root, name)).st_size
                except OSError:
                    pass
        return total // 1024

    def read_metrics(self):
        sums = {}
        status, body = self.admin("GET", "/metrics", timeout=10)
        if status != 200:
            return sums
        for line in body.decode().splitlines():
            if not line.startswith("rdock_") or " " not in line:
                continue
            name_labels, _, value = line.rpartition(" ")
            name = name_labels.split("{", 1)[0]
            try:
                number = float(value)
            except ValueError:
                continue
            sums[name] = sums.get(name, 0.0) + number
            if name == "rdock_http_requests_total" and 'status_class="5xx"' in name_labels:
                sums["5xx"] = sums.get("5xx", 0.0) + number
        return sums

    def sample_once(self, writer):
        pid = self.serving_pid() or self.pid
        if pid and pid != self.pid:
            self.set_pid(pid)
        try:
            rss, pss, fds, threads = self.read_proc(pid)
        except (OSError, TypeError):
            return False  # between two processes, or gone: no row, the analysis counts the gap
        try:
            m = self.read_metrics()
        except (OSError, ValueError, http.client.HTTPException):
            m = {}
        row = [
            int(time.time()), pid, int(m.get("rdock_upgrade_generation", 0)), rss, pss, fds, threads, self.data_kib(),
            int(m.get("rdock_http_requests_total", 0)), int(m.get("5xx", 0)), int(m.get("rdock_upstream_errors_total", 0)),
            int(m.get("rdock_connections_total", 0)), int(m.get("rdock_connections_open", 0)),
            int(m.get("rdock_cache_objects", 0)), int(m.get("rdock_cache_bytes", 0)),
        ]
        writer.writerow(row)
        return True

    def sampler(self):
        with open(os.path.join(self.out, "samples.csv"), "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(self.CSV_HEADER)
            misses = 0
            while not self.stop.is_set():
                if self.sample_once(writer):
                    misses = 0
                else:
                    misses += 1
                    if misses >= 5 and self.rdock_gone():
                        self.failed = "rdock is not running"
                        self.event("rdock_down", time.time(), time.time(), False, "no process answers the admin socket")
                        self.stop.set()
                f.flush()
                self.stop.wait(self.args.sample_every)

    def rdock_gone(self):
        return not any(os.path.exists(f"/proc/{p}") and not self.zombie(p) for p in self.pids[-2:])

    @staticmethod
    def zombie(pid):
        try:
            with open(f"/proc/{pid}/stat") as f:
                return f.read().rsplit(")", 1)[1].split()[0] == "Z"
        except OSError:
            return True

    # -- reload and upgrade ------------------------------------------------------------------

    def do_reload(self):
        self.generation_file += 1
        generation = self.generation_file
        start = time.time()
        self.write_config(generation)
        try:
            status, body = self.admin("POST", "/api/v1/config/reload", timeout=30)
        except (OSError, http.client.HTTPException) as err:
            self.event("reload", start, time.time(), False, f"generation {generation}: {err}")
            return
        seen = None
        deadline = time.time() + 15
        while status == 200 and time.time() < deadline:
            seen = self.get_generation()
            if seen == str(generation):
                break
            time.sleep(0.3)
        ok = status == 200 and seen == str(generation)
        self.event("reload", start, time.time(), ok, f"generation {generation}: HTTP {status}, answering {seen}")

    def do_upgrade(self):
        drain = self.args.drain
        deadline = time.time() + 20
        while time.time() < deadline and not all(h.alive() for h in self.held):
            time.sleep(0.5)
        before = {h.kind: h.snapshot() for h in self.held}
        if not all(h.alive() for h in self.held):
            self.event("held_check", time.time(), time.time(), False, "before the upgrade: a held connection is not open")
        old_pid = self.pid
        start = time.time()
        try:
            status, body = self.admin("POST", "/api/v1/upgrade", body=b"{}", timeout=180)
            answer = json.loads(body) if body else {}
        except (OSError, ValueError, http.client.HTTPException) as err:
            self.event("upgrade", start, time.time(), False, f"no answer: {err}")
            return
        swapped = time.time()
        new_pid = answer.get("pid") if isinstance(answer, dict) else None
        ok = status == 200 and isinstance(new_pid, int) and new_pid != old_pid
        serving = self.serving_pid()
        ok = ok and serving == new_pid
        self.event("upgrade", start, swapped, ok, f"HTTP {status}, pid {old_pid} -> {new_pid}, serving {serving}")
        if not ok:
            if serving:
                self.set_pid(serving)
            return
        self.set_pid(new_pid)

        # While the old process drains, what was held keeps working.
        self.sleep_until(swapped + max(3.0, drain * 0.4))
        problems = []
        for h in self.held:
            snap, was = h.snapshot(), before[h.kind]
            if was is None or snap["id"] != was["id"] or snap["closed"] is not None or snap["last_data"] < swapped:
                problems.append(f"{h.kind} not alive {time.time() - swapped:.0f} s after the swap ({snap['error']})")
        self.event("held_check", swapped, time.time(), not problems,
                   "mid-drain: " + ("; ".join(problems) if problems else "WebSocket and event stream still delivering"))

        # When the drain ends they are closed, not before and not long after.
        self.sleep_until(swapped + drain + 15, until=lambda: all(h.closed_at(before[h.kind]["id"]) for h in self.held if before[h.kind]))
        problems, notes = [], []
        for h in self.held:
            was = before[h.kind]
            closed = h.closed_at(was["id"]) if was else None
            if closed is None:
                problems.append(f"{h.kind} still open {drain + 15} s after the swap")
                continue
            after = closed - swapped
            notes.append(f"{h.kind} closed {after:.1f} s after the swap")
            if not drain - 6 <= after <= drain + 15:
                problems.append(f"{h.kind} closed {after:.1f} s after the swap (drain {drain} s)")
        self.event("held_check", swapped, time.time(), not problems,
                   "drain end: " + ("; ".join(problems) if problems else "; ".join(notes)))

        # The old process is gone, the new one holds the data directory, and new connections work.
        self.sleep_until(swapped + drain + 30, until=lambda: old_pid is None or self.zombie(old_pid))
        gone = old_pid is None or self.zombie(old_pid)
        again = self.wait_alive()
        self.event("handover_check", swapped, time.time(), gone and again and self.serving_pid() == new_pid,
                   f"old pid exited: {gone}; new held connections open: {again}")

    def wait_alive(self, wait=20):
        deadline = time.time() + wait
        while time.time() < deadline:
            if all(h.alive() for h in self.held):
                return True
            time.sleep(0.5)
        return False

    def sleep_until(self, when, until=None):
        while time.time() < when and not self.stop.is_set():
            if until and until():
                return
            time.sleep(0.25)

    def chaos(self):
        a = self.args
        start = time.time()
        end = start + a.duration
        next_reload = start + a.reload_every
        next_upgrade = start + a.upgrade_every
        # An upgrade needs time to finish its checks before the run ends.
        last_upgrade = min(start + a.duration * a.upgrade_until, end - (a.drain + 60))
        while not self.stop.is_set():
            now = time.time()
            if a.reload_every and now >= next_reload and now < end - 20:
                self.do_reload()
                next_reload += a.reload_every
            elif a.upgrade_every and now >= next_upgrade:
                if now <= last_upgrade:
                    self.do_upgrade()
                next_upgrade += a.upgrade_every
            else:
                self.stop.wait(1)

    # -- run ---------------------------------------------------------------------------------

    def run(self):
        a = self.args
        os.makedirs(self.out, exist_ok=True)
        self.events_file = open(os.path.join(self.out, "events.csv"), "w", newline="")
        self.events = csv.writer(self.events_file)
        self.events.writerow(["kind", "start", "end", "ok", "detail"])
        self.prepare()
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        threads = []
        load = None
        started = time.time()
        try:
            self.start_all()
            self.held = [Held("sse", self.ports, self.stop), Held("ws", self.ports, self.stop)]
            for h in self.held:
                h.start()
            self.event("start", time.time(), time.time(), True, f"pid {self.pid}, rate {a.rate}/s, {a.duration} s")
            load = self.spawn(
                [sys.executable, "-I", os.path.join(HERE, "load.py"), "--http-port", str(self.ports["http"]),
                 "--https-port", str(self.ports["https"]), "--out", self.out, "--rate", str(a.rate)]
            )
            started = time.time()
            for target in (self.sampler, self.chaos):
                t = threading.Thread(target=target, daemon=True)
                t.start()
                threads.append(t)
            self.stop.wait(a.duration)
        finally:
            self.stop.set()
            finished = time.time()
            for t in threads:
                t.join(timeout=self.args.drain + 90)
            self.event("end", finished, time.time(), self.failed is None, self.failed or "")
            self.shutdown(load)
            self.write_meta(started, finished)
        return 2 if self.failed else 0

    def shutdown(self, load):
        if load:
            load.send_signal(signal.SIGTERM)
            try:
                load.wait(timeout=30)
            except subprocess.TimeoutExpired:
                load.kill()
        pids = [p for p in self.pids if os.path.exists(f"/proc/{p}") and not self.zombie(p)]
        for pid in reversed(pids):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        deadline = time.time() + 60
        while time.time() < deadline and any(os.path.exists(f"/proc/{p}") and not self.zombie(p) for p in pids):
            time.sleep(0.3)
        for pid in pids:
            if os.path.exists(f"/proc/{pid}") and not self.zombie(pid):
                os.kill(pid, signal.SIGKILL)
        for child in self.children:
            if child.poll() is None:
                child.terminate()
        for child in self.children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
        self.events_file.close()
        if self.short_data:
            shutil.rmtree(self.data_dir, ignore_errors=True)

    def write_meta(self, started, finished):
        a = self.args
        version = subprocess.run([self.binary, "version"], capture_output=True, text=True).stdout.strip()
        with open(self.args.rdock, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        mem = 0
        with open("/proc/meminfo") as f:
            mem = int(f.readline().split()[1]) // 1024
        meta = {
            "started": started, "finished": finished, "duration": a.duration, "rate": a.rate,
            "sample_every": a.sample_every, "reload_every": a.reload_every, "upgrade_every": a.upgrade_every,
            "upgrade_until": a.upgrade_until, "drain": a.drain, "label": a.label,
            "rdock_version": version, "binary_sha256": digest,
            "machine": {"cpus": os.cpu_count(), "mem_mib": mem, "kernel": platform.release(), "python": platform.python_version()},
        }
        with open(os.path.join(self.out, "meta.json"), "w") as f:
            json.dump(meta, f, indent=2)


class Held(threading.Thread):
    """A connection kept open through upgrades: an event stream (HTTP) or a WebSocket (HTTPS).

    It reopens itself a second after it is closed. `snapshot()` says which connection (`id`) is
    open and when it last received data; `closed_at(id)` when that connection ended.
    """

    def __init__(self, kind, ports, stop):
        super().__init__(daemon=True)
        self.kind, self.ports, self.stop = kind, ports, stop
        self.lock = threading.Lock()
        self.id = 0
        self.last_data = 0.0
        self.closed = None
        self.error = ""
        self.ended = {}

    def snapshot(self):
        with self.lock:
            if self.id == 0:
                return None
            return {"id": self.id, "last_data": self.last_data, "closed": self.closed, "error": self.error}

    def alive(self):
        snap = self.snapshot()
        return bool(snap) and snap["closed"] is None and time.time() - snap["last_data"] < 4

    def closed_at(self, conn_id):
        with self.lock:
            return self.ended.get(conn_id)

    def run(self):
        while not self.stop.is_set():
            try:
                self.session()
                reason = "closed by the peer"
            except (OSError, ValueError, ssl.SSLError) as err:
                reason = f"{type(err).__name__}: {err}"
            with self.lock:
                if self.id and self.closed is None:
                    self.closed = time.time()
                    self.ended[self.id] = self.closed
                    self.error = reason
            self.stop.wait(1)

    def touch(self):
        with self.lock:
            self.last_data = time.time()

    def opened(self):
        with self.lock:
            self.id += 1
            self.closed = None
            self.error = ""
            self.last_data = time.time()

    def session(self):
        if self.kind == "sse":
            sock = socket.create_connection(("127.0.0.1", self.ports["http"]), timeout=5)
            sock.sendall(b"GET /stream/sse HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\r\n")
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = sock.recv(4096)
                if not chunk:
                    raise OSError("closed before the response head")
                head += chunk
            if not head.startswith(b"HTTP/1.1 200"):
                raise ValueError(f"event stream refused: {head[:40]!r}")
            self.opened()
            sock.settimeout(2)
            while not self.stop.is_set():
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    return
                self.touch()
            sock.close()
            return
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", self.ports["https"]), timeout=5)
        sock = ctx.wrap_socket(raw, server_hostname="localhost")
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall(
            (f"GET /stream/ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("closed before the handshake answer")
            head += chunk
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ValueError(f"WebSocket refused: {head[:40]!r}")
        buf = head.split(b"\r\n\r\n", 1)[1]
        self.opened()
        sock.settimeout(1)
        next_send = 0.0
        sent = 0
        while not self.stop.is_set():
            if time.time() >= next_send:
                payload = f"soak {sent}".encode()
                mask = os.urandom(4)
                masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)
                sent += 1
                next_send = time.time() + 1
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            if not data:
                return
            buf += data
            while len(buf) >= 2:
                opcode, n = buf[0] & 0x0F, buf[1] & 0x7F
                offset = 2
                if n == 126:
                    if len(buf) < 4:
                        break
                    n, offset = struct.unpack(">H", buf[2:4])[0], 4
                elif n == 127:
                    if len(buf) < 10:
                        break
                    n, offset = struct.unpack(">Q", buf[2:10])[0], 10
                if len(buf) < offset + n:
                    break
                buf = buf[offset + n:]
                if opcode == 0x8:
                    return
                if opcode == 0x1:
                    self.touch()
        sock.close()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rdock", required=True, help="the release binary to soak")
    p.add_argument("--out", required=True, help="output directory (created)")
    p.add_argument("--duration", type=parse_duration, default=parse_duration("5h20m"), help="e.g. 5h20m, 10m (default 5h20m)")
    p.add_argument("--rate", type=float, default=400.0, help="requests per second (default 400)")
    p.add_argument("--sample-every", type=float, default=30.0, help="seconds between samples (default 30)")
    p.add_argument("--reload-every", type=int, default=300, help="seconds between reloads; 0 for none (default 300)")
    p.add_argument("--upgrade-every", type=int, default=1800, help="seconds between binary upgrades; 0 for none (default 1800)")
    p.add_argument("--upgrade-until", type=float, default=0.5,
                   help="no upgrade after this fraction of the run, leaving one long process to judge memory by (default 0.5)")
    p.add_argument("--drain", type=int, default=30, help="upgrade.drain in seconds (default 30)")
    p.add_argument("--label", default="mimalloc", help="the allocator of the binary, recorded in the report only")
    args = p.parse_args()
    if os.path.exists(os.path.join(args.out, "samples.csv")):
        sys.exit(f"{args.out} holds a run already; use another directory")
    sys.exit(Soak(args).run())


if __name__ == "__main__":
    main()
