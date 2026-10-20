#!/usr/bin/env python3
"""Acceptance checks against real binaries or the real Compose deployment.

Only connects to the explicitly started local API, never to sample target IPs.
Uses the Python standard library and compares parsed JSON, not field ordering.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {"ip", "port", "protocol", "product", "version", "os_hint", "confidence"}
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(args, **kwargs):
    return subprocess.run(
        [str(arg) for arg in args], cwd=ROOT, check=True, **kwargs
    )


def capture(args):
    return run(args, text=True, encoding="utf-8", stdout=subprocess.PIPE).stdout


def http(base, path, data=None, content_type="application/json"):
    req = urllib.request.Request(
        base + path,
        data=data,
        headers={"Content-Type": content_type},
    )
    try:
        response = OPENER.open(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read(), response.headers


def ready(base, process=None):
    until = time.monotonic() + 45
    while time.monotonic() < until:
        if process is not None and process.poll() is not None:
            raise AssertionError("server exited during startup; inspect artifacts/server.log")
        try:
            status, body, _ = http(base, "/health")
            if status == 200 and body == b"":
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise AssertionError("server did not become healthy")


def results(body, count):
    value = json.loads(body)
    assert isinstance(value, list) and len(value) == count, value
    for item in value:
        assert set(item) == FIELDS, item
        assert 0 <= item["confidence"] <= 1, item
    return value


def acceptance(base):
    expected = json.loads((ROOT / "samples/expected.json").read_text("utf-8"))
    status, body, _ = http(base, "/fingerprint", (ROOT / "samples/input.json").read_bytes())
    assert status == 200, (status, body)
    assert results(body, 20) == expected, body
    mixed = (ROOT / "testdata/mixed.json").read_bytes()
    status, body, headers = http(base, "/fingerprint", mixed)
    assert status == 200, (status, body)
    value = results(body, 6)
    assert [x["protocol"] for x in value] == ["SSH", "unknown", "unknown", "unknown", "unknown", "HTTP"]
    assert value[1]["port"] == 0 and value[2]["ip"] == "", value
    assert value[5]["product"] == "Jetty" and value[5]["version"] == "12.0.8", value
    mixed_id = headers["X-Request-ID"]
    assert mixed_id
    for payload, code in [(b"[]", 200), (b"null", 400), (b"[", 400), (b"[] []", 400)]:
        status, body, _ = http(base, "/fingerprint", payload)
        assert status == code and json.loads(body) == [], (status, body)
    status, body, _ = http(base, "/fingerprint", b"[]", "text/plain")
    assert status == 415 and json.loads(body) == []
    # Binary transport and an unseen version on a non-default port.
    payload = json.dumps([
        {"ip": "::1", "port": 54321, "banner": "SgAAAAo4LjAuMzIA", "banner_encoding": "base64"},
        {"ip": "::1", "port": 54322, "banner": "SSH-2.0-OpenSSH_10.2p3 Debian-9"},
    ]).encode()
    status, body, _ = http(base, "/fingerprint", payload)
    value = results(body, 2)
    assert status == 200 and value[0]["version"] == "8.0.32"
    assert value[1]["version"] == "10.2p3" and value[1]["os_hint"] == "Debian"
    ready(base)
    return expected, mixed_id


def local():
    suffix = ".exe" if os.name == "nt" else ""
    server = ROOT / "bin" / ("server" + suffix)
    client = ROOT / "bin" / ("client" + suffix)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    (ROOT / "artifacts").mkdir(exist_ok=True)
    logfile = ROOT / "artifacts/server.log"
    with logfile.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [str(server), "serve", "--listen", f"127.0.0.1:{port}",
             "--rules", "rules/fingerprints.json"],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            ready(base, process)
            expected, mixed_id = acceptance(base)
            run([server, "healthcheck", "--url", base + "/health"])
            output = capture([client, "--server", base, "--input", "samples/input.json"])
            assert results(output, 20) == expected
            output = capture([client, "--server", base, "--input", "testdata/mixed.json"])
            results(output, 6)  # successful exit despite individual invalid inputs
            logs = logfile.read_text("utf-8")
            assert mixed_id in logs and '"code":"invalid_port"' in logs
            assert '"item_index":1' in logs and "OpenSSH_10.2p3" not in logs
        finally:
            process.terminate()
            try:
                process.wait(timeout=35)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("server did not stop")
        if os.name != "nt":
            assert process.returncode == 0, process.returncode
    # A broken rule file must fail before the listener becomes healthy.
    invalid = ROOT / "artifacts/invalid-rules.json"
    invalid.write_text('{"schema_version":1,"rules":[]}', encoding="utf-8")
    failed = subprocess.run(
        [str(server), "serve", "--rules", str(invalid)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
    )
    assert failed.returncode != 0 and b"rules_load_failed" in failed.stdout
    print("PASS: real server/client, 20 samples, mixed errors, binary data, health and bad rules")


def compose():
    run(["docker", "compose", "config", "--quiet"])
    run(["docker", "compose", "up", "--build", "-d"], timeout=600)
    base = "http://127.0.0.1:8080"
    ready(base)
    expected, mixed_id = acceptance(base)
    server_id = capture(["docker", "compose", "ps", "-q", "server"]).strip()
    client_id = capture(["docker", "compose", "ps", "-a", "-q", "client"]).strip()
    assert server_id and client_id
    until = time.monotonic() + 40
    while True:
        info = json.loads(capture(["docker", "inspect", client_id]))[0]
        if info["State"]["Status"] == "exited":
            assert info["State"]["ExitCode"] == 0, info["State"]
            break
        assert time.monotonic() < until, "default Compose client did not exit"
        time.sleep(0.2)
    output = capture(["docker", "compose", "run", "--rm", "-T", "client"])
    assert results(output, 20) == expected
    for container_id in (server_id, client_id):
        info = json.loads(capture(["docker", "inspect", container_id]))[0]
        assert info["Config"]["User"] == "65532:65532"
        host = info["HostConfig"]
        assert host["ReadonlyRootfs"]
        assert "ALL" in [x.upper() for x in host["CapDrop"]]
        assert any("no-new-privileges" in x for x in host["SecurityOpt"])
        assert all(not x["RW"] for x in info["Mounts"])
    info = json.loads(capture(["docker", "inspect", server_id]))[0]
    assert info["State"]["Health"]["Status"] == "healthy"
    bindings = info["HostConfig"]["PortBindings"]["8080/tcp"]
    assert bindings == [{"HostIp": "127.0.0.1", "HostPort": "8080"}], bindings
    networks = info["NetworkSettings"]["Networks"]
    assert len(networks) == 1
    network = json.loads(capture(["docker", "network", "inspect", next(iter(networks))]))[0]
    assert network["Internal"]
    logs = capture(["docker", "compose", "logs", "--no-color", "server"])
    assert mixed_id in logs and '"code":"invalid_port"' in logs
    # Explicitly verify SIGTERM reaches PID 1 and graceful shutdown completes.
    run(["docker", "compose", "stop", "server"], timeout=45)
    info = json.loads(capture(["docker", "inspect", server_id]))[0]
    assert info["State"]["ExitCode"] == 0, info["State"]
    print("PASS: Compose build, healthy dependency, client, API, internal network, least privilege and shutdown")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("local", "compose"), required=True)
    args = parser.parse_args()
    {"local": local, "compose": compose}[args.mode]()
