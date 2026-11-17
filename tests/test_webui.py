#!/usr/bin/env python3
"""Web UI server halves (no device, no flow run)."""
import json
import os
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "poc"))

import webui
from http.server import ThreadingHTTPServer


def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), webui._Handler)
    server.token = "t" * 32
    server.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _get(server, path, host=None):
    request = urllib.request.Request("http://127.0.0.1:%d%s" % (server.port, path))
    if host is not None:
        request.add_header("Host", host)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except Exception as exc:                                    # noqa: BLE001
        status = getattr(exc, "code", None)
        return status, b""


def main():
    token = "t" * 32
    server = _serve()
    try:
        status, body = _get(server, "/%s/" % token)
        assert status == 200 and b"BariSign" in body, (status, body[:60])
        print("ok  page served")

        status, _ = _get(server, "/wrongtoken/")
        assert status == 404, status
        print("ok  wrong token 404")

        status, _ = _get(server, "/%s/api/state" % token, host="evil.example:80")
        assert status == 404, status
        print("ok  host check")

        status, body = _get(server, "/%s/api/state" % token)
        assert status == 200, status
        snapshot = json.loads(body.decode())
        assert set(snapshot) >= {"steps", "question", "pin", "log", "done"}, snapshot.keys()
        print("ok  state snapshot")

        # log sanitizing: ANSI stripped, PIN masked in log but captured
        webui._WebLog().write("\r\x1b[2K  pairing code:  483920\n")
        with webui._LOCK:
            assert webui._STATE["pin"] == "483920", webui._STATE["pin"]
            assert webui._STATE["log"][-1] == "pairing code:  ••••••", webui._STATE["log"][-1]
        print("ok  pin capture + masking")
    finally:
        server.shutdown()

    # question round-trip without a flow
    with webui._LOCK:
        webui._STATE["question"] = {"id": 7, "kind": "bool", "label": "Sure?",
                                    "options": []}
        webui._QUESTION["event"] = threading.Event()
    answered = []
    thread = threading.Thread(
        target=lambda: answered.append(webui._ask_web("ignored", "text")))
    thread.start()
    time.sleep(0.2)
    with webui._LOCK:
        qid = webui._STATE["question"]["id"]
    data = json.dumps({"id": qid, "value": "y"}).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:%d/%s/api/answer" % (server.port, "t" * 32), data=data,
        headers={"Content-Type": "application/json", "Host": "127.0.0.1:%d" % server.port})
    server2 = _serve()
    try:
        with webui._LOCK:
            webui._STATE["question"] = {"id": qid, "kind": "bool", "label": "Sure?",
                                        "options": []}
        # answer through the live server is covered by the handler path; here
        # just check the waiter resolves when the event is set directly
        webui._QUESTION["answer"] = "y"
        webui._QUESTION["event"].set()
        thread.join(timeout=5)
        assert answered == ["y"], answered
        print("ok  question wait resolves")
    finally:
        server2.shutdown()


def _post(server, path, data, ctype):
    request = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (server.port, path), data=data,
        headers={"Content-Type": ctype, "Host": "127.0.0.1:%d" % server.port})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except Exception as exc:                                    # noqa: BLE001
        return getattr(exc, "code", None), b""


def _forms():
    import urllib.parse
    server = _serve()
    try:
        with webui._LOCK:
            webui._STATE["question"] = {"id": 11, "kind": "text",
                                        "label": "Name?", "options": []}
            webui._QUESTION["event"] = threading.Event()
        status, _ = _post(server, "/%s/api/answer" % ("t" * 32),
                           urllib.parse.urlencode({"id": "11", "value": "ada"}).encode(),
                           "application/x-www-form-urlencoded")
        assert status in (200, 303), status
        assert webui._QUESTION["answer"] == "ada", webui._QUESTION["answer"]
        print("ok  form answer posts")
        with webui._LOCK:
            webui._STATE["question"] = None
        status, _ = _post(server, "/%s/api/audio" % ("t" * 32), b"{}",
                           "application/json")
        assert status == 200, status
        print("ok  audio ping")
        status, body = _get(server, "/%s/" % ("t" * 32))
        assert status == 200 and b"<form" in body, (status, body[:60])
        print("ok  page renders forms")
    finally:
        server.shutdown()


def _panel_rev():
    server = _serve()
    try:
        with webui._LOCK:
            webui._STATE["started"] = True
            webui._STATE["steps"] = [{"id": "x", "label": "X", "state": "active"}]
            webui._STATE["question"] = {"id": 21, "kind": "choice",
                                        "label": "Pick?", "options": ["a", "b"]}
            webui._QUESTION["event"] = threading.Event()
        status, body = _get(server, "/%s/api/panel" % ("t" * 32))
        assert status == 200, status
        panel = json.loads(body.decode())
        assert panel["rev"] >= 0 and "Pick?" in panel["title"] and ">a<" in panel["body"], panel
        print("ok  panel rev")
        status, body = _get(server, "/%s/" % ("t" * 32))
        assert status == 200 and b"Pick?" in body and b"step 1 of 1" not in body, status
        print("ok  full render with question")
        with webui._LOCK:
            webui._STATE["question"] = None
            webui._STATE["pin"] = "123456"
        status, body = _get(server, "/%s/" % ("t" * 32))
        assert status == 200 and b"123456" in body, status
        print("ok  full render with pin")
        with webui._LOCK:
            webui._STATE["pin"] = None
            webui._STATE["done"] = {"ok": True, "title": "Done", "lines": ["hi"]}
        status, body = _get(server, "/%s/" % ("t" * 32))
        assert status == 200 and b"Done" in body and b"stopbtn" not in body, status
        print("ok  full render done")
        with webui._LOCK:
            webui._STATE["done"] = None
            webui._STATE["steps"] = []
            webui._STATE["started"] = False
    finally:
        server.shutdown()


if __name__ == "__main__":
    _forms()
    _panel_rev()
    main()
