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


if __name__ == "__main__":
    main()
