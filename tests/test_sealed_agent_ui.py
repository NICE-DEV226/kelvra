"""The page on the loopback interface: it runs the real pipeline and refuses what it should.

Requests are made with the standard library against a server on 127.0.0.1, port chosen by the
operating system. What this does not establish: how the page looks or behaves in a browser (that
was looked at by hand, and is not tested here).
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import sys
import threading
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "sealed_support_agent"


def load_ui():
    sys.path.insert(0, str(EXAMPLE))
    try:
        spec = importlib.util.spec_from_file_location("sealed_agent_ui", EXAMPLE / "ui.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(EXAMPLE))


ui = load_ui()


@pytest.fixture
def server():
    srv = ui.make_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def call(srv, method, path, body=None, headers=None, host=None):
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    sent = {"Host": host or f"127.0.0.1:{port}", **(headers or {})}
    payload = (
        body
        if isinstance(body, bytes)
        else (json.dumps(body).encode() if body is not None else None)
    )
    if payload is not None:
        sent.setdefault("Content-Type", "application/json")
    conn.putrequest(method, path, skip_host=True)
    for name, value in sent.items():
        conn.putheader(name, value)
    if payload is not None:
        conn.putheader("Content-Length", str(len(payload)))
    conn.endheaders(payload)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, dict(response.getheaders()), data


def run(srv, **request):
    status, _, data = call(srv, "POST", "/api/run", request)
    return status, json.loads(data)


# -- the page ----------------------------------------------------------------------------------


def test_the_page_and_its_two_files_are_served_with_a_policy_that_allows_nothing_else(server):
    for path, kind in (
        ("/", "text/html"),
        ("/app.js", "text/javascript"),
        ("/style.css", "text/css"),
    ):
        status, headers, body = call(server, "GET", path)
        assert status == 200 and headers["Content-Type"].startswith(kind) and body
        csp = headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "script-src 'self'" in csp
        assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Cache-Control"] == "no-store"
    html = call(server, "GET", "/")[2].decode()
    assert '<script src="/app.js">' in html and "<script>" not in html and " onclick=" not in html


def test_the_page_script_puts_model_and_customer_text_in_as_text_never_as_markup():
    script = (EXAMPLE / "ui" / "app.js").read_text(encoding="utf-8")
    # strings the script must NOT contain (this test only searches for them; it calls none)
    for dangerous in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert dangerous not in script, dangerous
    assert "textContent" in script


def test_the_defaults_the_page_shows_are_the_ones_the_pipeline_uses(server):
    status, _, body = call(server, "GET", "/api/defaults")
    data = json.loads(body)
    pipeline = sys.modules.get("sealed_agent_pipeline") or ui.sys.modules["pipeline"]
    assert status == 200
    assert (
        data["honest"] == pipeline.LEGIT.message and data["injected"] == pipeline.INJECTED.message
    )


def test_an_unknown_path_is_a_404_and_a_json_error(server):
    status, _, body = call(server, "GET", "/etc/passwd")
    assert status == 404 and json.loads(body) == {"error": "not found"}
    assert call(server, "GET", "/../ui.py")[0] == 404
    assert call(server, "POST", "/other", {})[0] == 404


# -- running the real pipeline -----------------------------------------------------------------


def test_a_normal_request_through_the_page_is_delivered_and_verified(server):
    status, data = run(server, behaviour="honest")
    assert status == 200
    assert [(a["sink"], a["outcome"]) for a in data["attempts"]] == [("mail.customer", "delivered")]
    assert data["plaintextInPrompt"] == [] and data["verified"] is True
    assert "Alice Martin" in data["attempts"][0]["detail"]  # the customer gets their own details


def test_an_injected_request_through_the_page_delivers_nothing(server):
    status, data = run(server, behaviour="injected")
    assert status == 200
    assert [a["outcome"] for a in data["attempts"]] == ["denied"] * 3 + ["refused"] * 3
    assert data["plaintextInPrompt"] == [] and data["verified"] is True
    assert data["summary"]["denied"] == 6 and data["summary"]["allowed"] == 1
    assert "Alice Martin" not in json.dumps(data) and "FR76" not in json.dumps(data)


def test_a_message_typed_into_the_page_reaches_the_model_as_untrusted_text(server):
    status, data = run(server, behaviour="honest", message="Please also check order 99.")
    assert status == 200 and "Please also check order 99." in data["prompt"]
    assert "Alice Martin" not in data["prompt"]


def test_markup_in_a_message_comes_back_as_text_for_the_page_to_draw_as_text(server):
    nasty = "<img src=x onerror=alert(1)><script>alert(2)</script>"
    status, data = run(server, behaviour="honest", message=nasty)
    assert status == 200 and nasty in data["prompt"]  # JSON string, no markup is interpreted here


# -- what it refuses ---------------------------------------------------------------------------


def test_a_request_for_another_host_name_is_refused_so_rebinding_cannot_reach_it(server):
    for host in (
        "evil.example",
        f"evil.example:{server.server_address[1]}",
        "127.0.0.1",
        "0.0.0.0",
    ):
        assert call(server, "GET", "/", host=host)[0] == 403
        assert call(server, "POST", "/api/run", {"behaviour": "honest"}, host=host)[0] == 403
    port = server.server_address[1]
    assert call(server, "GET", "/", host=f"localhost:{port}")[0] == 200  # the address people type


def test_a_post_from_another_site_is_refused(server):
    status, _, _ = call(
        server, "POST", "/api/run", {"behaviour": "honest"}, {"Origin": "https://evil.example"}
    )
    assert status == 403
    port = server.server_address[1]
    ok, _, _ = call(
        server, "POST", "/api/run", {"behaviour": "honest"}, {"Origin": f"http://127.0.0.1:{port}"}
    )
    assert ok == 200


def test_bad_requests_are_400_413_with_a_reason_and_never_a_traceback(server):
    assert call(server, "POST", "/api/run", b"{not json")[0] == 400
    assert call(server, "POST", "/api/run", b"[1, 2]")[0] == 400
    status, _, body = call(server, "POST", "/api/run", {"behaviour": "root"})
    assert status == 400 and json.loads(body) == {"error": "behaviour is 'honest' or 'injected'"}
    for message in (5, ["x"], "x" * (ui.MAX_MESSAGE + 1)):
        assert (
            call(server, "POST", "/api/run", {"behaviour": "honest", "message": message})[0] == 400
        )
    status, _, body = call(server, "POST", "/api/run", b"x" * (ui.MAX_BODY + 1))
    assert status == 413 and b"Traceback" not in body
    assert call(server, "POST", "/api/run", b"", {"Content-Length": "abc"})[0] in (400, 413)


def test_the_longest_allowed_message_is_accepted(server):
    status, data = run(server, behaviour="honest", message="m" * ui.MAX_MESSAGE)
    assert status == 200 and data["verified"] is True


def test_a_model_endpoint_failure_is_a_502_with_its_message_and_no_secret(server):
    def broken(_scripted):
        class Down:
            def complete(self, prompt):
                raise RuntimeError("the model endpoint answered HTTP 401")

        return Down()

    srv = ui.make_server("127.0.0.1", 0, broken)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, data = run(srv, behaviour="honest")
        assert status == 502 and data == {"error": "the model endpoint answered HTTP 401"}
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_server_will_not_listen_on_anything_but_loopback():
    for host in ("0.0.0.0", "192.168.1.10", "::", "8.8.8.8"):
        with pytest.raises(ValueError, match="loopback address only"):
            ui.make_server(host, 0)
    ui.make_server("127.0.0.1", 0).server_close()


def test_the_server_banner_does_not_name_the_python_version(server):
    _, headers, _ = call(server, "GET", "/")
    assert headers["Server"].strip() == "SealedDemo" and "Python" not in headers["Server"]
