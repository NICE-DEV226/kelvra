"""A page on the loopback interface that runs the real pipeline and shows what happened.

    python examples/sealed_support_agent/ui.py          # scripted model, offline
    python examples/sealed_support_agent/ui.py --provider groq --llm-model <model> \\
        --env-file ~/.config/kelvra/keys.env             # a real model; it says so on the page

Then open the address it prints. With a real model the page names it, and what the model does is
its own: it may copy a token exactly, alter one (the reply is then refused whole), or do what the
customer's message tells it. The account details are fictional in both modes.

The page decides nothing. Each button posts to ``/api/run``, the server runs
``pipeline.Pipeline`` (the same code the terminal demo and the tests run) and sends back what
the provider received, what the model asked for, what the boundary did with each request, and
what the auditor gets. Everything the page shows from the model or the customer is put in the
document as text, never as markup.

It listens on 127.0.0.1 only, refuses a request whose ``Host`` is not the address it listens on
(a web page cannot reach it through DNS rebinding) or whose ``Origin`` is another site, and sends a
content security policy that allows nothing but its own two files.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "editors"))

import highlight
from models import HonestModel, HttpChatModel, InjectedModel, Retrying
from pipeline import INJECTED, LEGIT, POLICY_FILE, Case, Pipeline
from providers import PRESETS, ProviderError, resolve

ASSETS = Path(__file__).with_name("ui")
MAX_BODY = 8 * 1024
MAX_MESSAGE = 2000

HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


def policy_payload() -> dict:
    """The policy the pipeline enforces, coloured by the editor's own grammar (highlight.py).

    Sent as (class, text) pieces per line so the page can draw it as text, never as markup.
    """
    text = POLICY_FILE.read_text(encoding="utf-8")
    return {
        "name": POLICY_FILE.name,
        "lines": [[[name, piece] for name, piece in line] for line in highlight.classes(text)],
    }


def default_message(behaviour: str) -> str:
    return (INJECTED if behaviour == "injected" else LEGIT).message


SCRIPTED_INFO = {"mode": "scripted", "label": "scripted model (offline)"}


def run_case(behaviour: str, message: str, model_factory, info: dict | None = None) -> dict:
    scripted = InjectedModel() if behaviour == "injected" else HonestModel()
    model = model_factory(scripted)
    base = INJECTED if behaviour == "injected" else LEGIT
    case = Case(message=message, name=base.name, iban=base.iban, phone=base.phone)
    result = Pipeline(model).run(case)
    seen = result.prompt + result.reply
    return {
        "prompt": result.prompt,
        "keyId": result.key_id,
        "plaintextInPrompt": [
            label
            for label, value in (("name", case.name), ("iban", case.iban), ("phone", case.phone))
            if value in seen
        ],
        "attempts": [
            {"sink": a.sink, "asked": a.text, "outcome": a.outcome, "detail": a.detail}
            for a in result.attempts
        ],
        "report": result.report,
        "summary": result.record["summary"],
        "verified": result.verified,
        "model": info or SCRIPTED_INFO,
    }


def make_handler(model_factory, info: dict | None = None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SealedDemo"
        sys_version = ""

        def log_message(self, *args):  # the demo prints nothing about requests
            pass

        def _host_ok(self) -> bool:
            host, port = self.server.server_address[:2]
            return self.headers.get("Host") in {f"{host}:{port}", f"localhost:{port}"}

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            if origin is None:
                return True
            host, port = self.server.server_address[:2]
            return origin in {f"http://{host}:{port}", f"http://localhost:{port}"}

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in HEADERS.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: dict) -> None:
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

        def do_GET(self):
            if not self._host_ok():
                return self._json(403, {"error": "unexpected Host header"})
            if self.path == "/api/config":
                return self._json(200, info or SCRIPTED_INFO)
            if self.path == "/api/policy":
                return self._json(200, policy_payload())
            if self.path == "/api/defaults":
                return self._json(
                    200,
                    {"honest": default_message("honest"), "injected": default_message("injected")},
                )
            entry = STATIC.get(self.path)
            if entry is None:
                return self._json(404, {"error": "not found"})
            name, content_type = entry
            self._send(200, (ASSETS / name).read_bytes(), content_type)

        def do_POST(self):
            if not self._host_ok() or not self._origin_ok():
                return self._json(403, {"error": "request refused"})
            if self.path != "/api/run":
                return self._json(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self._json(400, {"error": "bad Content-Length"})
            if length > MAX_BODY:
                return self._json(413, {"error": "request too large"})
            try:
                request = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._json(400, {"error": "body is not JSON"})
            if not isinstance(request, dict):
                return self._json(400, {"error": "body must be an object"})
            behaviour = request.get("behaviour", "honest")
            if behaviour not in ("honest", "injected"):
                return self._json(400, {"error": "behaviour is 'honest' or 'injected'"})
            message = request.get("message")
            if message is None:
                message = default_message(behaviour)
            if not isinstance(message, str) or len(message) > MAX_MESSAGE:
                return self._json(400, {"error": f"message is text of at most {MAX_MESSAGE}"})
            try:
                payload = run_case(behaviour, message, model_factory, info)
            except RuntimeError as error:  # a model endpoint problem; never carries a key
                return self._json(502, {"error": str(error)})
            return self._json(200, payload)

    return Handler


def make_server(
    host: str = "127.0.0.1",
    port: int = 0,
    model_factory=lambda scripted: scripted,
    info: dict | None = None,
):
    """A server bound to a loopback address. Anything else is refused, not warned about."""
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError("this page runs a demonstration; it listens on a loopback address only")
    return ThreadingHTTPServer((host, port), make_handler(model_factory, info))


def build_model(args: argparse.Namespace):
    """The model factory and the description the page shows, from the command line."""
    if not args.provider:
        return (lambda scripted: scripted), SCRIPTED_INFO
    try:
        preset, key_env = resolve(
            args.provider, args.llm_model, args.env_file, Path(__file__).resolve().parents[2]
        )
    except ProviderError as error:
        raise SystemExit(f"error: {error}") from None

    def factory(_scripted):
        # A busy provider answers 503 now and then: retry it as the measurements do.
        return Retrying(
            HttpChatModel(preset.base_url, args.llm_model, key_env, timeout=120.0, temperature=None)
        )

    return factory, {"mode": "live", "label": f"{args.llm_model} via {args.provider}"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--provider",
        choices=sorted(PRESETS),
        help="use a real model from this provider instead of the scripted one (needs a key)",
    )
    parser.add_argument("--llm-model", help="the model's name at that provider")
    parser.add_argument("--env-file", type=Path, help="NAME=value lines, outside the repository")
    args = parser.parse_args()

    factory, info = build_model(args)
    server = make_server("127.0.0.1", args.port, factory, info)
    host, port = server.server_address[:2]
    print(f"Sealed support agent on http://{host}:{port}/  ({info['label']}; Ctrl+C to stop)")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
