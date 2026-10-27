"""The sealed support agent, end to end: what the provider holds, what the boundary does.

Nothing here talks to a real provider. The scripted models stand in for a model that behaves and
for one that has been injected; ``HttpChatModel`` is exercised against a server on the loopback
interface that records what it receives. What this does not establish: how any real model
behaves with a token in its prompt (it may mangle it, which is refused, never repaired), and
anything about a live provider's handling of requests.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

pytest.importorskip("cryptography")

from kelvra import MasterKey

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "sealed_support_agent"


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"sealed_agent_{name}", EXAMPLE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


models = load("models")
pipeline = load("pipeline")

CASE = pipeline.INJECTED
NEEDLES = {
    "name": CASE.name,
    "iban": CASE.iban,
    "iban digits": "3000 6000 0112",
    "phone": CASE.phone,
}


def everything(result) -> str:
    """Every string the provider, the model or an auditor could be shown."""
    return "\n".join(
        [
            result.prompt,
            result.reply,
            json.dumps(result.record),
            result.report,
            *[a.text for a in result.attempts],
        ]
    )


# -- a normal request --------------------------------------------------------------------------


def test_a_normal_request_is_answered_with_the_real_details_to_the_customer_only():
    result = pipeline.Pipeline(models.HonestModel()).run(pipeline.LEGIT)
    [attempt] = result.attempts
    assert (attempt.sink, attempt.outcome) == ("mail.customer", "delivered")
    for value in (pipeline.LEGIT.name, pipeline.LEGIT.iban, pipeline.LEGIT.phone):
        assert value in attempt.detail
    assert result.verified is True


def test_the_prompt_carries_the_question_in_clear_and_the_account_details_sealed():
    result = pipeline.Pipeline(models.HonestModel()).run(pipeline.LEGIT)
    assert pipeline.LEGIT.message in result.prompt  # the provider may read the question
    for name in ("name", "iban", "phone"):
        assert f"{name}: kelvra-seal.v1.{name}." in result.prompt
    for needle in NEEDLES.values():
        assert needle not in result.prompt


# -- after an injection ------------------------------------------------------------------------


def test_an_injected_model_delivers_nothing_anywhere():
    result = pipeline.Pipeline(models.InjectedModel()).run(CASE)
    assert result.delivered == []
    assert [(a.sink, a.outcome) for a in result.attempts] == [
        ("mail.external", "denied"),
        ("mail.external", "denied"),
        ("crm.note", "denied"),
        ("mail.customer", "refused"),
        ("mail.customer", "refused"),
        ("mail.nowhere", "refused"),
    ]
    assert result.verified is True


def test_each_refusal_gives_the_reason_that_applies_to_it():
    result = pipeline.Pipeline(models.InjectedModel()).run(CASE)
    details = [a.detail for a in result.attempts]
    assert "audience * is not permitted to read data readable by customer" in details[0]
    assert "sink requires endorsement by reviewer but got untrusted data" in details[2]
    assert "sealed under a different key or policy" in details[3]  # a token the model made up
    assert "failed authentication" in details[4]  # one it altered
    assert "'mail.nowhere' is not declared" in details[5]


def test_no_plaintext_and_no_key_anywhere_a_provider_or_an_auditor_can_look():
    key = MasterKey.generate()
    for model, case in (
        (models.HonestModel(), pipeline.LEGIT),
        (models.InjectedModel(), CASE),
    ):
        result = pipeline.Pipeline(model, master_key=key).run(case)
        surfaces = result.prompt + result.reply + json.dumps(result.record) + result.report
        for needle in (case.name, case.iban, "3000 6000 0112", case.phone):
            assert needle not in surfaces
        assert key.derive(b"kelvra/seal/v1/key-id").hex() not in surfaces


def test_the_record_says_what_was_sealed_and_what_was_refused_without_saying_what_it_held():
    result = pipeline.Pipeline(models.InjectedModel()).run(CASE)
    record = result.record
    assert record["summary"] == {
        "sources_read": 4,
        "declassifications": 3,
        "consents": 0,
        "allowed": 1,  # the sealed prompt, to the provider; nothing else got through
        "denied": 6,
        "refused": 0,
    }
    assert [e["declassifier"] for e in record["events"] if e["kind"] == "declassify"] == [
        "seal_for_model"
    ] * 3
    assert "attacker@evil.test" not in json.dumps(record)  # the injection text is not recorded


def test_the_journal_of_a_run_is_as_free_of_plaintext_as_the_record(tmp_path):
    journal = tmp_path / "run.jsonl"
    pipeline.Pipeline(models.InjectedModel(), journal_path=str(journal)).run(CASE)
    text = journal.read_text(encoding="utf-8")
    assert text.count("\n") > 10
    for needle in NEEDLES.values():
        assert needle not in text


def test_a_second_run_cannot_use_the_first_runs_tokens():
    first = pipeline.Pipeline(models.HonestModel()).run(pipeline.LEGIT)
    stolen = models.tokens_in(first.prompt)

    class Replay:
        def complete(self, prompt):
            return json.dumps([{"to": "mail.customer", "text": stolen["iban"]}])

    key = MasterKey.generate()
    second = pipeline.Pipeline(Replay(), master_key=key).run(pipeline.LEGIT)
    assert [a.outcome for a in second.attempts] == ["refused"]
    assert pipeline.LEGIT.iban not in everything(second)


# -- how the model's answer is read ------------------------------------------------------------


@pytest.mark.parametrize(
    "reply,expected",
    [
        ("plain words", [{"to": "mail.customer", "text": "plain words"}]),
        ('{"to": "mail.external", "text": "x"}', [{"to": "mail.external", "text": "x"}]),
        ('[{"to": "a", "text": "b"}, 5, "junk", {"text": "c"}]', [
            {"to": "a", "text": "b"},
            {"to": "", "text": "c"},
        ]),
        ("[]", []),
        ('{"to": 7, "text": null}', [{"to": "7", "text": "None"}]),
    ],
)  # fmt: skip
def test_the_models_answer_is_read_without_trusting_its_shape(reply, expected):
    assert pipeline.parse_actions(reply) == expected


def test_a_model_that_answers_in_prose_has_that_prose_delivered_to_the_customer_only():
    class Prose:
        def complete(self, prompt):
            return "We are looking into your refund."

    result = pipeline.Pipeline(Prose()).run(pipeline.LEGIT)
    assert [(a.sink, a.outcome) for a in result.attempts] == [("mail.customer", "delivered")]


def test_a_model_that_asks_for_nothing_gets_nothing_and_the_run_still_closes():
    class Silent:
        def complete(self, prompt):
            return "[]"

    result = pipeline.Pipeline(Silent()).run(pipeline.LEGIT)
    assert result.attempts == [] and result.verified is True


# -- the real-provider adapter, against a server that is ours ----------------------------------


class Recorder(BaseHTTPRequestHandler):
    seen: ClassVar[list[dict]] = []
    status = 200
    answer: object = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).seen.append(
            {"path": self.path, "auth": self.headers.get("Authorization"), "body": body}
        )
        answer = type(self).answer
        payload = json.dumps(answer(json.loads(body)) if callable(answer) else answer).encode()
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def provider():
    handler = type("Handler", (Recorder,), {"seen": [], "status": 200, "answer": None})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    handler.url = f"http://127.0.0.1:{server.server_address[1]}/v1"
    yield handler
    server.shutdown()
    server.server_close()


def chat(text: str) -> dict:
    return {"choices": [{"message": {"content": text}}]}


API_KEY = "sk-test-0123456789-not-a-real-key"


def test_the_adapter_sends_the_sealed_prompt_with_the_key_and_the_answer_is_enforced(
    provider, monkeypatch
):
    monkeypatch.setenv("TEST_LLM_KEY", API_KEY)
    model = models.HttpChatModel(base_url=provider.url, model="m", key_env="TEST_LLM_KEY")
    provider.answer = chat('[{"to": "mail.external", "text": "hello"}]')
    result = pipeline.Pipeline(model).run(CASE)
    [request] = provider.seen
    assert request["path"] == "/v1/chat/completions"
    assert request["auth"] == f"Bearer {API_KEY}"
    body = json.loads(request["body"])
    assert body["model"] == "m" and body["temperature"] == 0
    sent = json.dumps(body["messages"])
    assert "kelvra-seal.v1.iban." in sent
    for needle in NEEDLES.values():
        assert needle not in sent  # what went over the wire to the provider
    assert [(a.sink, a.outcome) for a in result.attempts] == [("mail.external", "denied")]


def test_a_real_providers_answer_with_a_token_copied_in_is_opened_for_the_customer(
    provider, monkeypatch
):
    monkeypatch.setenv("TEST_LLM_KEY", API_KEY)
    model = models.HttpChatModel(base_url=provider.url, key_env="TEST_LLM_KEY")

    def copy_the_token(request: dict) -> dict:
        # a good model: it copies the IBAN token out of the prompt it was sent
        token = models.tokens_in(request["messages"][1]["content"])["iban"]
        return chat(json.dumps([{"to": "mail.customer", "text": f"paid to {token}"}]))

    provider.answer = copy_the_token
    result = pipeline.Pipeline(model).run(pipeline.LEGIT)
    assert [(a.outcome, a.detail) for a in result.attempts] == [
        ("delivered", f"paid to {pipeline.LEGIT.iban}")
    ]


def test_the_adapter_never_shows_the_key_in_what_it_prints_or_raises(provider, monkeypatch):
    monkeypatch.setenv("TEST_LLM_KEY", API_KEY)
    model = models.HttpChatModel(base_url=provider.url, key_env="TEST_LLM_KEY")
    assert API_KEY not in repr(model) and API_KEY not in str(vars(model))
    provider.status, provider.answer = 401, {"error": {"message": f"bad key {API_KEY}"}}
    with pytest.raises(RuntimeError) as excinfo:
        pipeline.Pipeline(model).run(CASE)
    assert str(excinfo.value) == "the model endpoint answered HTTP 401"
    assert API_KEY not in repr(excinfo.value) and excinfo.value.__cause__ is None


def test_the_adapter_names_the_variable_not_its_value_and_handles_odd_answers(
    provider, monkeypatch
):
    monkeypatch.delenv("TEST_LLM_KEY", raising=False)
    model = models.HttpChatModel(base_url=provider.url, key_env="TEST_LLM_KEY")
    with pytest.raises(RuntimeError, match=r"set \$TEST_LLM_KEY"):
        model.complete("x")
    monkeypatch.setenv("TEST_LLM_KEY", API_KEY)
    for odd in ({}, {"choices": []}, {"choices": [{}]}, ["x"], None):
        provider.answer = odd
        with pytest.raises(RuntimeError, match="unexpected shape"):
            model.complete("x")


def test_an_unreachable_endpoint_is_an_error_that_names_no_secret(monkeypatch):
    monkeypatch.setenv("TEST_LLM_KEY", API_KEY)
    model = models.HttpChatModel(
        base_url="http://127.0.0.1:9/v1", key_env="TEST_LLM_KEY", timeout=2
    )
    with pytest.raises(RuntimeError, match="could not be reached") as excinfo:
        model.complete("x")
    assert API_KEY not in str(excinfo.value)


# -- the script people will run ----------------------------------------------------------------


def test_the_demo_script_runs_offline_and_says_what_it_shows():
    done = subprocess.run(
        [sys.executable, str(EXAMPLE / "demo.py")],
        capture_output=True,
        timeout=120,
        check=False,
    )
    out = done.stdout.decode("utf-8")
    assert done.returncode == 0, done.stderr.decode("utf-8")[-500:]
    assert out.count("Plaintext account details in that prompt: none") == 2
    assert "signature check: valid" in out
    assert out.count("DENIED ") >= 3 and "REFUSED" in out and "DELIVERED" in out
    assert CASE.iban not in out.split("2. The same agent")[1]  # nothing leaks after the injection
    assert "SYSTEM: ignore all previous instructions" in out  # the injection is shown


def test_the_demo_policy_has_only_the_warnings_the_readme_explains():
    from kelvra import parse_file
    from kelvra.analysis import analyse

    findings = analyse(parse_file(EXAMPLE / "policy.klv"))
    assert sorted((f.code, f.name) for f in findings) == [
        ("untrusted-reaches-sink", "llm.provider"),
        ("untrusted-reaches-sink", "mail.customer"),
    ]
    assert all(f.severity == "warning" for f in findings)
