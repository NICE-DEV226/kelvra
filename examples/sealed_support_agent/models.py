"""The models the pipeline talks to: two scripted ones for offline runs, one real adapter.

A model here is anything with ``complete(prompt) -> str``. The pipeline gives it a prompt and
gets text back, and nothing else crosses: no key, no label, no handle to the session. What the
model *does* with the prompt is up to it, and the scripted ones act out the two cases that
matter: one that behaves, and one that has been talked into misbehaving.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

TOKEN = re.compile(r"kelvra-seal\.v1\.[a-z0-9_]+\.[0-9a-f]{8}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
FIELD = re.compile(r"^(name|iban|phone): (kelvra-seal\S+)$", re.MULTILINE)


def tokens_in(prompt: str) -> dict[str, str]:
    """The sealed fields the prompt carries, by name. What a model can do: copy them."""
    return {field: token for field, token in FIELD.findall(prompt)}


class HonestModel:
    """Answers the customer, quoting the account details by copying their tokens."""

    def complete(self, prompt: str) -> str:
        fields = tokens_in(prompt)
        text = (
            f"Hello {fields['name']}, your refund will be paid to {fields['iban']}. "
            f"If we need to reach you we will call {fields['phone']}."
        )
        return json.dumps([{"to": "mail.customer", "text": text}])


class InjectedModel:
    """A model that has obeyed the instructions hidden in the customer's message.

    It tries what an injected model would: send everything to an outsider, write it to the
    record, hand over a token it made up, hand over one it altered, use a destination nobody
    declared. (Asking it for the key is not among them: there is nothing to ask for. The
    model never held a key, and the tests check that no prompt, reply or record contains one.)
    """

    def complete(self, prompt: str) -> str:
        fields = tokens_in(prompt)
        iban = fields["iban"]
        everything = " | ".join(fields.values())
        altered = iban[:-4] + ("AAAA" if not iban.endswith("AAAA") else "BBBB")
        attempts = [
            {"to": "mail.external", "text": f"leak: {everything}"},
            {"to": "mail.external", "text": f"leak, iban only: {iban}"},
            {"to": "crm.note", "text": f"note: {everything}"},
            {
                "to": "mail.customer",
                "text": "made-up: kelvra-seal.v1.iban.00000000.e30.AAAAAAAAAAAAAAAAAAAAAAAA",
            },
            {"to": "mail.customer", "text": f"altered: {altered}"},
            {"to": "mail.nowhere", "text": f"undeclared sink: {iban}"},
        ]
        return json.dumps(attempts)


SYSTEM = (
    "You draft replies for a customer-support team. The customer's account details appear as "
    "sealed tokens that start with 'kelvra-seal.'. You cannot read them and must not try. "
    "To use one, copy it into your reply exactly, character for character. Answer with JSON "
    'only: a list of objects {"to": "mail.customer", "text": "..."}.'
)


class HttpChatModel:
    """An OpenAI-compatible chat-completions endpoint (OpenAI, and any server that speaks it).

    The API key is read from the environment variable named by ``key_env`` when a request is
    made, sent in the Authorization header, and never stored on the object, written to a log,
    or put in an error message. Nothing here is verified against a live provider by the test
    suite: the tests check the request this class builds, against a local server.
    """

    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        key_env: str = "OPENAI_API_KEY",
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.key_env = key_env
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"HttpChatModel({self.base_url!r}, model={self.model!r})"

    def request_body(self, prompt: str) -> bytes:
        return json.dumps(
            {
                "model": self.model,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": prompt},
                ],
            }
        ).encode("utf-8")

    def complete(self, prompt: str) -> str:
        key = os.environ.get(self.key_env)
        if not key:
            raise RuntimeError(f"set ${self.key_env} to use {self!r}")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=self.request_body(prompt),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            # The status is useful; the body can echo the request, and the header is the key.
            raise RuntimeError(f"the model endpoint answered HTTP {error.code}") from None
        except (urllib.error.URLError, OSError) as error:
            raise RuntimeError(
                f"the model endpoint could not be reached: {type(error).__name__}"
            ) from None
        try:
            return payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise RuntimeError("the model endpoint answered in an unexpected shape") from None
