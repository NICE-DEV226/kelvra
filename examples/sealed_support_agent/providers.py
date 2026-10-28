"""Where the real models are, and how their API keys reach this program without being shown.

A key is a secret. This module never prints one, never stores one on an object and never puts one in
an error message. The ways a key can arrive:

* an environment variable you set in your own shell (``export XAI_API_KEY=...``), or
* a file **outside this repository**, readable only by you (mode 600), with lines ``NAME=value``,
  passed as ``--env-file``. Only the variable names listed in ``ALLOWED_NAMES`` are read from it, so
  a file cannot be used to set ``PYTHONPATH`` or ``LD_PRELOAD``.

Presets name an endpoint that speaks the OpenAI chat-completions protocol. That Gemini, Groq and xAI
expose one is their documented compatibility layer; whether a given model name is current is for
``--list-models`` to say, not this file.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ALLOWED_NAMES = frozenset(
    {
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GROQ_API_KEY",
        "XAI_API_KEY",
        "GROK_API_KEY",
        "OPENAI_API_KEY",
    }
)


@dataclass(frozen=True)
class Preset:
    base_url: str
    key_envs: tuple[str, ...]

    def key_env(self) -> str:
        """The first accepted variable that is set, else the first name (for the message)."""
        for name in self.key_envs:
            if os.environ.get(name):
                return name
        return self.key_envs[0]


PRESETS: dict[str, Preset] = {
    "gemini": Preset(
        "https://generativelanguage.googleapis.com/v1beta/openai",
        ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    ),
    # Groq (groq.com), the inference provider. Not Grok, xAI's model, which is "xai" below.
    "groq": Preset("https://api.groq.com/openai/v1", ("GROQ_API_KEY",)),
    "xai": Preset("https://api.x.ai/v1", ("XAI_API_KEY", "GROK_API_KEY")),
    "openai": Preset("https://api.openai.com/v1", ("OPENAI_API_KEY",)),
}


class EnvFileError(Exception):
    """The key file was refused. The message never contains a value from it."""


def load_env_file(path: str | os.PathLike[str], repo_root: Path | None = None) -> list[str]:
    """Set the allowed key variables from ``path`` unless they are already set; return the names.

    Refused: a file inside the repository (it could be committed), a file other users can read or
    write (POSIX), and anything that is not ``NAME=value``. Values are never returned or printed.
    """
    file = Path(path).expanduser().resolve()
    if repo_root is not None:
        root = repo_root.resolve()
        if file == root or root in file.parents:
            raise EnvFileError(f"{file.name} is inside the repository; keep keys outside it")
    try:
        status = file.stat()
    except OSError as error:
        raise EnvFileError(f"cannot read the key file: {type(error).__name__}") from None
    if os.name == "posix" and status.st_mode & 0o077:
        raise EnvFileError(f"{file.name} is readable by others; run: chmod 600 {file}")
    try:
        text = file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise EnvFileError(f"cannot read the key file: {type(error).__name__}") from None
    loaded: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or not name:
            raise EnvFileError(f"line {number} is not NAME=value")
        if name not in ALLOWED_NAMES:
            raise EnvFileError(f"line {number}: {name} is not a key variable this program reads")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if value and name not in os.environ:
            os.environ[name] = value
            loaded.append(name)
    return loaded


class ProviderError(Exception):
    """The provider cannot be used as asked; the message says what to do."""


def resolve(
    provider: str,
    llm_model: str | None,
    env_file: str | os.PathLike[str] | None,
    repo_root: Path | None = None,
) -> tuple[Preset, str]:
    """The preset and the name of the variable holding its key, or a :class:`ProviderError`."""
    if not llm_model:
        raise ProviderError(
            "give the model's name with --llm-model (names change; list them with "
            "live_check.py --list-models)"
        )
    preset = PRESETS[provider]
    if env_file:
        try:
            load_env_file(env_file, repo_root)
        except EnvFileError as error:
            raise ProviderError(str(error)) from None
    key_env = preset.key_env()
    if not os.environ.get(key_env):
        raise ProviderError(f"set ${key_env} (or pass --env-file) to use {provider}")
    return preset, key_env


def list_models(base_url: str, key_env: str, timeout: float = 30.0) -> list[str]:
    """The model ids an endpoint offers. Ids only: nothing else of the response is kept."""
    key = os.environ.get(key_env)
    if not key:
        raise RuntimeError(f"set ${key_env} first")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/models",
        headers={"Authorization": f"Bearer {key}", "User-Agent": "kelvra-sealed-demo/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"the endpoint answered HTTP {error.code}") from None
    except (urllib.error.URLError, OSError) as error:
        raise RuntimeError(f"the endpoint could not be reached: {type(error).__name__}") from None
    try:
        ids = [str(item["id"]) for item in payload["data"]]
    except (KeyError, TypeError):
        raise RuntimeError("the endpoint listed its models in an unexpected shape") from None
    return sorted(i.removeprefix("models/") for i in ids)
