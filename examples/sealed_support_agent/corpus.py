"""Real text from public datasets: what customers write, and attacks people actually tried.

The messages in a test should be what a model meets in the world, so this loads them from public
datasets instead of inventing them:

* ``banking77`` (PolyAI, CC-BY-4.0): real online-banking customer queries, such as "My card has
  not arrived yet." and "I see a refund is not showing up".
* ``deepset`` (deepset/prompt-injections, Apache-2.0): prompts labelled as injections.
* ``yanis`` (yanismiraoui/prompt_injections, Apache-2.0): injections in several languages,
  French included.
* ``mosscap`` (Lakera, MIT): attacks people wrote against a chatbot guarding a secret, in a
  public game.

**What stays fictional.** The name, IBAN and telephone number the pipeline protects are
generated (simulation.py), never taken from a dataset or from anyone. Sending a real person's
bank details to an outside service to test a privacy tool would be the very harm the tool is
for. The text around them is real; they are not.

Nothing is committed. Rows are fetched on first use from the Hugging Face dataset viewer and
cached outside the repository (``~/.cache/kelvra/corpus``). A manifest records, for each source,
the dataset, split, licence, the revision the Hub reported, the number of rows and a SHA-256 of
them, so a result can say exactly what it was run on. Attribution for CC-BY-4.0 belongs in
whatever you publish: cite the dataset.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROWS_API = "https://datasets-server.huggingface.co"
HUB_API = "https://huggingface.co"
PAGE = 100
MIN_CHARS, MAX_CHARS = 15, 600


class CorpusError(Exception):
    """A dataset could not be fetched or read. Says which, never anything sensitive."""


@dataclass(frozen=True)
class Source:
    key: str
    dataset: str
    config: str
    splits: tuple[str, ...]
    licence: str
    column: str
    kind: str  # "query" or "injection"
    pages: int  # how many random pages of 100 rows to take; 0 means all of it
    only_label: int | None = None


SOURCES = (
    Source("banking77", "PolyAI/banking77", "default", ("test",), "cc-by-4.0", "text", "query", 3),
    Source(
        "deepset",
        "deepset/prompt-injections",
        "default",
        ("train", "test"),
        "apache-2.0",
        "text",
        "injection",
        0,
        only_label=1,
    ),
    Source(
        "yanis",
        "yanismiraoui/prompt_injections",
        "default",
        ("train",),
        "apache-2.0",
        "prompt_injections",
        "injection",
        3,
    ),
    Source(
        "mosscap",
        "Lakera/mosscap_prompt_injection",
        "default",
        ("test",),
        "mit",
        "prompt",
        "injection",
        3,
    ),
)


@dataclass(frozen=True)
class Corpus:
    queries: tuple[str, ...]
    injections: dict[str, tuple[str, ...]]
    manifest: tuple[dict, ...]

    def all_injections(self) -> list[tuple[str, str]]:
        """(source key, text) for every injection, in a fixed order."""
        return [(key, text) for key in sorted(self.injections) for text in self.injections[key]]


def default_cache() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "kelvra" / "corpus"


def _get(url: str, timeout: float = 60.0) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "kelvra-corpus/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise CorpusError(f"{error.code} from {urllib.parse.urlsplit(url).netloc}") from None
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise CorpusError(
            f"could not fetch from {urllib.parse.urlsplit(url).netloc}: {type(error).__name__}"
        ) from None


def _page(rows_api: str, source: Source, split: str, offset: int) -> tuple[list[dict], int]:
    query = urllib.parse.urlencode(
        {
            "dataset": source.dataset,
            "config": source.config,
            "split": split,
            "offset": offset,
            "length": PAGE,
        }
    )
    data = _get(f"{rows_api}/rows?{query}")
    try:
        return [item["row"] for item in data["rows"]], int(data["num_rows_total"])
    except (KeyError, TypeError, ValueError):
        raise CorpusError(f"{source.dataset} answered in an unexpected shape") from None


def _clean(texts: list[str]) -> list[str]:
    seen: set[str] = set()
    kept = []
    for text in texts:
        text = text.strip()
        if MIN_CHARS <= len(text) <= MAX_CHARS and text not in seen:
            seen.add(text)
            kept.append(text)
    return kept


def _fetch_source(source: Source, rows_api: str, hub_api: str, seed: int) -> dict:
    rng = random.Random(f"{seed}/{source.key}")
    texts: list[str] = []
    for split in source.splits:
        first, total = _page(rows_api, source, split, 0)
        total_pages = max(1, (total + PAGE - 1) // PAGE)
        chosen = (
            list(range(total_pages))
            if source.pages == 0
            else sorted(rng.sample(range(total_pages), min(source.pages, total_pages)))
        )
        for index in chosen:
            rows = first if index == 0 else _page(rows_api, source, split, index * PAGE)[0]
            for row in rows:
                if source.only_label is not None and row.get("label") != source.only_label:
                    continue
                value = row.get(source.column)
                if isinstance(value, str):
                    texts.append(value)
    rows_kept = _clean(texts)
    if not rows_kept:
        raise CorpusError(f"{source.dataset} gave no usable rows")
    try:
        revision = _get(f"{hub_api}/api/datasets/{source.dataset}").get("sha")
    except CorpusError:
        revision = None  # best effort: the rows matter more than naming the revision
    return {
        "key": source.key,
        "dataset": source.dataset,
        "config": source.config,
        "splits": list(source.splits),
        "licence": source.licence,
        "kind": source.kind,
        "revision": revision,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rows": len(rows_kept),
        "sha256": hashlib.sha256(json.dumps(rows_kept, ensure_ascii=False).encode()).hexdigest(),
        "texts": rows_kept,
    }


def load(
    cache_dir: Path | None = None,
    *,
    refresh: bool = False,
    seed: int = 2026,
    rows_api: str = ROWS_API,
    hub_api: str = HUB_API,
) -> Corpus:
    """The corpus, from the cache if it is there, else fetched and cached."""
    cache = cache_dir or default_cache()
    queries: list[str] = []
    injections: dict[str, tuple[str, ...]] = {}
    manifest = []
    for source in SOURCES:
        file = cache / f"{source.key}.json"
        record = None
        if file.exists() and not refresh:
            try:
                record = json.loads(file.read_text(encoding="utf-8"))
                if (
                    hashlib.sha256(
                        json.dumps(record["texts"], ensure_ascii=False).encode()
                    ).hexdigest()
                    != record["sha256"]
                ):
                    record = None  # a damaged cache is refetched, not trusted
            except (OSError, ValueError, KeyError, TypeError):
                record = None
        if record is None:
            record = _fetch_source(source, rows_api, hub_api, seed)
            cache.mkdir(parents=True, exist_ok=True)
            file.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        texts = tuple(record["texts"])
        if source.kind == "query":
            queries.extend(texts)
        else:
            injections[source.key] = texts
        manifest.append({k: v for k, v in record.items() if k != "texts"})
    return Corpus(tuple(queries), injections, tuple(manifest))
