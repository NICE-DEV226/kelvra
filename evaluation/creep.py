"""Label creep, measured.

Every document says it is "the standard practical failure of dynamic information flow
control" and that Kelvra "has no strategy" for it, and neither claim has ever had a number
next to it. This measures one concrete form.

The task: an agent reads ``k`` documents and must hand each result to the people that
document was meant for. Each document is readable by two or three of six principals.

* **One model call over everything** (the natural way to write it, and what spec/labels.md
  section 7 makes sound): the output carries the join of all ``k`` labels, so it can only go to
  someone who may read *every* document. A delivery to one document's audience is refused
  unless that person happens to be in all the others' audiences too.
* **One model call per document** (the structural mitigation the specification names:
  "split work across separate model calls"): each result carries only its own label.

What it measures is how often a *legitimate* delivery is refused, for ``k`` from 1 to 6. It
does not measure how often the split is possible in a real pipeline (some tasks need the
documents in one context), and the labels are drawn at random, not taken from any real
organisation. It is a synthetic upper-bound on the cost, not an estimate for a given
deployment.

Run it:  python evaluation/creep.py            (the table)
         python evaluation/creep.py --markdown
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kelvra import Denied, Kelvra, Label, Policy, PrincipalSet, Sink, Source

PRINCIPALS = ["hr", "manager", "employee", "customer", "support", "finance"]
TRIALS = 500
SEED = 20261026


def _world(rng: random.Random, k: int):
    """A policy with k documents, each readable by 2-3 principals, and one sink per principal."""
    policy = Policy(name="Creep")
    audiences = []
    for i in range(k):
        readers = rng.sample(PRINCIPALS, rng.choice([2, 3]))
        audiences.append(readers)
        policy.add_source(Source(f"doc{i}", Label.confidential(*readers)))
    for name in PRINCIPALS:
        policy.add_sink(Sink(f"to.{name}", audience=PrincipalSet.of(name)))
    return policy, audiences


def _deliveries(k: int, rng: random.Random, *, split: bool) -> tuple[int, int]:
    """(refused, attempted) legitimate deliveries over one session of k documents."""
    policy, audiences = _world(rng, k)
    kelvra = Kelvra(policy)
    docs = [kelvra.read(f"doc{i}", f"text {i}") for i in range(k)]
    joint = None if split else kelvra.model_call("all", *docs)
    refused = 0
    for i, readers in enumerate(audiences):
        result = kelvra.model_call(f"one{i}", docs[i]) if split else joint
        try:
            kelvra.emit(f"to.{rng.choice(readers)}", result)  # someone it was meant for
        except Denied:
            refused += 1
    return refused, k


def measure(trials: int = TRIALS) -> list[tuple[int, float, float]]:
    rows = []
    for k in range(1, 7):
        rng_a, rng_b = random.Random(SEED + k), random.Random(SEED + k)
        a_refused = a_total = b_refused = b_total = 0
        for _ in range(trials):
            r, n = _deliveries(k, rng_a, split=False)
            a_refused, a_total = a_refused + r, a_total + n
            r, n = _deliveries(k, rng_b, split=True)
            b_refused, b_total = b_refused + r, b_total + n
        rows.append((k, a_refused / a_total, b_refused / b_total))
    return rows


def table(rows, *, markdown: bool = False) -> str:
    head = (
        "documents in the session",
        "deliveries refused: one call over all",
        "one call per document",
    )
    body = [(str(k), f"{a:.1%}", f"{b:.1%}") for k, a, b in rows]
    if markdown:
        lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        return "\n".join(lines + ["| " + " | ".join(r) + " |" for r in body])
    widths = [max(len(x) for x in col) for col in zip(head, *body, strict=True)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    return "\n".join(
        [fmt.format(*head), fmt.format(*["-" * w for w in widths])] + [fmt.format(*r) for r in body]
    )


def main(argv: list[str]) -> int:
    print(table(measure(), markdown="--markdown" in argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
