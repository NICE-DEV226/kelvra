"""The label lattice.

Kelvra labels carry three components, all of them sets of names:

    readers    who is permitted to read the data      (confidentiality)
    endorsers  who vouches for the data               (integrity)
    purposes   what the data may be used for          (purpose limitation)

All three join the same way -- by intersection -- which is what makes the
model small enough to reason about. Combining two values yields data that
only the readers of *both* may see, that only the endorsers of *both*
vouch for, and that may only serve the purposes of *both*.

The confidentiality and integrity axes are duals, and both are required.
An integrity axis is what lets the model express indirect prompt
injection at all: untrusted content reaching a control decision is an
integrity violation, not a confidentiality one. See spec/threat-model.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class PrincipalSet:
    """A set of principals, or the universe of all of them.

    ``ALL`` is not the same as listing every principal you happen to know
    about: it means "any principal, including ones not yet named". Public
    data is readable by ALL; fully trusted data is endorsed by ALL.
    """

    _members: frozenset[str] | None  # None means the universe

    # -- construction ----------------------------------------------------

    @staticmethod
    def of(*names: str) -> PrincipalSet:
        return PrincipalSet(frozenset(names))

    @staticmethod
    def from_iterable(names: Iterable[str]) -> PrincipalSet:
        return PrincipalSet(frozenset(names))

    @staticmethod
    def all() -> PrincipalSet:
        return _ALL

    @staticmethod
    def none() -> PrincipalSet:
        return _NONE

    # -- predicates ------------------------------------------------------

    @property
    def is_all(self) -> bool:
        return self._members is None

    @property
    def is_empty(self) -> bool:
        return self._members is not None and len(self._members) == 0

    def __contains__(self, name: str) -> bool:
        return self._members is None or name in self._members

    def __iter__(self):
        if self._members is None:
            raise TypeError("cannot enumerate the universe of principals")
        return iter(sorted(self._members))

    # -- lattice operations ----------------------------------------------

    def __and__(self, other: PrincipalSet) -> PrincipalSet:
        """Intersection. This is the join of the label lattice."""
        if self._members is None:
            return other
        if other._members is None:
            return self
        return PrincipalSet(self._members & other._members)

    def __or__(self, other: PrincipalSet) -> PrincipalSet:
        """Union. Used by declassification, never by propagation."""
        if self._members is None or other._members is None:
            return _ALL
        return PrincipalSet(self._members | other._members)

    def __le__(self, other: PrincipalSet) -> bool:
        """Subset. ``a <= b`` reads "every principal in a is also in b"."""
        if other._members is None:
            return True
        if self._members is None:
            return False
        return self._members <= other._members

    # -- display ---------------------------------------------------------

    def __repr__(self) -> str:
        if self._members is None:
            return "*"
        if not self._members:
            return "-"
        return ",".join(sorted(self._members))

    def to_json(self) -> str | list[str]:
        return "*" if self._members is None else sorted(self._members)


_ALL = PrincipalSet(None)
_NONE = PrincipalSet(frozenset())


@dataclass(frozen=True)
class Label:
    """What a piece of data carries through the pipeline."""

    readers: PrincipalSet = _ALL
    endorsers: PrincipalSet = _ALL
    purposes: PrincipalSet = _ALL

    # -- constructors ----------------------------------------------------

    @staticmethod
    def public() -> Label:
        """The join identity: readable by anyone, fully endorsed, any purpose."""
        return PUBLIC

    @staticmethod
    def confidential(*readers: str, for_purpose: str | None = None) -> Label:
        return Label(
            readers=PrincipalSet.of(*readers),
            endorsers=_ALL,
            purposes=PrincipalSet.of(for_purpose) if for_purpose else _ALL,
        )

    def untrusted(self) -> Label:
        """Nobody vouches for this. The label of anything arriving from outside."""
        return Label(self.readers, _NONE, self.purposes)

    def endorsed_by(self, *principals: str) -> Label:
        return Label(self.readers, PrincipalSet.of(*principals), self.purposes)

    def for_purposes(self, *purposes: str) -> Label:
        return Label(self.readers, self.endorsers, PrincipalSet.of(*purposes))

    # -- lattice ---------------------------------------------------------

    def join(self, other: Label) -> Label:
        """Combine two labels. Restrictions accumulate; nothing is ever relaxed.

        This is the only operation propagation is allowed to use. Relaxing a
        label requires an explicitly declared declassification -- that is the
        whole point of the design.
        """
        return Label(
            self.readers & other.readers,
            self.endorsers & other.endorsers,
            self.purposes & other.purposes,
        )

    def __or__(self, other: Label) -> Label:
        return self.join(other)

    def is_at_least_as_restrictive_as(self, other: Label) -> bool:
        return (
            self.readers <= other.readers
            and self.endorsers <= other.endorsers
            and self.purposes <= other.purposes
        )

    # -- properties ------------------------------------------------------

    @property
    def is_public(self) -> bool:
        return self.readers.is_all

    @property
    def is_untrusted(self) -> bool:
        return self.endorsers.is_empty

    # -- display ---------------------------------------------------------

    def __repr__(self) -> str:
        return f"Label(readers={self.readers!r} endorsers={self.endorsers!r} purposes={self.purposes!r})"

    def describe(self) -> str:
        bits = []
        bits.append("public" if self.readers.is_all else f"confidential({self.readers!r})")
        if self.endorsers.is_empty:
            bits.append("untrusted")
        elif not self.endorsers.is_all:
            bits.append(f"endorsed({self.endorsers!r})")
        if not self.purposes.is_all:
            bits.append(f"for {self.purposes!r}")
        return " ".join(bits)

    def to_json(self) -> dict:
        return {
            "readers": self.readers.to_json(),
            "endorsers": self.endorsers.to_json(),
            "purposes": self.purposes.to_json(),
        }


PUBLIC = Label(_ALL, _ALL, _ALL)
"""Join identity. Joining anything with PUBLIC leaves it unchanged."""

SECRET = Label(_NONE, _NONE, _NONE)
"""Join absorbing element. Nobody may read it, nobody vouches for it."""


def join_all(labels: Iterable[Label]) -> Label:
    """Join a whole collection. Empty collection yields PUBLIC."""
    result = PUBLIC
    for label in labels:
        result = result.join(label)
    return result
