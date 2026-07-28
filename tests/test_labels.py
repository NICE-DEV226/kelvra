"""Lattice laws.

If join is not a proper lattice operation, every guarantee above it is
worthless, so these are checked directly rather than assumed.
"""

import itertools

import pytest

from kelvra import PUBLIC, SECRET, Label, PrincipalSet, join_all

SAMPLE = [
    PUBLIC,
    SECRET,
    Label.confidential("customer"),
    Label.confidential("customer", "support"),
    Label.confidential("support"),
    Label.confidential("customer").untrusted(),
    Label.confidential("customer", for_purpose="support"),
    PUBLIC.untrusted(),
    PUBLIC.endorsed_by("system"),
]


@pytest.mark.parametrize("a,b", itertools.product(SAMPLE, SAMPLE))
def test_join_is_commutative(a, b):
    assert a.join(b) == b.join(a)


@pytest.mark.parametrize("a,b,c", itertools.product(SAMPLE[:5], SAMPLE[:5], SAMPLE[:5]))
def test_join_is_associative(a, b, c):
    assert a.join(b).join(c) == a.join(b.join(c))


@pytest.mark.parametrize("a", SAMPLE)
def test_join_is_idempotent(a):
    assert a.join(a) == a


@pytest.mark.parametrize("a", SAMPLE)
def test_public_is_the_identity(a):
    assert a.join(PUBLIC) == a
    assert PUBLIC.join(a) == a


@pytest.mark.parametrize("a", SAMPLE)
def test_secret_absorbs(a):
    assert a.join(SECRET) == SECRET


@pytest.mark.parametrize("a,b", itertools.product(SAMPLE, SAMPLE))
def test_join_never_relaxes(a, b):
    """The result is at least as restrictive as either input, on every axis."""
    joined = a.join(b)
    assert joined.is_at_least_as_restrictive_as(a)
    assert joined.is_at_least_as_restrictive_as(b)


def test_join_all_of_nothing_is_public():
    assert join_all([]) == PUBLIC


# -- confidentiality --------------------------------------------------------


def test_combining_two_audiences_keeps_only_the_overlap():
    a = Label.confidential("customer", "support")
    b = Label.confidential("support", "billing")
    assert a.join(b) == Label.confidential("support")


def test_disjoint_audiences_produce_something_nobody_may_read():
    a = Label.confidential("customer")
    b = Label.confidential("billing")
    assert a.join(b).readers.is_empty


def test_public_joined_with_confidential_is_confidential():
    assert PUBLIC.join(Label.confidential("customer")) == Label.confidential("customer")


# -- integrity --------------------------------------------------------------


def test_untrusted_contaminates():
    """The property that makes indirect prompt injection expressible."""
    trusted = PUBLIC.endorsed_by("system")
    untrusted = PUBLIC.untrusted()
    assert trusted.join(untrusted).is_untrusted


def test_two_endorsers_keep_only_the_common_one():
    a = PUBLIC.endorsed_by("system", "reviewer")
    b = PUBLIC.endorsed_by("reviewer")
    assert a.join(b).endorsers <= PrincipalSet.of("reviewer")


def test_public_is_not_untrusted():
    """Public and untrusted are independent axes, not two names for one thing."""
    assert PUBLIC.is_public
    assert not PUBLIC.is_untrusted
    assert PUBLIC.untrusted().is_public
    assert PUBLIC.untrusted().is_untrusted


# -- purposes ---------------------------------------------------------------


def test_purposes_intersect():
    a = PUBLIC.for_purposes("support", "billing")
    b = PUBLIC.for_purposes("billing")
    assert "billing" in a.join(b).purposes
    assert "support" not in a.join(b).purposes


# -- principal sets ---------------------------------------------------------


def test_universe_intersects_to_the_other_side():
    assert (PrincipalSet.all() & PrincipalSet.of("a")) == PrincipalSet.of("a")


def test_everything_is_a_subset_of_the_universe():
    assert PrincipalSet.of("a") <= PrincipalSet.all()
    assert PrincipalSet.none() <= PrincipalSet.all()
    assert PrincipalSet.all() <= PrincipalSet.all()


def test_the_universe_is_not_a_subset_of_a_finite_set():
    assert not (PrincipalSet.all() <= PrincipalSet.of("a"))


def test_empty_set_is_a_subset_of_everything():
    assert PrincipalSet.none() <= PrincipalSet.of("a")
    assert PrincipalSet.none() <= PrincipalSet.none()
