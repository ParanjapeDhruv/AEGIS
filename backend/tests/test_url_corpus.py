"""
Parametrized corpus test for the URL analyser.
Loads backend/tests/data/url_corpus.json and asserts level + indicator expectations.
"""
import json
import socket
from pathlib import Path

import pytest

from backend.app.services.url_analyzer import analyse_url

_CORPUS_PATH = Path(__file__).parent / "data" / "url_corpus.json"
_CORPUS = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))


def _ids(url: str):
    _, _, _, indicators, _ = analyse_url(url)
    return [i.id for i in indicators]


def _level(url: str):
    _, _, level, _, _ = analyse_url(url)
    return level


@pytest.mark.parametrize("entry", _CORPUS, ids=[e["note"] for e in _CORPUS])
def test_corpus_entry(entry):
    url       = entry["url"]
    exp_level = entry["expect_level_in"]
    must_have = entry.get("must_have", [])
    must_not  = entry.get("must_not_have", [])

    try:
        normalized, score, level, indicators, recs = analyse_url(url)
    except ValueError as e:
        pytest.fail(f"analyse_url raised ValueError for {url!r}: {e}")

    ind_ids = [i.id for i in indicators]

    errors = []
    if level not in exp_level:
        errors.append(f"level={level!r} not in {exp_level} (score={score}, ids={ind_ids})")
    for m in must_have:
        if m not in ind_ids:
            errors.append(f"MISSING indicator '{m}' (got {ind_ids})")
    for m in must_not:
        if m in ind_ids:
            errors.append(f"UNEXPECTED indicator '{m}'")

    if errors:
        pytest.fail(f"{url!r}: " + "; ".join(errors))


def test_no_network_in_corpus(monkeypatch):
    """No socket calls allowed during analysis of any corpus URL."""
    def _raise(*a, **kw):
        raise RuntimeError("Network call during URL analysis!")
    monkeypatch.setattr(socket, "socket", _raise)
    monkeypatch.setattr(socket, "getaddrinfo", _raise)

    for entry in _CORPUS:
        try:
            analyse_url(entry["url"])
        except ValueError:
            pass  # hostless URLs may raise; that's fine


def test_score_always_bounded():
    for entry in _CORPUS:
        try:
            _, score, _, _, _ = analyse_url(entry["url"])
            assert 0 <= score <= 100, f"score {score} out of bounds for {entry['url']}"
        except ValueError:
            pass


def test_determinism_corpus():
    for entry in _CORPUS[:10]:
        try:
            r1 = analyse_url(entry["url"])
            r2 = analyse_url(entry["url"])
            assert r1[1] == r2[1] and r1[2] == r2[2]
        except ValueError:
            pass
