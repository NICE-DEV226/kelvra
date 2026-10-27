"""Real JSON decoders, asked what they make of a message.

A gateway is only sound if it reads a message the way the program behind it will.
JSON implementations disagree (duplicate keys, case, numbers, what counts as valid),
so the check is empirical: hand the same line to several real decoders and compare.

Each *peer* turns a line into a **view**: ``[method, name, to, has_result, has_error, id]``
where the first three are strings or ``None``, the next two booleans, and ``id`` is
``"i:<int>"``, ``"s:<text>"`` or ``None`` (not comparable). ``None`` for the whole view
means the decoder refused the line.

Peers that need an external program (node, ruby, php, perl, jq, go) are skipped when it
is not installed; the Python ones always run. Go matters most: its ``encoding/json``
matches member names without regard to case, which is the behaviour the gateway has to
survive. Everything here uses only the standard library of each runtime.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import tempfile
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SAFE_INT = 2**53

View = list | None


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _id_repr(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        return "s:" + value
    if isinstance(value, int) and abs(value) < SAFE_INT:
        return "i:" + str(value)
    return None


def view_of(message: Any, get: Callable[[dict, str], Any]) -> View:
    """The view of a parsed message, looking members up with ``get``."""
    if not isinstance(message, dict):
        message = {}
    params = get(message, "params")
    params = params if isinstance(params, dict) else {}
    arguments = get(params, "arguments")
    arguments = arguments if isinstance(arguments, dict) else {}
    return [
        _as_str(get(message, "method")),
        _as_str(get(params, "name")),
        _as_str(get(arguments, "to")),
        _has(message, "result", get),
        _has(message, "error", get),
        _id_repr(get(message, "id")),
    ]


def _has(obj: dict, key: str, get: Callable[..., Any]) -> bool:
    marker = object()
    return get(obj, key, marker) is not marker


# -- Python peers ------------------------------------------------------------


def _exact_get(obj: dict, key: str, default: Any = None) -> Any:
    return obj.get(key, default)


def _folded_get(obj: dict, key: str, default: Any = None) -> Any:
    """Case-insensitive lookup, the last matching key winning, as lenient decoders do."""
    wanted = unicodedata.normalize("NFKC", key).casefold()
    found = default
    for k, v in obj.items():
        if unicodedata.normalize("NFKC", k).casefold() == wanted:
            found = v
    return found


def _first_wins(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        out.setdefault(key, value)
    return out


def _python_last(line: str) -> View:
    try:
        return view_of(json.loads(line), _exact_get)
    except (ValueError, RecursionError):
        return None


def _python_first(line: str) -> View:
    try:
        return view_of(json.loads(line, object_pairs_hook=_first_wins), _exact_get)
    except (ValueError, RecursionError):
        return None


def _python_casefold(line: str) -> View:
    try:
        return view_of(json.loads(line), _folded_get)
    except (ValueError, RecursionError):
        return None


# -- external peers ----------------------------------------------------------

_NODE = r"""
const rl = require('readline').createInterface({input: process.stdin, crlfDelay: Infinity});
const s = v => typeof v === 'string' ? v : null;
const obj = v => (v && typeof v === 'object' && !Array.isArray(v)) ? v : {};
const idr = v => typeof v === 'string' ? 's:' + v
  : (typeof v === 'number' && Number.isInteger(v) && Math.abs(v) < 2 ** 53) ? 'i:' + v : null;
rl.on('line', l => {
  let m;
  try { m = JSON.parse(l); } catch (e) { console.log('"ERR"'); return; }
  const o = obj(m), p = obj(o.params), a = obj(p.arguments);
  const has = (x, k) => Object.prototype.hasOwnProperty.call(x, k);
  console.log(JSON.stringify([
    s(o.method), s(p.name), s(a.to), has(o, 'result'), has(o, 'error'), idr(o.id)]));
});
"""

_RUBY = r"""
require 'json'
def obj(v) v.is_a?(Hash) ? v : {} end
def s(v) v.is_a?(String) ? v : nil end
def idr(v)
  return "s:#{v}" if v.is_a?(String)
  return "i:#{v}" if v.is_a?(Integer) && v.abs < 2**53
  nil
end
STDIN.each_line do |l|
  begin
    m = JSON.parse(l.chomp)
  rescue StandardError
    puts '"ERR"'
    next
  end
  o = obj(m); p = obj(o['params']); a = obj(p['arguments'])
  puts JSON.generate([s(o['method']), s(p['name']), s(a['to']),
                      o.key?('result'), o.key?('error'), idr(o['id'])])
end
"""

_PHP = r"""<?php
function obj($v) {
  if (!is_array($v)) return [];
  return (count($v) === 0 || array_keys($v) !== range(0, count($v) - 1)) ? $v : [];
}
function s($v) { return is_string($v) ? $v : null; }
function idr($v) {
  if (is_string($v)) return 's:' . $v;
  if (is_int($v) && abs($v) < 9007199254740992) return 'i:' . $v;
  return null;
}
while (($l = fgets(STDIN)) !== false) {
  $m = json_decode(rtrim($l, "\r\n"), true, 512);
  if (json_last_error() !== JSON_ERROR_NONE) { echo "\"ERR\"\n"; continue; }
  $o = obj($m); $p = obj($o['params'] ?? null); $a = obj($p['arguments'] ?? null);
  echo json_encode([s($o['method'] ?? null), s($p['name'] ?? null), s($a['to'] ?? null),
    array_key_exists('result', $o), array_key_exists('error', $o), idr($o['id'] ?? null)]), "\n";
}
"""

_PERL = r"""
use strict; use warnings; use JSON::PP; use B;
my $j = JSON::PP->new->utf8;
sub obj { ref($_[0]) eq 'HASH' ? $_[0] : {} }
# JSON::PP gives a string a string flag and a number a number flag; only the former is text.
sub txt {
  my $v = $_[0];
  return undef if !defined $v || ref($v);
  my $f = B::svref_2object(\$v)->FLAGS;
  return ($f & B::SVp_POK) ? "$v" : undef;
}
$| = 1;
while (my $l = <STDIN>) {
  chomp $l; $l =~ s/\r$//;
  my $m = eval { $j->decode($l) };
  if ($@) { print "\"ERR\"\n"; next }
  my $o = obj($m); my $p = obj($o->{params}); my $a = obj($p->{arguments});
  print $j->encode([txt($o->{method}), txt($p->{name}), txt($a->{to}),
    (exists $o->{result} ? JSON::PP::true : JSON::PP::false),
    (exists $o->{error} ? JSON::PP::true : JSON::PP::false), undef]), "\n";
}
"""

_JQ = (
    'try (fromjson | (if type=="object" then . else {} end) as $o'
    ' | ($o.params | if type=="object" then . else {} end) as $p'
    ' | ($p.arguments | if type=="object" then . else {} end) as $a'
    ' | [($o.method | if type=="string" then . else null end),'
    ' ($p.name | if type=="string" then . else null end),'
    ' ($a.to | if type=="string" then . else null end),'
    ' ($o | has("result")), ($o | has("error")),'
    ' ($o.id | if type=="string" then "s:" + .'
    ' elif type=="number" and . == floor and (. | fabs) < 9007199254740992'
    ' then "i:" + (. | tostring) else null end)]) catch "ERR"'
)

_GO = r"""
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type args struct {
	To json.RawMessage `json:"to"`
}
type params struct {
	Name      json.RawMessage `json:"name"`
	Arguments *args           `json:"arguments"`
}
type msg struct {
	Method json.RawMessage `json:"method"`
	Params *params         `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
	ID     json.RawMessage `json:"id"`
}

func str(raw json.RawMessage) interface{} {
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
	}
	return nil
}

func idr(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return "s:" + s
		}
		return nil
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil && n < 9007199254740992 && n > -9007199254740992 &&
		!strings.ContainsAny(string(raw), ".eE") {
		return fmt.Sprintf("i:%d", n)
	}
	return nil
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for sc.Scan() {
		var m msg
		err := json.Unmarshal([]byte(strings.TrimRight(sc.Text(), "\r")), &m)
		if err != nil {
			if _, ok := err.(*json.UnmarshalTypeError); !ok {
				fmt.Fprintln(out, `"ERR"`)
				continue
			}
		}
		var p *params = m.Params
		var name, to interface{}
		if p != nil {
			name = str(p.Name)
			if p.Arguments != nil {
				to = str(p.Arguments.To)
			}
		}
		view := []interface{}{str(m.Method), name, to,
			len(m.Result) > 0, len(m.Error) > 0, idr(m.ID)}
		b, _ := json.Marshal(view)
		fmt.Fprintln(out, string(b))
	}
}
"""


def _run(command: list[str], lines: list[str], *, env: dict | None = None) -> list[View]:
    """Feed ``lines`` to a program on stdin, one JSON view per line back."""
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    done = subprocess.run(
        command, input=payload, capture_output=True, timeout=300, env=env, check=False
    )
    out = done.stdout.decode("utf-8", "replace").splitlines()
    if len(out) != len(lines):
        raise RuntimeError(
            f"{command[0]} returned {len(out)} lines for {len(lines)}: "
            f"{done.stderr.decode('utf-8', 'replace')[:300]}"
        )
    views: list[View] = []
    for text in out:
        value = json.loads(text)
        views.append(None if value == "ERR" else value)
    return views


@dataclass
class Peer:
    name: str
    available: Callable[[], bool]
    run: Callable[[list[str]], list[View]]
    case_insensitive: bool = False
    """Matches member names without regard to case, so ``Method`` is ``method``."""

    first_wins: bool = False
    """Takes the first of two equal keys, not the last."""


def _script_peer(name: str, binary: str, args: list[str], source: str, suffix: str) -> Peer:
    def available() -> bool:
        return shutil.which(binary) is not None

    def run(lines: list[str]) -> list[View]:
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / ("peer" + suffix)
            script.write_text(source, encoding="utf-8")
            return _run([binary, *args, str(script)], lines)

    return Peer(name, available, run)


def _go_peer() -> Peer:
    cache: dict[str, str] = {}

    def available() -> bool:
        return shutil.which("go") is not None

    def build() -> str:
        if "bin" not in cache:
            directory = tempfile.mkdtemp(prefix="kelvra-go-peer-")
            # The compiled peer is 4 MB. Left behind, every test run costs 4 MB of the
            # temporary directory; hundreds of runs filled it. Remove it when the process ends.
            atexit.register(shutil.rmtree, directory, ignore_errors=True)
            source = Path(directory) / "peer.go"
            source.write_text(_GO, encoding="utf-8")
            binary = str(Path(directory) / ("peer.exe" if os.name == "nt" else "peer"))
            env = dict(os.environ, GO111MODULE="off", CGO_ENABLED="0")
            built = subprocess.run(
                ["go", "build", "-o", binary, str(source)],
                capture_output=True,
                env=env,
                timeout=300,
                check=False,
            )
            if built.returncode != 0:
                raise RuntimeError("go build failed: " + built.stderr.decode()[:400])
            cache["bin"] = binary
        return cache["bin"]

    def run(lines: list[str]) -> list[View]:
        return _run([build()], lines)

    return Peer("go", available, run, case_insensitive=True)


def _jq_peer() -> Peer:
    def available() -> bool:
        return shutil.which("jq") is not None

    def run(lines: list[str]) -> list[View]:
        return _run(["jq", "-Rc", _JQ], lines)

    return Peer("jq", available, run)


def all_peers() -> list[Peer]:
    always = lambda: True  # noqa: E731
    return [
        Peer("python-last", always, lambda ls: [_python_last(x) for x in ls]),
        Peer("python-first", always, lambda ls: [_python_first(x) for x in ls], first_wins=True),
        Peer(
            "python-casefold",
            always,
            lambda ls: [_python_casefold(x) for x in ls],
            case_insensitive=True,
        ),
        _script_peer("node", "node", [], _NODE, ".js"),
        _script_peer("ruby", "ruby", [], _RUBY, ".rb"),
        _script_peer("php", "php", ["-f"], _PHP, ".php"),
        _script_peer("perl", "perl", [], _PERL, ".pl"),
        _jq_peer(),
        _go_peer(),
    ]
