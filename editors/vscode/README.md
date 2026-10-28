# Kelvra policy files in VS Code

Colouring, suggestions, hover, go to definition, rename and diagnostics for `.klv` policy files.

It has two layers, and the first needs nothing else:

1. **Declared in the extension, no server:** syntax colouring, snippets, whole-name word selection
   (`inbox.imap` is one word), indentation, folding by block, coloured parentheses, a file icon.
2. **From the language server `kelvra lsp`**, which this extension starts for you: errors and
   findings from the parser and the analysis as you type, hover that says who can reach a sink,
   the document outline, suggestions that depend on where the cursor is (after `integrity`,
   `accepts`, `requires`, `from`, `to`, `for`, `audit`; inside a `source`, `sink` or `declassify`
   block only the clauses valid there; whole blocks at the margin, with drop-downs of the
   principals and purposes you declared), go to definition, find all references, rename a principal
   or a purpose everywhere, highlight its occurrences, and a quick fix that declares a missing
   principal.

Colouring does not validate anything: a file full of nonsense still colours. The server is what
checks, and `kelvra check` does the same from a terminal or CI.

## Installing it

The server is a Python program; the extension finds it. From the repository root:

```bash
pip install -e ".[lsp]"                  # the language server (or: pip install "kelvra[lsp]")
cd editors/vscode && npm install --omit=dev    # the one dependency, vscode-languageclient
```

then copy or symlink `editors/vscode` into your extensions folder and restart the editor:

| Platform | Path |
|---|---|
| Linux (VS Code) | `~/.vscode/extensions/kelvra.kelvra-klv-0.1.0` |
| Linux (Code - OSS) | `~/.vscode-oss/extensions/kelvra.kelvra-klv-0.1.0` |
| macOS | `~/.vscode/extensions/kelvra.kelvra-klv-0.1.0` |
| Windows | `%USERPROFILE%\.vscode\extensions\kelvra.kelvra-klv-0.1.0` |

Or try it without installing: `code --extensionDevelopmentPath=./editors/vscode examples/support_agent/policy.klv`.

It looks for the server in this order and uses the first that answers `kelvra lsp --check`: the
`kelvra.server.command` setting, `~/.local/share/kelvra/venv/bin/kelvra`, `kelvra` on the PATH,
`python3 -m kelvra.cli`. If none does, it says so once, with the command to run, and the colouring
and snippets keep working. Settings: `kelvra.server.enabled`, `kelvra.server.command`,
`kelvra.diagnostics.delayMs`. Commands: *Kelvra: Restart the language server*, *Kelvra: Show the
language server log*.

It is not on the Marketplace and will not be published until the syntax stops changing. Shipping
a stable extension for an unstable grammar teaches people a syntax that is about to move.

What was tested, and what was not: the logic of each feature and a real server over the protocol
(`tests/test_editing.py`, `tests/test_lsp_features.py`); how this extension chooses and starts
the server, with doubles for VS Code (`tests/test_vscode_extension.py`); the colours against
VS Code's own engine (`tests/test_klv_highlighting.py`). **Not tested automatically: how it looks
and behaves inside an editor.** Open `examples/support_agent/policy.klv` and try: hover a sink,
press F12 on a principal, F2 to rename it, type a new `sink` and press Tab.

## What the colours mean

| Scope | Covers |
|---|---|
| `keyword.control.declaration` | `policy` `version` `principal` `purpose` `source` `sink` `declassify` `endorse` |
| `entity.name.type` | the name being declared |
| `keyword.other.directive` | `accepts` `requires` `integrity` `from` `to` `for` `audit` |
| `support.function.label` | `confidential(...)` `endorsed(...)` `consent(...)` |
| `variable.parameter.principal` | principals inside those constructors |
| `constant.language` | `public` `untrusted` `trusted` `always` |

Two of those constants are worth staring at: **`public` and `trusted` are not
synonyms, and neither are `confidential` and `untrusted`.** Confidentiality
and integrity are independent axes and all four combinations occur — a
fetched web page is public and untrusted; an inbound customer email is
confidential and untrusted. See [spec/labels.md](../../spec/labels.md) §2.

## On GitHub

GitHub renders `.klv` using the INI grammar, via an override in `.gitattributes`. Linguist only
accepts new languages once they are in wide use, so a proper entry is a long way off. The override
buys comment colouring and little else, and Markdown code fences tagged `klv` or `kelvra` get no
colour at all. So the README shows the main policy as a picture, `assets/policy.svg`, drawn from the
same grammar this extension ships (`editors/highlight.py`), with the text underneath for copying. A
test fails if the picture and the grammar or the policy drift apart.

## Snippets, word selection and indentation

Type `source`, `sink`, `sinkguarded`, `declassify` or `endorse` and press Tab for a skeleton. A
double click selects a whole name such as `inbox.imap` (the dot is part of it), and pressing Enter
after a `source`, `sink`, `declassify` or `endorse` line indents the clauses. In Markdown, a code
fence tagged `klv` or `kelvra` is coloured by this grammar in VS Code's own preview.

## Keeping it honest

The grammar is hand-written and checked against the parser in one place only:
`tests/test_editor_grammar.py` fails if the parser accepts a block keyword
(`source`, `sink`, `declassify`, `endorse`) that the grammar does not colour, and if the
example policy uses a word the grammar does not know. The other keyword lists above are
duplicated by hand and can still drift; generating the grammar from the parser's token
definitions would remove that, and is not done.
