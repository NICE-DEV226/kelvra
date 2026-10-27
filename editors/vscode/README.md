# Kelvra policy files in VS Code

Syntax highlighting for `.klv`. **Highlighting only.** This extension does not parse anything, so a
file full of nonsense still colours perfectly; the parser and the checks live in `kelvra check`, and
the same checks are available as editor diagnostics through the language server below.

## Diagnostics, hover, symbols and completion

`kelvra lsp` is a language server for `.klv` over stdio (install with `pip install "kelvra[lsp]"`). It
publishes the parser's errors and the analysis findings with their line, and offers hover, document
symbols and completion. **This extension does not start it.** To use it, point your editor's generic
language-server client at the command `kelvra lsp` for files with the `klv` language id. That wiring has
not been tried with any particular editor here; what is tested is the protocol exchange itself
(`tests/test_lsp.py`).

## Trying it without installing

From the repository root:

```bash
code --extensionDevelopmentPath=./editors/vscode examples/support_agent/policy.klv
```

That opens a second VS Code window with the grammar loaded.

## Installing it locally

Symlink or copy the directory into your extensions folder, then restart
VS Code:

| Platform | Path |
|---|---|
| Linux / macOS | `~/.vscode/extensions/kelvra-klv` |
| Windows | `%USERPROFILE%\.vscode\extensions\kelvra-klv` |

It is not on the Marketplace and will not be published until the syntax
stops changing. Shipping a stable extension for an unstable grammar teaches
people a syntax that is about to move.

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

GitHub renders `.klv` using the INI grammar, via an override in
`.gitattributes`. Linguist only accepts new languages once they are in wide
use, so a proper entry is a long way off. The override buys comment colouring
and little else; this extension is the accurate one.

## Keeping it honest

The grammar is hand-written and checked against the parser in one place only:
`tests/test_editor_grammar.py` fails if the parser accepts a block keyword
(`source`, `sink`, `declassify`, `endorse`) that the grammar does not colour, and if the
example policy uses a word the grammar does not know. The other keyword lists above are
duplicated by hand and can still drift; generating the grammar from the parser's token
definitions would remove that, and is not done.
