# Kelvra policy files in VS Code

Syntax highlighting for `.klv`. **Highlighting only** — there is no parser
yet, so nothing here checks that a policy is valid, or even that it is
well-formed. A file full of nonsense will colour perfectly.

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
| `constant.language` | `public` `untrusted` `trusted` `always` `never` |

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

The keyword lists above are duplicated in the grammar and will drift from the
real language the moment the parser exists. When it does, generate this
grammar from the parser's token definitions rather than maintaining both.
