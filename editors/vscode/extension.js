"use strict";
// Kelvra policy files: starts the language server (`kelvra lsp`) for the .klv files VS Code opens.
//
// Colouring, snippets, word selection and indentation need none of this: they are declared in
// package.json and work without a server. What the server adds is diagnostics, hover, outline,
// context-aware suggestions, go to definition, find references, rename and quick fixes.
//
// It looks for a way to run the server rather than assuming one. In order: the `kelvra.server.command`
// setting, a dedicated environment at ~/.local/share/kelvra/venv, `kelvra` on the PATH, and
// `python -m kelvra.cli`. Each candidate is asked `lsp --check` first, which says whether the optional
// `lsp` extra is installed, so a Python that has kelvra but not pygls is skipped, not started and left
// to fail. If none works the extension says so once, with the command that fixes it, and carries on.

const fs = require("fs");
const os = require("os");
const path = require("path");
const childProcess = require("child_process");

const INSTALL_COMMAND = 'pip install "kelvra[lsp]"';
const CHECK_TIMEOUT_MS = 15000;

// Overridable so a test can run this file without VS Code, a real Python or a real file system.
const deps = {
  spawnSync: childProcess.spawnSync,
  homedir: os.homedir,
  platform: () => process.platform,
};

function venvCommand() {
  // The separator of the platform this is for, not of the machine running it: a path built for
  // Windows is the same on any host, which is also what lets a test check it exactly.
  const windows = deps.platform() === "win32";
  return (windows ? path.win32 : path.posix).join(
    deps.homedir(), ".local", "share", "kelvra", "venv",
    windows ? "Scripts" : "bin", windows ? "kelvra.exe" : "kelvra"
  );
}

/** The ways to run the server, best first. Each is {command, base}: `command ...base lsp`. */
function candidates(configured) {
  const windows = deps.platform() === "win32";
  const list = [];
  if (Array.isArray(configured) && configured.length > 0) {
    list.push({ command: String(configured[0]), base: configured.slice(1).map(String), source: "setting" });
  }
  list.push({ command: venvCommand(), base: [], source: "environment" });
  list.push({ command: "kelvra", base: [], source: "PATH" });
  list.push({ command: windows ? "python" : "python3", base: ["-m", "kelvra.cli"], source: "python" });
  return list;
}

function usable(candidate) {
  const result = deps.spawnSync(candidate.command, [...candidate.base, "lsp", "--check"], {
    timeout: CHECK_TIMEOUT_MS,
    encoding: "utf8",
  });
  return !result.error && result.status === 0;
}

/** The first candidate that can start the server, or null. */
function firstUsable(configured) {
  for (const candidate of candidates(configured)) {
    if (usable(candidate)) return candidate;
  }
  return null;
}

let client = null;
let warned = false;

async function start(context, vscode) {
  const settings = vscode.workspace.getConfiguration("kelvra");
  if (!settings.get("server.enabled", true)) return null;

  const found = firstUsable(settings.get("server.command", []));
  if (!found) {
    if (!warned) {
      warned = true;
      const copy = "Copy install command";
      const choice = await vscode.window.showInformationMessage(
        "Kelvra: the language server was not found, so there are no diagnostics, hover, " +
          "suggestions or rename in .klv files. Colouring and snippets still work. To add them, " +
          `run: ${INSTALL_COMMAND}`,
        copy
      );
      if (choice === copy) await vscode.env.clipboard.writeText(INSTALL_COMMAND);
    }
    return null;
  }

  const { LanguageClient } = require("vscode-languageclient/node");
  const delay = settings.get("diagnostics.delayMs", 250);
  const run = {
    command: found.command,
    args: [...found.base, "lsp"],
    options: { env: { ...process.env, KELVRA_LSP_DEBOUNCE_MS: String(delay) } },
  };
  const created = new LanguageClient(
    "kelvra",
    "Kelvra policy language server",
    { run, debug: run },
    { documentSelector: [{ language: "klv" }] }
  );
  await created.start();
  context.subscriptions.push({ dispose: () => created.stop() });
  return created;
}

async function activate(context) {
  const vscode = require("vscode");
  client = await start(context, vscode).catch((error) => {
    vscode.window.showWarningMessage(`Kelvra: the language server did not start (${error.message})`);
    return null;
  });
  context.subscriptions.push(
    vscode.commands.registerCommand("kelvra.restartServer", async () => {
      if (client) await client.stop();
      client = await start(context, vscode).catch(() => null);
      if (!client) vscode.window.showWarningMessage("Kelvra: the language server could not be started.");
    }),
    vscode.commands.registerCommand("kelvra.showServerLog", () => {
      if (client) client.outputChannel.show();
      else vscode.window.showInformationMessage("Kelvra: the language server is not running.");
    }),
    vscode.workspace.onDidChangeConfiguration(async (event) => {
      if (!event.affectsConfiguration("kelvra")) return;
      if (client) await client.stop();
      client = await start(context, vscode).catch(() => null);
    })
  );
}

function deactivate() {
  return client ? client.stop() : undefined;
}

module.exports = { activate, deactivate, candidates, firstUsable, usable, deps, INSTALL_COMMAND };
