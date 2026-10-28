"use strict";
// Runs editors/vscode/extension.js outside VS Code, with the pieces it talks to replaced by doubles.
//   node extension_harness.js <extension.js> '<json scenario>'
// Prints one JSON object describing what the extension did. Used by tests/test_vscode_extension.py.
const Module = require("module");
const path = require("path");

const [, , extensionPath, rawScenario] = process.argv;
const scenario = JSON.parse(rawScenario || "{}");
const log = { calls: [], messages: [], clipboard: [], clients: [], commands: [], listeners: 0 };

const fakeVscode = {
  workspace: {
    getConfiguration: () => ({
      get: (key, fallback) => (key in (scenario.settings || {}) ? scenario.settings[key] : fallback),
    }),
    onDidChangeConfiguration: () => { log.listeners += 1; return { dispose() {} }; },
  },
  window: {
    showInformationMessage: async (text, ...buttons) => {
      log.messages.push({ kind: "info", text, buttons });
      return scenario.clickCopy ? buttons[0] : undefined;
    },
    showWarningMessage: async (text) => { log.messages.push({ kind: "warning", text }); },
  },
  env: { clipboard: { writeText: async (text) => { log.clipboard.push(text); } } },
  commands: {
    registerCommand: (name) => { log.commands.push(name); return { dispose() {} }; },
  },
};

class FakeClient {
  constructor(id, name, serverOptions, clientOptions) {
    log.clients.push({ id, name, serverOptions, clientOptions });
    this.outputChannel = { show() {} };
  }
  async start() { if (scenario.startFails) throw new Error("boom"); }
  async stop() {}
}

const original = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === "vscode") return fakeVscode;
  if (request === "vscode-languageclient/node") return { LanguageClient: FakeClient };
  return original.apply(this, arguments);
};

const ext = require(path.resolve(extensionPath));
if (!scenario.real) {
  const status = scenario.status || {};
  ext.deps.spawnSync = (command, args) => {
    log.calls.push([command, ...args]);
    return command in status ? { status: status[command] } : { error: new Error("ENOENT") };
  };
}
if (scenario.home) ext.deps.homedir = () => scenario.home;
if (scenario.platform) ext.deps.platform = () => scenario.platform;

(async () => {
  const out = { log };
  if (scenario.mode === "candidates") {
    out.candidates = ext.candidates(scenario.configured);
  } else if (scenario.mode === "first") {
    out.chosen = ext.firstUsable(scenario.configured);
  } else {
    const context = { subscriptions: [] };
    await ext.activate(context);
    out.subscriptions = context.subscriptions.length;
    if (scenario.activateTwice) await ext.activate({ subscriptions: [] });
  }
  console.log(JSON.stringify(out));
})();
