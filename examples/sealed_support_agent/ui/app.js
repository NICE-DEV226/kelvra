"use strict";
// Everything from the model or the customer goes in with textContent. Nothing here decides
// anything: it draws what /api/run returned.
const $ = (id) => document.getElementById(id);
const messageBox = $("message");
const behaviour = () => document.querySelector('input[name="behaviour"]:checked').value;

function shorten(text) {
  return text.replace(/(kelvra-seal\.v1\.[a-z0-9_]+\.[0-9a-f]{8}\.)[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g,
    (_m, head) => head + "…");
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function show(result) {
  $("results").hidden = false;
  showModel(result.model);
  $("model-used").textContent = result.model.label;
  const leaked = result.plaintextInPrompt;
  const line = $("leakline");
  line.textContent = leaked.length
    ? "Plaintext found in the prompt: " + leaked.join(", ")
    : "Plaintext account details in the prompt: none. Master key in the prompt: no (key id " + result.keyId + ").";
  line.className = "verdict " + (leaked.length ? "bad" : "good");
  $("prompt").textContent = shorten(result.prompt);

  const list = $("attempts");
  list.replaceChildren();
  if (!result.attempts.length) list.append(el("li", "", "The model asked for nothing."));
  for (const a of result.attempts) {
    const item = el("li");
    const head = el("div", "head");
    head.append(el("span", "badge " + a.outcome, a.outcome.toUpperCase()), el("span", "sink", a.sink));
    item.append(head);
    const asked = el("div", "row"); asked.append(el("b", "", "asked: "), document.createTextNode(shorten(a.asked)));
    item.append(asked);
    const why = el("div", "row");
    why.append(el("b", "", a.outcome === "delivered" ? "sent to the customer: " : "why: "),
      document.createTextNode(a.outcome === "delivered" ? a.detail : shorten(a.detail)));
    item.append(why);
    list.append(item);
  }

  const verdict = $("verdict");
  verdict.textContent = result.verified ? "Signed record: valid." : "Signed record: INVALID.";
  verdict.className = "verdict " + (result.verified ? "good" : "bad");
  const summary = $("summary");
  summary.replaceChildren();
  for (const [name, value] of Object.entries(result.summary)) {
    const box = el("div"); box.append(el("dt", "", name.replace(/_/g, " ")), el("dd", "", String(value)));
    summary.append(box);
  }
  $("report").textContent = result.report;
}

async function run() {
  const button = $("run"); const status = $("status");
  button.disabled = true; status.textContent = "Running…";
  try {
    const response = await fetch("/api/run", { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ behaviour: behaviour(), message: messageBox.value }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "request failed");
    show(data); status.textContent = "";
    $("results").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    status.textContent = "Error: " + error.message;
  } finally { button.disabled = false; }
}

function drawPolicy(policy) {
  const box = $("policy");
  box.replaceChildren();
  $("policy-name").textContent = policy.name;
  for (const line of policy.lines) {
    const row = el("div", "line");
    if (!line.length || line.every(([, text]) => text === "")) row.append(document.createTextNode("\u00a0"));
    for (const [name, text] of line) {
      if (text === "") continue;
      row.append(name ? el("span", "tok-" + name, text) : document.createTextNode(text));
    }
    box.append(row);
  }
}
fetch("/api/policy").then((r) => r.json()).then(drawPolicy).catch(() => {
  $("policy").textContent = "The policy could not be loaded.";
});

function showModel(info) {
  const banner = $("model-banner");
  const live = info.mode === "live";
  banner.textContent = live
    ? "Live model: " + info.label + ". Your request is sent to that provider; the account details in it are fictional and sealed."
    : "Scripted model, offline: it does what each choice below says, so what is on show is the boundary, not a model.";
  banner.className = "banner " + (live ? "live" : "scripted");
  $("honest-title").textContent = live ? "Normal message" : "Behaves";
  $("honest-note").textContent = live
    ? "a real banking question; the model answers it"
    : "answers the customer, copying the sealed tokens it needs";
  $("injected-title").textContent = live ? "Message with an injection" : "Obeys an injection";
  $("injected-note").textContent = live
    ? "the message hides an instruction; what the model does with it is up to the model"
    : "tries to send the details to an outsider, write them to the record, forge and alter tokens";
  $("limits-mode").textContent = live
    ? "A real model may copy a token exactly, alter it (the whole reply is then refused, which is the safe " +
      "outcome and a lost answer), or leave one out. How often depends on the model: see spec/sealing-verification.md, " +
      "section 5, for what was measured and how small the samples are."
    : "This page uses a scripted model, so it shows what the boundary does, not how a real model behaves. " +
      "Start it with --provider to use a real one.";
}
fetch("/api/config").then((r) => r.json()).then(showModel).catch(() => {});

let DEFAULTS = { honest: "", injected: "" };
function restore() { messageBox.value = DEFAULTS[behaviour()]; }
document.querySelectorAll('input[name="behaviour"]').forEach((r) => r.addEventListener("change", restore));
$("reset").addEventListener("click", restore);
$("run").addEventListener("click", run);
// The example messages come from the server, so the page and the pipeline cannot disagree.
fetch("/api/defaults").then((r) => r.json()).then((d) => {
  DEFAULTS = d; restore();
  // A link ending in #honest or #injected runs that scenario on load (handy for a recording).
  const wanted = location.hash.slice(1);
  if (wanted === "honest" || wanted === "injected") {
    document.querySelector('input[name="behaviour"][value="' + wanted + '"]').checked = true;
    restore(); run();
  }
});
