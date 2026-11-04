import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const script = fs.readFileSync(new URL("../ui/app.js", import.meta.url), "utf8");
const html = fs.readFileSync(new URL("../ui/index.html", import.meta.url), "utf8");
const messages = [];
const nodes = new Map();
let receive;
function node()
{
    const listeners = new Map();
    const classes = new Set(["hidden"]);
    return {
        value: "", children: [], dataset: {}, checked: false, style: {}, attributes: {},
        scrollTop: 0, scrollHeight: 0, clientHeight: 400,
        get textContent() { return this._text || ""; },
        set textContent(value) { this._text = value; this.children = []; },
        classList: {
            add(value) { classes.add(value); },
            remove(value) { classes.delete(value); },
            contains(value) { return classes.has(value); }
        },
        addEventListener(name, fn) { listeners.set(name, fn); },
        fire(name, event = {}) { listeners.get(name)?.(event); },
        appendChild(child) { this.children.push(child); },
        removeChild(child) { this.children.splice(this.children.indexOf(child), 1); },
        contains(child)
        {
            return child === this || this.children.some(item => item.contains(child));
        },
        querySelectorAll(selector)
        {
            return this.children.flatMap(child => [
                ...((child.className || "").split(/\s+/).includes(selector.slice(1)) ? [child] : []),
                ...child.querySelectorAll(selector)
            ]);
        },
        getBoundingClientRect() { return { width: 0 }; },
        focus() { document.activeElement = this; },
        setAttribute(name, value) { this.attributes[name] = String(value); },
        getAttribute(name) { return this.attributes[name] ?? null; }
    };
}
for (const match of html.matchAll(/\bid="([^"]+)"/g))
{
    nodes.set(match[1], node());
}
const documentListeners = new Map();
const document = {
    getElementById(id) { return nodes.get(id); },
    createElement: node,
    addEventListener(name, fn) { documentListeners.set(name, fn); }
};
const window = {
    chrome: { webview: {
        addEventListener(name, fn) { receive = fn; },
        postMessage(request)
        {
            messages.push(request);
            if (request.method === "resultTabs")
            {
                queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                    uiGeneration: "7", type: "completed", ok: true, result: { missing: [] } } }));
            }
        }
    } },
    addEventListener() {}
};
vm.runInNewContext(script, { document, window, performance, setTimeout() {}, clearTimeout() {}, console });
async function respond(method, response)
{
    const request = messages.findLast(m => m.method === method);
    assert.ok(request, "Missing request: " + method);
    receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
        uiGeneration: "7", type: "completed", ...response } });
    await Promise.resolve();
    await Promise.resolve();
}
function enter(command)
{
    nodes.get("prompt").value = command;
    nodes.get("prompt").fire("keydown", { key: "Enter", preventDefault() {} });
}

await respond("hello", { ok: true, result: { target: { sessionId: "fixture", targetGeneration: "1" } } });
await respond("catalog", { ok: true, result: { groups: {
    Debugger: [
        { name: "stack", synopsis: "stack [decimal-frame-count]", support: "Stable" },
        { name: "registers", synopsis: "registers [name]", support: "Stable" }
    ],
    Memory: [
        { name: "db", synopsis: "db <address> [L<count>]", support: "Stable" },
        { name: "eb", synopsis: "eb <address> <value...>", support: "Stable" }
    ]
} } });
await respond("status", { ok: true, result: { connected: false } });
enter("eb 1000 41");
enter("eb 1000 42");
assert.equal(messages.filter(m => m.method === "classify").length, 1, "Duplicate planning request");
await respond("classify", { ok: true, result: { write: true } });
assert.equal(messages.filter(m => m.method === "previewWrite").length, 1, "A mutation still required a global write switch");
assert.equal(messages.some(m => m.method === "gate" || m.method === "setGate"), false);
assert.equal(nodes.has("gate"), false);
await respond("previewWrite", { ok: false, error: "unreadable" });
nodes.get("modal-confirm").fire("click");
assert.equal(messages.filter(m => m.method === "executePlan").length, 0, "Failed preview could be approved");

enter("eb 1000 41");
await respond("classify", { ok: true, result: { write: true } });
await respond("previewWrite", { ok: true, result: {
    plan: { planId: "server-plan", approvalToken: "server-token" }, preview: "complete bytes"
} });
assert.equal(document.activeElement, nodes.get("modal-cancel"), "Modal initial focus");
documentListeners.get("keydown")({ key: "Tab", preventDefault() {} });
assert.equal(document.activeElement, nodes.get("modal-confirm"), "Modal tab trap");
documentListeners.get("keydown")({ key: "Tab", shiftKey: true, preventDefault() {} });
assert.equal(document.activeElement, nodes.get("modal-cancel"), "Modal reverse tab trap");
nodes.get("prompt").value = "eb 2000 ff";
nodes.get("modal-confirm").fire("click");
nodes.get("modal-confirm").fire("click");
const approved = messages.filter(m => m.method === "executePlan");
assert.equal(approved.length, 1, "Duplicate approval submitted");
assert.equal(approved[0].params.planId, "server-plan");
assert.equal(approved[0].params.approvalToken, "server-token");
assert.equal(approved[0].params.command, undefined, "Approval reused editable command text");
await respond("executePlan", { ok: true, result: { ok: true, output: "AppliedAndVerified" } });

enter("eb 1000 41");
await respond("classify", { ok: true, result: { write: true } });
await respond("previewWrite", { ok: true, result: {
    plan: { planId: "discard-me", approvalToken: "discard-token" }, preview: "complete bytes"
} });
nodes.get("modal-cancel").fire("click");
assert.equal(messages.findLast(m => m.method === "discardPlan").params.planId, "discard-me");
console.log("PASS T-PLAN-UI no global switch, duplicate submission, failed preview, token binding and discard");

const beforeIme = messages.filter(m => m.method === "classify").length;
nodes.get("prompt").fire("compositionstart");
enter("한글 입력");
assert.equal(messages.filter(m => m.method === "classify").length, beforeIme, "IME composition submitted early");
nodes.get("prompt").fire("compositionend");
nodes.get("prompt").fire("keydown", { key: "Enter", keyCode: 229, preventDefault() {} });
assert.equal(messages.filter(m => m.method === "classify").length, beforeIme, "IME keyCode 229 submitted early");
enter("db 1000");
await respond("classify", { ok: true, result: { write: false } });
await respond("execute", { ok: true, result: { ok: true, resultId: "large-result", rowCount: "100000" } });
const firstPage = messages.findLast(m => m.method === "resultPage");
assert.equal(firstPage.params.offset, "0");
const rows = Array.from({ length: 128 }, (_, i) => ({ kind: "Observation", value: i }));
await respond("resultPage", { ok: true, result: { resultId: "large-result", offset: "0", rows } });
assert.equal(nodes.get("result-rows").children.length, 128, "Result table was not virtualized");
assert.equal(nodes.get("result-spacer").style.height, "2800000px");
await respond("outputChunk", { type: "resultChunk", ok: true,
    result: { resultId: "large-result", offset: "0", next: "900000", complete: true, text: "line\n".repeat(100000) } });
assert.ok(nodes.get("output").children.length <= 256, "Console DOM exceeded budget");
assert.ok(nodes.get("output").children.reduce((n, x) => n + (x.innerHTML || "").length, 0) < 263000, "Console text exceeded budget");
nodes.get("result-view").scrollTop = 28000;
nodes.get("result-view").fire("scroll");
assert.equal(messages.findLast(m => m.method === "resultPage").params.offset, "992");
await respond("resultPage", { ok: true, result: { resultId: "large-result", offset: "992", rows: [] } });
console.log("PASS T-UX-01 Korean IME, 100k-row virtualization, bounded console and demand paging");

const sharedStamp = { sessionId: "fixture", targetGeneration: "1", stopEpoch: "2", contextGeneration: "3", symbolGeneration: "4" };
nodes.get("btn-refresh-status").fire("click");
await respond("status", { ok: true, result: { connected: true, stopped: true, target: sharedStamp } });
nodes.get("result-id-input").value = "cli-result";
nodes.get("btn-result-load").fire("click");
await respond("resultInfo", { ok: true, result: { resultId: "cli-result", rowCount: "1", data: { target: sharedStamp } } });
await respond("resultPage", { ok: true, result: { resultId: "cli-result", offset: "0", rows: [
  { addressSpace: "physical", address: "0x1234", rawBytes: "aabb" }
] } });
nodes.get("result-rows").children[0].fire("click");
assert.equal(nodes.get("btn-navigate").disabled, false, "Current scoped address should navigate");
assert.equal(nodes.get("btn-disassemble").disabled, true, "Physical address must not go to virtual disassembly");
nodes.get("btn-refresh-status").fire("click");
await respond("status", { ok: true, result: { connected: true, stopped: true, target: { ...sharedStamp, stopEpoch: "3" } } });
assert.equal(nodes.get("btn-navigate").disabled, true, "Historical result silently rebound to current target");
assert.ok(nodes.get("result-summary").textContent.includes("Historical"));
console.log("PASS T-NAV-UI shared CLI result, address-space routing, historical state and modal focus trap");

enter("eb 1000 41");
await respond("classify", { ok: true, result: { write: true } });
await respond("previewWrite", { ok: true, result: {
    plan: { planId: "chunked-plan", approvalToken: "chunked-token" }, previewResultId: "preview-result"
} });
const beforeIncompletePreview = messages.filter(m => m.method === "executePlan").length;
nodes.get("modal-confirm").fire("click");
assert.equal(messages.filter(m => m.method === "executePlan").length, beforeIncompletePreview, "Incomplete preview approved");
await respond("outputChunk", { ok: true, result: {
    resultId: "preview-result", offset: "0", next: "6", text: "before", complete: false
} });
await respond("outputChunk", { ok: true, result: {
    resultId: "preview-result", offset: "6", next: "11", text: "after", complete: true
} });
await Promise.resolve();
await Promise.resolve();
assert.ok(nodes.get("modal-preview").textContent.includes("beforeafter"), "Plan preview lost a chunk");
nodes.get("modal-cancel").fire("click");
assert.equal(messages.findLast(m => m.method === "discardPlan").params.planId, "chunked-plan");
console.log("PASS T-PLAN-STREAM complete preview required before approval and chunk sequence retained");

async function settle()
{
    for (let i = 0; i < 16; ++i)
    {
        await Promise.resolve();
    }
}
async function deliver(request, response)
{
    receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
        uiGeneration: "7", type: "completed", ...response } });
    await settle();
}
function key(name, extra = {})
{
    return { key: name, preventDefault() {}, ...extra };
}

const paletteClassifications = messages.filter(m => m.method === "classify").length;
nodes.get("btn-palette").fire("click");
assert.equal(nodes.get("root").inert, true);
nodes.get("palette-input").value = "reg";
nodes.get("palette-input").fire("input");
assert.equal(nodes.get("palette-results").children.length, 1);
nodes.get("palette-input").fire("keydown", key("Enter"));
assert.equal(nodes.get("prompt").value, "registers");
assert.equal(document.activeElement, nodes.get("prompt"));
assert.equal(nodes.get("root").inert, false);
assert.equal(messages.filter(m => m.method === "classify").length, paletteClassifications, "Palette executed instead of drafting");
assert.equal(nodes.get("btn-run").disabled, false);
assert.ok(nodes.get("command-hint").textContent.includes("registers [name]"));
nodes.get("btn-palette").fire("click");
nodes.get("palette-input").value = "eb";
nodes.get("palette-input").fire("input");
nodes.get("palette-input").fire("compositionstart");
nodes.get("palette-input").fire("keydown", key("Enter"));
assert.equal(nodes.get("root").inert, true, "Palette IME committed a selection early");
nodes.get("palette-input").fire("compositionend");
nodes.get("palette-input").value = "no-such-command-xyz";
nodes.get("palette-input").fire("input");
nodes.get("palette-input").fire("keydown", key("ArrowDown"));
nodes.get("palette-input").fire("keydown", key("Enter"));
assert.equal(nodes.get("root").inert, true, "Empty search accepted an obsolete selection");
assert.equal(nodes.get("palette-input").getAttribute("aria-activedescendant"), "");
documentListeners.get("keydown")(key("Tab"));
assert.equal(document.activeElement, nodes.get("palette-close"));
documentListeners.get("keydown")(key("Escape"));
assert.equal(nodes.get("root").inert, false);
assert.equal(document.activeElement, nodes.get("prompt"));
nodes.get("prompt").value = "";
let trapped = false;
nodes.get("prompt").fire("keydown", key("Tab", { preventDefault() { trapped = true; } }));
assert.equal(trapped, false, "Empty prompt trapped keyboard focus");
nodes.get("prompt").value = "reg";
nodes.get("prompt").fire("keydown", key("Tab", { shiftKey: true, preventDefault() { trapped = true; } }));
assert.equal(trapped, false, "Shift+Tab could not leave command input");
enter(":clear");
assert.equal(nodes.get("btn-run").disabled, true, "Run remained enabled for an empty local command");
nodes.get("btn-console").fire("click");
assert.equal(nodes.get("btn-console").getAttribute("aria-expanded"), "true");
documentListeners.get("keydown")(key("j", { ctrlKey: true }));
assert.equal(nodes.get("btn-console").getAttribute("aria-expanded"), "false");
nodes.get("btn-sidebar").fire("click");
assert.equal(nodes.get("btn-sidebar").getAttribute("aria-expanded"), "true");
assert.equal(document.activeElement, nodes.get("filter"));
nodes.get("btn-sidebar").fire("click");
assert.equal(nodes.get("btn-sidebar").getAttribute("aria-expanded"), "false");
nodes.get("btn-sidebar").fire("click");
assert.equal(document.activeElement, nodes.get("filter"));
nodes.get("filter").value = "registers";
nodes.get("filter").fire("input");
assert.equal(nodes.get("catalog-count").textContent, "1 / 4");
assert.equal(nodes.get("catalog").children.length, 2, "Empty command groups remained visible");
console.log("PASS T-UX-PALETTE draft-only search, IME, no matches, focus restoration, tab escape, pane controls and filtering");

nodes.get("result-id-input").value = "older-open";
nodes.get("btn-result-load").fire("click");
const olderOpen = messages.findLast(m => m.method === "resultInfo");
nodes.get("result-id-input").value = "newer-open";
nodes.get("btn-result-load").fire("click");
const newerOpen = messages.findLast(m => m.method === "resultInfo");
const currentStamp = { ...sharedStamp, stopEpoch: "3" };
await deliver(newerOpen, { ok: true, result: { resultId: "newer-open", rowCount: "0", data: { status: "Success", target: currentStamp, coverage: { complete: true } } } });
await deliver(olderOpen, { ok: true, result: { resultId: "older-open", rowCount: "0" } });
assert.equal(nodes.get("result-history").value, "newer-open", "Older resultInfo response replaced current choice");
assert.equal(nodes.get("result-notice").classList.contains("hidden"), true, "Successful results were marked incomplete");
nodes.get("result-id-input").value = "late-open";
nodes.get("btn-result-load").fire("click");
const lateOpen = messages.findLast(m => m.method === "resultInfo");
enter("stack");
await deliver(lateOpen, { ok: true, result: { resultId: "late-open", rowCount: "0" } });
assert.equal(nodes.get("result-history").value, "newer-open", "Old retrieval overtook a new command");
await respond("classify", { ok: true, result: { write: false } });
await respond("execute", { ok: true, result: { ok: true, command: "stack", output: "done" } });
await settle();
for (let i = 0; i < 20; ++i)
{
    nodes.get("result-id-input").value = "retained-" + i;
    nodes.get("btn-result-load").fire("click");
    await respond("resultInfo", { ok: true, result: { resultId: "retained-" + i, rowCount: "0" } });
}
assert.equal(nodes.get("result-history").children.length, 17, "UI result history exceeded host retention size");
nodes.get("result-history").value = "expired-id";
nodes.get("result-history").fire("change");
await respond("resultInfo", { ok: false, error: "expired" });
assert.equal(nodes.get("result-history").value, "retained-19");
assert.ok(nodes.get("result-load-status").textContent.includes("expired"));
assert.ok(nodes.get("result-notice-text").textContent.includes("previous selection"), "History failure was hidden in a closed popover");
console.log("PASS T-UX-HISTORY response ordering, command supersession, success status, bounded retention and expiry");

nodes.get("result-id-input").value = "byte-bounded";
nodes.get("btn-result-load").fire("click");
await respond("resultInfo", { ok: true, result: { resultId: "byte-bounded", rowCount: "2", data: { status: "Partial", target: currentStamp, coverage: { complete: false } } } });
const scopedRows = [
    { kind: "StackFrame", addressSpace: "virtual", address: "0xffff800012345678", name: "<img src=x>", sourceFile: null },
    { kind: "Register", name: "rax", value: "0xffff800012345679", unavailable: null }
];
await respond("resultPage", { ok: true, result: { resultId: "byte-bounded", offset: "0", rows: [scopedRows[0]], complete: false } });
await settle();
assert.equal(messages.findLast(m => m.method === "resultPage").params.offset, "1", "Byte-limited pages were not filled");
await respond("resultPage", { ok: true, result: { resultId: "byte-bounded", offset: "1", rows: [scopedRows[1]], complete: true } });
await settle();
assert.equal(nodes.get("result-rows").children.length, 2);
assert.ok(nodes.get("result-notice-text").textContent.includes("Partial"));
nodes.get("result-table").fire("keydown", key("ArrowDown"));
assert.equal(nodes.get("result-rows").children[0].getAttribute("aria-selected"), "true");
const scopedHeaders = nodes.get("table-head").children.map(node => node.children[0]?.textContent || node.textContent);
assert.equal(nodes.get("result-rows").children[0].children[scopedHeaders.indexOf("Address")].textContent, scopedRows[0].address, "64-bit address lost precision");
assert.equal(nodes.get("result-rows").children[0].children[scopedHeaders.indexOf("Name")].textContent, "<img src=x>");
assert.equal(nodes.get("btn-source").disabled, true, "Null source enabled navigation");
nodes.get("result-table").fire("keydown", key("ArrowDown"));
assert.ok(nodes.get("row-position").textContent.includes("2 of 2"));
assert.ok(nodes.get("detail-fields").children.some(n => n.textContent === "Unavailable"));
nodes.get("result-table").fire("keydown", key("Home"));
assert.equal(nodes.get("btn-navigate").disabled, false);
nodes.get("btn-refresh-status").fire("click");
await respond("status", { ok: true, result: { connected: false } });
assert.equal(nodes.get("btn-navigate").disabled, true, "Results from a disconnected target remained navigable");
console.log("PASS T-UX-ROWS byte-limited pages, keyboard selection, exact addresses, literal text, null fields and disconnected target");

nodes.get("result-id-input").value = "same-id";
nodes.get("btn-result-load").fire("click");
await respond("resultInfo", { ok: true, result: { resultId: "same-id", rowCount: "1" } });
const stalePage = messages.findLast(m => m.method === "resultPage");
nodes.get("btn-result-load").fire("click");
await respond("resultInfo", { ok: true, result: { resultId: "same-id", rowCount: "1" } });
await deliver(stalePage, { ok: true, result: { resultId: "same-id", offset: "0", rows: [{ kind: "OldRow" }] } });
assert.equal(nodes.get("result-rows").children.length, 0, "Same-ID stale page reached a new result revision");
await respond("resultPage", { ok: false, error: "expired" });
await settle();
assert.ok(nodes.get("result-notice-text").textContent.includes("Rows unavailable"));
nodes.get("btn-refresh-status").fire("click");
await respond("status", { ok: false });
assert.ok(nodes.get("result-notice-text").textContent.includes("Rows unavailable"), "Status refresh hid a row-load failure");
console.log("PASS T-UX-RACES same-ID reopen invalidates pending pages and row errors survive status refresh");

nodes.get("result-id-input").value = "keyboard-race";
nodes.get("btn-result-load").fire("click");
await respond("resultInfo", { ok: true, result: { resultId: "keyboard-race", rowCount: "1000" } });
await respond("resultPage", { ok: true, result: { resultId: "keyboard-race", offset: "0", rows } });
await settle();
nodes.get("result-table").fire("keydown", key("End"));
const pendingEndPage = messages.findLast(m => m.method === "resultPage");
nodes.get("result-table").fire("keydown", key("Home"));
assert.equal(nodes.get("result-detail").textContent, JSON.stringify(rows[0], null, 2), "Pending navigation changed cache addressing");
await deliver(pendingEndPage, { ok: true, result: { resultId: "keyboard-race", offset: pendingEndPage.params.offset, complete: true,
    rows: Array.from({ length: 1000 - Number(pendingEndPage.params.offset) }, () => ({ kind: "EndRow" })) } });
assert.ok(nodes.get("row-position").textContent.includes("Row 1 of"), "Late End response overrode a later Home selection");
const backToTop = messages.findLast(m => m.method === "resultPage");
assert.equal(backToTop.params.offset, "0", "Fast navigation failed to refill the visible viewport");
await deliver(backToTop, { ok: true, result: { resultId: "keyboard-race", offset: "0", rows } });
assert.equal(nodes.get("result-table").getAttribute("aria-busy"), "false");
assert.equal(nodes.get("result-rows").children[0].getAttribute("aria-selected"), "true");
console.log("PASS T-UX-KEYBOARD rapid End/Home preserves row identity, selection and viewport ordering");

nodes.get("btn-refresh-status").fire("click");
await respond("status", { ok: true, result: { connected: true, stopped: true, target: currentStamp } });
const hostCommand = '.echo first; .printf "value:%d", 0n42';
nodes.get("prompt").value = hostCommand;
nodes.get("prompt").fire("input");
assert.ok(nodes.get("command-hint").textContent.includes("WinDbg"));
const previewsBeforeHost = messages.filter(m => m.method === "previewWrite").length;
enter(hostCommand);
await respond("classify", { ok: true, result: { write: false, opaque: true, canonical: "windbg" } });
assert.equal(messages.findLast(m => m.method === "execute").params.command, hostCommand, "Host command syntax changed before execution");
assert.equal(messages.filter(m => m.method === "previewWrite").length, previewsBeforeHost, "Host input incorrectly required a write plan");
await respond("execute", { ok: true, result: { ok: true, command: hostCommand, resultId: "host-output", rowCount: "0", outputLength: "15",
    data: { commandId: "windbg", status: "Success", provenance: { source: "windbg", consistency: "UnverifiedEffects" } } } });
await respond("outputChunk", { ok: true, type: "resultChunk", result: {
    resultId: "host-output", offset: "0", next: "15", complete: true, text: "first\nvalue:42\n"
} });
await settle();
assert.ok(nodes.get("output").children.some(n => (n.innerHTML || "").includes("value:42")), "WinDbg output was not shown");
enter(".not-a-windbg-command");
await respond("classify", { ok: true, result: { write: false, opaque: true, canonical: "windbg" } });
const hostExecutions = messages.filter(m => m.method === "execute").length;
await respond("execute", { ok: true, result: { ok: false, error: "WinDbg command failed; see debugger output", output: "Syntax error" } });
await settle();
assert.ok(nodes.get("output").children.some(n => (n.innerHTML || "").includes("WinDbg command failed")), "WinDbg failure was hidden");
assert.equal(messages.filter(m => m.method === "execute").length, hostExecutions, "Failed WinDbg command was replayed");
console.log("PASS T-UX-WINDBG unknown commands, unchanged syntax, output and error delivery without replay");
