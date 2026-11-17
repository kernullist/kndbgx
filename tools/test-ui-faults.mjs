import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const script = fs.readFileSync(new URL("../ui/app.js", import.meta.url), "utf8");
const html = fs.readFileSync(new URL("../ui/index.html", import.meta.url), "utf8");
const stamp = { sessionId: "fault-fixture", targetGeneration: "1", stopEpoch: "2", contextGeneration: "3", symbolGeneration: "4" };
const unhandled = [];
process.on("unhandledRejection", error => unhandled.push(error));
let failures = 0;

function noop()
{
}

async function settle()
{
    await new Promise(resolve => setImmediate(resolve));
}

function harness(options = {})
{
    const nodes = new Map();
    const messages = [];
    const timers = new Map();
    const timerDelays = new Map();
    const timerDeadlines = new Map();
    const documentListeners = new Map();
    const windowListeners = new Map();
    let timerId = 0;
    let clock = 0;
    let receive;
    let onPost = request =>
    {
        if (options.breakpointAuto !== false && request.method === "execute" && request.params.command === "breakpoints")
        {
            queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                uiGeneration: "7", type: "completed", ok: true, result: { ok: true, resultId: "empty-breakpoints",
                    rowCount: "0", data: { commandId: "breakpoints", status: "Success", target: stamp } } } }));
        }
    };
    const makeNode = () =>
    {
        const listeners = new Map();
        const attributes = new Map();
        const element = {
            value: "", children: [], style: {}, dataset: {}, className: "", checked: false,
            scrollTop: 0, scrollLeft: 0, scrollHeight: 0, clientHeight: 400,
            get textContent()
            {
                return this._text || "";
            },
            set textContent(value)
            {
                this._text = value;
                this.children = [];
            },
            addEventListener(name, callback)
            {
                const handlers = listeners.get(name) || [];
                handlers.push(callback);
                listeners.set(name, handlers);
            },
            fire(name, event = {})
            {
                for (const callback of listeners.get(name) || [])
                {
                    callback({ target: this, preventDefault: noop, stopPropagation: noop, ...event });
                }
            },
            appendChild(child)
            {
                this.children.push(child);
            },
            removeChild(child)
            {
                this.children.splice(this.children.indexOf(child), 1);
            },
            insertBefore(child, before)
            {
                const previous = this.children.indexOf(child);
                if (previous >= 0)
                {
                    this.children.splice(previous, 1);
                }
                const index = before === null ? this.children.length : this.children.indexOf(before);
                assert.ok(index >= 0, "Missing insertion anchor");
                this.children.splice(index, 0, child);
            },
            contains(child)
            {
                return child === this || this.children.some(item => item.contains(child));
            },
            querySelectorAll(selector)
            {
                return this.children.flatMap(child => [
                    ...(child.classList.contains(selector.slice(1)) ? [child] : []), ...child.querySelectorAll(selector)
                ]);
            },
            focus()
            {
                document.activeElement = this;
            },
            select()
            {
                this.selectedText = this.value;
            },
            setSelectionRange(start, end)
            {
                this.selectionStart = start;
                this.selectionEnd = end;
            },
            scrollIntoView: noop,
            getBoundingClientRect()
            {
                return { left: 10, top: 20, right: 210, bottom: 48 };
            },
            setAttribute(name, value)
            {
                attributes.set(name, String(value));
            },
            getAttribute(name)
            {
                return attributes.get(name) ?? null;
            }
        };
        element.classList = {
            contains(value)
            {
                return element.className.split(/\s+/).includes(value);
            },
            add(value)
            {
                if (!this.contains(value))
                {
                    element.className += " " + value;
                }
            },
            remove(value)
            {
                element.className = element.className.split(/\s+/).filter(item => item !== value).join(" ");
            }
        };
        return element;
    };
    for (const match of html.matchAll(/<[^>]+\bid="([^"]+)"[^>]*>/g))
    {
        const element = makeNode();
        element.id = match[1];
        element.className = /\bclass="([^"]*)"/.exec(match[0])?.[1] || "";
        nodes.set(match[1], element);
    }
    nodes.get("memory").children.push(nodes.get("processes"));
    nodes.get("processes").children.push(nodes.get("process-filter"), nodes.get("process-grid"), nodes.get("process-inspector"));
    nodes.get("process-grid").children.push(nodes.get("process-rows"));
    nodes.get("process-inspector").children.push(nodes.get("process-fields"), nodes.get("btn-process-attach"));
    nodes.get("result-tab-menu").children.push(nodes.get("result-tab-close-current"),
        nodes.get("result-tab-close-others"), nodes.get("result-tab-close-all"));
    const document = {
        hidden: false,
        getElementById(id)
        {
            return nodes.get(id);
        },
        createElement: makeNode,
        addEventListener(name, callback)
        {
            documentListeners.set(name, callback);
        }
    };
    const window = {
        innerWidth: 900, innerHeight: 720,
        chrome: { webview: {
            addEventListener(name, callback)
            {
                receive = callback;
            },
            postMessage(request)
            {
                messages.push(request);
                if (request.method === "resultTabs" && options.retentionAuto !== false)
                {
                    queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                        uiGeneration: "7", type: "completed", ok: true, result: { missing: [] } } }));
                }
                else
                {
                    onPost(request);
                }
            }
        } },
        addEventListener(name, callback)
        {
            const callbacks = windowListeners.get(name) || [];
            callbacks.push(callback);
            windowListeners.set(name, callbacks);
        },
        localStorage: options.storage,
        getSelection: () => options.selection || ""
    };
    vm.runInNewContext(script, {
        document, window, console, navigator: { clipboard: options.clipboard },
        performance: { now: () => clock },
        setTimeout(callback, delay)
        {
            timers.set(++timerId, callback);
            timerDelays.set(timerId, delay);
            timerDeadlines.set(timerId, clock + delay);
            return timerId;
        },
        clearTimeout(id)
        {
            timers.delete(id);
            timerDelays.delete(id);
            timerDeadlines.delete(id);
        }
    });
    const latest = method => messages.findLast(message => message.method === method);
    const deliver = async (request, response) =>
    {
        assert.ok(request, "Expected RPC request");
        receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId, uiGeneration: "7", type: "completed", ...response } });
        await settle();
    };
    return {
        nodes, messages, timers, timerDelays, latest, deliver, documentListeners,
        visibility(hidden)
        {
            document.hidden = hidden;
            documentListeners.get("visibilitychange")?.();
        },
        advanceTime(milliseconds)
        {
            const until = clock + milliseconds;
            for (;;)
            {
                const due = [...timerDeadlines].filter(([id, deadline]) => timers.has(id) && deadline <= until)
                    .sort((left, right) => left[1] - right[1])[0];
                if (!due)
                {
                    break;
                }
                const [id, deadline] = due;
                clock = deadline;
                const callback = timers.get(id);
                timers.delete(id);
                timerDelays.delete(id);
                timerDeadlines.delete(id);
                callback();
            }
            clock = until;
        },
        windowEvent(name, event = {})
        {
            for (const callback of windowListeners.get(name) || [])
            {
                callback(event);
            }
        },
        tickActivity(milliseconds)
        {
            clock += milliseconds;
            for (const [id, callback] of [...timers])
            {
                if (timerDelays.get(id) === 250)
                {
                    timers.delete(id);
                    timerDelays.delete(id);
                    callback();
                }
            }
        },
        focused()
        {
            return document.activeElement;
        },
        onPost(callback)
        {
            onPost = callback;
        },
        reply(method, response)
        {
            return deliver(latest(method), response);
        },
        enter(command)
        {
            nodes.get("prompt").value = command;
            nodes.get("prompt").fire("keydown", { key: "Enter" });
        },
        async boot(groups = {})
        {
            await this.reply("hello", { ok: true, result: { target: stamp } });
            await this.reply("catalog", { ok: true, result: { groups } });
            await this.reply("status", { ok: true, result: { connected: true, stopped: true, target: stamp } });
        }
    };
}

async function check(name, test)
{
    try
    {
        await test();
        console.log("PASS " + name);
    }
    catch (error)
    {
        ++failures;
        console.error("FAIL " + name + ": " + error.message);
    }
}

function assertCommandActivity(app, active, phase)
{
    assert.equal(app.nodes.get("command-area").classList.contains("is-busy"), active);
    assert.equal(app.nodes.get("command-progress").classList.contains("hidden"), !active);
    assert.equal(app.nodes.get("prompt").getAttribute("aria-describedby"), active ? "command-progress" : "command-hint");
    assert.equal([...app.timers.keys()].filter(id => app.timerDelays.get(id) === 250).length, active ? 1 : 0,
        "Activity must own exactly one timer while busy and none after completion");
    if (phase)
    {
        assert.equal(app.nodes.get("command-phase").textContent, phase);
    }
}

await check("T-UI-ACTIVITY prompt tracks the whole command and resets for the next command", async () =>
{
    const app = harness();
    await app.boot();
    assertCommandActivity(app, false);
    app.enter("stack");
    assertCommandActivity(app, true, "Preparing");
    assert.equal(app.nodes.get("command-elapsed").textContent, "0.0s");
    app.tickActivity(1250);
    assert.equal(app.nodes.get("command-elapsed").textContent, "1.2s");
    await app.reply("classify", { ok: true, result: { write: false } });
    assertCommandActivity(app, true, "Queued");
    await app.reply("execute", { type: "progress", ok: true });
    assertCommandActivity(app, true, "Running");
    app.tickActivity(2250);
    assert.equal(app.nodes.get("command-elapsed").textContent, "3.5s");
    app.nodes.get("prompt").value = "next draft";
    app.nodes.get("prompt").fire("input");
    await app.reply("execute", { ok: true, result: { resultId: "activity-output", rowCount: "0", data: { target: stamp } } });
    assertCommandActivity(app, true, "Receiving output");
    await app.reply("outputChunk", { ok: true, result: { resultId: "activity-output", offset: "0", next: "4", complete: true, text: "done" } });
    assertCommandActivity(app, false);
    assert.equal(app.nodes.get("prompt").value, "next draft", "Progress must not overwrite a draft");
    app.tickActivity(60000);
    app.enter("stack");
    assertCommandActivity(app, true, "Preparing");
    assert.equal(app.nodes.get("command-elapsed").textContent, "0.0s");
    await app.reply("classify", { ok: false, error: "UnknownCommand" });
    assertCommandActivity(app, false);
});

await check("T-UI-HISTORY toolbar eviction preserves the original draft and traversal", async () =>
{
    const app = harness();
    await app.boot({ Debugger: [
        { name: "irp", grammar: "irp <hex-address>", synopsis: "Inspect an IRP", support: "Experimental" }
    ] });
    const prompt = app.nodes.get("prompt");
    for (let index = 0; index < 200; ++index)
    {
        app.enter(".echo history " + index);
        assert.equal(app.latest("classify").params.command, ".echo history " + index);
        await app.reply("classify", { ok: false, error: "FixtureCommandRejected" });
        await app.reply("status", { ok: true, result: { connected: true, stopped: true, target: stamp } });
    }
    prompt.focus();
    prompt.value = "irp";
    prompt.setSelectionRange(3, 3);
    prompt.fire("input");
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.value, "irp <hex-address>");
    prompt.fire("keydown", { key: "Escape" });
    for (let index = 0; index < 200; ++index)
    {
        prompt.fire("keydown", { key: "ArrowUp" });
    }
    assert.equal(prompt.value, ".echo history 0");
    for (const view of ["stack", "event"])
    {
        app.nodes.get("btn-" + view).fire("click");
        await app.reply("classify", { ok: false, error: "FixtureCommandRejected" });
        await app.reply("status", { ok: true, result: { connected: true, stopped: true, target: stamp } });
        assert.equal(prompt.value, ".echo history 0");
    }
    const requests = app.messages.length;
    prompt.fire("keydown", { key: "ArrowUp" });
    assert.equal(prompt.value, ".echo history 0", "Up at the evicted oldest entry must not move forward");
    prompt.fire("keydown", { key: "ArrowDown" });
    assert.equal(prompt.value, ".echo history 2", "Evicting the recalled entry stranded history navigation");
    for (let index = 0; index < 200; ++index)
    {
        prompt.fire("keydown", { key: "ArrowDown" });
    }
    assert.equal(prompt.value, "irp <hex-address>", "Eviction replaced the original draft with a recalled command");
    assert.equal(app.nodes.get("btn-run").disabled, true);
    prompt.fire("keydown", { key: "Enter" });
    assert.equal(app.messages.length, requests, "Restored placeholders must not execute");
});

await check("T-UI-ACTIVITY cancellation remains visible until confirmed even after status recovery", async () =>
{
    const app = harness();
    await app.boot();
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    const execution = app.latest("execute");
    app.nodes.get("btn-cancel").fire("click");
    assertCommandActivity(app, true, "Cancelling");
    await app.reply("interrupt", { ok: true, result: { requested: true } });
    await app.reply("operationStatus", { ok: true, result: { phase: "Running" } });
    await app.deliver(execution, { type: "progress", ok: true });
    assertCommandActivity(app, true, "Cancelling");
    app.tickActivity(2750);
    assert.equal(app.nodes.get("command-elapsed").textContent, "2.7s");
    await app.deliver(execution, { ok: false, error: "Cancelled" });
    assertCommandActivity(app, false);
});

await check("T-UI-ACTIVITY approval is visibly waiting and cancellation releases its timer", async () =>
{
    for (const confirm of [false, true])
    {
        const app = harness();
        await app.boot();
        app.enter("eb 1000 41");
        await app.reply("classify", { ok: true, result: { write: true } });
        await app.reply("previewWrite", { ok: true, result: {
            plan: { planId: "plan", approvalToken: "token" }, preview: "complete preview"
        } });
        assertCommandActivity(app, true, "Awaiting approval");
        assert.equal(app.nodes.get("command-area").classList.contains("awaiting-approval"), true);
        app.tickActivity(3500);
        app.nodes.get(confirm ? "modal-confirm" : "modal-cancel").fire("click");
        assert.equal(app.nodes.get("command-area").classList.contains("awaiting-approval"), false);
        if (confirm)
        {
            assertCommandActivity(app, true, "Queued");
            assert.equal(app.nodes.get("command-elapsed").textContent, "3.5s");
            await app.reply("executePlan", { ok: false, error: "StalePlan" });
        }
        assertCommandActivity(app, false);
    }
});

await check("T-UI-ACTIVITY Stop before preview acceptance waits for the original request to end", async () =>
{
    const app = harness();
    await app.boot();
    app.enter("eb 1000 41");
    await app.reply("classify", { ok: true, result: { write: true } });
    const preview = app.latest("previewWrite");
    const classifications = app.messages.filter(item => item.method === "classify").length;
    app.nodes.get("btn-cancel").fire("click");
    assertCommandActivity(app, true, "Cancelling");
    assert.equal(app.latest("interrupt").params.requestId, preview.requestId);
    app.enter("stack");
    assert.equal(app.messages.filter(item => item.method === "classify").length, classifications);
    await app.deliver(preview, { type: "accepted", ok: true });
    assertCommandActivity(app, true, "Cancelling");
    await app.deliver(preview, { ok: true, result: { plan: { planId: "abandoned", approvalToken: "token" }, preview: "bytes" } });
    assert.equal(app.latest("discardPlan").params.planId, "abandoned");
    assert.equal(app.latest("executePlan"), undefined);
    assertCommandActivity(app, false);
});

await check("T-UI-ACTIVITY unconfirmed preview cancellation never reopens an approval", async () =>
{
    for (const receivingPreview of [false, true])
    {
        const app = harness();
        await app.boot();
        app.enter("eb 1000 41");
        await app.reply("classify", { ok: true, result: { write: true } });
        await app.reply("previewWrite", { type: "progress", ok: true });
        const result = { plan: { planId: "cancelled-preview", approvalToken: "token" },
            previewResultId: "preview-text" };
        if (receivingPreview)
        {
            await app.reply("previewWrite", { ok: true, result });
        }
        app.nodes.get("btn-cancel").fire("click");
        await app.reply("interrupt", { ok: true, result: { requested: false } });
        if (!receivingPreview)
        {
            await app.reply("operationStatus", { ok: true, result: { phase: "Running" } });
            await app.reply("previewWrite", { ok: true, result });
        }
        if (app.latest("outputChunk"))
        {
            await app.reply("outputChunk", { ok: true, result: {
                resultId: "preview-text", offset: "0", next: "5", complete: true, text: "bytes"
            } });
        }
        assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), true,
            "A cancelled preview opened an approval after its cancellation was not confirmed");
        assert.equal(app.latest("discardPlan").params.planId, "cancelled-preview");
        assertCommandActivity(app, false);
        app.enter("eb 1000 42");
        await app.reply("classify", { ok: true, result: { write: true } });
        await app.reply("previewWrite", { ok: true, result: {
            plan: { planId: "new-preview", approvalToken: "new-token" }, preview: "new bytes"
        } });
        assertCommandActivity(app, true, "Awaiting approval");
        app.nodes.get("modal-cancel").fire("click");
        assertCommandActivity(app, false);
    }
});

await check("T-UI-ACTIVITY stopped output stays cancelling without interrupting a completed engine request", async () =>
{
    const app = harness();
    await app.boot();
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    await app.reply("execute", { ok: true, result: { resultId: "stop-output", rowCount: "0" } });
    app.nodes.get("btn-cancel").fire("click");
    assertCommandActivity(app, true, "Cancelling");
    app.nodes.get("btn-cancel").fire("click");
    assert.equal(app.latest("interrupt"), undefined);
    await app.reply("outputChunk", { ok: true, result: { resultId: "stop-output", offset: "0", next: "4", complete: false, text: "late" } });
    assertCommandActivity(app, false);
    assert.equal(app.messages.filter(item => item.method === "outputChunk").length, 1);
});

await check("T-UI-ACTIVITY a late cancellation reply cannot annotate or query the next command", async () =>
{
    const app = harness();
    await app.boot();
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    app.nodes.get("btn-cancel").fire("click");
    const interrupt = app.latest("interrupt");
    await app.reply("execute", { ok: false, error: "Cancelled" });
    app.enter("registers");
    await app.reply("classify", { ok: true, result: { write: false } });
    const queries = app.messages.filter(item => item.method === "operationStatus").length;
    const output = app.nodes.get("output").children.length;
    await app.deliver(interrupt, { ok: true, result: { requested: true } });
    assert.equal(app.messages.filter(item => item.method === "operationStatus").length, queries,
        "An old cancellation queried the new request");
    assert.equal(app.nodes.get("output").children.length, output, "An old cancellation wrote into the new command output");
    assertCommandActivity(app, true, "Queued");
    await app.reply("execute", { ok: true, result: { output: "done" } });
    assertCommandActivity(app, false);
});

await check("T-UI-ACTIVITY unconfirmed cancellation stays active and can be retried", async () =>
{
    for (const response of [{ ok: false, error: "Bridge send failed" }, { ok: true, result: { requested: false } },
        { ok: true, result: null }])
    {
        const app = harness();
        await app.boot();
        app.enter("stack");
        await app.reply("classify", { ok: true, result: { write: false } });
        app.nodes.get("btn-cancel").fire("click");
        await app.reply("interrupt", response);
        assertCommandActivity(app, true, "Cancellation unconfirmed");
        await app.reply("operationStatus", { ok: true, result: { phase: "Running" } });
        assertCommandActivity(app, true, "Running");
        app.nodes.get("btn-cancel").fire("click");
        assert.equal(app.messages.filter(item => item.method === "interrupt").length, 2);
        await app.reply("interrupt", { ok: true, result: { requested: true } });
        assertCommandActivity(app, true, "Cancelling");
        await app.reply("execute", { ok: false, error: "Cancelled" });
        assertCommandActivity(app, false);
    }
});

for (const scenario of [
    { command: "!threads", visited: "32", read: "31",
        row: { kind: "Thread", tid: "12", ethread: "0xffff800000001000" } },
    { command: "!vad", visited: "30", read: "29",
        row: { kind: "Vad", start: "0x10000", end: "0x1ffff", pageProtection: "0x4" } },
    { command: "!token", visited: "31", read: "30",
        row: { kind: "ProcessToken", address: "0xffff800000003000", tokenTypeName: "Primary" } }
])
{
    for (const previousCollection of ["rows", "findings"])
    {
        await check("T-UI-CANCEL " + scenario.command + " selection clears prior " + previousCollection + " and the next command completes", async () =>
        {
            const app = harness();
            await app.boot();
            app.nodes.get("result-id-input").value = "previous-result";
            app.nodes.get("btn-result-load").fire("click");
            await app.reply("resultInfo", { ok: true, result: { resultId: "previous-result", rowCount: "1", findingCount: "1",
                data: { commandId: scenario.command, status: "Success", target: stamp } } });
            await app.reply("resultPage", { ok: true, result: { resultId: "previous-result", offset: "0", next: "1",
                complete: true, rows: [scenario.row] } });
            if (previousCollection === "findings")
            {
                app.nodes.get("result-collection").value = "findings";
                app.nodes.get("result-collection").fire("change");
                assert.equal(app.latest("resultPage").params.collection, "findings");
                await app.reply("resultPage", { ok: true, result: { resultId: "previous-result", collection: "findings",
                    offset: "0", next: "1", complete: true,
                    findings: [{ ruleId: "fixture/previous", severity: "warning", message: "Previous finding" }] } });
            }
            app.nodes.get("result-rows").children[0].fire("click");
            assert.ok(app.nodes.get("result-detail").textContent.includes(
                previousCollection === "rows" ? scenario.row.kind : "Previous finding"));
            assert.equal(app.nodes.get("result-count").textContent, "1 rows / 1 findings");

            app.enter(scenario.command + " pid:4");
            await app.reply("classify", { ok: true, result: { write: false } });
            const cancelledExecution = app.latest("execute");
            assert.equal(cancelledExecution.params.command, scenario.command + " pid:4");
            await app.deliver(cancelledExecution, { type: "progress", ok: true });
            app.nodes.get("prompt").value = "!dml_proc pid:4";
            app.nodes.get("prompt").fire("input");
            app.nodes.get("btn-cancel").fire("click");
            const interrupt = app.latest("interrupt");
            assert.equal(interrupt.params.requestId, cancelledExecution.requestId);
            assertCommandActivity(app, true, "Cancelling");
            const pagesBeforeCancellation = app.messages.filter(item => item.method === "resultPage").length;
            await app.deliver(cancelledExecution, { ok: true, result: {
                ok: false, error: "Cancelled", resultId: "cancelled-selection", rowCount: "0", findingCount: "0",
                data: { commandId: scenario.command, status: "Cancelled", target: stamp,
                    coverage: { visitedEntries: scenario.visited, readEntries: scenario.read, decodedEntries: scenario.read,
                        complete: false, stopReason: "Cancelled" },
                    provenance: { source: "TargetMemory:PsActiveProcessHead", consistency: "stopped" },
                    limitations: ["Process selection did not complete; requested records were not collected."] }
            } });
            const cancelledOutput = "[proc.coverage] Cancelled\n";
            await app.reply("outputChunk", { ok: true, result: {
                resultId: "cancelled-selection", offset: "0", next: String(cancelledOutput.length), complete: true, text: cancelledOutput
            } });
            assertCommandActivity(app, false);
            assert.equal(app.nodes.get("activity").textContent, "Idle");
            assert.equal(app.nodes.get("btn-cancel").disabled, true);
            assert.equal(app.nodes.get("result-rows").children.length, 0);
            assert.equal(app.nodes.get("result-detail").textContent, "");
            assert.equal(app.nodes.get("result-count").textContent, "0 rows / 0 findings");
            assert.equal(app.nodes.get("result-title").textContent, scenario.command);
            assert.equal(app.nodes.get("result-summary").textContent, "Debug target / Cancelled / Current context");
            assert.equal(app.nodes.get("empty-title").textContent, "Cancelled");
            assert.equal(app.nodes.get("result-collection").value, "rows");
            assert.equal(app.messages.filter(item => item.method === "resultPage").length, pagesBeforeCancellation,
                "A zero-record cancellation must not request a result page");
            const facts = app.nodes.get("result-facts").children.map(node => node.textContent).join("\n");
            assert.ok(facts.includes(scenario.visited + " visited / " + scenario.read + " read / " + scenario.read + " decoded"));
            assert.match(facts, /TargetMemory:PsActiveProcessHead/);
            assert.match(facts, /Process selection did not complete/);
            assert.equal(app.nodes.get("prompt").value, "!dml_proc pid:4");

            app.nodes.get("prompt").fire("keydown", { key: "Enter" });
            await app.reply("classify", { ok: true, result: { write: false } });
            const nextExecution = app.latest("execute");
            assert.notEqual(nextExecution.requestId, cancelledExecution.requestId);
            assert.equal(nextExecution.params.command, "!dml_proc pid:4");
            const queries = app.messages.filter(item => item.method === "operationStatus").length;
            const outputBeforeLateReply = app.nodes.get("output").children.length;
            await app.deliver(interrupt, { ok: true, result: { requested: true } });
            assert.equal(app.messages.filter(item => item.method === "operationStatus").length, queries);
            assert.equal(app.nodes.get("output").children.length, outputBeforeLateReply);
            assertCommandActivity(app, true, "Queued");
            await app.deliver(nextExecution, { ok: true, result: {
                ok: true, resultId: "selected-system", rowCount: "1", findingCount: "0",
                data: { commandId: "!dml_proc", status: "Success", target: stamp,
                    coverage: { visitedEntries: "137", readEntries: "137", decodedEntries: "137", complete: true,
                        stopReason: "EndOfDeclaredWalk" } }
            } });
            assert.equal(app.latest("resultPage").params.resultId, "selected-system");
            assert.equal(app.latest("resultPage").params.collection, "rows");
            await app.reply("resultPage", { ok: true, result: { resultId: "selected-system", offset: "0", next: "1",
                complete: true, rows: [{ kind: "Process", pid: "4", image: "System", eprocess: "0xffff800000002000" }] } });
            const nextOutput = "[proc.list] count=1\n";
            await app.reply("outputChunk", { ok: true, result: {
                resultId: "selected-system", offset: "0", next: String(nextOutput.length), complete: true, text: nextOutput
            } });
            assertCommandActivity(app, false);
            assert.equal(app.nodes.get("activity").textContent, "Idle");
            assert.equal(app.nodes.get("btn-cancel").disabled, true);
            assert.equal(app.nodes.get("result-count").textContent, "1 rows / 0 findings");
            assert.equal(app.nodes.get("result-title").textContent, "!dml_proc");
            assert.equal(app.nodes.get("result-summary").textContent, "Source unspecified / Completed / Current context");
            const nextFacts = app.nodes.get("result-facts").children.map(node => node.textContent).join("\n");
            assert.match(nextFacts, /137 visited \/ 137 read \/ 137 decoded/);
            assert.doesNotMatch(nextFacts, /Process selection did not complete/);
            assert.equal(app.nodes.get("result-rows").children.length, 1);
            app.nodes.get("result-rows").children[0].fire("click");
            assert.match(app.nodes.get("result-detail").textContent, /"image": "System"/);
            assert.equal(app.messages.filter(item => item.method === "execute").length, 2);
            assert.equal(app.messages.filter(item => item.method === "interrupt").length, 1);
        });
    }
}

for (const method of ["classify", "execute", "previewWrite", "executePlan"])
{
    await check("T-UI-TRANSPORT " + method + " exceptions release busy state and pending capacity", async () =>
    {
        const app = harness();
        await app.boot();
        const beforeUnhandled = unhandled.length;
        app.onPost(request =>
        {
            if (request.method === method)
            {
                throw new Error("Injected bridge transport failure");
            }
            if (request.method === "status")
            {
                void app.deliver(request, { ok: true, result: { connected: true, stopped: true, target: stamp } });
            }
        });
        for (let attempt = 0; attempt < 40; ++attempt)
        {
            app.enter(method === "classify" || method === "execute" ? "stack" : "eb 1000 41");
            if (method !== "classify")
            {
                await app.reply("classify", { ok: true, result: { write: method !== "execute" } });
            }
            if (method === "executePlan")
            {
                await app.reply("previewWrite", { ok: true, result: {
                    plan: { planId: "plan", approvalToken: "token" }, preview: "complete preview"
                } });
                app.nodes.get("modal-confirm").fire("click");
            }
            await settle();
            assert.equal(unhandled.length, beforeUnhandled, "Transport exception escaped the UI request lifecycle");
            assert.equal(app.nodes.get("activity").textContent, "Idle", "Failed transport left UI busy");
            assert.equal(app.nodes.get("btn-cancel").disabled, true);
            assertCommandActivity(app, false);
        }
        assert.equal(app.messages.filter(message => message.method === method).length, 40, "Failed requests exhausted pending capacity");
        assert.deepEqual([...app.timers.keys()].map(id => app.timerDelays.get(id)), [3000],
            "Only the recurring status poll may remain after a failed transport");
    });
}

await check("T-UI-STATUS late status cannot restore a disconnected target", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-refresh-status").fire("click");
    const older = app.latest("status");
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "QueueFullOrClosing" });
    await app.deliver(older, { ok: true, result: { connected: true, stopped: true, target: stamp } });
    assert.equal(app.nodes.get("status").className, "status bad", "Older status replaced a newer failure");
});

await check("T-UI-STATUS running targets lock command input and resume without executing the retained draft", async () =>
{
    const app = harness();
    await app.boot({ Session: [{ name: "stack", synopsis: "Show stack", support: "Stable" }] });
    await openTable(app, "retained", [{ address: "0x1234", addressSpace: "virtual", sourceFile: "sample.cpp" }]);
    const prompt = app.nodes.get("prompt");
    prompt.value = "registers";
    prompt.fire("input");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { stopped: false, execStatus: "go" });
    assert.equal(prompt.disabled, true);
    assert.equal(prompt.value, "registers");
    for (const id of ["btn-run", "kernel-workflow", "btn-stack", "btn-registers-refresh", "btn-palette", "btn-empty-command", "btn-navigate", "btn-source"])
    {
        assert.equal(app.nodes.get(id).disabled, true, id);
    }
    assert.equal(app.nodes.get("activity").textContent, "Busy");
    assert.equal(app.nodes.get("command-phase").textContent, "Busy");
    assert.equal(app.nodes.get("command-progress").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("command-elapsed").textContent, "");
    assert.equal([...app.timerDelays.values()].includes(250), false, "Waiting for a target must not start a command timer");
    assert.notEqual(app.nodes.get("btn-cancel").disabled, false, "Target execution is not an owned cancellable command");
    const before = app.messages.length;
    prompt.fire("keydown", { key: "Enter" });
    prompt.fire("keydown", { key: "ArrowUp" });
    app.nodes.get("btn-run").fire("click");
    app.nodes.get("btn-stack").fire("click");
    app.nodes.get("catalog").querySelectorAll(".cmd-item").find(item => item.dataset.command === "stack").fire("click");
    app.nodes.get("kernel-workflow").value = "stack";
    app.nodes.get("kernel-workflow").fire("change");
    assert.equal(app.messages.length, before, "A disabled command path posted an RPC");
    assert.equal(prompt.value, "registers", "A command shortcut replaced the locked draft");
    assert.equal(app.nodes.get("result-rows").children.length, 1, "Busy discarded the retained result");
    const poll = [...app.timers].find(([id]) => app.timerDelays.get(id) === 3000);
    assert.ok(poll, "Running targets must continue polling for a break");
    poll[1]();
    await processStatus(app, { ...stamp, stopEpoch: "3" });
    assert.equal(prompt.disabled, false);
    assert.equal(app.nodes.get("btn-run").disabled, false);
    assert.equal(app.nodes.get("activity").textContent, "Idle");
    assert.equal(app.nodes.get("command-progress").classList.contains("hidden"), true);
    assert.equal(prompt.value, "registers");
    assert.equal(app.messages.some(item => ["classify", "execute", "navigateResult", "interrupt"].includes(item.method)), false);
    prompt.fire("keydown", { key: "Enter" });
    assert.equal(app.latest("classify").params.command, "registers");
});

await check("T-UI-STATUS EngineBusy and running status stay locked until a current stopped status succeeds", async () =>
{
    const app = harness();
    await app.boot();
    const prompt = app.nodes.get("prompt");
    prompt.value = "stack";
    prompt.fire("input");
    app.nodes.get("btn-refresh-status").fire("click");
    const older = app.latest("status");
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "EngineBusy" });
    await app.deliver(older, { ok: true, result: { connected: true, stopped: true, target: stamp } });
    assert.equal(prompt.disabled, true, "An older stopped status unlocked the input");
    assert.equal(app.nodes.get("activity").textContent, "Busy");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { stopped: false });
    assert.equal(prompt.disabled, true, "A successful running status unlocked the input");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    assert.equal(prompt.disabled, false);
    assert.equal(prompt.value, "stack");
    assert.equal(app.nodes.get("btn-run").disabled, false);
    assert.equal(app.nodes.get("activity").textContent, "Idle");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { stopped: false });
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { connected: false });
    assert.equal(prompt.disabled, false, "No-target debugger commands must remain available after disconnect");
    assert.equal(app.nodes.get("command-progress").classList.contains("hidden"), true);
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
});

await check("T-UI-STATUS target execution invalidates pending completion without replacing the draft", async () =>
{
    const app = harness();
    await app.boot({ Session: [{ name: "help", synopsis: "Help", support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    prompt.value = "help u";
    prompt.fire("keydown", { key: "Tab" });
    const completion = app.latest("complete");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { stopped: false });
    await app.deliver(completion, { ok: true, result: { items: ["help ui"] } });
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.disabled, true);
    assert.equal(prompt.value, "help u");
    assert.equal(app.nodes.get("suggest").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("prompt").getAttribute("aria-expanded"), "false");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    assert.equal(prompt.value, "help u");
    assert.equal(app.messages.filter(item => item.method === "complete").length, 1);
});

await check("T-UI-STATUS a target that resumes during classification or approval cannot submit the command", async () =>
{
    for (const write of [false, true])
    {
        const app = harness();
        await app.boot();
        app.enter(write ? "eb 1000 41" : "stack");
        if (write)
        {
            await app.reply("classify", { ok: true, result: { write: true } });
            await app.reply("previewWrite", { ok: true, result: {
                plan: { planId: "pending-plan", approvalToken: "pending-token" }, preview: "complete bytes"
            } });
        }
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, stamp, { stopped: false });
        if (write)
        {
            app.nodes.get("modal-confirm").fire("click");
            assert.equal(app.latest("discardPlan").params.planId, "pending-plan");
        }
        else
        {
            await app.reply("classify", { ok: true, result: { write: false } });
        }
        assert.equal(app.messages.some(item => ["execute", "executePlan", "navigateResult"].includes(item.method)), false);
        assert.equal(app.nodes.get("prompt").disabled, true);
        assert.equal(app.nodes.get("activity").textContent, "Busy");
        assert.equal(app.nodes.get("btn-cancel").disabled, true);
    }
});

await check("T-UI-STATUS first target status must arrive before commands can be entered", async () =>
{
    const app = harness();
    await app.reply("hello", { ok: true, result: { target: stamp } });
    await app.reply("catalog", { ok: true, result: { groups: {} } });
    assert.equal(app.nodes.get("prompt").disabled, true, "Handshake unlocked input before the initial target status");
    app.enter("stack");
    assert.equal(app.messages.some(item => item.method === "classify"), false);
    await processStatus(app, stamp, { stopped: false });
    assert.equal(app.nodes.get("prompt").disabled, true);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { connected: false });
    assert.equal(app.nodes.get("prompt").disabled, false, "Confirmed no-target status must allow setup commands");
});

await check("T-UI-STATUS failed or malformed status cannot unlock a running target", async () =>
{
    for (const response of [
        { ok: false, error: "TransportError" }, { ok: false, error: "NoSession" },
        { ok: false, error: "OwnerThreadRequired" }, { ok: true, result: null },
        { ok: true, result: {} }, { ok: true, result: { connected: true } },
        { ok: true, result: { connected: true, stopped: "false" } },
        { ok: true, result: { connected: "false", stopped: true } }
    ])
    {
        const app = harness();
        await app.boot();
        app.nodes.get("prompt").value = "stack";
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, stamp, { stopped: false });
        app.nodes.get("btn-refresh-status").fire("click");
        await app.reply("status", response);
        assert.equal(app.nodes.get("prompt").disabled, true, JSON.stringify(response));
        assert.equal(app.nodes.get("btn-run").disabled, true);
        app.nodes.get("prompt").fire("keydown", { key: "Enter" });
        assert.equal(app.messages.some(item => item.method === "classify"), false);
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app);
        assert.equal(app.nodes.get("prompt").disabled, false);
        assert.equal(app.nodes.get("prompt").value, "stack");
        assert.equal(app.nodes.get("btn-run").disabled, false);
    }
});

await check("T-UI-STATUS a stopped status cannot revive preparation invalidated by an earlier Busy observation", async () =>
{
    for (const stage of ["read-classification", "write-classification", "preview", "approval", "preview-text"])
    {
        const app = harness();
        await app.boot();
        app.enter(stage === "read-classification" ? "stack" : "eb 1000 41");
        if (stage.startsWith("preview") || stage === "approval")
        {
            await app.reply("classify", { ok: true, result: { write: true } });
        }
        if (stage === "preview-text")
        {
            await app.reply("previewWrite", { ok: true, result: {
                plan: { planId: "stale-plan", approvalToken: "stale-token" }, previewResultId: "stale-preview"
            } });
        }
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, stamp, { stopped: false });
        app.nodes.get("btn-refresh-status").fire("click");
        if (stage === "approval")
        {
            await app.reply("previewWrite", { ok: true, result: {
                plan: { planId: "stale-plan", approvalToken: "stale-token" }, preview: "complete bytes"
            } });
        }
        await processStatus(app, { ...stamp, stopEpoch: "3" });
        if (stage.endsWith("classification"))
        {
            await app.reply("classify", { ok: true, result: { write: stage === "write-classification" } });
            assert.equal(app.messages.some(item => item.method === "previewWrite"), false, "Stale classification started a new target preview");
        }
        else if (stage === "preview")
        {
            await app.reply("previewWrite", { ok: true, result: {
                plan: { planId: "stale-plan", approvalToken: "stale-token" }, preview: "complete bytes"
            } });
        }
        else if (stage === "preview-text")
        {
            await app.reply("outputChunk", { ok: true, result: {
                resultId: "stale-preview", offset: "0", next: "8", complete: true, text: "preview\n"
            } });
            assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), true,
                "Invalidated preview text was offered for approval");
        }
        if (!app.nodes.get("modal-backdrop").classList.contains("hidden"))
        {
            app.nodes.get("modal-confirm").fire("click");
        }
        assert.equal(app.messages.some(item => ["execute", "executePlan", "navigateResult"].includes(item.method)), false, stage);
        assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), true);
        if (stage.startsWith("preview") || stage === "approval")
        {
            assert.equal(app.latest("discardPlan").params.planId, "stale-plan");
        }
        assert.equal(app.nodes.get("btn-cancel").disabled, true);
    }
});

await check("T-UI-APPROVAL startup and refresh never query a global write switch", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: true, result: { connected: true, stopped: true, target: stamp } });
    assert.equal(app.nodes.has("gate"), false);
    assert.equal(app.nodes.has("policy-status"), false);
    assert.equal(app.messages.some(item => item.method === "gate" || item.method === "setGate"), false);
});

await check("T-UI-APPROVAL a mutation reaches preview without global permission and still needs explicit approval", async () =>
{
    const app = harness();
    await app.boot();
    app.enter("eb 1000 41");
    await app.reply("classify", { ok: true, result: { write: true } });
    assert.equal(app.latest("previewWrite").params.command, "eb 1000 41");
    await app.reply("previewWrite", { ok: true, result: {
        plan: { planId: "one-use-change", approvalToken: "one-use-token" }, preview: "before 00 / after 41" } });
    assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), false);
    assert.equal(app.messages.some(item => item.method === "executePlan" || item.method === "execute"), false);
    app.nodes.get("modal-confirm").fire("click");
    assert.equal(app.latest("executePlan").params.planId, "one-use-change");
    assert.equal(app.latest("executePlan").params.approvalToken, "one-use-token");
});

await check("T-UI-FEEDBACK collapsed console reveals command failures", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-console").fire("click");
    app.enter("invalid-command");
    await app.reply("classify", { ok: false, error: "UnknownCommand" });
    assert.equal(app.nodes.get("btn-console").getAttribute("aria-expanded"), "true", "Command failure remained invisible");
});

await check("T-UI-CAPACITY pending request saturation recovers without executing a rejected command", async () =>
{
    const app = harness();
    await app.boot();
    const firstRefresh = app.messages.length;
    for (let i = 0; i < 40; ++i)
    {
        app.nodes.get("btn-refresh-status").fire("click");
    }
    app.enter("stack");
    await settle();
    assert.equal(app.latest("execute"), undefined);
    assert.equal(app.nodes.get("btn-cancel").disabled, true);
    for (const request of app.messages.slice(firstRefresh))
    {
        await app.deliver(request, { ok: true, result: { connected: true, stopped: true, target: stamp } });
    }
    assert.equal(app.nodes.get("prompt").disabled, true, "Older replies unlocked input after the latest status was rejected");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    await app.reply("execute", { ok: true, result: { ok: true, output: "Recovered" } });
    assert.equal(app.nodes.get("btn-cancel").disabled, true);
    assert.equal(app.messages.filter(request => request.method === "execute").length, 1);
});

await check("T-UI-CANCEL late progress cannot undo cancellation", async () =>
{
    const app = harness();
    await app.boot();
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    const execution = app.latest("execute");
    app.nodes.get("btn-cancel").fire("click");
    await app.deliver(execution, { type: "progress", ok: true });
    assert.equal(app.nodes.get("activity").textContent, "Cancelling", "Late progress hid pending cancellation");
    await app.deliver(execution, { ok: false, error: "Cancelled" });
    assert.equal(app.nodes.get("btn-cancel").disabled, true);
});

await check("T-UI-TIMEOUT late completion cannot execute a timed-out classification", async () =>
{
    const app = harness();
    await app.boot();
    app.enter("stack");
    const classification = app.latest("classify");
    for (const [id, callback] of [...app.timers])
    {
        app.timers.delete(id);
        callback();
    }
    await settle();
    await app.deliver(classification, { ok: true, result: { write: false } });
    assert.equal(app.messages.filter(message => message.method === "execute").length, 0);
    assert.equal(app.nodes.get("btn-cancel").disabled, true);
});

await check("T-UI-OUTPUT stalled streams report failure and stopped streams ignore late text", async () =>
{
    for (const stop of [false, true])
    {
        const app = harness();
        await app.boot();
        app.enter("stack");
        await app.reply("classify", { ok: true, result: { write: false } });
        await app.reply("execute", { ok: true, result: { ok: true, resultId: "stream", rowCount: "0" } });
        if (stop)
        {
            app.nodes.get("btn-cancel").fire("click");
        }
        await app.reply("outputChunk", { ok: true, result: {
            resultId: "stream", offset: "0", next: stop ? "9" : "0", text: stop ? "LATE TEXT" : "", complete: false
        } });
        if (stop)
        {
            assert.ok(!app.nodes.get("output").children.some(node => node.innerHTML?.includes("LATE TEXT")), "Stopped stream appended late text");
        }
        else
        {
            assert.ok(app.nodes.get("output").children.some(node => node.className === "t-error"), "Non-progressing stream silently succeeded");
        }
        assert.equal(app.nodes.get("btn-cancel").disabled, true);
        assert.equal(app.messages.filter(message => message.method === "outputChunk").length, 1);
    }
});

await check("T-UI-EXPORT collapsed console reveals the export outcome", async () =>
{
    for (const success of [true, false])
    {
        const app = harness();
        await app.boot();
        app.nodes.get("result-id-input").value = "exported";
        app.nodes.get("btn-result-load").fire("click");
        await app.reply("resultInfo", { ok: true, result: { resultId: "exported", rowCount: "0" } });
        app.nodes.get("btn-console").fire("click");
        app.nodes.get("btn-save").fire("click");
        assertCommandActivity(app, true, "Queued");
        await app.reply("saveLog", success ? { ok: true, result: { path: "C:/fixture/result.json" } } : { ok: false, error: "DiskFull" });
        assertCommandActivity(app, false);
        assert.equal(app.nodes.get("btn-console").getAttribute("aria-expanded"), "true", "Export outcome remained invisible");
    }
});

await check("T-UI-FOCUS result popover returns focus after Escape and successful load", async () =>
{
    const app = harness();
    await app.boot();
    const input = app.nodes.get("result-id-input");
    const popover = app.nodes.get("result-open");
    popover.appendChild(input);
    popover.open = true;
    input.focus();
    app.documentListeners.get("keydown")({ key: "Escape", preventDefault: noop });
    assert.equal(app.focused()?.id, "result-open-toggle", "Escape left focus inside the closed popover");
    popover.open = true;
    input.focus();
    input.value = "focus-result";
    input.fire("keydown", { key: "Enter" });
    await app.reply("resultInfo", { ok: true, result: { resultId: "focus-result", rowCount: "0" } });
    assert.equal(app.focused()?.id, "result-table", "Successful result load lost keyboard position");
});

await check("T-UI-KERNEL investigation selection drafts input without executing", async () =>
{
    const app = harness();
    await app.boot();
    const workflow = app.nodes.get("kernel-workflow");
    const before = app.messages.length;
    workflow.value = "triage power";
    workflow.fire("change");
    assert.equal(app.nodes.get("prompt").value, "triage power");
    assert.equal(app.messages.length, before);
    assert.equal(workflow.value, "");
    assert.equal(app.focused()?.id, "prompt");
    app.nodes.get("btn-run").fire("click");
    assert.equal(workflow.disabled, true);
    const executingDraft = app.nodes.get("prompt").value;
    workflow.value = "triage memory";
    workflow.fire("change");
    assert.equal(app.nodes.get("prompt").value, executingDraft);
});

await check("T-UI-FINDINGS finding-only results are visible and collection switches keep independent pages", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("result-id-input").value = "finding-only";
    app.nodes.get("btn-result-load").fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "finding-only", rowCount: "0", findingCount: "2", data: { target: stamp } } });
    assert.equal(app.latest("resultPage").params.collection, "findings");
    const findings = [
        { ruleId: "pe/WritableExecutable", severity: "warning", message: "Fixture finding", evidence: { section: ".fixture" } },
        { kind: "RecordReference", resultId: "finding-only", collection: "findings", index: "1", reason: "Export to inspect" }
    ];
    await app.reply("resultPage", { ok: true, result: { resultId: "finding-only", collection: "findings", offset: "0", next: "2", complete: true, findings } });
    assert.equal(app.nodes.get("result-rows").children.length, 2);
    app.nodes.get("result-rows").children[0].fire("click");
    assert.ok(app.nodes.get("result-detail").textContent.includes(".fixture"));
    assert.ok(app.nodes.get("result-count").textContent.includes("2 findings"));
    assert.equal(app.nodes.get("btn-save").disabled, false);
    const selector = app.nodes.get("result-collection");
    selector.value = "rows";
    selector.fire("change");
    assert.equal(app.nodes.get("result-rows").children.length, 0);
    selector.value = "findings";
    selector.fire("change");
    assert.equal(app.latest("resultPage").params.offset, "0");
    assert.equal(app.latest("resultPage").params.collection, "findings");
});

await check("T-UI-BOUND row actions preserve source identity and never retry as manual commands", async () =>
{
    for (const action of ["navigate", "disassemble", "source"])
    {
        const app = harness();
        await app.boot();
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app);
        app.nodes.get("result-id-input").value = "bound-result";
        app.nodes.get("btn-result-load").fire("click");
        await app.reply("resultInfo", { ok: true, result: { resultId: "bound-result", rowCount: "1", data: { target: stamp } } });
        await app.reply("resultPage", { ok: true, result: { resultId: "bound-result", offset: "0", next: "1", complete: true,
            rows: [{ address: "0x1234", addressSpace: "virtual", sourceFile: "fixture.cpp" }] } });
        app.nodes.get("result-rows").children[0].fire("click");
        app.nodes.get("btn-" + action).fire("click");
        const request = app.latest(action === "disassemble" ? "disassemblyRead" : "navigateResult");
        const binding = action === "disassemble" ? request.params.source : request.params;
        assert.equal(request.schema, "kndbgx.rpc.v3");
        assert.equal(binding.resultId, "bound-result");
        assert.equal(binding.index, "0");
        assert.equal(binding.collection, "rows");
        assert.equal(binding.action, action);
        assert.equal(JSON.stringify(binding.expectedStamp), JSON.stringify(stamp));
        await app.deliver(request, { ok: false, error: "StaleResultOrInvalidNavigation" });
        assert.equal(app.messages.filter(message => message.method === "execute" || message.method === "classify").length, 0);
        assert.equal(app.nodes.get("btn-cancel").disabled, true);
    }
});

await check("T-UI-PAGE non-advancing result pages report failure and keep export available", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("result-id-input").value = "stalled-page";
    app.nodes.get("btn-result-load").fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "stalled-page", rowCount: "1", data: { target: stamp } } });
    const requests = app.messages.filter(message => message.method === "resultPage").length;
    await app.reply("resultPage", { ok: true, result: { resultId: "stalled-page", offset: "0", next: "0", complete: false, rows: [] } });
    assert.ok(app.nodes.get("result-notice-text").textContent.includes("did not advance"));
    assert.equal(app.messages.filter(message => message.method === "resultPage").length, requests);
    assert.equal(app.nodes.get("btn-save").disabled, false);
});

await check("T-UI-LIMIT final viewport respects the display cap and retains original counts", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("result-id-input").value = "over-display-limit";
    app.nodes.get("btn-result-load").fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "over-display-limit", rowCount: "100100", data: { target: stamp } } });
    const rows = Array.from({ length: 128 }, (_, index) => ({ kind: "Fixture", index }));
    await app.reply("resultPage", { ok: true, result: { resultId: "over-display-limit", offset: "0", next: "128", complete: false, rows } });
    app.nodes.get("result-view").scrollTop = 99990 * 28;
    app.nodes.get("result-view").fire("scroll");
    const offset = Number(app.latest("resultPage").params.offset);
    const finalPage = rows.slice(0, 100100 - offset);
    await app.reply("resultPage", { ok: true, result: { resultId: "over-display-limit", offset: String(offset),
        next: String(offset + finalPage.length), complete: true, rows: finalPage } });
    assert.equal(app.nodes.get("result-rows").children.length, 100000 - offset);
    assert.ok(app.nodes.get("result-count").textContent.includes("100,100"));
    assert.equal(app.nodes.get("btn-save").disabled, false);
});

async function expireTimers(app)
{
    const timers = [...app.timers.entries()];
    for (const [id, callback] of timers)
    {
        app.timers.delete(id);
        callback();
    }
    await settle();
}

await check("T-THIRD-EXPORT queued and running export survives deadlines and recovers lost terminal without replay", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("result-id-input").value = "retained-export";
    app.nodes.get("btn-result-load").fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "retained-export", rowCount: "0", outputLength: "0", data: { target: stamp } } });
    app.nodes.get("btn-save").fire("click");
    const request = app.latest("saveLog");
    app.nodes.get("btn-save").fire("click");
    assert.equal(app.messages.filter(item => item.method === "saveLog").length, 1);
    assert.equal(app.nodes.get("btn-cancel").disabled, false);
    for (const phase of ["Queued", "Running", "Running", "Running"])
    {
        await app.deliver(request, { type: phase === "Queued" ? "accepted" : "progress", operationId: "91", ok: true });
        await expireTimers(app);
        await app.reply("operationStatus", { ok: true, result: { phase, operationId: "91" } });
        assert.notEqual(app.nodes.get("activity").textContent, "Idle");
    }
    app.nodes.get("btn-cancel").fire("click");
    assert.equal(app.latest("interrupt").params.requestId, request.requestId);
    await app.reply("interrupt", { ok: true, result: { requested: false } });
    const terminal = { schema: "kndbgx.rpc.v3", uiGeneration: "7", requestId: request.requestId,
        type: "completed", operationId: "91", ok: true, result: { path: "C:/fixture/exact-result.json" } };
    await app.reply("operationStatus", { ok: true, result: { phase: "Completed", terminal } });
    assert.equal(app.nodes.get("activity").textContent, "Idle");
    assert.equal(app.latest("operationAck").params.operationId, "91");
    await app.reply("operationAck", { ok: true, result: true });
    assert.ok(app.nodes.get("output").children.some(node => node.innerHTML?.includes("C:/fixture/exact-result.json")));
    await app.deliver(request, terminal);
    assert.equal(app.messages.filter(item => item.method === "saveLog").length, 1);
    assert.equal(app.messages.filter(item => item.method === "operationAck").length, 1);
});

await check("T-THIRD-DELIVERY missing completed and status timeout show unknown outcome with ongoing recovery", async () =>
{
    const app = harness();
    await app.boot();
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    const execute = app.latest("execute");
    await app.reply("execute", { type: "accepted", operationId: "92", ok: true });
    await expireTimers(app);
    await expireTimers(app);
    assert.equal(app.nodes.get("activity").textContent, "Outcome unknown; checking");
    assertCommandActivity(app, true, "Outcome unknown; checking");
    assert.ok(app.timers.size > 0);
    await expireTimers(app);
    await app.reply("operationStatus", { ok: true, result: { terminal: { schema: "kndbgx.rpc.v3", uiGeneration: "7",
        requestId: execute.requestId, type: "completed", operationId: "92", ok: false, error: "CancelledBeforeExecution" } } });
    assert.equal(app.nodes.get("activity").textContent, "Idle");
    assert.equal(app.messages.filter(item => item.method === "execute").length, 1);
});

await check("T-THIRD-RECOVERY prior document artifact paths are read-only and never replay exports", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-operations").fire("click");
    await app.reply("operations", { ok: true, result: { records: [{ operationId: "1" }], complete: true, next: "1" } });
    await app.reply("operationStatus", { ok: true, result: { operationId: "1", method: "saveLog", phase: "Completed", ok: true,
        uiGeneration: "6", path: "C:/fixture/old-export.json" } });
    await app.reply("operationAck", { ok: true, result: true });
    assert.ok(app.nodes.get("operations-list").children.some(node => node.children.some(child => child.textContent.includes("old-export.json"))));
    assert.equal(app.messages.filter(item => item.method === "saveLog" || item.method === "execute").length, 0);
});

await check("T-THIRD-EXPIRED host-confirmed missing receipt ends waiting without asserting execution failure or replay", async () =>
{
    const app = harness();
    await app.boot();
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    await expireTimers(app);
    await app.reply("operationStatus", { ok: false, error: "OperationUnknownOrExpired" });
    assert.equal(app.nodes.get("activity").textContent, "Outcome unknown");
    assertCommandActivity(app, false);
    assert.equal(app.nodes.get("btn-cancel").disabled, true);
    await app.reply("status", { ok: true, result: { connected: true, stopped: true, target: stamp } });
    assert.deepEqual([...app.timers.keys()].map(id => app.timerDelays.get(id)), [3000],
        "An expired operation retained a request timeout instead of only the status poll");
    assert.ok(app.nodes.get("output").children.some(node => node.innerHTML?.includes("Outcome unknown")));
    assert.equal(app.messages.filter(item => item.method === "execute").length, 1);
});

await check("T-THIRD-EXPIRED export absence is unknown rather than a failed or repeated save", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("result-id-input").value = "expired-export";
    app.nodes.get("btn-result-load").fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "expired-export", rowCount: "0", outputLength: "0", data: { target: stamp } } });
    app.nodes.get("btn-save").fire("click");
    await expireTimers(app);
    await app.reply("operationStatus", { ok: false, error: "OperationUnknownOrExpired" });
    assert.equal(app.nodes.get("activity").textContent, "Outcome unknown");
    assert.equal(app.nodes.get("btn-save").disabled, false);
    assert.ok(app.nodes.get("output").children.some(node => node.innerHTML?.includes("save outcome unknown")));
    assert.ok(!app.nodes.get("output").children.some(node => node.innerHTML?.includes("save failed")));
    assert.equal(app.messages.filter(item => item.method === "saveLog").length, 1);
});

function headers(app)
{
    return app.nodes.get("table-head").children.map(node => node.children[0]?.textContent || node.textContent);
}

function tableCell(app, row, label)
{
    const index = headers(app).indexOf(label);
    assert.ok(index >= 0, "Missing column: " + label);
    return app.nodes.get("result-rows").children[row].children[index].textContent;
}

async function openTable(app, command, rows, options = {})
{
    const id = options.id || command;
    const collection = options.collection || "rows";
    app.nodes.get("result-id-input").value = id;
    app.nodes.get("btn-result-load").fire("click");
    await app.reply("resultInfo", { ok: true, result: {
        resultId: id, rowCount: collection === "rows" ? String(options.total || rows.length) : "0",
        findingCount: collection === "findings" ? String(rows.length) : "0", outputLength: options.outputLength,
        data: { commandId: command, target: stamp, ...options.metadata }
    } });
    if (app.nodes.get("result-collection").value !== collection)
    {
        app.nodes.get("result-collection").value = collection;
        app.nodes.get("result-collection").fire("change");
    }
    if (rows.length)
    {
        await app.reply("resultPage", { ok: true, result: {
            resultId: id, collection, offset: "0", next: String(rows.length), complete: !options.total,
            [collection]: rows, ...(options.addressFields ? { addressFields: options.addressFields } : {})
        } });
    }
}

await check("T-UI-RECORD-NAV semantic routine records retain inspector actions", async () =>
{
    for (const [command, kind] of [["!hive", "RegistryHive"], ["!timer", "KernelTimer"], ["!dpc", "QueuedDpc"]])
    {
        const app = await memoryApp();
        const row = { kind, routine: "0xffff800000002000" };
        await openTable(app, command, [row]);
        app.nodes.get("result-rows").children[0].fire("click");
        assert.equal(app.nodes.get("btn-open-memory").disabled, false, command);
        assert.equal(app.nodes.get("btn-disassemble").disabled, false, command);
        app.nodes.get("btn-open-memory").fire("click");
        const request = app.latest("memoryRead");
        assert.equal(request.params.source.field, "routine");
        assert.equal(request.params.source.resultId, command);
        assert.equal(request.params.source.index, "0");
        await memoryReply(app, Array(64).fill(0x41), { address: row.routine });
        app.nodes.get("btn-disassemble").fire("click");
        const code = app.latest("disassemblyRead");
        assert.equal(code.params.source.field, "routine");
        assert.equal(code.params.source.resultId, command);
        await disassemblyReply(app, { address: row.routine });
        for (const routine of [null, "0x0000000000000000"])
        {
            await openTable(app, command, [{ ...row, routine }]);
            app.nodes.get("result-rows").children[0].fire("click");
            assert.equal(app.nodes.get("btn-open-memory").disabled, true, command);
            assert.equal(app.nodes.get("btn-disassemble").disabled, true, command);
        }
    }
});

await check("T-UI-PIDDB driver identity and cached status replace topology columns", async () =>
{
    const app = harness();
    await app.boot();
    const row = { kind: "PiDDBEntry", name: "fixture.sys", timeDateStamp: "0xfedcba98", loadStatus: "0x00000000",
        loadStatusClass: "STATUS_SUCCESS", entry: "0xffff800000002020",
        topology: { kind: "PiDDBAvlNode", address: "0xffff800000002000", parent: "0xffff800000001000", left: "0x0", right: "0x0" } };
    await openTable(app, "!piddb", [row]);
    assert.deepEqual(headers(app), ["#", "Driver name", "PE timestamp (raw)", "Load status (NTSTATUS)", "Cached result", "Cache entry"]);
    assert.equal(tableCell(app, 0, "Driver name"), "fixture.sys");
    assert.equal(tableCell(app, 0, "PE timestamp (raw)"), "0xfedcba98");
    assert.equal(tableCell(app, 0, "Load status (NTSTATUS)"), "0x00000000");
    assert.equal(tableCell(app, 0, "Cached result"), "STATUS_SUCCESS");
    const unavailable = { ...row, name: null, reason: "UnreadableDriverName", loadStatus: "0xc0000428", loadStatusClass: "Error" };
    await openTable(app, "!piddb", [unavailable], { id: "piddb-partial" });
    assert.equal(tableCell(app, 0, "Driver name"), "Unknown");
    assert.equal(tableCell(app, 0, "Reason"), "UnreadableDriverName");
    assert.equal(tableCell(app, 0, "Cached result"), "Error");
});

await check("T-UI-RECORDS semantic collector fields survive sparse routines and zero values", async () =>
{
    const app = harness();
    await app.boot();
    const cases = [
        ["!ssdt /policy", { kind: "Win32kProcessPolicy", pid: "100", image: "sample.exe", session: "0",
            filterMode: "Enforce", filterSet: "3", blockedServices: "1496", allowedServices: "1", auditServices: "0",
            unknownServices: "0", win32kDisable: false },
            { "PID": "100", "Filter Mode": "Enforce", "Filter Set": "3", "Blocked Services": "1496", "Allowed Services": "1" }],
        ["!ssdt /policy 100", { kind: "Win32kServicePolicy", pid: "100", image: "sample.exe", session: "0",
            filterMode: "Audit only", filterSet: "3", filterDecision: "Audit only", serviceId: "0x1000",
            serviceName: "NtUserGetThreadState", filterBit: true, entryRoutine: "0xffff800000002000" },
            { "PID": "100", "Filter Decision": "Audit only", "Service ID": "0x1000", "Service Name": "NtUserGetThreadState" }],
        ["!cihash", { kind: "CiHashEntry", name: "fixture.sys", hash: "ab".repeat(20), secondaryHash: "00".repeat(20),
            cacheStatusRaw: "0x00000000", entry: "0xffff800000002000", topology: { kind: "CiHashLink", next: "0x0" } },
            { "Name": "fixture.sys", "Hash (20 bytes)": "ab".repeat(20), "Cache status (raw)": "0x00000000" }],
        ["!hive", { kind: "RegistryHive", rootPath: "\\REGISTRY\\MACHINE\\SYSTEM", filePath: "\\SystemRoot\\System32\\config\\SYSTEM",
            fileUserName: "", hive: "0xffff800000002000", flags: "0x0", fileSize: "8192", routine: null, symbol: null },
            { "Root Path": "\\REGISTRY\\MACHINE\\SYSTEM", "File Size": "8192" }],
        ["!timer", { kind: "KernelTimer", cpu: "0", queue: "4", object: "0xffff800000002000", dueTimeRaw: "0x0000000000001234",
            periodMs: "0", signalState: "0", routine: null, symbol: null, decode: "Encoded DPC" },
            { "CPU": "0", "Due time (raw 100 ns)": "0x0000000000001234", "Period (ms)": "0", "Signal State": "0" }],
        ["!dpc", { kind: "QueuedDpc", cpu: "2", queue: "0", routine: "0xffff800000002000", symbol: "sample!Deferred",
            importance: "2", deferredContext: "0x0000000000000000" }, { "CPU": "2", "Importance": "2", "Symbol": "sample!Deferred" }],
        ["!ssdt", { kind: "RoutineObservation", family: "ShadowSSDT", serviceId: "0x1000", index: "0",
            routine: "0xffff800000002000", symbol: "win32k!NtUserExample" },
            { "Family": "ShadowSSDT", "Service ID": "0x1000", "Symbol": "win32k!NtUserExample" }],
        ["!ssdt", { kind: "RoutineObservation", family: "FilteredShadowSSDT", serviceId: "0x1000", session: "1",
            serviceName: "NtUserExample", symbol: "win32kfull!NtUserExample", routine: "0xffff800000002000",
            dispatchState: "Conditional: Session dispatch", entryRoutine: "0xffff800000004000" },
            { "Session": "1", "Service Name": "NtUserExample", "Dispatch State": "Conditional: Session dispatch" }],
        ["!alpc", { kind: "AlpcPort", name: "\\RPC Control\\Example", address: "0xffff800000002000", owner: { pid: "4", image: "System" },
            ownerProcess: "0xffff800000003000", connectionPort: "0x0", depth: "1" },
            { "Name": "\\RPC Control\\Example", "Owner / PID": "4", "Owner / Image": "System" }],
        ["!alpc", { kind: "AlpcPort", name: null, nameState: "Unnamed", portType: "Client communication",
            connectionName: "\\RPC Control\\Example", owner: { pid: "8", image: "client.exe" }, peerPort: "0xffff800000004000" },
            { "Name": "Unnamed", "Port Type": "Client communication", "Connection Name": "\\RPC Control\\Example" }],
        ["!alpc", { kind: "AlpcPort", name: null, nameState: "Unknown", address: "0xffff800000002000" },
            { "Name": "Name unavailable" }],
        ["!fwtable", { kind: "RoutineObservation", family: "FirmwareProvider", provider: "ACPI", routine: "0xffff800000002000",
            symbol: "nt!ExpGetAcpiTable", signature: "0x41435049", record: "0xffff800000003000" }, { "Provider": "ACPI" }],
        ["!devstack", { kind: "Device", driverName: "\\Driver\\ACPI", device: "0xffff800000002000", type: "0x32", stackSize: "3",
            flags: "0x0", driverObject: "0xffff800000003000", link: "AttachedTo" }, { "Driver Name": "\\Driver\\ACPI", "Stack Size": "3" }],
        ["!drvobj", { kind: "DriverDispatch", major: "14", majorName: "IRP_MJ_DEVICE_CONTROL", handler: "0xffff800000002000" },
            { "Major": "IRP_MJ_DEVICE_CONTROL" }],
        ["!payload", { kind: "BigPoolAllocation", address: "0xffff800000002000", tag: "Test", size: "8192", wxObserved: false,
            rangeClassified: false, inspectedPages: "1", totalPages: "2", unavailablePages: "0", ownership: "Unknown" },
            { "W+X observed": "No", "Range Classified": "No", "Inspected Pages": "1", "Total Pages": "2" }],
        ["!etw", { kind: "EtwLoggerContext", name: "Example trace", loggerId: "3", loggerStatus: "0x0", loggerMode: "0x100",
            eventsLost: "0", logFile: "", clockType: "1", rawClock: "0x1", object: "0xffff800000002000" },
            { "Name": "Example trace", "Events Lost": "0", "Logger Mode": "0x100" }],
        ["!mapper", { kind: "CiHashEntry", sourceCommand: "!cihash", name: "fixture.sys", hash: "ab".repeat(20),
            cacheStatusRaw: "0x0", entry: "0xffff800000002000" }, { "Source Command": "!cihash", "Name": "fixture.sys" }],
        ["!wnf decode 0", { kind: "WnfNameDecode", encoded: "0x0", lifetimeName: "Temporary", scopeName: "Process",
            permanentData: false, ownerTagText: "TEST", sequence: "1", version: "1" },
            { "Lifetime Name": "Temporary", "Scope Name": "Process", "Permanent Data": "No", "Owner Tag Text": "TEST" }],
        ["etl-import example.etl", { kind: "EtwEvent", providerName: "ExampleProvider", eventId: "12", taskName: "Read",
            opcodeName: "Start", pid: "4", tid: "8", timestampFileTime: "1234", payloadBytes: "0" },
            { "Provider Name": "ExampleProvider", "Event ID": "12", "Task Name": "Read" }]
    ];
    for (const [command, row, cells] of cases)
    {
        await openTable(app, command, [row]);
        if (row.kind === "Win32kServicePolicy")
        {
            assert.deepEqual(headers(app).slice(1, 5), ["Service Name", "Filter Decision", "Service ID", "PID"]);
        }
        for (const [label, value] of Object.entries(cells))
        {
            assert.equal(tableCell(app, 0, label), value, command + ": " + label);
        }
        if (command === "!alpc" && row.name === null)
        {
            app.nodes.get("result-rows").children[0].fire("click");
            const fields = app.nodes.get("detail-fields").children;
            const index = fields.findIndex(field => field.textContent === "name");
            assert.equal(fields[index + 1].textContent, cells.Name);
            assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).name, null);
        }
        if (command === "!cihash")
        {
            assert.equal(headers(app).some(label => /Topology|Next/.test(label)), false);
            assert.equal(headers(app).length, 6);
            assert.ok(Number(columnHandle(app, "Name").getAttribute("aria-valuenow")) >= 400);
            assert.ok(Number(columnHandle(app, "Hash (20 bytes)").getAttribute("aria-valuenow")) >= 300);
        }
        if (command === "!hive")
        {
            assert.ok(Number(columnHandle(app, "File User Name").getAttribute("aria-valuenow")) >= 400);
        }
    }
    await openTable(app, "!cihash", [{ kind: "CiHashEntry", name: null, hash: "ab".repeat(20), cacheStatusRaw: "0x0",
        entry: "0xffff800000002000", reason: "CiHashNameUnavailable" }]);
    assert.equal(tableCell(app, 0, "Name"), "Unknown");
    assert.equal(tableCell(app, 0, "Reason"), "CiHashNameUnavailable");
});

await check("T-UI-TABLE-SEMANTICS command records expose their actual payload and source scope", async () =>
{
    const app = harness();
    await app.boot();
    const examples = [
        ["dt nt!_EXAMPLE 0x1000", { field: "Flags", offset: "0x8", type: "unsigned long", pointer: null, symbol: null,
            size: "4", bitOffset: "3", bitWidth: "2", arrayCount: null, bytes: "18000000", value: "0x3", valueStatus: "Success" },
            { "Value": "0x3", "Bytes": "18000000", "Value Status": "Success" }],
        ["dt nt!_EXAMPLE 0x1000", { field: "Buffer", offset: "0x10", type: "char [1024]", size: "1024", bytes: null,
            valueStatus: "NotRead:FieldSizeLimit" }, { "Bytes": "Unknown", "Value Status": "NotRead:FieldSizeLimit" }],
        ["uf nt!Example", { kind: "HostFunctionDisassembly", address: "0xffff800000002000", output: "nt!Example:\nret",
            engineCompleted: true, outputTruncated: false, source: "DbgEng uf" }, { "Output": "nt!Example:\nret", "Output Truncated": "No" }],
        ["!driver", { kind: "DriverObject", name: "\\Driver\\Example", address: "0xffff800000002000", start: "0xffff800000004000",
            size: "4096", flags: "0x0", firstDevice: "0x0", driverInit: "0xffff800000004100", driverInitSymbol: "sample!DriverEntry",
            driverUnload: "0x0", driverUnloadSymbol: null, driverUnloadSymbolSource: "NotRegistered", driverStartIo: null },
            { "Name": "\\Driver\\Example", "Size": "4096", "Driver Init Symbol": "sample!DriverEntry", "Driver Unload Symbol": "Not registered", "Driver Start Io": "Unknown" }],
        ["!pool summary", { kind: "PoolTagSummary", tag: "Test", allocationCount: "2", totalBytes: "12288" },
            { "Tag": "Test", "Allocation Count": "2", "Total Bytes": "12288" }],
        ["!pool summary /wx", { kind: "PoolTagSummary", tag: "Test", allocationCount: "2", totalBytes: "12288",
            wxObservedAllocations: "0", fullyClassifiedAllocations: "1", incompleteAllocations: "1", inspectedPages: "2", unavailablePages: "0" },
            { "Wx Observed Allocations": "0", "Fully Classified Allocations": "1", "Incomplete Allocations": "1", "Inspected Pages": "2" }],
        ["!token", { kind: "ThreadToken", process: { pid: "4", image: "System" }, selection: "CurrentThreadEffectiveToken",
            tokenTypeName: "Impersonation", mandatoryLabelRid: "16384", privilegesPresent: "0x0", privilegesEnabled: "0x0",
            privilegesEnabledByDefault: "0x0", address: "0xffff800000002000", AuthenticationId: "999", TokenId: "1001", SessionId: "0" },
            { "Selection": "CurrentThreadEffectiveToken", "Process / Image": "System", "Session ID": "0", "Token ID": "1001" }],
        ["!ci /host", { kind: "HostCodeIntegrity", scope: "DebuggerHost", known: true, source: "NtQuerySystemInformation", raw: "0x400",
            ntStatus: "0x0", queryAvailable: true, returnedLength: "8", structureLength: "8", unknownOptions: "0x0",
            codeIntegrityEnabled: false, testSign: false, umciEnabled: false, umciAuditMode: false, hvciEnabled: true,
            hvciAuditMode: false, hvciStrictMode: false, hvciIumEnabled: false },
            { "Scope": "DebuggerHost", "Hvci Enabled": "Yes", "Code Integrity Enabled": "No", "Unknown Options": "0x0" }],
        ["ntstatus c0000005", { kind: "NtStatus", code: "0xc0000005", severity: "Error", ntSuccess: false, facility: "0x0", statusCode: "0x5", customer: false, reservedBit: false },
            { "Code": "0xc0000005", "Nt Success": "No", "Status Code": "0x5" }],
        ["bugcheck-decode 1f2 1000 4 2000 181", { kind: "Bugcheck", code: "0x1f2", name: "KASAN", parameters: ["0x1000", "0x4", "0x2000", "0x181"],
            address: "0x1000", instructionPointer: "0x2000", access: "write", accessBytes: "4", shadowByte: "0x81", shadowMeaning: "Alloca left redzone" },
            { "Parameters": '["0x1000","0x4","0x2000","0x181"]', "Shadow Meaning": "Alloca left redzone" }],
        ["!address 1000", { kind: "Address", address: "0x1000", space: "virtual", physical: "0x0", dtb: "0x2000", writable: false, executable: true, pageSize: "4096", error: "" },
            { "Physical": "0x0", "Writable": "No", "Executable": "Yes" }],
        ["!diff before after", { kind: "SnapshotDifference", collector: "processes", key: "example", state: "Unknown", knownChanged: false, unknownFields: true,
            beforeCount: "1", afterCount: "1", before: { image: "example" }, after: { image: null } },
            { "State": "Unknown", "Unknown Fields": "Yes", "Known Changed": "No" }],
        ["diagnose drivers", { kind: "HostDiagnostic", recipe: "drivers", command: "lm", engineAccepted: true, contextRestored: true, outputTruncated: false,
            output: "native output" }, { "Output": "native output", "Context Restored": "Yes" }],
        ["diag-catalog", { kind: "DiagnosticRecipe", name: "drivers", group: "kernel", description: "Inspect drivers", operand: "none", hostCommand: "lm" },
            { "Group": "kernel", "Operand": "none", "Host Command": "lm" }],
        ["!byovd", { kind: "ModuleFileCatalogObservation", module: "example", path: "example.sys", imageIdentityMatches: false, sha256: null, catalogMatch: null },
            { "Image Identity Matches": "No", "Catalog Match": "Unknown" }],
        ["driver-audit example.sys", { kind: "DriverImage", machine: "0x8664", subsystem: "1", imageSize: "4096", entryRva: "0x1000",
            timestamp: "0x0", nxCompatible: true, dynamicBase: true, highEntropyVa: false, guardCfDeclared: false, forceIntegrity: false,
            relocationsStripped: false, loadConfigValid: true, certificateTablePresent: false, certificateTableBoundsValid: true },
            { "High Entropy Va": "No", "Guard Cf Declared": "No", "Force Integrity": "No", "Certificate Table Present": "No" }],
        ["driver-audit example.sys", { kind: "EmbeddedSignature", status: "NoEmbeddedSignature", trustedByHostOfflinePolicy: false,
            revocationChecked: false, catalogChecked: false, scope: "HostOfflinePolicy" },
            { "Catalog Checked": "No", "Revocation Checked": "No", "Scope": "HostOfflinePolicy" }],
        ["!dma", { table: "DMAR (Intel VT-d)", bytes: "0", error: "0x2", available: false }, { "Table": "DMAR (Intel VT-d)", "Available": "No" }],
        ["!wfp", { kind: "filters", name: "example", key: "filter-guid", action: "0x1001", actionName: "Block", layer: "layer-guid",
            subLayer: "sub-layer-guid", filterId: "18446744073709551615", conditionCount: "0", flags: "0x0", hasProviderKey: false,
            usesCallout: false, providerKey: null, calloutKey: null },
            { "Action": "0x1001", "Action Name": "Block", "Layer": "layer-guid", "Filter ID": "18446744073709551615", "Condition Count": "0", "Provider Key": "None", "Callout Key": "N/A" }],
        ["!wfp filters", { kind: "filters", source: "DebugTargetRuntime", filterId: "9007199254740993", actionName: "Permit",
            layerId: "48", layerName: "ALE_AUTH_CONNECT_V4", conditionCount: "1", conditionSummary: "IP_PROTOCOL Equal 6",
            weight: "18446744073709551615", subLayerWeight: "3", usesCallout: false, calloutId: null, calloutKey: null,
            nameState: "NotInRuntimeSchema" },
            { "Filter ID": "9007199254740993", "Layer Name": "ALE_AUTH_CONNECT_V4", "Condition Summary": "IP_PROTOCOL Equal 6",
                "Weight": "18446744073709551615", "Callout ID": "N/A", "Callout Key": "N/A", "Name State": "NotInRuntimeSchema" }],
        ["!wfp callouts", { kind: "callouts", source: "DebugTargetRuntime", calloutId: "7", calloutKey: "callout-guid", registered: true,
            layerName: "NotAssigned", policyEntryPresent: false, classifyRoutine: "0xfffff80000001000", classifyRoutineSymbol: "example!Classify",
            notifyRoutine: "0x0000000000000000", flowDeleteRoutine: "0x0000000000000000" },
            { "Callout ID": "7", "Callout Key": "callout-guid", "Registered": "Yes", "Layer Name": "NotAssigned",
                "Policy Entry Present": "No", "Classify Routine Symbol": "example!Classify" }],
        ["features", { feature: "ttd-replay", enabled: false, status: "Unavailable", reason: "Not enabled" }, { "Feature": "ttd-replay", "Enabled": "No" }],
        ["!wfp filters", { kind: "filters", filterId: "100", name: "Target filter", description: "Target description",
            providerName: "Target provider", subLayerName: "Target sublayer", managementState: "Matched", nameState: "Present" },
            { "Name": "Target filter", "Description": "Target description", "Provider Name": "Target provider",
                "Sub Layer Name": "Target sublayer", "Management State": "Matched" }],
        ["!wfp providers", { kind: "providers", source: "DebugTargetBfe", name: "@example.dll,-1", description: null,
            nameState: "IndirectResource", descriptionState: "Absent", serviceName: "ExampleService" },
            { "Name": "@example.dll,-1", "Name State": "IndirectResource", "Description State": "Absent", "Service Name": "ExampleService" }],
        ["results", { commandId: "!timer", status: "Partial", rowCount: "1", findingCount: "0", historical: true, resultId: "sample" },
            { "Command ID": "!timer", "Row Count": "1", "Historical": "Yes" }]
    ];
    for (const [command, row, cells] of examples)
    {
        await openTable(app, command, [row]);
        for (const [label, expected] of Object.entries(cells))
        {
            assert.equal(tableCell(app, 0, label), expected, command + ": " + label);
        }
    }
    await openTable(app, "!wfp filters callouts", [
        { kind: "filters", filterId: "100", actionName: "Permit", usesCallout: false, calloutId: null, calloutKey: null, conditionCount: "0", conditionSummary: "None" },
        { kind: "callouts", calloutId: "7", calloutKey: "callout-guid", registered: true, policyEntryPresent: false,
            classifyRoutineSymbol: "example!Classify", notifyRoutineSymbol: null, notifyRoutineSymbolSource: "NotRegistered" }
    ]);
    assert.equal(tableCell(app, 0, "Filter ID"), "100");
    assert.ok(headers(app).indexOf("Callout ID") < headers(app).indexOf("Condition Summary"), "Mixed WFP rows must keep callout identity before filter-only details");
    assert.equal(tableCell(app, 0, "Callout ID"), "N/A");
    assert.equal(tableCell(app, 1, "Policy Entry Present"), "No");
    assert.equal(tableCell(app, 1, "Classify Routine Symbol"), "example!Classify");
    assert.equal(tableCell(app, 1, "Notify Routine Symbol"), "Not registered");
    await openTable(app, "!drvobj example", [
        { kind: "Driver", name: "\\Driver\\Example", object: "0xffff800000001000", start: "0xffff800000002000", size: "0x1000", firstDevice: "0x0" },
        { kind: "DriverDispatch", major: "14", majorName: "DEVICE_CONTROL", handler: "0xffff800000002100", symbol: "example!Dispatch", ownership: "KnownModule", driverObject: "0xffff800000001000" },
        { kind: "Device", driverName: "\\Driver\\Example", device: "0xffff800000003000", type: "0x22", stackSize: "1", flags: "0x0", link: "NextDevice" }
    ]);
    assert.equal(tableCell(app, 0, "Size"), "0x1000");
    assert.equal(tableCell(app, 0, "First Device"), "0x0");
    assert.equal(tableCell(app, 1, "Major"), "DEVICE_CONTROL");
    assert.equal(tableCell(app, 2, "Stack Size"), "1");
    await openTable(app, "irp 0xffff800000001000", [
        { kind: "Irp", address: "0xffff800000001000", status: "0x0", information: "0x10", stackCount: "1", currentLocation: "1", cancel: "0", pendingReturned: "0", flags: "0x0" },
        { kind: "IoStackLocation", address: "0xffff8000000010d0", slot: "1", current: true, majorName: "DEVICE_CONTROL", minor: "0x0",
            DeviceObject: "0xffff800000002000", FileObject: "0x0", CompletionRoutine: "0x0", ioctl: { code: "0x222003" }, inputLength: "0", outputLength: "16" }
    ]);
    assert.equal(tableCell(app, 0, "Information"), "0x10");
    assert.equal(tableCell(app, 1, "Major Name"), "DEVICE_CONTROL");
    assert.equal(tableCell(app, 1, "IOCTL / Code"), "0x222003");
    assert.equal(tableCell(app, 1, "Output Length"), "16");
});

await check("T-UI-STACK captured identity survives sorting, context changes and retained-result recall", async () =>
{
    const app = harness({ breakpointAuto: false });
    await app.boot();
    const stackContext = { engineProcessId: "0", engineThreadId: "1", processor: "1",
        targetContext: { image: "captured.exe", pid: "424", tid: "428", processor: "1", source: "SelectedImplicitThread" } };
    const rows = [{ kind: "StackFrame", index: "0", address: "0xffff800000002000" },
        { kind: "StackFrame", index: "1", address: "0xffff800000001000" }];
    const options = { metadata: { analysis: { stackContext } } };
    await openTable(app, "stack", rows, options);
    const label = "captured.exe / PID 424 / TID 428 / CPU 1";
    assert.equal(app.nodes.get("stack-summary").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("stack-context").textContent, label);
    assert.match(app.nodes.get("stack-context").title, /Selected implicit thread.*Engine process ID: 0; engine thread ID: 1/);
    sortHeader(app, "Address");
    assert.equal(tableCell(app, 0, "Index"), "1");
    assert.equal(app.nodes.get("stack-context").textContent, label);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stamp, contextGeneration: "99" },
        { currentProcess: { image: "other.exe", pid: "900" } });
    assert.equal(app.nodes.get("stack-context").textContent, label);
    await openTable(app, "registers", []);
    assert.equal(app.nodes.get("stack-summary").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("stack-context").textContent, "");
    assert.equal(app.nodes.get("stack-context").title, "");
    await openTable(app, "stack", rows, options);
    assert.equal(app.nodes.get("stack-context").textContent, label);
    assert.equal(app.messages.filter(item => item.method === "execute").length, 0);
});

await check("T-UI-STACK legacy and unavailable identity are not engine IDs and known zero IDs survive", async () =>
{
    for (const targetContext of [undefined, { pid: "0", tid: "0", image: "Idle" }, { pid: "424", tid: null }])
    {
        const app = harness({ breakpointAuto: false });
        await app.boot();
        const stackContext = { processId: "0", threadId: "1", processor: "0", targetContext };
        await openTable(app, "stack", [], { metadata: { analysis: { stackContext } } });
        const label = app.nodes.get("stack-context").textContent;
        assert.match(label, !targetContext ? /PID Unavailable \/ TID Unavailable/ :
            targetContext.pid === "0" ? /Idle \/ PID 0 \/ TID 0/ : /PID 424 \/ TID Unavailable/);
        assert.doesNotMatch(label, /Debugger process|TID 1\b/);
        assert.match(label, /CPU 0/);
        await openTable(app, "stack", [], { id: "legacy-stack-without-metadata" });
        assert.equal(app.nodes.get("stack-context").textContent, "PID Unavailable / TID Unavailable");
    }
});

async function openToolbarResult(app, screen, id = "toolbar-" + screen)
{
    app.nodes.get("btn-" + screen).fire("click");
    if (screen === "breakpoints")
    {
        await breakpointListReply(app, [], { id });
        return;
    }
    await app.reply("classify", { ok: true, result: { write: false } });
    await app.reply("execute", { ok: true, result: { ok: true, resultId: id, command: screen,
        rowCount: "0", findingCount: "0", outputLength: "0", data: { commandId: screen, status: "Success", target: stamp } } });
    await app.reply("outputChunk", { ok: true, result: { resultId: id, offset: "0", next: "0", complete: true, text: "" } });
    await processStatus(app);
}

await check("T-UI-RESULTS toolbar screens retain one return target and restore its row collection scroll and draft without execution", async () =>
{
    const app = harness({ breakpointAuto: false });
    await app.boot();
    const rows = Array.from({ length: 60 }, (_, index) => ({ pid: String(index + 1) }));
    await openTable(app, "!original", rows);
    app.nodes.get("result-rows").children[2].fire("click");
    app.nodes.get("result-view").scrollTop = 56;
    app.nodes.get("result-view").scrollLeft = 37;
    for (const screen of ["stack", "breakpoints", "event"])
    {
        await openToolbarResult(app, screen);
        assert.equal(app.nodes.get("btn-" + screen).getAttribute("aria-pressed"), "true");
        assert.equal(app.nodes.get("btn-results").disabled, false);
    }
    app.nodes.get("prompt").value = "next draft";
    app.nodes.get("prompt").fire("input");
    const executions = app.messages.filter(item => item.method === "execute").length;
    app.nodes.get("btn-results").fire("click");
    assert.equal(app.latest("resultInfo").params.resultId, "!original");
    await app.reply("resultInfo", { ok: true, result: { resultId: "!original", rowCount: "60", findingCount: "1",
        data: { commandId: "!original", target: stamp } } });
    assert.equal(app.latest("resultPage").params.collection, "rows");
    await app.reply("resultPage", { ok: true, result: { resultId: "!original", collection: "rows", offset: "0", complete: true, rows } });
    assert.equal(app.nodes.get("result-title").textContent, "!original");
    assert.equal(app.nodes.get("result-view").scrollTop, 56);
    assert.equal(app.nodes.get("result-view").scrollLeft, 37);
    assert.equal(app.nodes.get("row-position").textContent, "Row 3 of 60");
    assert.equal(app.nodes.get("btn-results").getAttribute("aria-pressed"), "true");
    assert.equal(app.nodes.get("prompt").value, "next draft");
    assert.equal(app.messages.filter(item => item.method === "execute").length, executions);
});

await check("T-UI-RESULTS findings and sorted selection survive return while auxiliary collection changes keep the original", async () =>
{
    const app = harness({ breakpointAuto: false });
    await app.boot();
    const findings = [{ severity: "warning", message: "zulu" }, { severity: "warning", message: "alpha" }];
    await openTable(app, "finding-result", findings, { collection: "findings" });
    sortHeader(app, "Message");
    app.nodes.get("result-rows").children[0].fire("click");
    await openToolbarResult(app, "stack");
    app.nodes.get("result-collection").value = "findings";
    app.nodes.get("result-collection").fire("change");
    await openToolbarResult(app, "event");
    app.nodes.get("btn-results").fire("click");
    assert.equal(app.latest("resultInfo").params.resultId, "finding-result");
    await app.reply("resultInfo", { ok: true, result: { resultId: "finding-result", rowCount: "0", findingCount: "2",
        data: { commandId: "finding-result", target: stamp } } });
    await app.reply("resultPage", { ok: true, result: { resultId: "finding-result", collection: "findings", offset: "0", complete: true, findings } });
    assert.equal(app.nodes.get("result-collection").value, "findings");
    assert.equal(tableCell(app, 0, "Message"), "alpha");
    assert.equal(app.nodes.get("detail-fields").children.find(node => node.textContent === "alpha")?.textContent, "alpha");
    assert.equal(app.nodes.get("row-position").textContent, "Sorted by Message (ascending) / Row 1 of 2");
});

await check("T-UI-RESULTS expired return preserves the current screen and remains available for an explicit retry", async () =>
{
    const app = harness({ breakpointAuto: false });
    await app.boot();
    await openTable(app, "expired-original", []);
    await openToolbarResult(app, "stack");
    const executions = app.messages.filter(item => item.method === "execute").length;
    app.nodes.get("btn-results").fire("click");
    await app.reply("resultInfo", { ok: false, error: "ResultNotFound" });
    assert.equal(app.nodes.get("result-title").textContent, "stack");
    assert.equal(app.nodes.get("btn-results").disabled, false);
    assert.match(app.nodes.get("result-notice-text").textContent, /expired or unavailable/);
    assert.equal(app.messages.filter(item => item.method === "execute").length, executions);
    app.nodes.get("btn-results").fire("click");
    assert.equal(app.latest("resultInfo").params.resultId, "expired-original");
});

await check("T-UI-RESULTS an obsolete return cannot replace a newly selected breakpoint screen", async () =>
{
    const app = harness({ breakpointAuto: false });
    await app.boot();
    await openTable(app, "original", []);
    await openToolbarResult(app, "stack");
    app.nodes.get("btn-results").fire("click");
    const pending = app.latest("resultInfo");
    await openToolbarResult(app, "breakpoints");
    await app.deliver(pending, { ok: true, result: { resultId: "original", rowCount: "0", data: { commandId: "original", target: stamp } } });
    assert.equal(app.nodes.get("result-title").textContent, "breakpoints");
    assert.equal(app.nodes.get("btn-breakpoints").getAttribute("aria-pressed"), "true");
    app.nodes.get("btn-results").fire("click");
    assert.equal(app.latest("resultInfo").params.resultId, "original");
});

await check("T-UI-RESULTS explicit command results replace the return target even when their command is a toolbar name", async () =>
{
    const app = harness({ breakpointAuto: false });
    await app.boot();
    await openTable(app, "older", []);
    await openToolbarResult(app, "event");
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    await app.reply("execute", { ok: true, result: { resultId: "typed-stack", rowCount: "0", command: "stack", data: { commandId: "stack", target: stamp } } });
    await app.reply("outputChunk", { ok: true, result: { resultId: "typed-stack", offset: "0", next: "0", complete: true, text: "" } });
    await processStatus(app);
    assert.equal(app.nodes.get("btn-results").getAttribute("aria-pressed"), "true");
    await openToolbarResult(app, "stack");
    app.nodes.get("btn-results").fire("click");
    assert.equal(app.latest("resultInfo").params.resultId, "typed-stack");
});

await check("T-UI-RESULTS a running target permits stored-result return while keeping target actions locked", async () =>
{
    const app = harness({ breakpointAuto: false });
    await app.boot();
    await openTable(app, "retained", [{ address: "0xffff800000001000", addressSpace: "virtual" }]);
    await openToolbarResult(app, "event");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stamp, stopEpoch: "99" }, { stopped: false, execStatus: "go" });
    assert.equal(app.nodes.get("btn-results").disabled, false);
    const executions = app.messages.filter(item => item.method === "execute").length;
    app.nodes.get("btn-results").fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "retained", rowCount: "1", data: { commandId: "retained", target: stamp } } });
    await app.reply("resultPage", { ok: true, result: { resultId: "retained", collection: "rows", offset: "0", complete: true,
        rows: [{ address: "0xffff800000001000", addressSpace: "virtual" }] } });
    app.nodes.get("result-rows").children[0].fire("click");
    assert.equal(app.nodes.get("prompt").disabled, true);
    assert.equal(app.nodes.get("btn-navigate").disabled, true);
    assert.match(app.nodes.get("result-notice-text").textContent, /earlier debugger context/);
    assert.equal(app.messages.filter(item => item.method === "execute").length, executions);
});

await check("T-UI-RESULTS an open tab retains its sort and source address binding beyond the layout cache", async () =>
{
    const app = harness({ breakpointAuto: false });
    await app.boot();
    const rows = [30, 10, 20].map(pid => ({ pid: String(pid), address: "0xffff80000000" + pid.toString(16).padStart(4, "0"), addressSpace: "virtual" }));
    await openTable(app, "evicted-layout", rows);
    sortHeader(app, "PID");
    app.nodes.get("result-rows").children[0].fire("click");
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, "10");
    for (let index = 0; index < 33; ++index)
    {
        await openToolbarResult(app, "stack", "distinct-stack-" + index);
    }
    app.nodes.get("btn-results").fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "evicted-layout", rowCount: "3",
        data: { commandId: "evicted-layout", target: stamp } } });
    await app.reply("resultPage", { ok: true, result: { resultId: "evicted-layout", collection: "rows", offset: "0", complete: true, rows } });
    assert.equal(app.nodes.get("row-position").textContent, "Sorted by PID (ascending) / Row 1 of 3");
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, "10");
    app.nodes.get("btn-navigate").fire("click");
    assert.equal(app.latest("navigateResult").params.resultId, "evicted-layout");
    assert.equal(app.latest("navigateResult").params.index, "1");
});

await check("T-UI-RESULTS starting a breakpoint edit supersedes pending return success and failure replies", async () =>
{
    for (const action of ["add", "remove", "disable"])
    {
        for (const expired of [false, true])
        {
            const app = harness({ breakpointAuto: false });
            await app.boot();
            await openTable(app, "original-before-edit", []);
            app.nodes.get("btn-breakpoints").fire("click");
            await breakpointListReply(app, [{ kind: "Breakpoint", id: "12", address: "0xffff800000001000",
                addressSpace: "virtual", enabled: true, type: "0", identity: "review-guid" }], { id: "edit-list" });
            app.nodes.get("result-rows").children[0].fire("click");
            app.nodes.get("btn-results").fire("click");
            const pending = app.latest("resultInfo");
            if (action === "add")
            {
                app.nodes.get("breakpoint-address").value = "nt!ReviewFixture";
                app.nodes.get("breakpoint-address").fire("input");
            }
            app.nodes.get("btn-breakpoint-" + action).fire("click");
            assert.equal(app.latest("breakpointPlan").params.operation, "breakpoint-" + action);
            await app.reply("breakpointPlan", breakpointPreview("breakpoint-" + action));
            await app.deliver(pending, expired ? { ok: false, error: "ResultExpiredOrUnknown" } : { ok: true, result: {
                resultId: "original-before-edit", rowCount: "0", data: { commandId: "original-before-edit", target: stamp } } });
            assert.equal(app.nodes.get("result-title").textContent, "breakpoints", action);
            assert.equal(app.nodes.get("btn-breakpoints").getAttribute("aria-pressed"), "true");
            assert.doesNotMatch(app.nodes.get("result-notice-text").textContent, /expired or unavailable/);
            assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), action === "disable");
            assert.equal(app.messages.filter(request => request.method === "breakpointApply").length, action === "disable" ? 1 : 0);
        }
    }
});

function resultTab(app, id)
{
    const tab = app.nodes.get("result-tabs").children.find(item => item.children[0].title.endsWith(" / " + id));
    assert.ok(tab, "Missing result tab: " + id);
    return { element: tab, button: tab.children[0], close: tab.children.find(item => item.classList.contains("result-tab-close")) };
}

async function tabReply(app, id, command, rows, findings = [])
{
    await app.reply("resultInfo", { ok: true, result: { resultId: id, command, rowCount: String(rows.length),
        findingCount: String(findings.length), data: { commandId: command, target: stamp } } });
    const collection = app.nodes.get("result-collection").value;
    const values = collection === "findings" ? findings : rows;
    if (values.length)
    {
        await app.reply("resultPage", { ok: true, result: { resultId: id, collection, offset: "0",
            complete: true, [collection]: values } });
    }
}

await check("T-UI-TABS separate command executions retain sorted selection scroll widths and drafts without replay", async () =>
{
    const app = harness();
    await app.boot();
    const rows = [{ pid: "30" }, { pid: "10" }, { pid: "20" }];
    for (const id of ["first-execution", "second-execution"])
    {
        app.enter("!process");
        await app.reply("classify", { ok: true, result: { write: false } });
        await app.reply("execute", { ok: true, result: { resultId: id, command: "!process", rowCount: "3",
            findingCount: "0", outputLength: "0", data: { commandId: "!process", target: stamp } } });
        await app.reply("resultPage", { ok: true, result: { resultId: id, offset: "0", collection: "rows", complete: true, rows } });
        await app.reply("outputChunk", { ok: true, result: { resultId: id, offset: "0", next: "0", complete: true, text: "" } });
        await processStatus(app);
        sortHeader(app, "PID");
        if (id === "second-execution")
        {
            sortHeader(app, "PID");
        }
        app.nodes.get("result-rows").children[0].fire("click");
        columnHandle(app, "PID").fire("keydown", { key: "ArrowRight", shiftKey: true });
        app.nodes.get("result-view").scrollLeft = id === "first-execution" ? 73 : 39;
    }
    assert.equal(app.nodes.get("result-tabs").children.length, 2);
    app.nodes.get("prompt").value = "next draft";
    const executions = app.messages.filter(item => item.method === "execute").length;
    for (const [id, direction, pid, left] of [["first-execution", "ascending", "10", 73], ["second-execution", "descending", "30", 39]])
    {
        resultTab(app, id).button.fire("click");
        await tabReply(app, id, "!process", rows);
        assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, pid);
        assert.equal(app.nodes.get("row-position").textContent, "Sorted by PID (" + direction + ") / Row 1 of 3");
        assert.equal(app.nodes.get("result-view").scrollLeft, left);
        assert.equal(columnHandle(app, "PID").getAttribute("aria-valuenow"), "160");
        assert.equal(resultTab(app, id).button.getAttribute("aria-selected"), "true");
    }
    assert.equal(app.nodes.get("prompt").value, "next draft");
    assert.equal(app.messages.filter(item => item.method === "execute").length, executions);
});

await check("T-UI-TABS each collection retains its selection sort and viewport when another result is active", async () =>
{
    const app = harness();
    await app.boot();
    const rows = [{ pid: "20" }, { pid: "10" }];
    const findings = [{ message: "zulu" }, { message: "alpha" }];
    app.nodes.get("result-id-input").value = "both-collections";
    app.nodes.get("btn-result-load").fire("click");
    await tabReply(app, "both-collections", "!process", rows, findings);
    sortHeader(app, "PID");
    app.nodes.get("result-rows").children[0].fire("click");
    app.nodes.get("result-view").scrollLeft = 61;
    app.nodes.get("result-collection").value = "findings";
    app.nodes.get("result-collection").fire("change");
    await app.reply("resultPage", { ok: true, result: { resultId: "both-collections", collection: "findings",
        offset: "0", complete: true, findings } });
    sortHeader(app, "Message");
    app.nodes.get("result-rows").children[0].fire("click");
    app.nodes.get("result-view").scrollLeft = 94;
    await openTable(app, "other-tab", []);
    resultTab(app, "both-collections").button.fire("click");
    await tabReply(app, "both-collections", "!process", rows, findings);
    assert.equal(app.nodes.get("result-collection").value, "findings");
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).message, "alpha");
    assert.equal(app.nodes.get("result-view").scrollLeft, 94);
    app.nodes.get("result-collection").value = "rows";
    app.nodes.get("result-collection").fire("change");
    await app.reply("resultPage", { ok: true, result: { resultId: "both-collections", collection: "rows",
        offset: "0", complete: true, rows } });
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, "10");
    assert.equal(app.nodes.get("result-view").scrollLeft, 61);
    assert.equal(app.nodes.get("row-position").textContent, "Sorted by PID (ascending) / Row 1 of 2");
});

await check("T-UI-TABS rapid switching and closing reject obsolete metadata and never reopen a closed tab", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "tab-a", []);
    await openTable(app, "tab-b", []);
    await openTable(app, "tab-c", []);
    resultTab(app, "tab-a").button.fire("click");
    const older = app.latest("resultInfo");
    resultTab(app, "tab-b").button.fire("click");
    await tabReply(app, "tab-b", "tab-b", []);
    await app.deliver(older, { ok: true, result: { resultId: "tab-a", rowCount: "0" } });
    assert.equal(app.nodes.get("result-title").textContent, "tab-b");
    const detached = resultTab(app, "tab-a");
    detached.button.fire("click");
    const closing = app.latest("resultInfo");
    detached.close.fire("click");
    await app.deliver(closing, { ok: true, result: { resultId: "tab-a", rowCount: "0" } });
    const requests = app.messages.length;
    detached.button.fire("click");
    assert.equal(app.messages.length, requests);
    assert.equal(app.nodes.get("result-tabs").children.length, 2);
    assert.equal(app.nodes.get("result-title").textContent, "tab-b");
});

await check("T-UI-TABS closing active last and expired tabs preserves stored data without executing commands", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "close-a", []);
    await openTable(app, "close-b", []);
    const executions = app.messages.filter(item => item.method === "execute").length;
    resultTab(app, "close-b").close.fire("click");
    assert.equal(app.latest("resultInfo").params.resultId, "close-a");
    await app.reply("resultInfo", { ok: false, error: "ResultNotFound" });
    assert.equal(app.nodes.get("result-title").textContent, "Debugger workspace");
    assert.match(app.nodes.get("result-notice-text").textContent, /expired or unavailable/);
    resultTab(app, "close-a").button.fire("click");
    await tabReply(app, "close-a", "close-a", []);
    resultTab(app, "close-a").close.fire("click");
    assert.equal(app.nodes.get("result-tabs").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("result-title").textContent, "Debugger workspace");
    assert.equal(app.nodes.get("empty-title").textContent, "Ready to inspect");
    assert.equal(app.nodes.get("result-history").children.length, 3);
    assert.equal(app.messages.filter(item => item.method === "execute").length, executions);
    assert.equal(app.focused().id, "result-table");
});

await check("T-UI-TABS keyboard navigation and target Busy permit browsing but active operations lock tab actions", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "busy-tab-a", []);
    await openTable(app, "busy-tab-b", []);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stamp, stopEpoch: "99" }, { stopped: false, execStatus: "go" });
    assert.equal(resultTab(app, "busy-tab-a").button.disabled, false);
    resultTab(app, "busy-tab-b").button.fire("keydown", { key: "Home" });
    assert.equal(app.latest("resultInfo").params.resultId, "busy-tab-a");
    await tabReply(app, "busy-tab-a", "busy-tab-a", []);
    assert.equal(app.nodes.get("prompt").disabled, true);
    assert.match(app.nodes.get("result-notice-text").textContent, /earlier debugger context/);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    app.enter("!process");
    assert.equal(resultTab(app, "busy-tab-a").button.disabled, true);
    const requests = app.messages.length;
    resultTab(app, "busy-tab-a").button.fire("keydown", { key: "End" });
    resultTab(app, "busy-tab-b").close.fire("click");
    assert.equal(app.messages.length, requests);
    assert.equal(app.nodes.get("result-tabs").children.length, 2);
});

await check("T-UI-TABS retention follows open tabs while delayed failures cannot annotate a newer set", async () =>
{
    const app = harness({ retentionAuto: false });
    await app.boot();
    await openTable(app, "retain-a", []);
    const older = app.latest("resultTabs");
    await openTable(app, "retain-b", []);
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("resultTabs").params.resultIds)), ["retain-a", "retain-b"]);
    await app.reply("resultTabs", { ok: true, result: { missing: [] } });
    await app.deliver(older, { ok: false, error: "obsolete failure" });
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true);
    resultTab(app, "retain-a").close.fire("click");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("resultTabs").params.resultIds)), ["retain-b"]);
    await app.reply("resultTabs", { ok: true, result: { missing: ["retain-b"] } });
    assert.match(app.nodes.get("workspace-feedback-text").textContent, /could not be retained/);
    assert.equal(app.nodes.get("result-title").textContent, "retain-b");
});

await check("T-UI-TABS the open-tab cap refuses a new execution without losing existing results", async () =>
{
    const app = harness();
    await app.boot();
    for (let index = 0; index < 128; ++index)
    {
        await openTable(app, "limited-tab-" + index, []);
    }
    const before = app.messages.length;
    app.enter("!process");
    assert.equal(app.messages.length, before);
    assert.match(app.nodes.get("workspace-feedback-text").textContent, /128 result tabs/);
    assert.equal(app.nodes.get("prompt").value, "!process");
    resultTab(app, "limited-tab-0").button.fire("click");
    await tabReply(app, "limited-tab-0", "limited-tab-0", []);
    resultTab(app, "limited-tab-127").close.fire("click");
    assert.equal(app.latest("resultTabs").params.resultIds.length, 127);
    app.enter("!process");
    assert.equal(app.latest("classify").params.command, "!process");
});

await check("T-UI-TABS late row pages cannot populate a different tab or the closed workspace", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "page-tab-a", []);
    await openTable(app, "page-tab-b", []);
    resultTab(app, "page-tab-a").button.fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "page-tab-a", rowCount: "1", data: { commandId: "page-tab-a", target: stamp } } });
    const older = app.latest("resultPage");
    resultTab(app, "page-tab-b").button.fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "page-tab-b", rowCount: "1", data: { commandId: "page-tab-b", target: stamp } } });
    await app.deliver(older, { ok: true, result: { resultId: "page-tab-a", collection: "rows", offset: "0", complete: true, rows: [{ pid: "1" }] } });
    assert.equal(app.latest("resultPage").params.resultId, "page-tab-b");
    assert.equal(app.nodes.get("result-rows").children.length, 0);
    const closing = app.latest("resultPage");
    resultTab(app, "page-tab-a").close.fire("click");
    resultTab(app, "page-tab-b").close.fire("click");
    await app.deliver(closing, { ok: true, result: { resultId: "page-tab-b", collection: "rows", offset: "0", complete: true, rows: [{ pid: "2" }] } });
    assert.equal(app.nodes.get("result-title").textContent, "Debugger workspace");
    assert.equal(app.nodes.get("result-rows").children.length, 0);
});

await check("T-UI-TABS a scroll event during a restored sort cannot consume its pending viewport", async () =>
{
    const app = harness();
    await app.boot();
    const rows = Array.from({ length: 260 }, (_, index) => ({ pid: String(260 - index) }));
    await openTable(app, "sort-restore-tab", rows.slice(0, 128), { total: 260 });
    sortHeader(app, "PID");
    await app.reply("resultPage", { ok: true, result: { resultId: "sort-restore-tab", collection: "rows",
        offset: "128", next: "256", complete: false, rows: rows.slice(128, 256) } });
    await app.reply("resultPage", { ok: true, result: { resultId: "sort-restore-tab", collection: "rows",
        offset: "256", next: "260", complete: true, rows: rows.slice(256) } });
    sortHeader(app, "PID");
    app.nodes.get("result-rows").children[20].fire("click");
    app.nodes.get("result-view").scrollTop = 560;
    app.nodes.get("result-view").scrollLeft = 73;
    await openTable(app, "sort-restore-other", []);
    resultTab(app, "sort-restore-tab").button.fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "sort-restore-tab", rowCount: "260",
        findingCount: "0", data: { commandId: "sort-restore-tab", target: stamp } } });
    const sortPage = app.latest("resultPage");
    const requests = app.messages.filter(item => item.method === "resultPage").length;
    app.nodes.get("result-view").fire("scroll");
    const viewport = app.latest("resultPage");
    if (viewport !== sortPage)
    {
        const cursor = Number(viewport.params.offset);
        await app.deliver(viewport, { ok: true, result: { resultId: "sort-restore-tab", collection: "rows",
            offset: String(cursor), next: String(cursor + 128), complete: false, rows: rows.slice(cursor, cursor + 128) } });
    }
    await app.deliver(sortPage, { ok: true, result: { resultId: "sort-restore-tab", collection: "rows",
        offset: "0", next: "128", complete: false, rows: rows.slice(0, 128) } });
    await app.reply("resultPage", { ok: true, result: { resultId: "sort-restore-tab", collection: "rows",
        offset: "128", next: "256", complete: false, rows: rows.slice(128, 256) } });
    await app.reply("resultPage", { ok: true, result: { resultId: "sort-restore-tab", collection: "rows",
        offset: "256", next: "260", complete: true, rows: rows.slice(256) } });
    assert.equal(app.nodes.get("result-view").scrollTop, 560);
    assert.equal(app.nodes.get("result-view").scrollLeft, 73);
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, "240");
    assert.equal(app.nodes.get("row-position").textContent, "Sorted by PID (descending) / Row 21 of 260");
    assert.equal(app.messages.filter(item => item.method === "resultPage").length, requests + 2,
        "Restoration must not start an unsorted viewport read while sorting is pending");
});

await check("T-UI-TABS closing an unrelated background tab preserves a pending tab switch", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "pending-tab-a", []);
    await openTable(app, "pending-tab-b", []);
    await openTable(app, "pending-tab-c", []);
    resultTab(app, "pending-tab-a").button.fire("click");
    await tabReply(app, "pending-tab-a", "pending-tab-a", []);
    resultTab(app, "pending-tab-b").button.fire("click");
    const pending = app.latest("resultInfo");
    resultTab(app, "pending-tab-c").close.fire("click");
    await app.deliver(pending, { ok: true, result: { resultId: "pending-tab-b", rowCount: "0",
        findingCount: "0", data: { commandId: "pending-tab-b", target: stamp } } });
    assert.equal(app.nodes.get("result-title").textContent, "pending-tab-b");
    assert.equal(resultTab(app, "pending-tab-b").button.getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("result-tabs").children.length, 2);
});

await check("T-UI-TABMENU closing the right-clicked background tab preserves the active result and draft", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "menu-background", []);
    await openTable(app, "menu-active", [{ pid: "30" }, { pid: "10" }]);
    sortHeader(app, "PID");
    app.nodes.get("result-rows").children[0].fire("click");
    app.nodes.get("result-view").scrollLeft = 73;
    app.nodes.get("prompt").value = "keep draft";
    const before = app.messages.length;
    resultTab(app, "menu-background").element.fire("contextmenu", { clientX: 890, clientY: 710 });
    assert.equal(app.nodes.get("result-title").textContent, "menu-active");
    assert.equal(app.messages.length, before);
    assert.equal(app.focused(), app.nodes.get("result-tab-close-current"));
    app.nodes.get("result-tab-close-current").fire("click");
    assert.equal(app.messages.length, before + 1);
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("resultTabs").params.resultIds)), ["menu-active"]);
    assert.equal(app.nodes.get("result-tabs").children.length, 1);
    assert.equal(app.nodes.get("result-title").textContent, "menu-active");
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, "10");
    assert.equal(app.nodes.get("result-view").scrollLeft, 73);
    assert.equal(app.nodes.get("prompt").value, "keep draft");
    assert.equal(app.focused(), resultTab(app, "menu-active").button);
});

await check("T-UI-TABMENU closing others retains the clicked tab state and rejects the removed pending switch", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "menu-a", []);
    const rows = [{ pid: "30" }, { pid: "10" }, { pid: "20" }];
    await openTable(app, "menu-keep", rows);
    sortHeader(app, "PID");
    app.nodes.get("result-rows").children[0].fire("click");
    app.nodes.get("result-view").scrollLeft = 91;
    await openTable(app, "menu-pending", []);
    await openTable(app, "menu-last", []);
    resultTab(app, "menu-pending").button.fire("click");
    const obsolete = app.latest("resultInfo");
    resultTab(app, "menu-keep").element.fire("contextmenu");
    const before = app.messages.length;
    app.nodes.get("result-tab-close-others").fire("click");
    assert.equal(app.messages.length, before + 2, "Batch close must send one retention update and one result open");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("resultTabs").params.resultIds)), ["menu-keep"]);
    assert.equal(app.latest("resultInfo").params.resultId, "menu-keep");
    await app.deliver(obsolete, { ok: true, result: { resultId: "menu-pending", rowCount: "0" } });
    await tabReply(app, "menu-keep", "menu-keep", rows);
    assert.equal(app.nodes.get("result-tabs").children.length, 1);
    assert.equal(app.nodes.get("result-title").textContent, "menu-keep");
    assert.equal(app.nodes.get("row-position").textContent, "Sorted by PID (ascending) / Row 1 of 3");
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, "10");
    assert.equal(app.nodes.get("result-view").scrollLeft, 91);
    assert.equal(app.messages.some(item => item.method === "execute"), false);
});

await check("T-UI-TABMENU closing all clears the workspace and supersedes an unopened result request", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "menu-all-a", []);
    await openTable(app, "menu-all-b", []);
    app.nodes.get("result-id-input").value = "not-yet-open";
    app.nodes.get("btn-result-load").fire("click");
    const obsolete = app.latest("resultInfo");
    app.nodes.get("prompt").value = "keep all-close draft";
    resultTab(app, "menu-all-a").element.fire("contextmenu");
    const before = app.messages.length;
    app.nodes.get("result-tab-close-all").fire("click");
    assert.equal(app.messages.length, before + 1);
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("resultTabs").params.resultIds)), []);
    assert.equal(app.nodes.get("result-tabs").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("result-title").textContent, "Debugger workspace");
    assert.equal(app.focused(), app.nodes.get("result-table"));
    await app.deliver(obsolete, { ok: true, result: { resultId: "not-yet-open", rowCount: "0" } });
    assert.equal(app.nodes.get("result-tabs").children.length, 0);
    assert.equal(app.nodes.get("result-title").textContent, "Debugger workspace");
    assert.equal(app.nodes.get("prompt").value, "keep all-close draft");
    assert.equal(app.nodes.get("empty-title").textContent, "Ready to inspect");
    assert.equal(app.nodes.get("btn-empty-output").classList.contains("hidden"), true);
    assert.equal(app.messages.some(item => item.method === "execute"), false);
});

await check("T-UI-TABMENU keyboard dismissal singleton actions and Busy gating preserve tab ownership", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "menu-single", []);
    const tab = resultTab(app, "menu-single");
    const title = tab.button.title;
    tab.element.fire("keydown", { key: "F10", shiftKey: true });
    assert.equal(tab.button.title, "");
    assert.equal(tab.close.title, "");
    assert.equal(tab.button.getAttribute("aria-expanded"), "true");
    assert.equal(app.nodes.get("result-tab-close-others").disabled, true);
    const before = app.messages.length;
    app.nodes.get("result-tab-close-others").fire("click");
    assert.equal(app.messages.length, before);
    app.nodes.get("result-tab-menu").fire("keydown", { key: "ArrowDown" });
    assert.equal(app.focused(), app.nodes.get("result-tab-close-all"));
    app.nodes.get("result-tab-menu").fire("keydown", { key: "Escape" });
    assert.equal(app.nodes.get("result-tab-menu").classList.contains("hidden"), true);
    assert.equal(app.focused(), tab.button);
    assert.equal(tab.button.getAttribute("aria-expanded"), "false");
    assert.equal(tab.button.title, title);
    assert.equal(tab.close.title, "Close result tab");
    tab.element.fire("keydown", { key: "ContextMenu" });
    app.documentListeners.get("pointerdown")({ target: app.nodes.get("prompt") });
    assert.equal(app.nodes.get("result-tab-menu").classList.contains("hidden"), true);
    tab.element.fire("contextmenu");
    app.documentListeners.get("focusin")({ target: app.nodes.get("palette-input") });
    assert.equal(app.nodes.get("result-tab-menu").classList.contains("hidden"), true);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stamp, stopEpoch: "99" }, { stopped: false, execStatus: "go" });
    tab.element.fire("contextmenu");
    assert.equal(app.nodes.get("result-tab-menu").classList.contains("hidden"), false);
    app.nodes.get("result-tab-menu").fire("keydown", { key: "Tab" });
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    tab.element.fire("contextmenu");
    app.enter("!process");
    assert.equal(app.nodes.get("result-tab-menu").classList.contains("hidden"), true);
    tab.element.fire("contextmenu");
    assert.equal(app.nodes.get("result-tab-menu").classList.contains("hidden"), true);
    app.nodes.get("result-tab-close-all").fire("click");
    assert.equal(app.nodes.get("result-tabs").children.length, 1);
});

await check("T-UI-TABMENU closing others opens the kept tab after an adjacent result failed to open", async () =>
{
    const app = harness();
    await app.boot();
    const rows = [{ pid: "30" }, { pid: "10" }];
    await openTable(app, "menu-recover-keep", rows);
    sortHeader(app, "PID");
    app.nodes.get("result-rows").children[0].fire("click");
    await openTable(app, "menu-recover-missing", []);
    await openTable(app, "menu-recover-last", []);
    resultTab(app, "menu-recover-last").close.fire("click");
    await app.reply("resultInfo", { ok: false, error: "ResultNotFound" });
    assert.equal(app.nodes.get("result-title").textContent, "Debugger workspace");
    assert.equal(app.nodes.get("result-tabs").children.length, 2);
    resultTab(app, "menu-recover-keep").element.fire("contextmenu");
    app.nodes.get("result-tab-close-others").fire("click");
    assert.equal(app.latest("resultInfo").params.resultId, "menu-recover-keep",
        "The remaining tab must be opened when no result tab is active");
    await tabReply(app, "menu-recover-keep", "menu-recover-keep", rows);
    assert.equal(app.nodes.get("result-tabs").children.length, 1);
    assert.equal(resultTab(app, "menu-recover-keep").button.getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("row-position").textContent, "Sorted by PID (ascending) / Row 1 of 2");
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, "10");
    assert.equal(app.messages.some(item => item.method === "execute"), false);
    await openTable(app, "menu-recover-other", []);
    app.enter("results");
    await app.reply("classify", { ok: true, result: { write: false } });
    await app.reply("execute", { ok: true, result: { command: "results", ephemeral: true,
        output: "Stored results", data: { commandId: "results", status: "Success", target: stamp } } });
    await processStatus(app);
    assert.equal(app.nodes.get("result-title").textContent, "results");
    resultTab(app, "menu-recover-keep").element.fire("contextmenu");
    app.nodes.get("result-tab-close-others").fire("click");
    assert.equal(app.latest("resultInfo").params.resultId, "menu-recover-keep");
    await tabReply(app, "menu-recover-keep", "menu-recover-keep", rows);
    assert.equal(resultTab(app, "menu-recover-keep").button.getAttribute("aria-selected"), "true");
    assert.equal(app.messages.filter(item => item.method === "execute").length, 1);
});

await check("T-UI-TABMENU cancelling a result open clears its loading status and rejects late success or failure", async () =>
{
    for (const action of ["current", "others", "all"])
    {
        for (const failed of [false, true])
        {
            const app = harness();
            await app.boot();
            await openTable(app, "menu-cancel-a", []);
            await openTable(app, "menu-cancel-b", []);
            resultTab(app, "menu-cancel-a").button.fire("click");
            await tabReply(app, "menu-cancel-a", "menu-cancel-a", []);
            resultTab(app, "menu-cancel-b").button.fire("click");
            const pending = app.latest("resultInfo");
            assert.equal(app.nodes.get("result-load-status").textContent, "Opening result...");
            resultTab(app, action === "current" ? "menu-cancel-b" : "menu-cancel-a").element.fire("contextmenu");
            app.nodes.get("result-tab-close-" + action).fire("click");
            assert.equal(app.nodes.get("result-load-status").textContent, "", action + " left a cancelled open pending");
            await app.deliver(pending, failed ? { ok: false, error: "ResultNotFound" } :
                { ok: true, result: { resultId: "menu-cancel-b", rowCount: "0" } });
            assert.equal(app.nodes.get("result-load-status").textContent, "");
            assert.equal(app.nodes.get("result-title").textContent, action === "all" ? "Debugger workspace" : "menu-cancel-a");
            assert.equal(app.nodes.get("result-tabs").children.length, action === "all" ? 0 : 1);
        }
    }
});

function tabDragLayout(app, width = 600)
{
    const strip = app.nodes.get("result-tabs");
    strip.clientWidth = width;
    strip.scrollWidth = strip.children.length * 100;
    strip.getBoundingClientRect = () => ({ left: 0, right: width, top: 0, bottom: 40 });
    for (const element of strip.children)
    {
        element.getBoundingClientRect = () =>
        {
            const left = strip.children.indexOf(element) * 100 - strip.scrollLeft;
            return { left, right: left + 100, top: 0, bottom: 40 };
        };
    }
}

function tabPointer(app, name, x, y = 20, pointerId = 21)
{
    app.documentListeners.get(name)({ pointerId, clientX: x, clientY: y, preventDefault: noop });
}

function tabOrder(app)
{
    return app.nodes.get("result-tabs").children.map(element => element.children[0].title.split(" / ").at(-1));
}

function tabNameInput(tab)
{
    return tab.element.children.find(item => item.classList.contains("result-tab-name"));
}

await check("T-UI-TABNAME repeated commands retain independent names views and result identities without host writes", async () =>
{
    const app = harness();
    await app.boot();
    const rows = [{ pid: "30" }, { pid: "10" }, { pid: "20" }];
    for (const id of ["rename-first", "rename-second"])
    {
        await openTable(app, "!process", rows, { id });
        sortHeader(app, "PID");
        if (id === "rename-second")
        {
            sortHeader(app, "PID");
        }
        app.nodes.get("result-rows").children[0].fire("click");
        app.nodes.get("result-view").scrollTop = id === "rename-first" ? 12 : 8;
        app.nodes.get("result-view").scrollLeft = id === "rename-first" ? 73 : 39;
    }
    app.nodes.get("prompt").value = "keep rename draft";
    const first = resultTab(app, "rename-first");
    const second = resultTab(app, "rename-second");
    const activeRows = app.nodes.get("result-rows").children;
    const requests = app.messages.length;
    second.button.fire("click", { detail: 1 });
    second.button.fire("click", { detail: 2 });
    second.button.fire("dblclick", { button: 0 });
    const input = tabNameInput(second);
    assert.equal(app.focused(), input);
    assert.equal(input.selectedText, "!process");
    input.value = "  after <&> \uafc0\ubcf4  ";
    input.fire("keydown", { key: "Enter" });
    assert.equal(tabNameInput(second), undefined);
    assert.equal(second.button.children[0].textContent, "after <&> \uafc0\ubcf4");
    assert.equal(second.button.getAttribute("aria-label"), "after <&> \uafc0\ubcf4 / rename-s");
    assert.equal(second.close.getAttribute("aria-label"), "Close result: after <&> \uafc0\ubcf4 / rename-s");
    assert.equal(second.button.title, "after <&> \uafc0\ubcf4\n!process / rename-second");
    assert.equal(app.focused(), second.button);
    first.button.fire("keydown", { key: "F2" });
    tabNameInput(first).value = "before";
    tabNameInput(first).fire("blur");
    assert.equal(first.button.children[0].textContent, "before");
    assert.equal(second.button.getAttribute("aria-selected"), "true");
    first.button.fire("keydown", { key: "ArrowRight", ctrlKey: true, shiftKey: true });
    assert.deepEqual(tabOrder(app), ["rename-second", "rename-first"]);
    assert.equal(app.nodes.get("result-rows").children, activeRows);
    assert.equal(app.messages.length, requests, "Naming and reordering must not query, execute or change retention");
    for (const [tab, direction, pid, top, left, name] of [[first, "ascending", "10", 12, 73, "before"],
        [second, "descending", "30", 8, 39, "after <&> \uafc0\ubcf4"]])
    {
        tab.button.fire("click", { detail: 0 });
        await tabReply(app, tab === first ? "rename-first" : "rename-second", "!process", rows);
        assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, pid);
        assert.equal(app.nodes.get("row-position").textContent, "Sorted by PID (" + direction + ") / Row 1 of 3");
        assert.equal(app.nodes.get("result-view").scrollTop, top);
        assert.equal(app.nodes.get("result-view").scrollLeft, left);
        assert.equal(tab.button.children[0].textContent, name);
        assert.equal(app.nodes.get("result-title").textContent, "!process");
    }
    assert.equal(app.nodes.get("prompt").value, "keep rename draft");
    assert.equal(app.messages.some(request => request.method === "execute"), false);
});

await check("T-UI-WORKSPACE hide and show retain renamed reordered tabs and independent views without replay", async () =>
{
    const app = harness();
    await app.boot();
    const rows = [{ pid: "30" }, { pid: "10" }, { pid: "20" }];
    for (const [index, id] of ["persist-first", "persist-second"].entries())
    {
        await openTable(app, "!process", rows, { id });
        sortHeader(app, "PID");
        if (index)
        {
            sortHeader(app, "PID");
        }
        app.nodes.get("result-rows").children[0].fire("click");
        app.nodes.get("result-view").scrollTop = index ? 8 : 12;
        app.nodes.get("result-view").scrollLeft = index ? 39 : 73;
        const tab = resultTab(app, id);
        tab.button.fire("keydown", { key: "F2" });
        tabNameInput(tab).value = "Saved " + index;
        tabNameInput(tab).fire("keydown", { key: "Enter" });
    }
    const first = resultTab(app, "persist-first");
    const second = resultTab(app, "persist-second");
    first.button.fire("keydown", { key: "ArrowRight", ctrlKey: true, shiftKey: true });
    const activeRows = app.nodes.get("result-rows").children;
    const retention = app.messages.filter(request => request.method === "resultTabs").length;
    const before = app.messages.length;
    app.visibility(true);
    app.advanceTime(10000);
    assert.equal(app.messages.length, before, "Hidden workspaces must not poll");
    app.visibility(false);
    assert.equal(app.nodes.get("prompt").disabled, true, "Reopening must lock commands until fresh status arrives");
    assert.equal(app.messages.length, before + 1);
    assert.equal(app.latest("status"), app.messages.at(-1), "Reopening must refresh current status only");
    await app.reply("status", { ok: true, result: { connected: true, stopped: true, target: stamp } });
    assert.equal(app.nodes.get("result-rows").children, activeRows);
    assert.deepEqual(tabOrder(app), ["persist-second", "persist-first"]);
    for (const [tab, id, direction, pid, top, left, name] of [
        [first, "persist-first", "ascending", "10", 12, 73, "Saved 0"],
        [second, "persist-second", "descending", "30", 8, 39, "Saved 1"]])
    {
        tab.button.fire("click");
        await tabReply(app, id, "!process", rows);
        assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, pid);
        assert.equal(app.nodes.get("row-position").textContent, "Sorted by PID (" + direction + ") / Row 1 of 3");
        assert.equal(app.nodes.get("result-view").scrollTop, top);
        assert.equal(app.nodes.get("result-view").scrollLeft, left);
        assert.equal(tab.button.children[0].textContent, name);
    }
    assert.equal(app.messages.filter(request => request.method === "resultTabs").length, retention);
    assert.equal(app.messages.some(request => request.method === "execute"), false);
});

await check("T-UI-WORKSPACE a late hidden status waits for visibility before following the current stop", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-refresh-status").fire("click");
    app.visibility(true);
    const target = { ...stamp, stopEpoch: "3" };
    const status = { connected: true, stopped: true, target, instructionPointer: "0xffff800000001000" };
    await app.reply("status", { ok: true, result: status });
    assert.equal(app.messages.some(request => request.method === "disassemblyRead"), false);
    const before = app.messages.length;
    app.advanceTime(10000);
    assert.equal(app.messages.length, before);
    app.visibility(false);
    await app.reply("status", { ok: true, result: status });
    assert.equal(app.messages.filter(request => request.method === "disassemblyRead").length, 1);
});

await check("T-UI-WORKSPACE pre-hide status cannot unlock commands after reopening", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-refresh-status").fire("click");
    const old = app.latest("status");
    app.visibility(true);
    app.visibility(false);
    const fresh = app.latest("status");
    assert.notEqual(old, fresh);
    await app.deliver(old, { ok: true, result: { connected: true, stopped: true, target: stamp } });
    assert.equal(app.nodes.get("prompt").disabled, true);
    await app.deliver(fresh, { ok: true, result: { connected: true, stopped: false, target: stamp } });
    assert.equal(app.nodes.get("prompt").disabled, true);
    assert.equal(app.nodes.get("command-phase").textContent, "Busy");
});

await check("T-UI-WORKSPACE reopening locks memory disassembly and Inspector reads until fresh status", async () =>
{
    const app = await disassemblyApp();
    await openTable(app, "workspace-address", [{ address: "0xffff800000002000", addressSpace: "virtual", sourceFile: "fixture.cpp" }]);
    app.nodes.get("result-rows").children[0].fire("click");
    const actions = ["btn-memory-read", "btn-disassembly-read", "btn-disassembly-ip", "btn-disassemble"];
    for (const id of actions)
    {
        assert.equal(app.nodes.get(id).disabled, false, id + " is unavailable before hiding");
    }
    app.visibility(true);
    app.visibility(false);
    const before = app.messages.length;
    for (const id of actions)
    {
        assert.equal(app.nodes.get(id).disabled, true, id + " remained actionable before fresh status");
        app.nodes.get(id).fire("click");
    }
    assert.equal(app.messages.length, before);
    await processStatus(app);
    for (const id of actions)
    {
        assert.equal(app.nodes.get(id).disabled, false, id + " did not recover after fresh stopped status");
    }
});

await check("T-UI-WORKSPACE reopening locks retained process actions and refresh until fresh status", async () =>
{
    const app = harness();
    await app.boot();
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, [{ kind: "Process", eprocess: "0xffff800000001000", pid: "4", image: "System",
        createTime: "1234", dtb: "0x1000" }]);
    app.nodes.get("process-rows").children[0].fire("click");
    const actions = ["refresh", "details", "threads", "vad", "token", "attach"].map(name => "btn-process-" + name);
    for (const id of actions)
    {
        assert.equal(app.nodes.get(id).disabled, false, id + " is unavailable before hiding");
    }
    app.visibility(true);
    app.visibility(false);
    const before = app.messages.length;
    for (const id of actions)
    {
        assert.equal(app.nodes.get(id).disabled, true, id + " remained actionable before fresh status");
        app.nodes.get(id).fire("click");
    }
    assert.equal(app.messages.length, before);
    await processStatus(app);
    for (const id of actions)
    {
        assert.equal(app.nodes.get(id).disabled, false, id + " did not recover after fresh stopped status");
    }
});

await check("T-UI-TABNAME cancellation IME literal names limits and reset preserve the original command", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [], { id: "rename-input" });
    const tab = resultTab(app, "rename-input");
    tab.button.fire("keydown", { key: "F2" });
    let input = tabNameInput(tab);
    input.value = "\uad6c\ubd84";
    input.fire("compositionstart");
    for (const event of [{ key: "Enter" }, { key: "Escape" }, { key: "Enter", isComposing: true }, { key: "Enter", keyCode: 229 }])
    {
        input.fire("keydown", event);
        assert.equal(tabNameInput(tab), input);
    }
    input.fire("compositionend");
    input.fire("keydown", { key: "Enter" });
    assert.equal(tab.button.children[0].textContent, "\uad6c\ubd84");
    tab.button.fire("keydown", { key: "F2" });
    input = tabNameInput(tab);
    input.value = "discard this";
    input.fire("keydown", { key: "Escape" });
    assert.equal(tab.button.children[0].textContent, "\uad6c\ubd84");
    assert.equal(app.focused(), tab.button);
    input.fire("blur");
    assert.equal(tab.button.children[0].textContent, "\uad6c\ubd84");
    tab.button.fire("keydown", { key: "F2" });
    input = tabNameInput(tab);
    input.value = "<img src=x onerror=alert(1)>\u0000tail";
    input.fire("blur");
    assert.equal(tab.button.children[0].textContent, "<img src=x onerror=alert(1)> tail");
    assert.equal(tab.button.children[0].children.length, 0);
    tab.button.fire("keydown", { key: "F2" });
    input = tabNameInput(tab);
    assert.equal(input.maxLength, 128);
    input.value = "a".repeat(127) + "\ud83d\ude00";
    input.fire("keydown", { key: "Enter" });
    assert.equal(tab.button.children[0].textContent, "a".repeat(127));
    tab.button.fire("keydown", { key: "F2" });
    input = tabNameInput(tab);
    input.value = "  \t  ";
    input.fire("keydown", { key: "Enter" });
    assert.equal(tab.button.children[0].textContent, "!callbacks");
    assert.equal(tab.button.title, "!callbacks / rename-input");
});

await check("T-UI-TABNAME pending opens Busy and closed editors cannot revive a tab or lose its identity", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [], { id: "rename-pending" });
    await openTable(app, "!callbacks", [], { id: "rename-current" });
    const tab = resultTab(app, "rename-pending");
    tab.button.fire("click", { detail: 1 });
    const pending = app.latest("resultInfo");
    tab.button.fire("click", { detail: 2 });
    assert.equal(app.latest("resultInfo"), pending);
    tab.button.fire("dblclick", { button: 0 });
    let input = tabNameInput(tab);
    input.value = "pending name";
    await app.deliver(pending, { ok: true, result: { resultId: "rename-pending", command: "!callbacks", rowCount: "0" } });
    assert.equal(tabNameInput(tab), input, "The first click's late metadata must not remove the editor");
    input.fire("keydown", { key: "Enter" });
    assert.equal(tab.button.children[0].textContent, "pending name");
    tab.button.fire("keydown", { key: "F2" });
    input = tabNameInput(tab);
    input.value = "saved before command";
    app.enter("!process");
    assert.equal(tabNameInput(tab), undefined);
    assert.equal(tab.button.children[0].textContent, "saved before command");
    tab.button.fire("dblclick", { button: 0 });
    tab.button.fire("keydown", { key: "F2" });
    assert.equal(tabNameInput(tab), undefined, "Busy must not open an editor");
    await app.reply("classify", { ok: true, result: { write: false } });
    await app.reply("execute", { ok: true, result: { resultId: "rename-new", command: "!process", rowCount: "0" } });
    await app.reply("outputChunk", { ok: true, result: { resultId: "rename-new", offset: "0", next: "0", complete: true, text: "" } });
    tab.button.fire("keydown", { key: "F2" });
    input = tabNameInput(tab);
    assert.ok(input);
    tab.close.fire("click");
    input.value = "late discarded name";
    input.fire("keydown", { key: "Enter" });
    input.fire("blur");
    assert.equal(app.nodes.get("result-tabs").children.includes(tab.element), false);
    assert.equal(app.nodes.get("result-title").textContent, "!process");
    assert.equal(app.nodes.get("result-tabs").children.some(item => item.children.some(child => child.classList.contains("result-tab-name"))), false);
});

await check("T-UI-TABNAME another tab's delayed metadata leaves the focused name draft editable", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [], { id: "rename-race-a" });
    await openTable(app, "!callbacks", [], { id: "rename-race-b" });
    const first = resultTab(app, "rename-race-a");
    const second = resultTab(app, "rename-race-b");
    first.button.fire("click", { detail: 1 });
    const pending = app.latest("resultInfo");
    second.button.fire("keydown", { key: "F2" });
    const input = tabNameInput(second);
    input.value = "unfinished \uad6c\ubd84";
    await app.deliver(pending, { ok: true, result: { resultId: "rename-race-a", command: "!callbacks", rowCount: "0" } });
    assert.equal(tabNameInput(second), input, "Unrelated metadata committed and removed the focused editor");
    assert.equal(app.focused(), input);
    assert.equal(first.button.getAttribute("aria-selected"), "true");
    input.value += " complete";
    input.fire("keydown", { key: "Enter" });
    assert.equal(second.button.children[0].textContent, "unfinished \uad6c\ubd84 complete");
    assert.equal(first.button.getAttribute("aria-selected"), "true");
    assert.equal(app.messages.some(request => request.method === "execute"), false);
});

await check("T-UI-TABNAME clicking the active named tab retries failed row metadata and sort reads", async () =>
{
    for (const failure of ["rows", "metadata", "sort"])
    {
        const app = harness();
        await app.boot();
        const rows = Array.from({ length: failure === "sort" ? 129 : 1 }, () => ({ pid: "4" }));
        app.nodes.get("result-id-input").value = "rename-retry";
        app.nodes.get("btn-result-load").fire("click");
        await app.reply("resultInfo", { ok: true, result: { resultId: "rename-retry", command: "!process", rowCount: String(rows.length),
            data: { commandId: "!process", target: stamp } } });
        await app.reply("resultPage", failure === "rows" ? { ok: false, error: "TransientFailure" } :
            { ok: true, result: { resultId: "rename-retry", offset: "0", complete: rows.length <= 128, rows: rows.slice(0, 128) } });
        if (failure === "sort")
        {
            sortHeader(app, "PID");
            await app.reply("resultPage", { ok: false, error: "TransientFailure" });
            assert.ok(app.nodes.get("result-notice-text").textContent.includes("Sort could not be applied"));
        }
        const tab = resultTab(app, "rename-retry");
        tab.button.fire("keydown", { key: "F2" });
        tabNameInput(tab).value = "retry named result";
        tabNameInput(tab).fire("keydown", { key: "Enter" });
        if (failure === "metadata")
        {
            app.nodes.get("result-id-input").value = "unavailable-other-result";
            app.nodes.get("btn-result-load").fire("click");
            await app.reply("resultInfo", { ok: false, error: "ResultNotFound" });
        }
        const requests = app.messages.filter(request => request.method === "resultInfo").length;
        tab.button.fire("click", { detail: 1 });
        assert.equal(app.messages.filter(request => request.method === "resultInfo").length, requests + 1,
            "An active tab with a " + failure + " error must allow a fresh stored-result read");
        await app.reply("resultInfo", { ok: true, result: { resultId: "rename-retry", command: "!process", rowCount: String(rows.length),
            data: { commandId: "!process", target: stamp } } });
        await app.reply("resultPage", { ok: true, result: { resultId: "rename-retry", offset: "0",
            complete: rows.length <= 128, rows: rows.slice(0, 128) } });
        assert.equal(tab.button.children[0].textContent, "retry named result");
        assert.equal(tableCell(app, 0, "PID"), "4");
        assert.equal(app.nodes.get("result-notice-text").textContent.includes("unavailable"), false);
        assert.equal(app.messages.some(request => request.method === "execute"), false);
    }
});

await check("T-UI-TABDRAG moving background and active tabs preserves independent views without reloading", async () =>
{
    const app = harness();
    await app.boot();
    const rows = [{ pid: "30" }, { pid: "10" }, { pid: "20" }];
    for (const id of ["drag-first", "drag-second"])
    {
        await openTable(app, id, rows);
        sortHeader(app, "PID");
        if (id === "drag-second")
        {
            sortHeader(app, "PID");
        }
        app.nodes.get("result-rows").children[0].fire("click");
        columnHandle(app, "PID").fire("keydown", { key: "ArrowRight", shiftKey: true });
        app.nodes.get("result-view").scrollLeft = id === "drag-first" ? 73 : 39;
        app.nodes.get("result-view").scrollTop = id === "drag-first" ? 12 : 8;
    }
    tabDragLayout(app);
    app.nodes.get("prompt").value = "keep drag draft";
    const first = resultTab(app, "drag-first");
    const second = resultTab(app, "drag-second");
    const activeRows = app.nodes.get("result-rows").children;
    const requests = app.messages.length;
    for (const tab of [first, second])
    {
        tab.button.focus();
        tab.button.fire("pointerdown", { pointerId: 21, button: 0, clientX: 50, clientY: 20 });
        tabPointer(app, "pointermove", 250);
        tabPointer(app, "pointerup", 250);
        tab.button.fire("click", { detail: 1 });
        assert.equal(app.focused(), tab.button);
        assert.equal(app.nodes.get("result-rows").children, activeRows);
        assert.equal(app.nodes.get("result-title").textContent, "drag-second");
        assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, "30");
        assert.equal(app.nodes.get("result-view").scrollLeft, 39);
        assert.equal(app.nodes.get("result-view").scrollTop, 8);
    }
    assert.deepEqual(tabOrder(app), ["drag-first", "drag-second"]);
    assert.equal(app.messages.length, requests, "Reordering must not reload or change host retention");
    for (const [id, direction, pid, left, top] of [["drag-first", "ascending", "10", 73, 12], ["drag-second", "descending", "30", 39, 8]])
    {
        resultTab(app, id).button.fire("click", { detail: 0 });
        await tabReply(app, id, id, rows);
        assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, pid);
        assert.equal(app.nodes.get("row-position").textContent, "Sorted by PID (" + direction + ") / Row 1 of 3");
        assert.equal(app.nodes.get("result-view").scrollLeft, left);
        assert.equal(app.nodes.get("result-view").scrollTop, top);
        assert.equal(columnHandle(app, "PID").getAttribute("aria-valuenow"), "160");
    }
    assert.equal(app.nodes.get("prompt").value, "keep drag draft");
    assert.equal(app.messages.some(request => request.method === "execute"), false);
});

await check("T-UI-TABDRAG moving a pending tab keeps its response valid and closing uses the new order", async () =>
{
    const app = harness();
    await app.boot();
    for (const id of ["drag-pending-a", "drag-pending-b", "drag-pending-c"])
    {
        await openTable(app, id, []);
    }
    tabDragLayout(app);
    const pendingTab = resultTab(app, "drag-pending-b");
    pendingTab.button.fire("click");
    const pending = app.latest("resultInfo");
    const requests = app.messages.length;
    pendingTab.button.fire("pointerdown", { pointerId: 21, button: 0, clientX: 150, clientY: 20 });
    tabPointer(app, "pointermove", 5);
    tabPointer(app, "pointerup", 5);
    pendingTab.button.fire("click", { detail: 1 });
    assert.deepEqual(tabOrder(app), ["drag-pending-b", "drag-pending-a", "drag-pending-c"]);
    assert.equal(app.messages.length, requests);
    assert.equal(app.nodes.get("result-load-status").textContent, "Opening result...");
    await app.deliver(pending, { ok: true, result: { resultId: "drag-pending-b", rowCount: "0" } });
    assert.equal(pendingTab.button.getAttribute("aria-selected"), "true");
    pendingTab.close.fire("click");
    assert.equal(app.latest("resultInfo").params.resultId, "drag-pending-a");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("resultTabs").params.resultIds)), ["drag-pending-a", "drag-pending-c"]);
});

await check("T-UI-TABDRAG cancellation outside escape capture loss focus blur resize and Busy never reorder", async () =>
{
    for (const reason of ["outside", "escape", "capture", "cancel", "focus", "blur", "resize", "busy", "close"])
    {
        const app = harness();
        await app.boot();
        await openTable(app, "drag-cancel-a", []);
        await openTable(app, "drag-cancel-b", []);
        tabDragLayout(app);
        const tab = resultTab(app, "drag-cancel-a");
        tab.button.fire("pointerdown", { pointerId: 21, button: 0, clientX: 50, clientY: 20 });
        tabPointer(app, "pointermove", 250);
        assert.equal(tab.element.classList.contains("drag-source"), true, reason);
        if (reason === "escape")
        {
            app.documentListeners.get("keydown")({ key: "Escape", preventDefault: noop, stopPropagation: noop });
        }
        else if (reason === "capture")
        {
            tab.button.fire("lostpointercapture");
        }
        else if (reason === "cancel")
        {
            tabPointer(app, "pointercancel", 250);
        }
        else if (reason === "focus")
        {
            app.documentListeners.get("focusin")({ target: app.nodes.get("prompt") });
        }
        else if (reason === "blur" || reason === "resize")
        {
            app.windowEvent(reason);
        }
        else if (reason === "busy")
        {
            app.enter("!process");
        }
        else if (reason === "close")
        {
            resultTab(app, "drag-cancel-b").close.fire("click");
        }
        tabPointer(app, "pointerup", 250, reason === "outside" ? 60 : 20);
        tab.button.fire("click", { detail: 1 });
        assert.equal(tab.element.classList.contains("drag-source"), false, reason);
        assert.equal(app.nodes.get("result-tabs").classList.contains("reordering"), false, reason);
        assert.deepEqual(tabOrder(app), reason === "close" ? ["drag-cancel-a"] : ["drag-cancel-a", "drag-cancel-b"], reason);
        assert.equal(app.nodes.get("result-tabs").children.some(item => item.classList.contains("drop-before") || item.classList.contains("drop-after")), false);
    }
});

await check("T-UI-TABDRAG threshold pointer identity and keyboard moves preserve active result", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "drag-input-a", []);
    await openTable(app, "drag-input-b", []);
    tabDragLayout(app);
    const tab = resultTab(app, "drag-input-a");
    for (const extra of [{ button: 2 }, { isPrimary: false }, { clientX: NaN }])
    {
        tab.button.fire("pointerdown", { pointerId: 21, button: 0, clientX: 50, clientY: 20, ...extra });
        tabPointer(app, "pointermove", 250);
        tabPointer(app, "pointerup", 250);
        assert.deepEqual(tabOrder(app), ["drag-input-a", "drag-input-b"]);
    }
    tab.button.fire("pointerdown", { pointerId: 21, button: 0, clientX: 50, clientY: 20 });
    tabPointer(app, "pointermove", 250, 20, 22);
    tabPointer(app, "pointerup", 250, 20, 22);
    tabPointer(app, "pointerup", 53);
    assert.deepEqual(tabOrder(app), ["drag-input-a", "drag-input-b"]);
    tab.button.fire("click", { detail: 1 });
    assert.equal(app.latest("resultInfo").params.resultId, "drag-input-a");
    await tabReply(app, "drag-input-a", "drag-input-a", []);
    tab.button.focus();
    const requests = app.messages.length;
    tab.button.fire("keydown", { key: "ArrowRight", ctrlKey: true, shiftKey: true });
    assert.deepEqual(tabOrder(app), ["drag-input-b", "drag-input-a"]);
    tab.button.fire("keydown", { key: "ArrowRight", ctrlKey: true, shiftKey: true });
    assert.deepEqual(tabOrder(app), ["drag-input-b", "drag-input-a"]);
    tab.button.fire("keydown", { key: "ArrowLeft", ctrlKey: true, shiftKey: true });
    assert.deepEqual(tabOrder(app), ["drag-input-a", "drag-input-b"]);
    assert.equal(app.focused(), tab.button);
    assert.equal(tab.button.getAttribute("aria-selected"), "true");
    assert.equal(app.messages.length, requests);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stamp, stopEpoch: "99" }, { stopped: false, execStatus: "go" });
    tab.button.fire("keydown", { key: "ArrowRight", ctrlKey: true, shiftKey: true });
    assert.deepEqual(tabOrder(app), ["drag-input-b", "drag-input-a"]);
});

await check("T-UI-TABDRAG edge scrolling reaches hidden tabs and releases its timer after drop", async () =>
{
    const app = harness();
    await app.boot();
    for (const id of ["drag-edge-a", "drag-edge-b", "drag-edge-c", "drag-edge-d", "drag-edge-e"])
    {
        await openTable(app, id, []);
    }
    tabDragLayout(app, 200);
    const tab = resultTab(app, "drag-edge-a");
    const requests = app.messages.length;
    tab.button.fire("pointerdown", { pointerId: 21, button: 0, clientX: 50, clientY: 20 });
    tabPointer(app, "pointermove", 195);
    for (let tick = 0; tick < 25; ++tick)
    {
        for (const [id, callback] of [...app.timers])
        {
            if (app.timerDelays.get(id) === 32)
            {
                app.timers.delete(id);
                app.timerDelays.delete(id);
                callback();
            }
        }
    }
    assert.equal(app.nodes.get("result-tabs").scrollLeft, 300);
    tabPointer(app, "pointerup", 195);
    assert.deepEqual(tabOrder(app), ["drag-edge-b", "drag-edge-c", "drag-edge-d", "drag-edge-e", "drag-edge-a"]);
    assert.equal([...app.timers.keys()].some(id => app.timerDelays.get(id) === 32), false);
    assert.equal(app.messages.length, requests);
});

await check("T-UI-TABDRAG continuous edge movement scrolls while updates and direction changes use the current viewport", async () =>
{
    const app = harness();
    await app.boot();
    for (const id of ["edge-motion-a", "edge-motion-b", "edge-motion-c", "edge-motion-d", "edge-motion-e"])
    {
        await openTable(app, id, []);
    }
    tabDragLayout(app, 200);
    const strip = app.nodes.get("result-tabs");
    const tab = resultTab(app, "edge-motion-a");
    const requests = app.messages.length;
    tab.button.fire("pointerdown", { pointerId: 21, button: 0, clientX: 50, clientY: 20 });
    for (let move = 0; move < 80; ++move)
    {
        tabPointer(app, "pointermove", 195, 20 + move % 2);
        app.advanceTime(8);
    }
    assert.equal(strip.scrollLeft, 300, "Continuous pointer input must not starve edge scrolling");
    strip.scrollLeft = 100;
    tabPointer(app, "pointermove", 195);
    strip.scrollLeft = 220;
    app.windowEvent("scroll", { target: strip });
    assert.equal(resultTab(app, "edge-motion-e").element.classList.contains("drop-before"), true,
        "External strip scrolling must update the insertion marker before the next pointer event");
    app.advanceTime(32);
    assert.equal(strip.scrollLeft, 236, "A pending tick must advance from the newer viewport instead of jumping backward");
    tabPointer(app, "pointermove", 5);
    app.advanceTime(32);
    assert.equal(strip.scrollLeft, 220, "A pending tick must use the newest edge direction");
    tabPointer(app, "pointermove", 100);
    app.advanceTime(64);
    assert.equal(strip.scrollLeft, 220, "Leaving the edge must stop scrolling");
    tabPointer(app, "pointercancel", 100);
    app.advanceTime(64);
    assert.equal(app.messages.length, requests);
    assert.deepEqual(tabOrder(app), ["edge-motion-a", "edge-motion-b", "edge-motion-c", "edge-motion-d", "edge-motion-e"]);
});

await check("T-UI-TABDRAG releasing a short press outside or cancelling before the threshold does not activate the tab", async () =>
{
    for (const action of ["outside", "escape", "focus", "capture"])
    {
        const app = harness();
        await app.boot();
        await openTable(app, "short-press-a", []);
        await openTable(app, "short-press-b", []);
        tabDragLayout(app);
        const tab = resultTab(app, "short-press-a");
        tab.button.getBoundingClientRect = () => ({ left: 0, right: 100, top: 0, bottom: 40 });
        const requests = app.messages.length;
        tab.button.fire("pointerdown", { pointerId: 21, button: 0, clientX: 50, clientY: 38 });
        if (action === "escape")
        {
            app.documentListeners.get("keydown")({ key: "Escape", preventDefault: noop, stopPropagation: noop });
        }
        else if (action === "focus")
        {
            app.documentListeners.get("focusin")({ target: app.nodes.get("prompt") });
        }
        else if (action === "capture")
        {
            tab.button.fire("lostpointercapture");
        }
        tabPointer(app, "pointerup", 50, action === "outside" ? 42 : 38);
        tab.button.fire("click", { detail: 1 });
        assert.equal(app.messages.length, requests, action + " must not issue a result read after cancellation");
        assert.equal(app.nodes.get("result-title").textContent, "short-press-b");
        tab.button.fire("pointerdown", { pointerId: 21, button: 0, clientX: 50, clientY: 20 });
        tabPointer(app, "pointerup", 53, 20);
        tab.button.fire("click", { detail: 1 });
        assert.equal(app.latest("resultInfo").params.resultId, "short-press-a", "The next ordinary click must still work");
    }
});

await check("T-UI-COLUMNS command-specific fields replace fixed summaries for debugger and kernel records", async () =>
{
    const app = harness();
    await app.boot();
    const examples = [
        ["!callbacks", { kind: "RoutineObservation", family: "ProcessNotify", slot: "0xffff800000001000", routine: "0xffff800000002008", module: "sample", ownership: "KnownModule", layoutSource: "MatchedPdb" }, ["Routine", "Module", "Family", "Ownership", "Slot"]],
        ["!process", { kind: "Process", eprocess: "0xffff800000001000", pid: "4", image: "System", dtb: "0x1000", createTime: "123" }, ["EPROCESS", "PID", "Image", "DTB", "Create Time"]],
        ["lm", { name: "sample.sys", base: "0xffff800000002000", size: "4096", timestamp: "0x123", symbolType: "3" }, ["Name", "Base", "Size", "Timestamp", "Symbol Type"]],
        ["stack", { kind: "StackFrame", index: "0", address: "0xffff800000002008", symbol: "sample!Start", stack: "0xffff80000000f000", return: "0xffff800000003000", context: { process: "4" } }, ["Index", "Address", "Symbol", "Stack", "Return"]],
        ["registers", { kind: "Register", name: "rax", type: "4", rawBytes: "00 00 00 00 00 00 00 00", context: { process: "4" } }, ["Name", "Raw bytes", "Type"]],
        ["!drvobj", { kind: "DriverDispatch", driverObject: "0xffff800000001000", major: "14", handler: "0xffff800000002000", ownership: "sample.sys" }, ["Major", "Handler", "Ownership", "Driver Object"]],
        ["!idt", { kind: "IdtGate", cpu: "0", vector: "14", family: "IDT", routine: "0xffff800000002000", module: "nt", ownership: "KnownModule", present: true }, ["CPU", "Vector", "Routine", "Module", "Ownership", "Present", "Family"]],
        ["!etw", { kind: "EtwLoggerContext", loggerId: "2", name: "Logger", object: "0xffff800000002000", clockType: "Selector", rawClock: "0x1", clockRepresentation: "Qpc" }, ["Name", "Logger ID", "Clock Type", "Raw Clock", "Object", "Clock Representation"]],
        ["!vad", { kind: "Vad", object: "0xffff800000004000", start: "0x10000", end: "0x11000", pageProtection: "0x4", executableByVad: false, process: { pid: "100", image: "sample.exe" } }, ["Start", "End", "Page Protection", "Executable By Vad", "Object", "Process / PID", "Process / Image", "Process"]],
        ["dt", { field: "Field", offset: "0x8", type: "unsigned long", size: "4", bitOffset: null, bitWidth: null }, ["Field", "Offset", "Type", "Size", "Bit Offset", "Bit Width"]],
        ["u", { address: "0xffff800000002008", bytes: "90", instruction: "nop" }, ["Address", "Bytes", "Instruction"]]
    ];
    for (const [command, row, expected] of examples)
    {
        await openTable(app, command, [row]);
        assert.deepEqual(headers(app), ["#", ...expected], command);
        assert.equal(app.nodes.get("result-table").getAttribute("aria-colcount"), String(expected.length + 1));
        assert.equal(app.nodes.get("result-rows").children[0].children.length, expected.length + 1);
        assert.equal(app.nodes.get("result-rows").children[0].style.gridTemplateColumns, app.nodes.get("table-head").style.gridTemplateColumns);
        assert.equal(app.nodes.get("result-title").textContent, command, "Opened CLI result lost its command identity");
    }
});

await check("T-UI-COLUMNS remote process comparisons expose both target identities and the observation", async () =>
{
    const app = harness();
    await app.boot();
    const process = { image: "System", eprocess: "0xffff800000001000", createTime: "123" };
    await openTable(app, "!hiddenproc", [{ kind: "ProcessCrossView", pid: "4", observation: "SameObservedIdentity",
        activeList: process, cidTable: process }]);
    assert.deepEqual(headers(app).slice(0, 9), ["#", "PID", "Observation", "Active List / Image", "Cid Table / Image",
        "Active List / EPROCESS", "Cid Table / EPROCESS", "Active List / Create Time", "Cid Table / Create Time"]);
});

await check("T-UI-CROSSVIEW counts cover the retained comparison beyond loaded rows and the display limit", async () =>
{
    const app = harness();
    await app.boot();
    const summary = { total: "100100", matched: "100000", mismatchCandidates: "99", indeterminate: "1" };
    await openTable(app, "!hiddenproc", [{ kind: "ProcessCrossView", pid: "4", observation: "SameObservedIdentity" }],
        { total: 100100, metadata: { status: "Partial", coverage: { complete: false }, analysis: { processComparison: summary } } });
    assert.equal(app.nodes.get("result-count").textContent, "Total 100,100 / Matched 100,000 / Mismatch candidates 99 / Indeterminate 1");
    assert.match(app.nodes.get("process-comparison-note").textContent, /including matches.*not confirmed hidden processes/);
    assert.match(app.nodes.get("process-comparison-note").textContent, /incomplete.*collected rows only/);
    assert.equal(app.nodes.get("process-comparison-note").classList.contains("hidden"), false);
    await openTable(app, "registers", [{ name: "rax" }]);
    assert.equal(app.nodes.get("process-comparison-note").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("process-comparison-note").textContent, "");
    assert.equal(app.nodes.get("result-count").textContent, "1 rows / 0 findings");
});

await check("T-UI-CROSSVIEW sorting and historical context preserve captured counts", async () =>
{
    const app = harness();
    await app.boot();
    const rows = ["SameObservedIdentity", "CidOnlyReobserveCandidate", "IdentityUnknown"].map((observation, index) =>
        ({ kind: "ProcessCrossView", pid: String(index + 4), observation }));
    const metadata = { status: "Success", coverage: { complete: true },
        analysis: { processComparison: { total: "3", matched: "1", mismatchCandidates: "1", indeterminate: "1" } } };
    await openTable(app, "!hiddenproc", rows, { metadata });
    const count = "Total 3 / Matched 1 / Mismatch candidates 1 / Indeterminate 1";
    sortHeader(app, "Observation");
    await settle();
    assert.equal(app.nodes.get("result-count").textContent, count);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stamp, contextGeneration: "99" });
    assert.equal(app.nodes.get("result-count").textContent, count);
    assert.match(app.nodes.get("result-summary").textContent, /Historical/);
});

await check("T-UI-CROSSVIEW missing and malformed summaries never invent zero matches or candidates", async () =>
{
    const app = harness();
    await app.boot();
    const valid = { total: "1", matched: "1", mismatchCandidates: "0", indeterminate: "0" };
    for (const summary of [undefined, { ...valid, total: "2" }, { ...valid, matched: "0" },
        { ...valid, matched: null }, { ...valid, matched: true }, { ...valid, matched: "0x1" },
        { ...valid, matched: -1 }, { ...valid, matched: 1.5 }, { ...valid, matched: "9007199254740992" }])
    {
        await openTable(app, "!hiddenproc", [{ kind: "ProcessCrossView", observation: "SameObservedIdentity" }],
            { metadata: { status: "Success", analysis: { processComparison: summary } } });
        assert.equal(app.nodes.get("result-count").textContent,
            "Total 1 / Matched Unavailable / Mismatch candidates Unavailable / Indeterminate Unavailable");
        assert.match(app.nodes.get("process-comparison-note").textContent, /no valid count breakdown/);
    }
    await openTable(app, "!hiddenproc", [], { metadata: { status: "Unavailable", coverage: { complete: false },
        analysis: { processComparison: { total: "0", matched: "0", mismatchCandidates: "0", indeterminate: "0" } } } });
    assert.equal(app.nodes.get("result-count").textContent, "Total 0 / Matched 0 / Mismatch candidates 0 / Indeterminate 0");
    assert.match(app.nodes.get("process-comparison-note").textContent, /incomplete.*cannot establish absence/);
});

await check("T-UI-COLUMNS pointer and routine symbols use the same explicit columns", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "dqs", [{ kind: "MemoryPointer", address: "0xffff800000001000", pointer: "0xffff800000002000",
        symbol: "sample+0x0000000000002000", symbolSource: "ModuleRva", readable: true, width: "8" }]);
    assert.equal(tableCell(app, 0, "Pointer"), "0xffff800000002000");
    assert.equal(tableCell(app, 0, "Symbol"), "sample+0x0000000000002000");
    assert.equal(tableCell(app, 0, "Symbol Source"), "ModuleRva");
    await openTable(app, "!hive", [{ kind: "RoutineObservation", family: "Hive.GetCellRoutine", slot: "0xffff800000001008",
        routine: "0xffff800000002000", symbol: "nt!HvpGetCellMapped", symbolSource: "LoadedDebuggerSymbols" }]);
    assert.equal(tableCell(app, 0, "Symbol"), "nt!HvpGetCellMapped");
});

await check("T-UI-COLUMNS sparse legacy and mixed rows retain a visible observation", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!drvobj", [{ kind: "DriverDispatch", major: "14", handler: "0xffff800000002000" },
        { kind: "UnrelatedRecord", unexpectedField: "Observed value" }, {}, { kind: "UnknownRecord", pointer: null }]);
    assert.match(tableCell(app, 1, "Observation"), /Unexpected Field: Observed value/);
    assert.match(tableCell(app, 2, "Observation"), /no observation fields/);
    assert.match(tableCell(app, 3, "Observation"), /Pointer: Unknown/);
});

await check("T-UI-COLUMNS symbol absence distinguishes a known null address and unresolved names", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "dqs", [{ kind: "MemoryPointer", address: "0x1000", pointer: "0x0", symbol: null,
        symbolSource: "NullAddress", readable: true }, { kind: "MemoryPointer", address: "0x1008", pointer: null,
        symbol: null, symbolSource: "Unavailable", readable: false }]);
    assert.equal(tableCell(app, 0, "Symbol"), "Null address");
    assert.equal(tableCell(app, 1, "Pointer"), "Unknown");
    assert.equal(tableCell(app, 1, "Symbol"), "Unresolved");
});

await check("T-UI-COLUMNS required sparse-row summary stays synchronized with column controls", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [
        { kind: "ObjectCallbackRegistration", callbackType: "Object.Process", preRoutine: "0xffff800000001000", flags: "0x1",
            postRoutine: "0xffff800000002000", preSymbol: "sample!Pre", postSymbol: "sample!Post" },
        { kind: "CoverageGap", reason: "Unavailable registration layout" }
    ]);
    const summaryChoice = () => app.nodes.get("column-list").children.find(item => item.children[1].textContent === "Observation");
    assert.ok(summaryChoice(), "Visible summary has no column control");
    assert.equal(summaryChoice().children[0].checked, true);
    assert.equal(app.nodes.get("columns-toggle").textContent,
        "Columns " + (headers(app).length - 1) + "/" + app.nodes.get("column-list").children.length);
    summaryChoice().children[0].checked = false;
    summaryChoice().children[0].fire("change");
    assert.ok(headers(app).includes("Observation"), "Sparse rows lost their required summary");
    assert.equal(summaryChoice().children[0].checked, true, "Required summary checkbox disagrees with the table");
});

await check("T-UI-COLUMNS primitive legacy records preserve their actual values", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "future-command", ["<literal value>", 0, false]);
    assert.equal(tableCell(app, 0, "Value"), "<literal value>");
    assert.equal(tableCell(app, 1, "Value"), "0");
    assert.equal(tableCell(app, 2, "Value"), "No");
});

await check("T-UI-COLUMNS mixed callbacks keep coverage diagnostics and exact routine ownership visible", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [
        { kind: "CallbackTable", family: "ProcessNotify", address: "0xffff800000001000", slots: "64" },
        { kind: "RoutineObservation", family: "ProcessNotify", slot: "0xffff800000001008", routine: "0xffff800012345679", module: "sample.sys", ownership: "KnownModule" },
        { kind: "CoverageGap", scope: "Registry", reason: "Missing page" }
    ]);
    assert.equal(tableCell(app, 1, "Routine"), "0xffff800012345679");
    assert.equal(tableCell(app, 1, "Module"), "sample.sys");
    assert.equal(tableCell(app, 2, "Reason"), "Missing page");
    assert.equal(tableCell(app, 2, "Scope"), "Registry");
    assert.equal(tableCell(app, 0, "Routine"), "\u2014", "Absent fields must not invent routine addresses");
});

await check("T-UI-CALLBACKS paired callbacks expose type, both addresses, flags and symbols before diagnostics", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [
        { kind: "ObjectCallbackRegistration", callbackType: "Object.Process", preRoutine: "0xffff800000001000",
            postRoutine: "0xffff800000002000", flags: "0x0000000000000003", preSymbol: "sample!Pre+0x4", postSymbol: "sample!Post",
            family: "Object.Process", objectType: "Process", operations: "0x3", active: true },
        { kind: "CoverageGap", scope: "Registry", reason: "Missing type" }
    ]);
    assert.deepEqual(headers(app).slice(1), ["Callback type", "Routine / Pre", "Post callback", "Flags", "Symbol / Pre", "Post symbol", "Observation"]);
    assert.match(tableCell(app, 1, "Observation"), /Missing type/);
    assert.equal(tableCell(app, 0, "Routine / Pre"), "0xffff800000001000");
    assert.equal(tableCell(app, 0, "Post callback"), "0xffff800000002000");
    assert.equal(tableCell(app, 0, "Flags"), "0x0000000000000003");
    assert.equal(tableCell(app, 0, "Symbol / Pre"), "sample!Pre+0x4");
    assert.equal(tableCell(app, 0, "Post symbol"), "sample!Post");
});

await check("T-UI-CALLBACKS absent phases and known null registrations remain distinct from unknown symbols", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [
        { kind: "ObjectCallbackRegistration", callbackType: "Object.Process", preRoutine: "0xffff800000001000",
            postRoutine: "0x0000000000000000", flags: "0x1", preSymbol: null, preSymbolSource: "Unavailable",
            postSymbol: null, postSymbolSource: "NotRegistered" },
        { kind: "RoutineObservation", callbackType: "Notify.Process", routine: "0xffff800000002000", flags: "0x0", symbol: "sample!Notify" }
    ]);
    assert.equal(tableCell(app, 0, "Symbol / Pre"), "Unresolved");
    assert.equal(tableCell(app, 0, "Post symbol"), "Not registered");
    assert.equal(tableCell(app, 0, "Post callback"), "0x0000000000000000");
    assert.equal(tableCell(app, 1, "Post callback"), "N/A");
    assert.equal(tableCell(app, 1, "Routine / Pre"), "0xffff800000002000");
    assert.equal(tableCell(app, 1, "Symbol / Pre"), "sample!Notify");
    assert.equal(headers(app).includes("Routine"), false);
});

await check("T-UI-CALLBACKS coverage gap reasons remain visible in Details without diagnostic table rows", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [
        { kind: "ObjectCallbackRegistration", callbackType: "Object.Process", preRoutine: null, postRoutine: null, flags: null }
    ], { metadata: { status: "Partial", coverage: { complete: false, unknownEntries: "3" },
        analysis: { diagnostics: [{ kind: "CoverageGap", scope: "Process callbacks", reason: "No matching layout profile" }] } } });
    const details = app.nodes.get("result-facts").children.map(node => node.textContent).join(" ");
    assert.ok(details.includes("Gap / Process callbacks"));
    assert.ok(details.includes("No matching layout profile"));
    assert.equal(app.nodes.get("result-rows").children.length, 1);
});

await check("T-UI-CALLBACKS single-routine pages do not show duplicate primary fields", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [
        { kind: "RoutineObservation", callbackType: "Notify.Image", routine: "0xffff800000001000", symbol: "sample!ImageNotify",
            flags: "0x1", family: "PspLoadImageNotifyRoutine", slot: "0xffff800000002000", module: "sample" }
    ]);
    assert.deepEqual(headers(app), ["#", "Callback type", "Routine / Pre", "Flags", "Symbol / Pre"]);
    assert.equal(tableCell(app, 0, "Routine / Pre"), "0xffff800000001000");
    assert.equal(tableCell(app, 0, "Symbol / Pre"), "sample!ImageNotify");
});

await check("T-UI-COLUMNS unknown fields, nested paths, null, false, zero and literal HTML remain distinct", async () =>
{
    const app = harness();
    await app.boot();
    const rows = [JSON.parse('{"name":"<img src=x>","value":0,"enabled":false,"unknown":null,"empty":"","owner":{"pid":"42"},"owner.pid":"literal","__proto__":{"polluted":"text"}}')];
    await openTable(app, "future-command", rows);
    app.nodes.get("btn-columns-all").fire("click");
    assert.equal(tableCell(app, 0, "Name"), "<img src=x>");
    assert.equal(tableCell(app, 0, "Value"), "0");
    assert.equal(tableCell(app, 0, "Enabled"), "No");
    assert.equal(tableCell(app, 0, "Unknown"), "Unknown");
    assert.equal(tableCell(app, 0, "Empty"), "(empty)");
    assert.equal(tableCell(app, 0, "Owner / PID"), "42");
    assert.equal(tableCell(app, 0, "Owner.PID"), "literal");
    assert.equal(Object.prototype.polluted, undefined);
    app.nodes.get("result-rows").children[0].fire("click");
    assert.deepEqual(JSON.parse(app.nodes.get("result-detail").textContent), rows[0]);
});

await check("T-UI-COLUMNS choices persist per result and collection, and empty results discard stale headers", async () =>
{
    const app = harness();
    await app.boot();
    const row = { kind: "Process", eprocess: "0xffff800000001000", pid: "4", image: "System", dtb: "0x1000" };
    await openTable(app, "!process", [row]);
    const label = app.nodes.get("column-list").children.find(item => item.children[1].textContent === "DTB");
    label.children[0].checked = false;
    label.children[0].fire("change");
    assert.ok(!headers(app).includes("DTB"));
    const before = app.messages.length;
    app.nodes.get("result-columns").open = true;
    app.nodes.get("result-columns").fire("keydown", { key: "Escape" });
    assert.equal(app.nodes.get("result-columns").open, false);
    assert.equal(app.focused().id, "columns-toggle");
    assert.equal(app.messages.length, before, "Column settings must not execute a host command");
    await openTable(app, "!process", [{ ruleId: "sample/rule", severity: "warning", message: "Observed", evidence: { count: 0 } }], { collection: "findings" });
    assert.deepEqual(headers(app).slice(0, 4), ["#", "Severity", "Rule", "Message"]);
    await openTable(app, "!process", [row]);
    assert.ok(!headers(app).includes("DTB"), "Findings overwrote observation choices");
    app.nodes.get("btn-columns-reset").fire("click");
    assert.ok(headers(app).includes("DTB"));
    await openTable(app, "no-observations", []);
    assert.deepEqual(headers(app), ["#"]);
    assert.equal(app.nodes.get("result-rows").children.length, 0);
});

await check("T-UI-COLUMNS later pages extend the field union without deleting choices or changing row identity", async () =>
{
    const app = harness();
    await app.boot();
    const rows = Array.from({ length: 128 }, (_, i) => ({ name: "Record " + i, value: i }));
    await openTable(app, "future-command", rows, { total: 300 });
    const initial = headers(app);
    app.nodes.get("btn-columns-all").fire("click");
    const focusedChoice = app.nodes.get("column-list").children[0].children[0];
    focusedChoice.focus();
    const view = app.nodes.get("result-view");
    view.scrollTop = 200 * 28;
    view.scrollLeft = 120;
    view.fire("scroll");
    const offset = Number(app.latest("resultPage").params.offset);
    await app.reply("resultPage", { ok: true, result: {
        resultId: "future-command", collection: "rows", offset: String(offset), next: "300", complete: true,
        rows: Array.from({ length: 300 - offset }, (_, i) => ({ name: "Later " + i, extra: "Late field" }))
    } });
    assert.deepEqual(headers(app), initial, "Discovering a field changed a manual selection");
    assert.equal(app.focused().dataset.columnKey, focusedChoice.dataset.columnKey, "New fields lost keyboard focus in the chooser");
    const extra = app.nodes.get("column-list").children.find(item => item.children[1].textContent === "Extra");
    assert.ok(extra, "Late-page field was dropped");
    extra.children[0].checked = true;
    extra.children[0].fire("change");
    assert.equal(tableCell(app, 0, "Extra"), "Late field");
    assert.equal(tableCell(app, 0, "Value"), "\u2014");
    assert.equal(app.nodes.get("result-rows").children[0].getAttribute("aria-rowindex"), String(offset + 2));
    assert.equal(app.nodes.get("table-head").style.transform, "translateX(-120px)");
    assert.ok(app.nodes.get("result-rows").children.length <= 128);
});

await check("T-UI-COLUMNS field and text limits retain the full record in the inspector", async () =>
{
    const app = harness();
    await app.boot();
    const row = { message: "a".repeat(6000) };
    for (let i = 0; i < 150; ++i)
    {
        row["field" + i] = i;
    }
    await openTable(app, "wide-result", [row]);
    assert.equal(app.nodes.get("column-list").children.length, 96);
    assert.ok(app.nodes.get("column-status").textContent.includes("Field limit"));
    assert.equal(tableCell(app, 0, "Message").length, 515);
    app.nodes.get("btn-columns-all").fire("click");
    assert.equal(headers(app).length, 97);
    app.nodes.get("result-rows").children[0].fire("click");
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).field149, 149);
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).message.length, 6000);
});

await check("T-UI-COLUMNS primitive records can be selected without another page request", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "primitive-result", [0, false, null]);
    assert.deepEqual(headers(app), ["#", "Value"]);
    for (const [index, expected] of [[0, "0"], [1, "false"], [2, "null"]])
    {
        const before = app.messages.length;
        app.nodes.get("result-rows").children[index].fire("click");
        assert.equal(app.nodes.get("result-detail").textContent, expected);
        assert.equal(app.messages.length, before);
    }
});

await check("T-UI-COLUMNS colliding and blank field labels remain unambiguous", async () =>
{
    const app = harness();
    await app.boot();
    const row = { value: 1, pid: 2, PID: 3, owner: { pid: 4 }, "owner / pid": 5, "": 6, " ": 7, "#": 8 };
    await openTable(app, "ambiguous-fields", [row, false]);
    app.nodes.get("btn-columns-all").fire("click");
    const labels = headers(app).map(label => label.replace(/\s+/g, " ").trim());
    assert.equal(new Set(labels).size, labels.length, "Distinct fields have identical visible labels");
    assert.ok(labels.every(Boolean), "A field has an empty header");
    for (const choice of app.nodes.get("column-list").children)
    {
        assert.equal(choice.title, choice.children[0].dataset.columnKey, "The exact path is missing from the tooltip");
    }
    app.nodes.get("result-rows").children[0].fire("click");
    assert.deepEqual(JSON.parse(app.nodes.get("result-detail").textContent), row);
});

await check("T-UI-COLUMNS metadata cannot consume the field budget before command fields", async () =>
{
    const app = harness();
    await app.boot();
    const context = Object.fromEntries(Array.from({ length: 110 }, (_, i) => ["meta" + i, i]));
    await openTable(app, "!callbacks", [{ context, kind: "RoutineObservation", family: "ProcessNotify",
        routine: "0xffff800000001008", module: "sample.sys", ownership: "KnownModule" }]);
    assert.equal(tableCell(app, 0, "Routine"), "0xffff800000001008");
    assert.equal(tableCell(app, 0, "Module"), "sample.sys");
    assert.equal(app.nodes.get("column-list").children.length, 96);
    assert.ok(app.nodes.get("column-status").textContent.includes("Field limit"));
});

await check("T-UI-PAGE premature completion and excess rows cannot silently change retained counts", async () =>
{
    for (const [total, rows, complete, reportedTotal] of [
        [2, [], true], [2, [{ name: "First" }], true], [1, [{ name: "First" }, { name: "Extra" }], true],
        [1, [{ name: "First" }], false], [2, [{ name: "First" }], false, "3"]])
    {
        const app = harness();
        await app.boot();
        app.nodes.get("result-id-input").value = "invalid-count";
        app.nodes.get("btn-result-load").fire("click");
        await app.reply("resultInfo", { ok: true, result: { resultId: "invalid-count", rowCount: String(total), data: { target: stamp } } });
        await app.reply("resultPage", { ok: true, result: { resultId: "invalid-count", offset: "0", next: String(rows.length), total: reportedTotal, complete, rows } });
        assert.ok(app.nodes.get("result-notice-text").textContent.includes("Result page"), "An inconsistent page was accepted: " + JSON.stringify({ total, count: rows.length, complete }));
        assert.equal(app.nodes.get("result-rows").children.length, 0);
        assert.equal(app.nodes.get("btn-save").disabled, false);
    }
});

await check("T-UI-COLUMNS stale pages cannot populate a different collection or result schema", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("result-id-input").value = "old-result";
    app.nodes.get("btn-result-load").fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "old-result", rowCount: "1", data: { commandId: "!process" } } });
    const obsolete = app.latest("resultPage");
    app.nodes.get("result-id-input").value = "new-result";
    app.nodes.get("btn-result-load").fire("click");
    await app.reply("resultInfo", { ok: true, result: { resultId: "new-result", rowCount: "1", findingCount: "1", data: { commandId: "!callbacks" } } });
    const selector = app.nodes.get("result-collection");
    selector.value = "findings";
    selector.fire("change");
    await app.deliver(obsolete, { ok: true, result: { resultId: "old-result", collection: "rows", offset: "0", complete: true, rows: [{ pid: "4" }] } });
    assert.deepEqual(headers(app), ["#"]);
    assert.equal(app.latest("resultPage").params.resultId, "new-result");
    assert.equal(app.latest("resultPage").params.collection, "findings");
    await app.reply("resultPage", { ok: true, result: { resultId: "new-result", collection: "findings", offset: "0", complete: true,
        findings: [{ severity: "warning", message: "Current finding" }] } });
    assert.deepEqual(headers(app), ["#", "Severity", "Message"]);
    assert.equal(app.nodes.get("column-list").children.some(item => item.children[1].textContent === "PID"), false);
    assert.equal(tableCell(app, 0, "Message"), "Current finding");
});

await check("T-UI-COLUMNS whitespace and path-like labels cannot impersonate another field", async () =>
{
    const app = harness();
    await app.boot();
    const row = Object.fromEntries(["pid", "PID", 'PID ["pid"]', "a b", "a  b", "a\tb", "\t", "\n", "toString", "constructor", "__proto__"]
        .map((key, index) => [key, index]));
    await openTable(app, "label-collisions", [row]);
    app.nodes.get("btn-columns-all").fire("click");
    const labels = headers(app).map(label => label.replace(/\s+/g, " ").trim());
    assert.equal(new Set(labels).size, labels.length);
    for (const choice of app.nodes.get("column-list").children)
    {
        const field = JSON.parse(choice.children[0].dataset.columnKey)[0];
        assert.equal(tableCell(app, 0, choice.children[1].textContent), String(row[field]));
    }
});

function sortHeader(app, label)
{
    const header = app.nodes.get("table-head").children[headers(app).indexOf(label)];
    assert.ok(header, "Missing sortable header: " + label);
    header.children[0].fire("click");
}

function originalOrder(app)
{
    return app.nodes.get("result-rows").children.map(row => Number(row.children[0].textContent));
}

function columnHandle(app, label)
{
    return app.nodes.get("table-head").children[headers(app).indexOf(label)].children[1];
}

await check("T-UI-COLUMN-WIDTH keyboard resizing clamps each column without sorting or changing source records", async () =>
{
    const app = harness();
    await app.boot();
    const rows = [{ pid: "20", image: "first.exe" }, { pid: "2", image: "second.exe" }];
    await openTable(app, "!process", rows);
    app.nodes.get("result-rows").children[1].fire("click");
    const count = app.messages.length;
    const handle = columnHandle(app, "PID");
    handle.fire("keydown", { key: "ArrowRight" });
    assert.equal(handle.getAttribute("aria-valuenow"), "112");
    handle.fire("keydown", { key: "ArrowLeft", shiftKey: true });
    assert.equal(handle.getAttribute("aria-valuenow"), "64");
    handle.fire("keydown", { key: "End" });
    assert.equal(handle.getAttribute("aria-valuenow"), "4096");
    handle.fire("keydown", { key: "Home" });
    assert.equal(handle.getAttribute("aria-valuenow"), "64");
    handle.fire("keydown", { key: "ArrowRight", ctrlKey: true });
    assert.equal(handle.getAttribute("aria-valuenow"), "64");
    const number = columnHandle(app, "#");
    number.fire("keydown", { key: "ArrowRight" });
    assert.equal(number.getAttribute("aria-valuenow"), "64");
    number.fire("keydown", { key: "Home" });
    assert.equal(number.getAttribute("aria-valuenow"), "48");
    assert.deepEqual(originalOrder(app), [1, 2]);
    assert.deepEqual(JSON.parse(app.nodes.get("result-detail").textContent), rows[1]);
    assert.equal(app.messages.length, count);
    assert.equal(app.nodes.get("table-head").style.gridTemplateColumns,
        app.nodes.get("result-rows").children[0].style.gridTemplateColumns);
});

await check("T-UI-COLUMN-WIDTH pointer drags track the captured pointer and rollback on cancel or Escape", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!process", [{ pid: "4", image: "sample.exe" }]);
    const handle = columnHandle(app, "PID");
    const move = (pointerId, clientX) => app.documentListeners.get("pointermove")({ pointerId, clientX, preventDefault: noop });
    handle.fire("pointerdown", { button: 2, pointerId: 7, clientX: 200 });
    move(7, 250);
    assert.equal(handle.getAttribute("aria-valuenow"), "96");
    handle.fire("pointerdown", { button: 0, pointerId: 7, clientX: 200 });
    move(8, 400);
    move(7, NaN);
    assert.equal(handle.getAttribute("aria-valuenow"), "96");
    move(7, 300);
    assert.equal(handle.getAttribute("aria-valuenow"), "196");
    move(7, 200);
    assert.equal(handle.getAttribute("aria-valuenow"), "96");
    move(7, 260);
    app.documentListeners.get("pointercancel")({ pointerId: 7 });
    assert.equal(handle.getAttribute("aria-valuenow"), "96");
    assert.equal(app.nodes.get("root").classList.contains("column-resizing"), false);
    handle.fire("pointerdown", { button: 0, pointerId: 7, clientX: 200 });
    move(7, 260);
    app.documentListeners.get("keydown")({ key: "Escape", preventDefault: noop });
    assert.equal(handle.getAttribute("aria-valuenow"), "96");
    handle.fire("pointerdown", { button: 0, pointerId: 7, clientX: 200 });
    move(7, 260);
    handle.fire("lostpointercapture");
    move(7, 1000);
    assert.equal(handle.getAttribute("aria-valuenow"), "156");
    assert.equal(app.nodes.get("root").classList.contains("column-resizing"), false);
});

await check("T-UI-COLUMN-WIDTH the stretched last column starts at its actual width and can shrink below the viewport", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "width-last", [{ message: "long message" }]);
    const cell = app.nodes.get("table-head").children.at(-1);
    cell.getBoundingClientRect = () => ({ width: 900 });
    const handle = columnHandle(app, "Message");
    handle.fire("pointerdown", { button: 0, pointerId: 1, clientX: 800 });
    cell.getBoundingClientRect = () => ({ width: 0 });
    app.documentListeners.get("pointermove")({ pointerId: 1, clientX: 600, preventDefault: noop });
    app.documentListeners.get("pointerup")({ pointerId: 1 });
    assert.equal(handle.getAttribute("aria-valuenow"), "700");
    assert.equal(app.nodes.get("table-head").style.gridTemplateColumns, "48px 700px");
    handle.fire("dblclick");
    assert.equal(app.nodes.get("table-head").style.gridTemplateColumns, "48px minmax(280px, 1fr)");
});

await check("T-UI-COLUMN-WIDTH cancelling a scrolled drag restores its viewport as well as the previous width", async () =>
{
    for (const cancel of ["Escape", "pointercancel"])
    {
        const app = harness();
        await app.boot();
        await openTable(app, "width-cancel-scroll", [{ message: "sample" }]);
        const handle = columnHandle(app, "Message");
        handle.fire("keydown", { key: "End" });
        app.nodes.get("result-view").scrollLeft = 1000;
        handle.fire("pointerdown", { button: 0, pointerId: 3, clientX: 200 });
        app.documentListeners.get("pointermove")({ pointerId: 3, clientX: 104, preventDefault: noop });
        app.nodes.get("result-view").scrollLeft = 904;
        if (cancel === "Escape")
        {
            app.documentListeners.get("keydown")({ key: "Escape", preventDefault: noop });
        }
        else
        {
            app.documentListeners.get("pointercancel")({ pointerId: 3 });
        }
        assert.equal(handle.getAttribute("aria-valuenow"), "4096");
        assert.equal(app.nodes.get("result-view").scrollLeft, 1000, cancel);
        assert.equal(app.nodes.get("root").classList.contains("column-resizing"), false);
    }
});

await check("T-UI-COLUMN-WIDTH widths survive sorting, hiding and revisiting while collections stay independent", async () =>
{
    const app = harness();
    await app.boot();
    const rows = [{ pid: "20", image: "first.exe" }, { pid: "2", image: "second.exe" }];
    await openTable(app, "width-retained", rows);
    columnHandle(app, "PID").fire("keydown", { key: "ArrowRight", shiftKey: true });
    sortHeader(app, "PID");
    assert.equal(columnHandle(app, "PID").getAttribute("aria-valuenow"), "160");
    const choice = app.nodes.get("column-list").children.find(node => node.children[0].dataset.columnKey === '["pid"]');
    choice.children[0].checked = false;
    choice.children[0].fire("change");
    choice.children[0].checked = true;
    choice.children[0].fire("change");
    assert.equal(columnHandle(app, "PID").getAttribute("aria-valuenow"), "160");
    await openTable(app, "width-retained", [{ pid: "4" }], { collection: "findings" });
    assert.equal(columnHandle(app, "PID").getAttribute("aria-valuenow"), "96");
    await openTable(app, "width-retained", rows);
    assert.equal(columnHandle(app, "PID").getAttribute("aria-valuenow"), "160");
    app.nodes.get("btn-columns-widths").fire("click");
    assert.equal(columnHandle(app, "PID").getAttribute("aria-valuenow"), "96");
    assert.equal(app.nodes.get("table-head").children[headers(app).indexOf("PID")].getAttribute("aria-sort"), "ascending");
    assert.deepEqual(originalOrder(app), [2, 1]);
});

await check("T-UI-COLUMN-WIDTH capture failures and replacement headers cannot mutate another result", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "old-width", [{ pid: "4" }]);
    const handle = columnHandle(app, "PID");
    handle.setPointerCapture = () =>
    {
        throw new Error("Capture denied");
    };
    handle.fire("pointerdown", { button: 0, pointerId: 1, clientX: 100 });
    assert.equal(app.nodes.get("root").classList.contains("column-resizing"), false);
    assert.match(app.nodes.get("workspace-feedback-text").textContent, /Left\/Right/);
    handle.setPointerCapture = noop;
    handle.fire("pointerdown", { button: 0, pointerId: 1, clientX: 100 });
    app.documentListeners.get("pointermove")({ pointerId: 1, clientX: 150, preventDefault: noop });
    await openTable(app, "new-width", [{ pid: "8" }]);
    app.documentListeners.get("pointermove")({ pointerId: 1, clientX: 400, preventDefault: noop });
    assert.equal(app.nodes.get("root").classList.contains("column-resizing"), false);
    assert.equal(columnHandle(app, "PID").getAttribute("aria-valuenow"), "96");
    await openTable(app, "old-width", [{ pid: "4" }]);
    assert.equal(columnHandle(app, "PID").getAttribute("aria-valuenow"), "146");
});

await check("T-UI-SORT exact 64-bit values, missing values, stable ties and natural text ordering", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "sort-addresses", [
        { address: "0xffffffffffffffff" }, { address: "0xfffffffffffffffe" }, { address: null },
        { address: "fffff803`00000000" }, { address: "0x2" }, { address: "" }, {}
    ]);
    sortHeader(app, "Address");
    assert.deepEqual(originalOrder(app), [5, 4, 2, 1, 3, 6, 7]);
    sortHeader(app, "Address");
    assert.deepEqual(originalOrder(app), [1, 2, 4, 5, 3, 6, 7]);
    assert.equal(app.nodes.get("table-head").children[headers(app).indexOf("Address")].getAttribute("aria-sort"), "descending");
    await openTable(app, "sort-counts", [
        { count: "18446744073709551615" }, { count: "9007199254740993" }, { count: "9007199254740992" },
        { count: "10" }, { count: "2" }, { count: false }, { count: "0" }, { count: true }, { count: null }
    ]);
    sortHeader(app, "Count");
    assert.deepEqual(originalOrder(app), [6, 7, 8, 5, 4, 3, 2, 1, 9]);
    sortHeader(app, "Count");
    assert.deepEqual(originalOrder(app), [1, 2, 3, 4, 5, 8, 6, 7, 9]);
    await openTable(app, "sort-text", [{ symbol: "driver!Callback10" }, { symbol: "driver!Callback2" },
        { symbol: "DRIVER!callback2" }, { symbol: null }]);
    sortHeader(app, "Symbol");
    assert.deepEqual(originalOrder(app), [2, 3, 1, 4]);
    sortHeader(app, "#");
    assert.deepEqual(originalOrder(app), [1, 2, 3, 4]);
    sortHeader(app, "#");
    assert.deepEqual(originalOrder(app), [4, 3, 2, 1]);
});

await check("T-UI-SORT shared callback columns sort the displayed single and paired routine values", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "!callbacks", [
        { callbackType: "Notify.Process", routine: "0x20", symbol: "module!B" },
        { callbackType: "Object.Process", preRoutine: "0x10", preSymbol: "module!A", postRoutine: "0x0",
            postSymbol: null, postSymbolSource: "NotRegistered" },
        { callbackType: "Registry", routine: "0x30", symbol: "module!C" }
    ]);
    sortHeader(app, "Routine / Pre");
    assert.deepEqual(originalOrder(app), [2, 1, 3]);
    assert.equal(tableCell(app, 0, "Post symbol"), "Not registered");
    sortHeader(app, "Symbol / Pre");
    sortHeader(app, "Symbol / Pre");
    assert.deepEqual(originalOrder(app), [3, 1, 2]);
    assert.equal(tableCell(app, 0, "Post callback"), "N/A");
});

await check("T-UI-MINIFILTER Major displays, sorts and copies names while preserving raw codes", async () =>
{
    for (const command of ["!minifilter", "!fltmgr"])
    {
        const copied = [];
        const app = harness({ clipboard: { writeText: text =>
        {
            copied.push(text);
            return Promise.resolve();
        } } });
        await app.boot();
        const rows = [
            { kind: "Minifilter", name: "sample", altitude: "12345" },
            { kind: "RoutineObservation", family: "Minifilter.PreOperation", major: "3", majorName: "IRP_MJ_READ" },
            { kind: "RoutineObservation", family: "Minifilter.PostOperation", major: "0", majorName: "IRP_MJ_CREATE" },
            { kind: "RoutineObservation", family: "Minifilter.PreOperation", major: "255", majorName: "IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION" },
            { kind: "RoutineObservation", family: "Minifilter.PreOperation", major: "42", majorName: "IRP_MJ_UNKNOWN (42)" }
        ];
        await openTable(app, command, rows);
        assert.equal(tableCell(app, 1, "Major"), "IRP_MJ_READ");
        assert.equal(tableCell(app, 2, "Major"), "IRP_MJ_CREATE");
        assert.equal(tableCell(app, 3, "Major"), "IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION");
        assert.equal(tableCell(app, 4, "Major"), "IRP_MJ_UNKNOWN (42)");
        sortHeader(app, "Major");
        assert.deepEqual(originalOrder(app), [4, 3, 2, 5, 1]);
        app.nodes.get("result-rows").children[0].children[headers(app).indexOf("Major")].fire("click");
        await settle();
        assert.equal(copied.at(-1), "IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION");
        app.nodes.get("btn-copy-row").fire("click");
        await settle();
        assert.deepEqual(JSON.parse(copied.at(-1)), rows[3]);
        const fields = app.nodes.get("detail-fields").children;
        const rawCode = fields.findIndex(node => node.textContent === "major");
        const decodedName = fields.findIndex(node => node.textContent === "majorName");
        assert.ok(rawCode >= 0 && decodedName >= 0);
        assert.equal(fields[rawCode + 1].textContent, "255");
        fields[rawCode + 1].fire("click");
        await settle();
        assert.equal(copied.at(-1), "255");
        fields[decodedName + 1].fire("click");
        await settle();
        assert.equal(copied.at(-1), "IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION");
        sortHeader(app, "Major");
        assert.deepEqual(originalOrder(app), [5, 2, 3, 4, 1]);
        await openTable(app, command, [{ kind: "RoutineObservation", family: "Minifilter.PreOperation", major: "3" }], { id: command + "-legacy" });
        assert.equal(tableCell(app, 0, "Major"), "3");
        await openTable(app, "!drvobj", [{ kind: "DriverDispatch", major: "3", majorName: "READ" }]);
        assert.equal(tableCell(app, 0, "Major"), "READ");
        for (const majorName of ["", null, {}, []])
        {
            await openTable(app, command, [{ kind: "RoutineObservation", family: "Minifilter.PostOperation", major: "3", majorName }],
                { id: command + "-invalid-label-" + JSON.stringify(majorName) });
            assert.equal(tableCell(app, 0, "Major"), "3");
        }
    }
});

await check("T-UI-SORT selection, copies and every bound action retain the original source index", async () =>
{
    for (const action of ["navigate", "disassemble", "source"])
    {
        const copied = [];
        const app = harness({ clipboard: { writeText: text =>
        {
            copied.push(text);
            return Promise.resolve();
        } } });
        await app.boot();
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app);
        const rows = [20, 2, 10].map(value => ({ address: "0x" + value.toString(16), addressSpace: "virtual",
            sourceFile: "fixture.cpp", count: value }));
        await openTable(app, "sort-bound", rows);
        app.nodes.get("result-rows").children[1].fire("click");
        sortHeader(app, "Count");
        assert.equal(app.nodes.get("result-rows").children[0].getAttribute("aria-selected"), "true");
        sortHeader(app, "Count");
        assert.equal(app.nodes.get("result-rows").children[2].getAttribute("aria-selected"), "true");
        app.nodes.get("btn-copy-row").fire("click");
        await settle();
        assert.deepEqual(JSON.parse(copied.at(-1)), rows[1]);
        app.nodes.get("btn-" + action).fire("click");
        const binding = action === "disassemble" ? app.latest("disassemblyRead").params.source : app.latest("navigateResult").params;
        assert.equal(binding.index, "1");
        assert.equal(binding.action, action);
        if (action === "disassemble")
        {
            assert.equal(app.nodes.get("tab-disassembly").getAttribute("aria-selected"), "true");
            assert.equal(app.nodes.get("result-title").textContent, "sort-bound");
        }
        assert.equal(app.messages.some(request => request.method === "execute"), false);
    }
});

await check("T-UI-SORT all pages participate, short pages advance and the virtual viewport stays bounded", async () =>
{
    const app = harness();
    await app.boot();
    const rows = Array.from({ length: 260 }, (_, index) => ({ pid: String(260 - index), image: "process" + index }));
    await openTable(app, "sort-pages", rows.slice(0, 128), { total: 260 });
    sortHeader(app, "PID");
    assert.equal(app.latest("resultPage").params.offset, "128");
    await app.reply("resultPage", { ok: true, result: { resultId: "sort-pages", offset: "128", next: "145", total: "260",
        complete: false, rows: rows.slice(128, 145) } });
    assert.ok(app.nodes.get("row-position").textContent.includes("145 / 260"));
    assert.equal(app.nodes.get("table-head").children[headers(app).indexOf("PID")].getAttribute("aria-sort"), "none");
    await app.reply("resultPage", { ok: true, result: { resultId: "sort-pages", offset: "145", next: "260", total: "260",
        complete: true, rows: rows.slice(145) } });
    assert.equal(tableCell(app, 0, "PID"), "1");
    assert.equal(originalOrder(app)[0], 260);
    const requests = app.messages.filter(request => request.method === "resultPage").length;
    app.nodes.get("result-table").fire("keydown", { key: "End" });
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).pid, "260");
    assert.ok(app.nodes.get("result-rows").children.length <= 128);
    assert.equal(app.messages.filter(request => request.method === "resultPage").length, requests);
    assert.equal(app.nodes.get("result-table").getAttribute("aria-rowcount"), "261");
});

await check("T-UI-SORT pending clicks choose the final direction and obsolete loads cannot replace a reopened result", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "sort-race", Array.from({ length: 128 }, () => ({ pid: "20" })), { total: 129 });
    sortHeader(app, "PID");
    sortHeader(app, "PID");
    await app.reply("resultPage", { ok: true, result: { resultId: "sort-race", offset: "128", complete: true, rows: [{ pid: "2" }] } });
    assert.equal(tableCell(app, 0, "PID"), "20");
    assert.equal(app.nodes.get("table-head").children[headers(app).indexOf("PID")].getAttribute("aria-sort"), "descending");
    await openTable(app, "obsolete-sort", Array.from({ length: 128 }, () => ({ pid: "10" })), { total: 129 });
    sortHeader(app, "PID");
    const old = app.latest("resultPage");
    await openTable(app, "current-sort", [{ symbol: "current!Name" }]);
    await app.deliver(old, { ok: true, result: { resultId: "obsolete-sort", offset: "128", complete: true, rows: [{ pid: "1" }] } });
    assert.deepEqual(headers(app), ["#", "Symbol"]);
    assert.equal(tableCell(app, 0, "Symbol"), "current!Name");
    assert.equal(app.nodes.get("result-table").getAttribute("aria-busy"), "false");
});

await check("T-UI-SORT collection changes and reopening restore each collection's sort without accepting obsolete pages", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "sort-collections", [{ pid: "20" }, { pid: "2" }]);
    sortHeader(app, "PID");
    const selector = app.nodes.get("result-collection");
    selector.value = "findings";
    selector.fire("change");
    assert.equal(app.nodes.get("table-head").children.length, 1);
    selector.value = "rows";
    selector.fire("change");
    assert.equal(app.latest("resultPage").params.collection, "rows");
    await app.reply("resultPage", { ok: true, result: { resultId: "sort-collections", offset: "0", complete: true,
        rows: [{ pid: "20" }, { pid: "2" }] } });
    assert.equal(tableCell(app, 0, "PID"), "2");
    assert.equal(app.nodes.get("table-head").children[1].getAttribute("aria-sort"), "ascending");
    await openTable(app, "sort-findings", [{ severity: "warning", message: "z" }, { severity: "error", message: "a" }],
        { collection: "findings" });
    sortHeader(app, "Message");
    assert.deepEqual(originalOrder(app), [2, 1]);
    assert.equal(app.nodes.get("result-table").getAttribute("aria-label"), "Findings");
    assert.equal(app.nodes.get("table-head").children[headers(app).indexOf("Severity")].getAttribute("aria-sort"), "none");
});

await check("T-UI-SORT a late unsorted viewport cannot overwrite the newly sorted order", async () =>
{
    const app = harness();
    await app.boot();
    const rows = Array.from({ length: 260 }, (_, index) => ({ pid: String(260 - index) }));
    await openTable(app, "sort-viewport", rows.slice(0, 128), { total: 260 });
    app.nodes.get("result-view").scrollTop = 200 * 28;
    app.nodes.get("result-view").fire("scroll");
    const obsolete = app.latest("resultPage");
    sortHeader(app, "PID");
    for (const offset of [128, 256])
    {
        await app.reply("resultPage", { ok: true, result: { resultId: "sort-viewport", offset: String(offset),
            next: String(Math.min(offset + 128, rows.length)), complete: offset + 128 >= rows.length,
            rows: rows.slice(offset, offset + 128) } });
    }
    assert.equal(tableCell(app, 0, "PID"), "1");
    const offset = Number(obsolete.params.offset);
    await app.deliver(obsolete, { ok: true, result: { resultId: "sort-viewport", offset: String(offset),
        complete: true, rows: rows.slice(offset) } });
    assert.equal(tableCell(app, 0, "PID"), "1");
    assert.equal(originalOrder(app)[0], 260);
});

await check("T-UI-SORT display-cap sorting includes the last displayed record without fetching the excluded tail", async () =>
{
    const app = harness();
    await app.boot();
    const total = 100100;
    const rowsAt = offset => Array.from({ length: Math.min(128, total - offset) }, (_, index) => ({ pid: String(total - offset - index) }));
    await openTable(app, "sort-cap", rowsAt(0), { total });
    app.onPost(request =>
    {
        if (request.method === "resultPage")
        {
            const offset = Number(request.params.offset);
            const rows = rowsAt(offset);
            app.deliver(request, { ok: true, result: { resultId: "sort-cap", offset: String(offset), total: String(total),
                next: String(offset + rows.length), complete: offset + rows.length === total, rows } });
        }
    });
    sortHeader(app, "PID");
    for (let i = 0; i < 1000 && app.nodes.get("row-position").textContent.startsWith("Loading"); ++i)
    {
        await settle();
    }
    assert.equal(tableCell(app, 0, "PID"), "101");
    assert.equal(originalOrder(app)[0], 100000);
    assert.equal(app.nodes.get("result-table").getAttribute("aria-rowcount"), "100001");
    assert.ok(app.messages.filter(request => request.method === "resultPage").every(request => Number(request.params.offset) < 100000));
    assert.ok(app.nodes.get("result-rows").children.length <= 128);
    assert.ok(app.nodes.get("result-count").textContent.includes("100,100"));
});

await check("T-UI-SORT failed or malformed pages keep the original order and allow a fresh retry", async () =>
{
    for (const response of [{ ok: false, error: "ResultExpired" },
        { ok: true, result: { resultId: "sort-failure", offset: "128", next: "128", complete: false, rows: [] } }])
    {
        const app = harness();
        await app.boot();
        await openTable(app, "sort-failure", Array.from({ length: 128 }, () => ({ pid: "20" })), { total: 129 });
        sortHeader(app, "PID");
        await app.reply("resultPage", response);
        assert.equal(tableCell(app, 0, "PID"), "20");
        assert.equal(app.nodes.get("table-head").children[headers(app).indexOf("PID")].getAttribute("aria-sort"), "none");
        assert.match(app.nodes.get("result-notice-text").textContent, /Sort could not be applied/);
        assert.equal(app.nodes.get("btn-save").disabled, false);
        sortHeader(app, "PID");
        await app.reply("resultPage", { ok: true, result: { resultId: "sort-failure", offset: "128", complete: true, rows: [{ pid: "2" }] } });
        assert.equal(tableCell(app, 0, "PID"), "2");
        assert.equal(app.nodes.get("result-notice-text").textContent.includes("Sort could not"), false);
    }
});

await check("T-UI-COPY full values preserve addresses, Unicode, empty strings, null and nested paths", async () =>
{
    const copied = [];
    const app = harness({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return Promise.resolve();
    } } });
    await app.boot();
    const row = { address: "0xffffffffffffffff", message: "\uafc0\ubcf4 <&>\n".repeat(1000), zero: 0, flag: false, unknown: null,
        empty: "", nested: { value: "inner" }, "nested.value": "literal", array: [0, false, null],
        deep: { value: { message: "object" } } };
    await openTable(app, "copy-fixture", [row, { message: "second" }]);
    app.nodes.get("btn-columns-all").fire("click");
    app.nodes.get("result-rows").children[0].fire("click");
    for (const [key, value] of Object.entries(row))
    {
        const terms = app.nodes.get("detail-fields").children;
        const index = terms.findIndex(node => node.textContent === key);
        terms[index + 1].fire("click");
        await settle();
        assert.equal(copied.at(-1), typeof value === "string" ? value : JSON.stringify(value, null, 2));
    }
    for (const choice of app.nodes.get("column-list").children)
    {
        const path = JSON.parse(choice.children[0].dataset.columnKey);
        const value = path.reduce((parent, key) => parent[key], row);
        const label = choice.children[1].textContent;
        const cell = app.nodes.get("result-rows").children[0].children[headers(app).indexOf(label)];
        const button = cell;
        assert.equal(button.getAttribute("aria-label"), "Copy " + label + ", row 1");
        button.fire("click");
        await settle();
        assert.equal(copied.at(-1), typeof value === "string" ? value : JSON.stringify(value, null, 2));
    }
    app.nodes.get("result-rows").children[0].children[headers(app).indexOf("Message")].fire("click");
    await settle();
    assert.equal(copied.at(-1), row.message, "Copied the truncated table preview");
    app.nodes.get("btn-copy-row").fire("click");
    await settle();
    assert.deepEqual(JSON.parse(copied.at(-1)), row);
    const count = copied.length;
    assert.equal(app.nodes.get("result-rows").children[1].children[headers(app).indexOf("Address")].children.length, 0);
    app.nodes.get("result-rows").children[1].children[headers(app).indexOf("Address")].fire("click");
    await settle();
    assert.equal(copied.length, count, "An absent field was copied as a value");
    await openTable(app, "primitives", [null, false, 0, ""]);
    for (const [i, value] of [null, false, 0, ""].entries())
    {
        app.nodes.get("result-rows").children[i].fire("click");
        app.nodes.get("btn-copy-row").fire("click");
        await settle();
        assert.equal(copied.at(-1), JSON.stringify(value));
        app.nodes.get("result-rows").children[i].children[1].fire("click");
        await settle();
        assert.equal(copied.at(-1), typeof value === "string" ? value : JSON.stringify(value));
    }
});

await check("T-UI-COPY cells select their own row, bound Tab stops and restore focus when rows are replaced", async () =>
{
    const app = harness({ clipboard: { writeText: () => Promise.resolve() } });
    await app.boot();
    await openTable(app, "cell-copy-focus", [{ message: "first" }, { message: "second" }]);
    const rows = app.nodes.get("result-rows").children;
    const first = rows[0].children[1];
    const second = rows[1].children[1];
    assert.equal(first.tabIndex, -1);
    assert.equal(second.tabIndex, -1);
    let stopped = false;
    second.focus();
    second.fire("click", { stopPropagation: () =>
    {
        stopped = true;
    } });
    await settle();
    assert.equal(stopped, true);
    assert.equal(JSON.parse(app.nodes.get("result-detail").textContent).message, "second");
    assert.equal(app.focused(), second);
    assert.equal(first.tabIndex, -1);
    assert.equal(second.tabIndex, 0);
    app.nodes.get("result-table").fire("keydown", { key: "Escape", target: second });
    assert.equal(app.focused(), app.nodes.get("result-table"));
    second.focus();
    app.nodes.get("result-table").fire("keydown", { key: "ArrowUp", target: second });
    assert.equal(app.focused(), app.nodes.get("result-table"));
    assert.equal(first.tabIndex, 0);
    assert.equal(second.tabIndex, -1);
    first.focus();
    app.nodes.get("btn-columns-all").fire("click");
    assert.equal(app.focused(), app.nodes.get("result-table"));
    assert.equal(app.messages.some(message => message.method === "execute" || message.method === "executePlan"), false);
});

await check("T-UI-COPY context menus capture full values and original rows without executing commands", async () =>
{
    const copied = [];
    const app = harness({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return Promise.resolve();
    } } });
    await app.boot();
    const row = { value: "full\n".repeat(400), unknown: null };
    await openTable(app, "context-copy", [row]);
    const cell = app.nodes.get("result-rows").children[0].children[1];
    assert.equal(cell.children.length, 0);
    cell.fire("contextmenu", { clientX: 890, clientY: 710 });
    assert.equal(copied.length, 0, "Opening the menu copied a value");
    assert.equal(app.focused(), app.nodes.get("cell-copy-value"));
    assert.equal(app.nodes.get("cell-copy-menu").classList.contains("hidden"), false);
    app.nodes.get("cell-copy-value").fire("click");
    await settle();
    assert.equal(copied.at(-1), row.value);
    cell.fire("keydown", { key: "F10", shiftKey: true });
    app.nodes.get("cell-copy-row").fire("click");
    await settle();
    assert.deepEqual(JSON.parse(copied.at(-1)), row);
    cell.fire("keydown", { key: "c", ctrlKey: true });
    await settle();
    assert.equal(copied.at(-1), row.value);
    cell.fire("contextmenu");
    app.nodes.get("btn-columns-all").fire("click");
    assert.equal(app.nodes.get("cell-copy-menu").classList.contains("hidden"), true);
    assert.equal(app.messages.some(message => message.method === "execute" || message.method === "executePlan"), false);
});

await check("T-UI-COPY Ctrl+C preserves selected text and copies complete rows when no text is selected", async () =>
{
    const options = {};
    const app = harness(options);
    await app.boot();
    const row = { value: "0xffffabcdef012345" };
    await openTable(app, "keyboard-copy", [row]);
    app.nodes.get("result-rows").children[0].fire("click");
    const copied = [];
    const copy = { clipboardData: { setData: (type, text) => copied.push([type, text]) } };
    app.nodes.get("result-table").fire("copy", copy);
    assert.deepEqual(copied, [["text/plain", JSON.stringify(row, null, 2)]]);
    options.selection = "selected substring";
    app.nodes.get("result-table").fire("copy", copy);
    assert.equal(copied.length, 1, "Native text selection was overridden");
    await openTable(app, "empty", []);
    assert.equal(app.nodes.get("btn-copy-row").disabled, true);
    app.nodes.get("result-table").fire("copy", copy);
    assert.equal(copied.length, 1);
});

await check("T-UI-COPY denied, missing and throwing APIs offer the exact value for manual copy", async () =>
{
    for (const clipboard of [undefined, { writeText: () => Promise.reject(new Error("Denied")) },
        { writeText()
        {
            throw new Error("Unavailable");
        } }])
    {
        const app = harness({ clipboard });
        await app.boot();
        const row = { message: "large\n<&>".repeat(1000) };
        await openTable(app, "copy-denied", [row]);
        app.nodes.get("result-rows").children[0].fire("click");
        app.nodes.get("btn-copy-row").fire("click");
        await settle();
        assert.equal(app.nodes.get("copy-fallback").classList.contains("hidden"), false);
        assert.equal(app.nodes.get("copy-text").selectedText, JSON.stringify(row, null, 2));
        assert.equal(app.focused(), app.nodes.get("copy-text"));
        app.nodes.get("btn-copy-close").fire("click");
        assert.equal(app.nodes.get("copy-text").value, "");
        assert.equal(app.nodes.get("copy-fallback").classList.contains("hidden"), true);
    }
});

await check("T-UI-COPY pending writes keep their original snapshot and cannot hide command errors", async () =>
{
    let complete;
    const copied = [];
    const app = harness({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return new Promise(resolve =>
        {
            complete = resolve;
        });
    } } });
    await app.boot();
    await openTable(app, "copy-race", [{ value: "first" }, { value: "second" }]);
    app.nodes.get("result-rows").children[0].fire("click");
    app.nodes.get("btn-copy-row").fire("click");
    app.nodes.get("result-rows").children[1].fire("click");
    app.nodes.get("btn-copy-row").fire("click");
    const keyboardWrites = [];
    app.nodes.get("result-table").fire("copy", { clipboardData: { setData: (type, text) => keyboardWrites.push(text) } });
    assert.equal(keyboardWrites.length, 0, "Keyboard copy raced an outstanding clipboard write");
    app.nodes.get("btn-console-output").fire("click");
    app.enter("stack");
    await app.reply("classify", { ok: false, error: "classification failed" });
    complete();
    await settle();
    assert.equal(copied.length, 1);
    assert.equal(JSON.parse(copied[0]).value, "first");
    assert.match(app.nodes.get("workspace-feedback-text").textContent, /classification failed/);
});

await check("T-UI-COPY target refresh preserves focused field controls and Inspector text selection", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "focus-copy", [{ value: "keep me" }]);
    app.nodes.get("result-rows").children[0].fire("click");
    const button = app.nodes.get("detail-fields").children[1];
    button.focus();
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: true, result: { connected: true, stopped: true, target: stamp } });
    assert.equal(app.nodes.get("detail-fields").children[1], button);
    assert.equal(app.focused(), button);
});

await check("T-UI-SELECTION library highlight survives submission, filtering, history and retained results", async () =>
{
    const app = harness();
    await app.boot({ Kernel: [{ name: "!callbacks", synopsis: "Callbacks", support: "Stable" }],
        Debugger: [{ name: "stack", synopsis: "stack", support: "Stable" }] });
    const selected = () => app.nodes.get("catalog").querySelectorAll(".cmd-item").filter(item => item.getAttribute("aria-current") === "true");
    app.nodes.get("catalog").querySelectorAll(".cmd-item").find(item => item.dataset.command === "callbacks").fire("click");
    assert.equal(selected()[0].dataset.command, "callbacks");
    app.enter("!CALLBACKS");
    assert.equal(selected()[0].dataset.command, "callbacks");
    await app.reply("classify", { ok: false, error: "fixture end" });
    app.nodes.get("filter").value = "stack";
    app.nodes.get("filter").fire("input");
    assert.equal(selected().length, 0);
    assert.equal(app.nodes.get("selected-command").textContent, "Selected: !callbacks");
    app.nodes.get("selected-command").fire("click");
    assert.equal(selected()[0].dataset.command, "callbacks");
    assert.equal(app.focused(), selected()[0]);
    await openTable(app, "stack", [{ value: 1 }]);
    assert.equal(selected()[0].dataset.command, "stack");
    app.nodes.get("prompt").fire("keydown", { key: "ArrowUp" });
    assert.equal(selected()[0].dataset.command, "callbacks");
    await openTable(app, "stack", [{ value: 2 }]);
    assert.equal(selected()[0].dataset.command, "callbacks", "Result retrieval replaced the active draft selection");
    app.nodes.get("prompt").value = "";
    app.nodes.get("prompt").fire("input");
    assert.equal(selected()[0].dataset.command, "callbacks", "Clearing the prompt lost the last selection");
});

await check("T-UI-CONSOLE Off persists, skips streams, keeps errors and Export, and is independent of collapse", async () =>
{
    const saved = new Map([["kndbgx.console-output", "off"]]);
    const app = harness({ storage: { getItem: key => saved.get(key), setItem: (key, value) => saved.set(key, value) } });
    await app.boot();
    assert.equal(app.nodes.get("btn-console-output").getAttribute("aria-checked"), "false");
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    await app.reply("execute", { ok: true, result: { resultId: "off-result", rowCount: "0", data: { commandId: "stack", target: stamp } } });
    assert.equal(app.messages.filter(item => item.method === "outputChunk").length, 0);
    assert.equal(app.nodes.get("output").children.length, 0);
    assert.equal(app.nodes.get("btn-save").disabled, false);
    app.nodes.get("btn-save").fire("click");
    await app.reply("saveLog", { ok: true, result: { path: "C:\\temp\\retained.json" } });
    assert.match(app.nodes.get("workspace-feedback-text").textContent, /retained.json/);
    assert.equal(app.nodes.get("btn-console").getAttribute("aria-expanded"), "false");
    app.enter("failed");
    await app.reply("classify", { ok: false, error: "visible failure" });
    assert.match(app.nodes.get("workspace-feedback-text").textContent, /visible failure/);
    assert.equal(app.nodes.get("output").children.length, 0);
    app.nodes.get("btn-console-output").fire("click");
    assert.equal(saved.get("kndbgx.console-output"), "on");
    assert.equal(app.nodes.get("btn-console").getAttribute("aria-expanded"), "false");
});

await check("T-UI-CONSOLE toggling during planning, execution or streaming never resumes skipped output", async () =>
{
    for (const stage of ["planning", "execution", "streaming"])
    {
        const initiallyOff = stage !== "streaming";
        const app = harness();
        await app.boot();
        if (initiallyOff)
        {
            app.nodes.get("btn-console-output").fire("click");
        }
        app.enter("stack");
        if (stage === "planning")
        {
            app.nodes.get("btn-console-output").fire("click");
        }
        await app.reply("classify", { ok: true, result: { write: false } });
        if (initiallyOff)
        {
            if (stage === "execution")
            {
                app.nodes.get("btn-console-output").fire("click");
            }
            await app.reply("execute", { ok: true, result: { resultId: "muted", rowCount: "0" } });
            assert.equal(app.messages.filter(item => item.method === "outputChunk").length, 0);
        }
        else
        {
            await app.reply("execute", { ok: true, result: { resultId: "muted", rowCount: "0" } });
            app.nodes.get("btn-console-output").fire("click");
            app.nodes.get("btn-console-output").fire("click");
            await app.reply("outputChunk", { ok: true, result: { resultId: "muted", offset: "0", next: "5", complete: false, text: "LATE!" } });
            assert.equal(app.messages.filter(item => item.method === "outputChunk").length, 1);
            assert.ok(!app.nodes.get("output").children.some(node => (node.innerHTML || "").includes("LATE!")));
        }
        assert.equal(app.nodes.get("btn-cancel").disabled, true);
    }
});

await check("T-UI-CONSOLE Copy preserves literal displayed text and respects Clear", async () =>
{
    const copied = [];
    const app = harness({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return Promise.resolve();
    } } });
    await app.boot();
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    app.nodes.get("btn-clear").fire("click");
    const output = "[tag] <script>&\n\uafc0\ubcf4\r\n  tail  ";
    await app.reply("execute", { ok: true, result: { output, rowCount: "0" } });
    app.nodes.get("btn-copy-console").fire("click");
    await settle();
    assert.equal(copied.at(-1), output);
    app.nodes.get("btn-clear").fire("click");
    assert.equal(app.nodes.get("btn-copy-console").disabled, true);
    app.nodes.get("btn-copy-console").fire("click");
    assert.equal(copied.length, 1);
});

await check("T-UI-COPY embedded NUL values use JSON escaping instead of silently truncating Windows clipboard text", async () =>
{
    const copied = [];
    const app = harness({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return Promise.resolve();
    } } });
    await app.boot();
    const value = "before\u0000after";
    await openTable(app, "nul-copy", [{ value }]);
    app.nodes.get("result-rows").children[0].children[1].fire("click");
    await settle();
    assert.equal(copied[0], JSON.stringify(value));
    assert.match(app.nodes.get("copy-status").textContent, /embedded NUL/);
});

await check("T-UI-SELECTION late command and retained-result completions cannot replace a newer cleared draft", async () =>
{
    for (const retained of [false, true])
    {
        const app = harness();
        await app.boot({ Debugger: [{ name: "stack", synopsis: "stack", support: "Stable" },
            { name: "registers", synopsis: "registers", support: "Stable" }] });
        if (retained)
        {
            app.nodes.get("result-id-input").value = "older";
            app.nodes.get("btn-result-load").fire("click");
        }
        else
        {
            app.enter("stack");
            await app.reply("classify", { ok: true, result: { write: false } });
        }
        app.nodes.get("catalog").querySelectorAll(".cmd-item").find(item => item.dataset.command === "registers").fire("click");
        app.nodes.get("prompt").value = "";
        app.nodes.get("prompt").fire("input");
        await app.reply(retained ? "resultInfo" : "execute", { ok: true, result: { resultId: "older", command: "stack", rowCount: "0" } });
        assert.equal(app.nodes.get("selected-command").textContent, "Selected: registers");
    }
});

await check("T-UI-CONSOLE Operations displays and acknowledges recovered receipts with output off", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-operations").fire("click");
    await app.reply("operations", { ok: true, result: { records: [{ operationId: "op-1" }], complete: true, next: "1" } });
    await app.reply("operationStatus", { ok: true, result: { operationId: "op-1", phase: "Completed", ok: true, path: "C:/saved.json" } });
    await app.reply("operationAck", { ok: true, result: true });
    assert.equal(app.messages.filter(item => item.method === "operationAck").length, 1);
    assert.equal(app.nodes.get("operations-list").children.length, 1);
    assert.equal(app.nodes.get("operations-panel").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("btn-console-output").getAttribute("aria-checked"), "false");
    assert.equal(app.nodes.get("btn-console").getAttribute("aria-expanded"), "false");
    assert.equal(app.messages.filter(item => item.method === "execute" || item.method === "saveLog").length, 0);
});

await check("T-UI-RESULT live collection gaps, exact counters, errors and limits are visible without console output", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-console-output").fire("click");
    await openTable(app, "!dml_proc", [], { metadata: { status: "Partial",
        coverage: { complete: false, stopReason: "GlobalWalkBudget", visitedEntries: "18446744073709551615", unknownEntries: "5", unreadableEntries: "2" },
        limitations: ["<img src=x> is literal text"], analysis: { expectedQueues: "512", completedQueues: "18", firstUnreadAddress: "0xffff800012345678",
            inputCollections: [{ metadata: "nested context metadata" }, {}, {}] },
        provenance: { source: "TargetMemory:PsActiveProcessHead" } } });
    assert.match(app.nodes.get("result-summary").textContent, /Partial result/);
    assert.match(app.nodes.get("result-notice-text").textContent, /time or entry limit/);
    assert.match(app.nodes.get("result-notice-text").textContent, /5 unknown \/ 2 unreadable/);
    const details = app.nodes.get("result-facts").children;
    assert.ok(details.some(node => node.textContent.includes("18,446,744,073,709,551,615 visited")));
    assert.ok(details.some(node => node.textContent === "<img src=x> is literal text"));
    assert.ok(details.some(node => node.textContent === "Completed Queues"));
    assert.ok(details.some(node => node.textContent === "0xffff800012345678"));
    assert.ok(details.some(node => node.textContent === "3 items (see Export for full details)"));
    assert.ok(!details.some(node => node.textContent.includes("nested context metadata")));
    assert.equal(app.nodes.get("empty-title").textContent, "No rows collected");
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: true, result: { connected: true, stopped: true, target: stamp } });
    assert.equal(app.nodes.get("result-facts").children[0], details[0], "Status refresh destroyed detail text selection");
    await openTable(app, "db invalid", [], { metadata: { status: "InvalidInput", error: { message: "Cannot evaluate <address>" },
        coverage: { complete: false, stopReason: "NotCollected" } } });
    assert.equal(app.nodes.get("empty-message").textContent, "Cannot evaluate <address>");
    assert.match(app.nodes.get("result-notice-text").textContent, /Cannot evaluate <address>/);
    await openTable(app, "status", [], { metadata: { status: "Success", coverage: { complete: false, stopReason: "NotCollected" } } });
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), true, "Non-collector success was marked incomplete");
    await openTable(app, "inconsistent", [], { metadata: { status: "Success", coverage: { complete: false, stopReason: "CollectionBudget" } } });
    assert.match(app.nodes.get("result-summary").textContent, /Partial result/);
});

await check("T-UI-RESULT native function text reports unverified coverage with an output action", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "uf", [{ kind: "HostFunctionDisassembly", address: "0xffff800000001000",
        addressSpace: "virtual", engineCompleted: true }], { metadata: { status: "Partial",
        coverage: { complete: false, unknownEntries: "1", stopReason: "HostFunctionDisassemblyUnparsed" } } });
    assert.match(app.nodes.get("result-summary").textContent, /Partial result/);
    assert.match(app.nodes.get("result-notice-text").textContent, /complete function coverage has not been verified/);
});

await check("T-UI-RESULT a live Partial reply does not replace the collection reason with its status name", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-console-output").fire("click");
    app.enter("!timer");
    await app.reply("classify", { ok: true, result: { write: false } });
    await app.reply("execute", { ok: true, result: { ok: false, error: "Partial", resultId: "timer-result", rowCount: "0",
        outputLength: "80", data: { commandId: "!timer", status: "Partial", target: stamp,
            coverage: { complete: false, stopReason: "CollectionBudget" }, error: { message: "" } } } });
    assert.equal(app.nodes.get("empty-title").textContent, "No rows collected");
    assert.match(app.nodes.get("empty-message").textContent, /time or entry limit/);
    assert.ok(!app.nodes.get("result-notice-text").textContent.startsWith("Partial Collection"));
});

await check("T-UI-RESULT CPU columns explain unavailable values while copy and raw records retain original data", async () =>
{
    const copied = [];
    const app = harness({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return Promise.resolve();
    } } });
    await app.boot();
    const row = { kind: "ProcessorRegister", cpu: "1", register: "LSTAR", value: null,
        registerSource: "CurrentProcessorMsr", unavailableReason: "ProcessorSwitchRequired" };
    await openTable(app, "!msrcheck", [row], { metadata: { status: "Partial", coverage: { complete: false, stopReason: "FieldsOrOwnershipUnavailable" },
        provenance: { source: "TargetRegisters:CurrentProcessorMsr" } } });
    assert.deepEqual(headers(app).slice(1, 4), ["CPU", "Register", "Value"]);
    assert.equal(tableCell(app, 0, "Value"), "Unknown");
    assert.equal(tableCell(app, 0, "Why unavailable"), "Not read on this CPU");
    assert.match(app.nodes.get("result-notice-text").textContent, /not a comparison across CPUs/);
    assert.match(app.nodes.get("result-notice-text").textContent, /Some MSRs were not read/);
    assert.ok(!app.nodes.get("result-notice-text").textContent.includes("owning modules"));
    app.nodes.get("result-rows").children[0].children[headers(app).indexOf("Why unavailable")].fire("click");
    await settle();
    assert.equal(copied[0], "ProcessorSwitchRequired");
    app.nodes.get("result-rows").children[0].fire("click");
    assert.deepEqual(JSON.parse(app.nodes.get("result-detail").textContent), row);
    await openTable(app, "!cr", [{ cpu: "0", register: "cr4", value: "0x00000000003506f8", smep: true, smap: true }],
        { metadata: { status: "Success", provenance: { source: "TargetMemory:SavedProcessorControl" } } });
    assert.ok(headers(app).includes("SMEP"));
    assert.match(app.nodes.get("result-notice-text").textContent, /saved CPU state/);
});

function feedbackTimers(app)
{
    return [...app.timers].filter(([id]) => app.timerDelays.get(id) === 5000);
}

await check("T-UI-NOTICE transient messages reset their timeout and expire without changing drafts or focus", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-console-output").fire("click");
    const first = feedbackTimers(app)[0];
    assert.ok(first);
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    const second = feedbackTimers(app)[0];
    assert.notEqual(second[0], first[0]);
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    const current = feedbackTimers(app)[0];
    assert.notEqual(current[0], second[0]);
    assert.equal(feedbackTimers(app).length, 1);
    first[1]();
    second[1]();
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), false);
    app.nodes.get("prompt").value = "unsent draft";
    app.nodes.get("prompt").focus();
    const count = app.messages.length;
    app.timers.delete(current[0]);
    app.timerDelays.delete(current[0]);
    current[1]();
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("prompt").value, "unsent draft");
    assert.equal(app.focused(), app.nodes.get("prompt"));
    assert.equal(app.messages.length, count);
    assert.equal(feedbackTimers(app).length, 0);
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-workspace-dismiss").focus();
    const focused = feedbackTimers(app)[0];
    app.timers.delete(focused[0]);
    app.timerDelays.delete(focused[0]);
    focused[1]();
    assert.equal(app.focused(), app.nodes.get("prompt"));
    assert.equal(app.nodes.get("prompt").value, "unsent draft");
});

await check("T-UI-NOTICE expiry restores focused Dismiss to the results when the command input is locked", async () =>
{
    const app = await memoryApp();
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "EngineBusy" });
    assert.equal(app.nodes.get("prompt").disabled, true);
    app.nodes.get("btn-workspace-dismiss").focus();
    const pending = feedbackTimers(app)[0];
    assert.ok(pending);
    app.timers.delete(pending[0]);
    app.timerDelays.delete(pending[0]);
    const count = app.messages.length;
    pending[1]();
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true);
    assert.equal(app.focused(), app.nodes.get("result-table"));
    assert.equal(app.messages.length, count);
    assert.equal(app.nodes.get("prompt").disabled, true);
});

await check("T-UI-NOTICE old timers cannot hide persistent failures and manual dismissal cancels timeouts", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-console-output").fire("click");
    const old = feedbackTimers(app)[0];
    app.enter("broken-command");
    await app.reply("classify", { ok: false, error: "classification failed" });
    assert.equal(feedbackTimers(app).length, 0);
    old[1]();
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), false);
    assert.match(app.nodes.get("workspace-feedback-text").textContent, /classification failed/);
    app.nodes.get("btn-workspace-dismiss").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    const pending = feedbackTimers(app)[0];
    app.nodes.get("btn-workspace-dismiss").fire("click");
    assert.equal(feedbackTimers(app).length, 0);
    pending[1]();
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true);
});

await check("T-UI-NOTICE workspace messages dismiss without RPCs and later messages remain visible", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-console-output").fire("click");
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), false);
    const count = app.messages.length;
    app.nodes.get("btn-workspace-dismiss").focus();
    app.nodes.get("btn-workspace-dismiss").fire("click");
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true);
    assert.equal(app.focused(), app.nodes.get("prompt"));
    assert.equal(app.messages.length, count);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true);
    app.nodes.get("btn-console-output").fire("click");
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), false);
    assert.match(app.nodes.get("workspace-feedback-text").textContent, /output is on/);
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    const repeated = app.nodes.get("workspace-feedback-text").textContent;
    app.nodes.get("btn-workspace-dismiss").fire("click");
    const beforeRepeat = app.messages.length;
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("workspace-feedback-text").textContent, repeated);
    assert.equal(app.messages.length, beforeRepeat);
});

await check("T-UI-NOTICE historical result dismissal survives polling and sorting without enabling stale actions", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    const rows = [{ address: "0xffff800000002000", addressSpace: "virtual", sourceFile: "fixture.cpp" }];
    const old = { ...stamp, contextGeneration: "2" };
    await openTable(app, "u", rows, { metadata: { status: "Success", target: old } });
    app.nodes.get("result-rows").children[0].fire("click");
    assert.match(app.nodes.get("result-notice-text").textContent, /earlier debugger context/);
    const count = app.messages.length;
    app.nodes.get("btn-result-notice-dismiss").focus();
    app.nodes.get("btn-result-notice-dismiss").fire("click");
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), true);
    assert.equal(app.focused(), app.nodes.get("result-table"));
    assert.equal(app.messages.length, count);
    for (let attempt = 0; attempt < 3; ++attempt)
    {
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app);
        assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), true);
        for (const id of ["btn-navigate", "btn-disassemble", "btn-source"])
        {
            assert.equal(app.nodes.get(id).disabled, true);
        }
    }
    sortHeader(app, "Address");
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), true);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stamp, contextGeneration: "4" });
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), false);
    app.nodes.get("btn-result-notice-dismiss").fire("click");
    await openTable(app, "u", rows, { id: "other-result", metadata: { status: "Success", target: old } });
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), false);
});

await check("T-UI-NOTICE dismissing partial coverage retains Details and a new delivery failure reopens the banner", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    const rows = Array.from({ length: 128 }, (_, index) => ({ address: "0x" + (4096 + index).toString(16) }));
    await openTable(app, "partial", rows, { total: 129, metadata: { status: "Partial",
        coverage: { complete: false, unknownEntries: "1", stopReason: "CollectionBudget" } } });
    const facts = app.nodes.get("result-facts").children.map(node => node.textContent);
    app.nodes.get("btn-result-notice-dismiss").fire("click");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), true);
    assert.match(app.nodes.get("result-summary").textContent, /Partial result/);
    assert.deepEqual(app.nodes.get("result-facts").children.map(node => node.textContent), facts);
    sortHeader(app, "Address");
    await app.reply("resultPage", { ok: false, error: "Stored result expired" });
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), false);
    assert.match(app.nodes.get("result-notice-text").textContent, /Sort could not be applied/);
});

await check("T-UI-NOTICE empty partial results keep their evidence through busy status, disconnect and reconnect", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "empty-partial", [], { metadata: { status: "Partial",
        coverage: { complete: false, unknownEntries: "1", stopReason: "CollectionBudget" } } });
    const facts = app.nodes.get("result-facts").children.map(node => node.textContent);
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-result-notice-dismiss").focus();
    app.nodes.get("btn-result-notice-dismiss").fire("click");
    assert.equal(app.focused(), app.nodes.get("result-table"));
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), false);
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "EngineBusy" });
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), true);
    assert.match(app.nodes.get("result-summary").textContent, /Partial result \/ Current/);
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "NoSession" });
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), false);
    assert.match(app.nodes.get("result-summary").textContent, /Partial result \/ Historical/);
    app.nodes.get("btn-result-notice-dismiss").fire("click");
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "NoSession" });
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), true);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), false);
    assert.match(app.nodes.get("result-summary").textContent, /Partial result \/ Current/);
    assert.deepEqual(app.nodes.get("result-facts").children.map(node => node.textContent), facts);
    assert.equal(app.nodes.get("result-empty").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("btn-navigate").disabled, true);
    app.nodes.get("btn-workspace-dismiss").focus();
    app.nodes.get("btn-workspace-dismiss").fire("click");
    assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), false);
});

await check("T-UI-NOTICE every debugger context component reopens an acknowledged historical notice", async () =>
{
    for (const changed of [
        { sessionId: "other-session" }, { targetGeneration: "2" }, { stopEpoch: "3" },
        { contextGeneration: "4" }, { symbolGeneration: "5" },
        { contextIdentity: { implicitProcess: "0xffff800000003000" } }
    ])
    {
        const app = harness();
        await app.boot();
        const old = { ...stamp, contextGeneration: "0" };
        await openTable(app, "u", [{ address: "0xffff800000002000", addressSpace: "virtual" }],
            { metadata: { status: "Success", target: old } });
        app.nodes.get("result-rows").children[0].fire("click");
        app.nodes.get("btn-result-notice-dismiss").fire("click");
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, { ...stamp, ...changed });
        assert.equal(app.nodes.get("result-notice").classList.contains("hidden"), false, JSON.stringify(changed));
        assert.equal(app.nodes.get("btn-navigate").disabled, true);
        assert.equal(app.nodes.get("btn-disassemble").disabled, true);
    }
});

await check("T-UI-RESULT View output reads saved text without re-execution and handles duplicates, cancellation and expiry", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-console-output").fire("click");
    await openTable(app, "db nt L10", [], { outputLength: "128", metadata: { status: "Success" } });
    assert.equal(app.nodes.get("empty-title").textContent, "Text output");
    const before = app.messages.length;
    app.nodes.get("btn-empty-output").fire("click");
    app.nodes.get("btn-result-output").fire("click");
    assert.equal(app.messages.slice(before).filter(item => item.method === "outputChunk").length, 1);
    assert.equal(app.messages.slice(before).filter(item => item.method === "classify" || item.method === "execute").length, 0);
    assert.equal(app.nodes.get("btn-console-output").getAttribute("aria-checked"), "true");
    await app.reply("outputChunk", { ok: true, result: { resultId: "db nt L10", offset: "0", next: "16", complete: true, text: "4d 5a <literal>" } });
    assert.equal(app.nodes.get("btn-result-output").disabled, false);
    assert.ok(app.nodes.get("output").children.some(node => node.innerHTML.includes("4d 5a")));
    app.nodes.get("btn-result-output").fire("click");
    const pending = app.latest("outputChunk");
    app.nodes.get("btn-cancel").fire("click");
    await app.deliver(pending, { ok: true, result: { resultId: "db nt L10", offset: "0", next: "6", complete: true, text: "STALE!" } });
    assert.ok(!app.nodes.get("output").children.some(node => node.innerHTML.includes("STALE!")));
    app.nodes.get("btn-result-output").fire("click");
    await app.reply("outputChunk", { ok: false, error: "Stored result expired" });
    assert.ok(app.nodes.get("output").children.some(node => node.innerHTML.includes("Stored result expired")));
    assert.equal(app.nodes.get("btn-result-output").disabled, false);
    assert.equal(app.messages.filter(item => item.method === "execute").length, 0);
    await openTable(app, "empty", [], { outputLength: "0", metadata: { status: "Success" } });
    assert.equal(app.nodes.get("btn-empty-output").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("btn-result-output").disabled, true);
    app.nodes.get("result-collection").value = "findings";
    app.nodes.get("result-collection").fire("change", { target: app.nodes.get("result-collection") });
    assert.equal(app.nodes.get("btn-result-output").disabled, true, "Changing collections lost the saved output length");
    app.nodes.get("result-collection").value = "rows";
    app.nodes.get("result-collection").fire("change", { target: app.nodes.get("result-collection") });
    assert.equal(app.nodes.get("empty-title").textContent, "No rows returned");
});

const processRows = Array.from({ length: 257 }, (_, i) => ({ kind: "Process", pid: String(i * 4), image: "process" + i + ".exe",
    eprocess: "0xffff8000" + (0x1000 + i * 0x100).toString(16).padStart(8, "0"), dtb: "0x12345000", createTime: "18446744073709551000" }));

function showProcesses(app)
{
    if (app.nodes.get("memory").classList.contains("hidden"))
    {
        app.nodes.get("btn-memory-panel").fire("click");
    }
    app.nodes.get("tab-processes").fire("click");
}

async function processStatus(app, target = stamp, overrides = {})
{
    await app.reply("status", { ok: true, result: { connected: true, kernelMode: true, stopped: true, canEditBreakpoints: true, canControlExecution: true, execStatus: "break",
        canAttachProcess: true, target, ...overrides } });
}

async function collectProcessPages(app, rows = processRows, options = {})
{
    const id = options.id || "process-inventory";
    await app.reply("execute", { ok: true, result: { ok: !options.partial, resultId: id, rowCount: String(rows.length),
        findingCount: "0", data: { commandId: "!dml_proc", status: options.partial ? "Partial" : "Success", target: options.target || stamp,
            coverage: { complete: !options.partial, stopReason: options.partial ? "ReadLimit" : "Complete" } } } });
    for (let offset = 0; offset < rows.length; offset += 128)
    {
        const page = rows.slice(offset, offset + 128);
        await app.reply("resultPage", { ok: true, result: { resultId: id, collection: "rows", offset: String(offset),
            next: String(offset + page.length), total: String(rows.length), complete: offset + page.length === rows.length, rows: page } });
    }
    await processStatus(app, options.target || stamp);
}

const processSortRows = [
    { kind: "Process", pid: "10", image: "worker10.exe", eprocess: "0xffff800000001002", dtb: "0x1000000000000001", createTime: "18446744073709551001" },
    { kind: "Process", pid: "2", image: "worker2.exe", eprocess: "0xffff800000001001", dtb: "0x1000000000000000", createTime: "18446744073709551000" },
    { kind: "Process", pid: "0", image: "Idle", eprocess: "0xffff800000001000", dtb: "0x0", createTime: "0" },
    { kind: "Process", pid: null, image: null, eprocess: "0xffff800000001004", dtb: null, createTime: null },
    { kind: "Process", pid: "2", image: "WORKER2.exe", eprocess: "0xffff800000001003", dtb: "0x1000000000000000", createTime: "18446744073709551000" }
];

await check("T-UI-PROCESSES every column sorts both ways with exact integers, stable ties and unknowns last", async () =>
{
    const app = harness();
    await app.boot();
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, processSortRows);
    const before = app.messages.length;
    const order = () => app.nodes.get("process-rows").children.map(row => Number(row.dataset.processIndex));
    assert.deepEqual(order(), [0, 1, 2, 3, 4]);
    for (const key of ["pid", "image", "eprocess", "dtb", "createTime"])
    {
        const button = app.nodes.get("process-sort-" + key);
        button.fire("click");
        assert.deepEqual(order(), key === "eprocess" ? [2, 1, 0, 4, 3] : [2, 1, 4, 0, 3], key);
        assert.equal(app.nodes.get("process-column-" + key).getAttribute("aria-sort"), "ascending");
        assert.equal(button.dataset.sortDirection, "ascending");
        button.fire("click");
        assert.deepEqual(order(), key === "eprocess" ? [3, 4, 0, 1, 2] : [0, 1, 4, 2, 3], key);
        assert.equal(app.nodes.get("process-column-" + key).getAttribute("aria-sort"), "descending");
        assert.match(button.title, /Sort ascending/);
    }
    assert.equal(app.nodes.get("process-column-pid").getAttribute("aria-sort"), "none");
    assert.equal(app.messages.length, before, "Sorting must not query the debugger or reload result pages");
});

await check("T-UI-PROCESSES sorting retains source action bindings and survives filtering, refresh and page failure", async () =>
{
    const app = harness();
    await app.boot();
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, processSortRows);
    app.nodes.get("process-rows").children[4].fire("click");
    app.nodes.get("process-sort-pid").fire("click");
    assert.match(app.nodes.get("process-name").textContent, /WORKER2.exe \/ PID 2/);
    assert.match(app.nodes.get("process-position").textContent, /row 3/);
    app.nodes.get("process-sort-pid").fire("click");
    app.nodes.get("process-filter").value = "worker";
    app.nodes.get("process-filter").fire("input");
    assert.deepEqual(app.nodes.get("process-rows").children.map(row => row.dataset.processIndex), ["0", "1", "4"]);
    app.nodes.get("btn-process-threads").fire("click");
    assert.equal(app.latest("processAction").params.index, "4");
    await app.reply("processAction", { ok: true, result: { ok: true, resultId: "sorted-threads", rowCount: "0", outputLength: "0",
        data: { commandId: "!threads", status: "Success", target: stamp } } });
    await app.reply("outputChunk", { ok: true, result: { resultId: "sorted-threads", offset: "0", next: "0", text: "", complete: true } });
    await processStatus(app);
    app.nodes.get("btn-process-refresh").fire("click");
    app.nodes.get("process-sort-image").fire("click");
    await collectProcessPages(app, processSortRows.slice().reverse(), { id: "refreshed-sorted-processes" });
    assert.equal(app.nodes.get("process-column-image").getAttribute("aria-sort"), "ascending");
    assert.match(app.nodes.get("process-name").textContent, /WORKER2.exe \/ PID 2/);
    assert.deepEqual(app.nodes.get("process-rows").children.map(row => row.dataset.processIndex), ["0", "3", "4"]);
    app.nodes.get("btn-process-refresh").fire("click");
    await app.reply("execute", { ok: true, result: { resultId: "failed-sorted-processes", rowCount: "1",
        data: { commandId: "!dml_proc", status: "Success", target: stamp } } });
    await app.reply("resultPage", { ok: false, error: "Fixture page unavailable" });
    await processStatus(app);
    assert.deepEqual(app.nodes.get("process-rows").children.map(row => row.dataset.processIndex), ["0", "3", "4"]);
    assert.equal(app.nodes.get("process-column-image").getAttribute("aria-sort"), "ascending");
    assert.match(app.nodes.get("process-name").textContent, /WORKER2.exe/);
});

await check("T-UI-PROCESSES independent paged inventory, search, bound details and no replay on stale attach", async () =>
{
    const app = harness();
    await app.boot();
    await openTable(app, "previous-command", [{ address: "0x1000" }]);
    showProcesses(app);
    await processStatus(app);
    assert.equal(app.latest("execute").params.command, "!dml_proc");
    await collectProcessPages(app);
    assert.match(app.nodes.get("process-summary").textContent, /257 shown \/ 257 collected \/ complete/);
    assert.equal(app.nodes.get("result-title").textContent, "previous-command");
    assert.ok(app.nodes.get("process-rows").children.length <= 128);
    app.nodes.get("process-filter").value = "process256";
    app.nodes.get("process-filter").fire("input");
    assert.equal(app.nodes.get("process-rows").children.length, 1);
    app.nodes.get("process-rows").children[0].fire("click");
    app.nodes.get("btn-process-threads").fire("click");
    assert.equal(app.latest("processAction").params.index, "256");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("processAction").params.expectedStamp)), stamp);
    await app.reply("processAction", { ok: true, result: { ok: true, resultId: "thread-result", rowCount: "0", outputLength: "0",
        data: { commandId: "!threads", status: "Success", target: stamp } } });
    await app.reply("outputChunk", { ok: true, result: { resultId: "thread-result", offset: "0", next: "0", text: "", complete: true } });
    await processStatus(app);
    assert.equal(app.nodes.get("evidence").classList.contains("hidden"), false);
    const count = app.messages.filter(item => item.method === "execute").length;
    showProcesses(app);
    await processStatus(app);
    assert.equal(app.messages.filter(item => item.method === "execute").length, count, "Tab return unnecessarily recollected processes");
    app.nodes.get("btn-process-attach").fire("click");
    await app.reply("processAction", { ok: false, error: "StaleProcessList" });
    await processStatus(app);
    assert.match(app.nodes.get("workspace-feedback-text").textContent, /StaleProcessList/);
    assert.equal(app.nodes.get("btn-process-attach").disabled, true, "Rejected inventory remained actionable");
    assert.equal(app.messages.filter(item => item.method === "processAction" && item.params.action === "attach").length, 1);
    assert.equal(app.messages.filter(item => item.method === "execute").length, count);
    app.nodes.get("process-filter").value = "no-such-process";
    app.nodes.get("process-filter").fire("input");
    assert.equal(app.nodes.get("btn-process-attach").disabled, true, "A filtered-out process retained an enabled attach button");
});

await check("T-UI-PROCESSES stale, running, disconnected and partial snapshots keep their coverage", async () =>
{
    const app = harness();
    await app.boot();
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, processRows.slice(0, 2), { partial: true });
    app.nodes.get("process-rows").children[1].fire("click");
    assert.match(app.nodes.get("process-notice").textContent, /ReadLimit/);
    assert.equal(app.nodes.get("btn-process-attach").disabled, false);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { stopped: false, canAttachProcess: false });
    assert.equal(app.nodes.get("btn-process-attach").disabled, true);
    assert.equal(app.nodes.get("process-rows").children.length, 2);
    app.nodes.get("btn-refresh-status").fire("click");
    const nextStop = { ...stamp, stopEpoch: "3" };
    await processStatus(app, nextStop);
    assert.equal(app.messages.filter(item => item.method === "execute").length, 2);
    await collectProcessPages(app, processRows.slice(0, 2), { target: nextStop });
    assert.equal(app.nodes.get("btn-process-attach").disabled, false);
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "Disconnected" });
    assert.equal(app.nodes.get("btn-process-attach").disabled, true);
    assert.match(app.nodes.get("process-notice").textContent, /disconnected/);
});

await check("T-UI-PROCESSES invalid pages and cancellation preserve the previous complete list", async () =>
{
    const app = harness();
    await app.boot();
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, processRows.slice(0, 2));
    app.nodes.get("btn-process-refresh").fire("click");
    assertCommandActivity(app, true, "Loading processes");
    await app.reply("execute", { ok: true, result: { resultId: "bad-page", rowCount: "2",
        data: { commandId: "!dml_proc", status: "Success", target: stamp } } });
    await app.reply("resultPage", { ok: true, result: { resultId: "bad-page", collection: "rows", offset: "0", next: "0",
        total: "2", complete: false, rows: [] } });
    assertCommandActivity(app, false);
    await processStatus(app);
    assert.match(app.nodes.get("process-notice").textContent, /Invalid process page/);
    assert.equal(app.nodes.get("process-rows").children.length, 2);
    app.nodes.get("btn-process-refresh").fire("click");
    app.nodes.get("btn-cancel").fire("click");
    await app.reply("execute", { ok: true, result: { resultId: "cancelled-list", rowCount: "0",
        data: { commandId: "!dml_proc", status: "Success", target: stamp } } });
    await processStatus(app);
    assert.match(app.nodes.get("process-notice").textContent, /cancelled/);
    assert.equal(app.nodes.get("process-rows").children.length, 2);
    app.nodes.get("btn-process-refresh").fire("click");
    await collectProcessPages(app, []);
    assert.equal(app.nodes.get("process-rows").children.length, 0);
    assert.match(app.nodes.get("process-summary").textContent, /0 shown \/ 0 collected \/ complete/);
    assert.equal(app.nodes.get("btn-process-attach").disabled, true);
});

await check("T-UI-PROCESSES Stop cancels detail output delivery without interrupting a completed engine action", async () =>
{
    const app = harness();
    await app.boot();
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, processRows.slice(0, 2));
    app.nodes.get("process-rows").children[1].fire("click");
    app.nodes.get("btn-process-threads").fire("click");
    await app.reply("processAction", { ok: true, result: { ok: true, resultId: "thread-output", rowCount: "0", outputLength: "100",
        data: { commandId: "!threads", status: "Success", target: stamp } } });
    const interrupts = app.messages.filter(item => item.method === "interrupt").length;
    app.nodes.get("btn-cancel").fire("click");
    await app.reply("outputChunk", { ok: true, result: { resultId: "thread-output", offset: "0", next: "10", text: "first page", complete: false } });
    assert.equal(app.messages.filter(item => item.method === "outputChunk").length, 1, "Stopped output requested another page");
    assert.equal(app.messages.filter(item => item.method === "interrupt").length, interrupts, "Output Stop interrupted an already completed action");
    assert.equal(app.nodes.get("btn-cancel").disabled, true);
    assert.equal(app.nodes.get("result-title").textContent, "!threads");
});

await check("T-UI-PROCESSES toggling Console Off during details never resumes skipped output", async () =>
{
    const app = harness();
    await app.boot();
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, processRows.slice(0, 2));
    app.nodes.get("process-rows").children[1].fire("click");
    app.nodes.get("btn-process-details").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    app.nodes.get("btn-console-output").fire("click");
    await app.reply("processAction", { ok: true, result: { ok: true, resultId: "process-output", rowCount: "0", outputLength: "100",
        data: { commandId: "!process", status: "Success", target: stamp } } });
    assert.equal(app.messages.some(item => item.method === "outputChunk"), false, "A late detail reply resumed muted output");
    assert.equal(app.nodes.get("btn-cancel").disabled, true);
    assert.equal(app.nodes.get("result-title").textContent, "!process");
});

function memoryRows(bytes, address = "0xffff800000001000", space = "virtual")
{
    return Array.from({ length: bytes.length / 16 }, (_, index) => ({ kind: "MemoryBytes", addressSpace: space,
        address: "0x" + (BigInt(address) + BigInt(index * 16)).toString(16).padStart(16, "0"), bytes: bytes.slice(index * 16, index * 16 + 16) }));
}

async function memoryReply(app, bytes, options = {})
{
    const id = options.id || "memory-view";
    const rows = memoryRows(bytes, options.address, options.space);
    await app.reply("memoryRead", { ok: true, result: { resultId: id, rowCount: String(rows.length),
        data: { commandId: options.space === "physical" ? "!db" : "db", target: options.target || stamp,
            status: bytes.includes(null) ? "Partial" : "Success", analysis: { memoryRead: options.evidence } } } });
    for (let offset = 0; offset < rows.length; offset += 2)
    {
        const page = rows.slice(offset, offset + 2);
        await app.reply("resultPage", { ok: true, result: { resultId: id, collection: "rows", offset: String(offset),
            rows: page, next: String(offset + page.length), total: String(rows.length), complete: offset + page.length === rows.length } });
    }
    await processStatus(app, options.target || stamp);
}

async function memoryApp(options = {})
{
    const app = harness(options);
    app.nodes.get("memory").children.push(app.nodes.get("memory-view"), app.nodes.get("disassembly-view"), app.nodes.get("btn-memory-close"));
    app.nodes.get("memory-view").children.push(app.nodes.get("memory-address"), app.nodes.get("memory-grid"));
    app.nodes.get("disassembly-view").children.push(app.nodes.get("disassembly-address"), app.nodes.get("disassembly-grid"));
    app.nodes.get("disassembly-grid").children.push(app.nodes.get("disassembly-rows"));
    app.nodes.get("memory-grid").children.push(app.nodes.get("memory-head"), app.nodes.get("memory-rows"));
    app.nodes.get("copy-fallback").children.push(app.nodes.get("copy-text"), app.nodes.get("btn-copy-close"));
    await app.boot();
    await openTable(app, "retained-result", [{ address: "0x1234" }]);
    if (app.nodes.get("memory").classList.contains("hidden"))
    {
        app.nodes.get("btn-memory-panel").fire("click");
    }
    else
    {
        app.nodes.get("btn-refresh-status").fire("click");
    }
    await processStatus(app);
    app.nodes.get("memory-size").value = "64";
    return app;
}

function instructionRows(count, address = "0xffff800000001000")
{
    let cursor = BigInt(address);
    return Array.from({ length: count }, (_, index) =>
    {
        const start = cursor;
        const bytes = index % 2 ? "e800000000" : "cc";
        cursor += BigInt(bytes.length / 2);
        return { address: "0x" + start.toString(16).padStart(16, "0"), addressSpace: "virtual", bytes,
            nextAddress: "0x" + cursor.toString(16).padStart(16, "0"),
            instructionText: index % 2 ? "call test!Target" : "int3", symbol: "test!Code+0x" + index.toString(16) };
    });
}

async function disassemblyApp(options = {})
{
    const app = await memoryApp(options);
    app.nodes.get("tab-disassembly").fire("click");
    app.nodes.get("disassembly-count").value = "16";
    return app;
}

async function disassemblyReply(app, options = {})
{
    const request = app.latest("disassemblyRead");
    const target = options.target || request.params.expectedStamp;
    const rows = options.rows || instructionRows(Number(request.params.count), options.address);
    const id = "instructions-" + request.requestId;
    await app.deliver(request, { ok: true, result: { resultId: id, rowCount: String(rows.length),
        data: { commandId: "u", target, status: options.partial ? "Partial" : "Success",
            error: { message: options.partial ? "Instruction bytes unavailable after decoded prefix" : "" } },
            instructionPointer: options.instructionPointer } });
    for (let offset = 0; offset < rows.length; offset += 3)
    {
        const page = rows.slice(offset, offset + 3);
        await app.reply("resultPage", { ok: true, result: { resultId: id, collection: "rows", offset: String(offset),
            next: String(offset + page.length), total: String(rows.length), complete: offset + page.length === rows.length, rows: page } });
    }
    await processStatus(app, target);
    return rows;
}

await check("T-UI-INSPECT-NAV Memory and Disassembly addresses cross-open their retained source rows independently of Results", async () =>
{
    const app = await memoryApp();
    app.nodes.get("tab-memory-view").fire("click");
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(0x90));
    await openTable(app, "another-result", [{ flags: "0x1234" }]);
    const memoryCell = app.nodes.get("memory-rows").children[1].children[0];
    memoryCell.fire("contextmenu");
    assert.equal(app.nodes.get("cell-open-memory").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("cell-open-disassembly").disabled, false);
    app.nodes.get("cell-open-disassembly").fire("click");
    const decode = app.latest("disassemblyRead");
    assert.equal(decode.params.source.resultId, "memory-view");
    assert.equal(decode.params.source.index, "1");
    assert.deepEqual(JSON.parse(JSON.stringify(decode.params.source.path)), ["address"]);
    assert.equal(decode.params.expression, "0xffff800000001010");
    const rows = await disassemblyReply(app, { address: decode.params.expression });
    assert.equal(app.nodes.get("result-title").textContent, "another-result");
    assert.equal(app.nodes.get("btn-disassembly-follow").textContent, "IP follow paused");
    app.nodes.get("disassembly-rows").children[2].children[1].fire("contextmenu");
    assert.equal(app.nodes.get("cell-open-disassembly").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("cell-open-memory").disabled, false);
    app.nodes.get("cell-open-memory").fire("click");
    const read = app.latest("memoryRead");
    assert.equal(read.params.source.resultId, "instructions-" + decode.requestId);
    assert.equal(read.params.source.index, "2");
    assert.equal(read.params.expression, rows[2].address);
    assert.equal(read.params.space, "virtual");
    await memoryReply(app, Array(64).fill(0x90), { address: rows[2].address, id: "cross-memory" });
    assert.equal(app.nodes.get("result-title").textContent, "another-result");
});

await check("T-UI-INSPECT-NAV physical memory, stale contexts and running targets cannot decode captured addresses", async () =>
{
    for (const mode of ["physical", "changed", "running"])
    {
        const app = await memoryApp();
        app.nodes.get("tab-memory-view").fire("click");
        if (mode === "physical")
        {
            app.nodes.get("memory-space").value = "physical";
        }
        app.nodes.get("btn-memory-read").fire("click");
        await memoryReply(app, Array(64).fill(0x90), { space: mode === "physical" ? "physical" : "virtual" });
        app.nodes.get("memory-rows").children[0].children[0].fire("contextmenu");
        if (mode !== "physical")
        {
            assert.equal(app.nodes.get("cell-open-disassembly").disabled, false);
            app.nodes.get("btn-refresh-status").fire("click");
            await processStatus(app, mode === "changed" ? { ...stamp, contextGeneration: "99" } : stamp,
                mode === "running" ? { stopped: false } : {});
        }
        assert.equal(app.nodes.get("cell-open-disassembly").disabled, true, mode);
        app.nodes.get("cell-open-disassembly").fire("click");
        assert.equal(app.messages.some(item => item.method === "disassemblyRead"), false, mode);
        app.nodes.get("memory-rows").children[0].children[1].fire("contextmenu");
        assert.equal(app.nodes.get("cell-open-disassembly").classList.contains("hidden"), true);
    }
});

await check("T-UI-INSPECT-NAV expired captures fail without retrying as manual input", async () =>
{
    const app = await memoryApp();
    app.nodes.get("tab-memory-view").fire("click");
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(0x90));
    app.nodes.get("memory-rows").children[0].children[0].fire("contextmenu");
    app.nodes.get("cell-open-disassembly").fire("click");
    await app.reply("disassemblyRead", { ok: false, error: "Source result expired" });
    await processStatus(app);
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, 1);
    assert.match(app.nodes.get("disassembly-notice").textContent, /Source result expired/);
    assert.equal(app.nodes.get("memory-rows").children.length, 4);
});

await check("T-UI-ADDRESS-MENU sorted generic addresses bind the original field without changing Results", async () =>
{
    const app = await memoryApp();
    const rows = [{ kind: "Module", name: "second", base: "0xffff800000004000" },
        { kind: "Module", name: "first", base: "0xffff800000002000" }];
    await openTable(app, "lm", rows, { addressFields: rows.map(() => [{ path: ["base"], space: "virtual", allowZero: false }]) });
    sortHeader(app, "Base");
    const cell = app.nodes.get("result-rows").children[0].children.find(node => node.textContent === rows[1].base);
    assert.ok(cell);
    cell.fire("contextmenu");
    app.nodes.get("cell-open-disassembly").fire("click");
    const request = app.latest("disassemblyRead");
    assert.equal(request.params.source.index, "1");
    assert.deepEqual(JSON.parse(JSON.stringify(request.params.source.path)), ["base"]);
    assert.equal(request.params.expression, rows[1].base);
    await disassemblyReply(app, { address: rows[1].base });
    assert.equal(app.nodes.get("result-title").textContent, "lm");
    assert.deepEqual(JSON.parse(app.nodes.get("result-detail").textContent), rows[1]);
});

await check("T-UI-ADDRESS-MENU physical zero opens Physical Memory while flags and stored records remain unchanged", async () =>
{
    const app = await memoryApp();
    const row = { kind: "PageTranslation", va: "0xffff800000004000", pa: "0x0000000000000000", flags: "0xffff800000006000" };
    await openTable(app, "vtop", [row], { addressFields: [[{ path: ["va"], space: "virtual", allowZero: false },
        { path: ["pa"], space: "physical", allowZero: true }]] });
    app.nodes.get("result-rows").children[0].children.find(node => node.textContent === row.pa).fire("contextmenu");
    assert.equal(app.nodes.get("cell-open-memory").disabled, false);
    assert.equal(app.nodes.get("cell-open-disassembly").disabled, true);
    app.nodes.get("cell-open-disassembly").fire("click");
    assert.equal(app.messages.some(item => item.method === "disassemblyRead"), false);
    app.nodes.get("result-rows").children[0].children.find(node => node.textContent === row.pa).fire("contextmenu");
    app.nodes.get("cell-open-memory").fire("click");
    assert.equal(app.latest("memoryRead").params.space, "physical");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("memoryRead").params.source.path)), ["pa"]);
    await memoryReply(app, Array(64).fill(0), { address: row.pa, space: "physical" });
    assert.deepEqual(JSON.parse(app.nodes.get("result-detail").textContent), row);
    const values = app.nodes.get("detail-fields").children;
    values[values.findIndex(node => node.textContent === "va") + 1].fire("contextmenu");
    assert.equal(app.nodes.get("cell-open-disassembly").disabled, false);
    app.nodes.get("result-rows").children[0].children.find(node => node.textContent === row.flags).fire("contextmenu");
    assert.equal(app.nodes.get("cell-open-memory").classList.contains("hidden"), true);
});

await check("T-UI-ADDRESS-MENU nested addresses retain their path and foreign user addresses require the owning process", async () =>
{
    const app = await memoryApp();
    const row = { owner: { eprocess: "0xffff800000008000" } };
    await openTable(app, "nested", [row], { addressFields: [[{ path: ["owner", "eprocess"], space: "virtual", allowZero: false }]] });
    app.nodes.get("result-rows").children[0].children.find(node => node.textContent === row.owner.eprocess).fire("contextmenu");
    app.nodes.get("cell-open-memory").fire("click");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("memoryRead").params.source.path)), ["owner", "eprocess"]);
    await memoryReply(app, Array(64).fill(0), { address: row.owner.eprocess });
    await openTable(app, "!vad", [{ start: "0x10000", process: { eprocess: "0xffff800000009000" } }],
        { addressFields: [[{ path: ["start"], space: "virtual", allowZero: false, process: "0xffff800000009000" }]] });
    app.nodes.get("result-rows").children[0].children.find(node => node.textContent === "0x10000").fire("contextmenu");
    assert.equal(app.nodes.get("cell-open-memory").disabled, true);
    assert.match(app.nodes.get("cell-open-memory").title, /owning process/);
    app.nodes.get("cell-open-memory").fire("click");
    assert.equal(app.messages.filter(item => item.method === "memoryRead").length, 1);
});

await check("T-UI-ADDRESS-MENU x86 high user addresses and unknown owning processes stay blocked", async () =>
{
    for (const mode of ["x86", "unknown"])
    {
        const app = await memoryApp();
        const current = { ...stamp, contextIdentity: { effectiveArchitecture: "0x000000000000014c",
            implicitProcess: mode === "unknown" ? "0x0000000000000000" : "0xffff800000001000" } };
        const owner = mode === "unknown" ? "0x0000000000000000" : "0xffff800000002000";
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, current);
        await openTable(app, "!vad", [{ start: "0xa0000000", process: { eprocess: owner } }],
            { metadata: { target: current }, addressFields: [[{ path: ["start"], space: "virtual", allowZero: false, process: owner }]] });
        app.nodes.get("result-rows").children[0].children.find(node => node.textContent === "0xa0000000").fire("contextmenu");
        assert.equal(app.nodes.get("cell-open-memory").disabled, true, mode);
        assert.equal(app.nodes.get("cell-open-disassembly").disabled, true, mode);
        app.nodes.get("cell-open-memory").fire("click");
        assert.equal(app.messages.some(item => ["memoryRead", "disassemblyRead"].includes(item.method)), false);
    }
});

await check("T-UI-ADDRESS-MENU malformed page metadata fails closed without rendering address actions", async () =>
{
    for (const addressFields of [[], [[{ path: [], space: "virtual", allowZero: false }]],
        [[{ path: ["base"], space: "file", allowZero: false }]], [[{ path: ["base"], space: "virtual", allowZero: "true" }]]])
    {
        const app = await memoryApp();
        await openTable(app, "lm", [{ base: "0xffff800000001000" }], { addressFields });
        assert.equal(app.nodes.get("result-rows").children.length, 0);
        assert.match(app.nodes.get("result-notice-text").textContent, /Invalid result address metadata/);
        assert.equal(app.messages.some(item => ["memoryRead", "disassemblyRead"].includes(item.method)), false);
    }
});

await check("T-UI-ADDRESS-MENU Inspector actions respect the same owning-process guard as the address menu", async () =>
{
    const app = await memoryApp();
    const row = { kind: "Address", address: "0x0000000012340000", addressSpace: "virtual", sourceFile: "sample.cpp",
        process: { eprocess: "0xffff800000002000" } };
    await openTable(app, "address", [row], { addressFields: [[{
        path: ["address"], space: "virtual", allowZero: true, process: row.process.eprocess
    }]] });
    app.nodes.get("result-rows").children[0].children.find(node => node.textContent === row.address).fire("contextmenu");
    assert.equal(app.nodes.get("cell-open-disassembly").disabled, true);
    assert.equal(app.nodes.get("btn-disassemble").disabled, true);
    assert.equal(app.nodes.get("btn-navigate").disabled, true);
    assert.equal(app.nodes.get("btn-source").disabled, true);
    app.nodes.get("btn-disassemble").fire("click");
    app.nodes.get("btn-navigate").fire("click");
    app.nodes.get("btn-source").fire("click");
    assert.equal(app.messages.some(item => ["memoryRead", "disassemblyRead", "navigateResult"].includes(item.method)), false);
});

await check("T-UI-ADDRESS-MENU copy-only host fields cannot use Inspector actions while current addresses retain path binding", async () =>
{
    const app = await memoryApp();
    const row = { address: "0xffff800000003000", addressSpace: "virtual", sourceFile: "sample.cpp" };
    await openTable(app, "imported", [row], { addressFields: [[]] });
    app.nodes.get("result-rows").children[0].children.find(node => node.textContent === row.address).fire("contextmenu");
    assert.equal(app.nodes.get("cell-open-disassembly").classList.contains("hidden"), true);
    for (const id of ["btn-navigate", "btn-disassemble", "btn-source"])
    {
        assert.equal(app.nodes.get(id).disabled, true, id);
        app.nodes.get(id).fire("click");
    }
    assert.equal(app.messages.some(item => ["disassemblyRead", "navigateResult"].includes(item.method)), false);
    await openTable(app, "current", [row], { addressFields: [[{ path: ["address"], space: "virtual", allowZero: true }]] });
    app.nodes.get("result-rows").children[0].children.find(node => node.textContent === row.address).fire("click");
    assert.equal(app.nodes.get("btn-disassemble").disabled, false);
    app.nodes.get("btn-disassemble").fire("click");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("disassemblyRead").params.source.path)), ["address"]);
    assert.equal(app.latest("disassemblyRead").params.source.index, "0");
});

await check("T-UI-CALLBACK-NAV Inspector selects Pre and Post and opens Memory without replacing Results", async () =>
{
    const app = await memoryApp();
    const row = { kind: "ObjectCallbackRegistration", callbackType: "Object.Process",
        preRoutine: "0xffff800000001000", postRoutine: "0xffff800000002000" };
    await openTable(app, "!callbacks", [row]);
    app.nodes.get("result-rows").children[0].fire("click");
    assert.equal(app.nodes.get("callback-address").value, "preRoutine");
    app.nodes.get("callback-address").value = "postRoutine";
    app.nodes.get("callback-address").fire("change");
    assert.match(app.nodes.get("selection-scope").textContent, /Post.*0xffff800000002000/);
    app.nodes.get("btn-open-memory").fire("click");
    const request = app.latest("memoryRead");
    assert.equal(request.params.expression, row.postRoutine);
    assert.equal(request.params.source.field, "postRoutine");
    assert.equal(request.params.source.index, "0");
    assert.equal(request.params.source.action, "memory");
    assert.deepEqual(JSON.parse(JSON.stringify(request.params.source.expectedStamp)), stamp);
    await memoryReply(app, Array(64).fill(0x41), { address: row.postRoutine });
    assert.equal(app.nodes.get("memory-address").value, row.postRoutine);
    assert.equal(app.nodes.get("result-title").textContent, "!callbacks");
    assert.deepEqual(JSON.parse(app.nodes.get("result-detail").textContent), row);
    assert.equal(app.nodes.get("callback-address").value, "postRoutine");
});

await check("T-UI-CALLBACK-NAV sorted address menus bind the clicked Post field and preserve the clipboard", async () =>
{
    const copied = [];
    const app = await memoryApp({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return Promise.resolve();
    } } });
    const rows = [
        { kind: "ObjectCallbackRegistration", callbackType: "Object.Process", preRoutine: "0xffff800000003000", postRoutine: "0xffff800000004000" },
        { kind: "ObjectCallbackRegistration", callbackType: "Object.Thread", preRoutine: "0xffff800000001000", postRoutine: "0xffff800000002000" }
    ];
    await openTable(app, "!callbacks", rows);
    sortHeader(app, "Routine / Pre");
    const post = app.nodes.get("result-rows").children[0].children[headers(app).indexOf("Post callback")];
    post.fire("contextmenu");
    assert.equal(copied.length, 0);
    assert.equal(app.nodes.get("callback-address").value, "postRoutine");
    app.nodes.get("cell-copy-menu").fire("keydown", { key: "End" });
    assert.equal(app.focused(), app.nodes.get("cell-open-disassembly"));
    app.nodes.get("cell-open-disassembly").fire("click");
    const request = app.latest("disassemblyRead");
    assert.equal(request.params.source.resultId, "!callbacks");
    assert.equal(request.params.source.index, "1");
    assert.equal(request.params.source.field, "postRoutine");
    assert.equal(request.params.expression, rows[1].postRoutine);
    assert.equal(copied.length, 0);
    await disassemblyReply(app, { address: rows[1].postRoutine });
    assert.equal(app.nodes.get("result-title").textContent, "!callbacks");
});

await check("T-UI-CALLBACK-NAV notify routines and Inspector field menus use the actual retained routine field", async () =>
{
    const app = await memoryApp();
    const row = { kind: "RoutineObservation", callbackType: "Notify.Image", routine: "0xffff800000001234" };
    await openTable(app, "!callbacks", [row]);
    app.nodes.get("result-rows").children[0].children[headers(app).indexOf("Routine / Pre")].fire("contextmenu");
    assert.equal(app.nodes.get("callback-address").value, "routine");
    app.nodes.get("cell-open-memory").fire("click");
    assert.equal(app.latest("memoryRead").params.source.field, "routine");
    await memoryReply(app, Array(64).fill(0), { address: row.routine });
    const values = app.nodes.get("detail-fields").children;
    const routine = values.findIndex(node => node.textContent === "routine");
    values[routine + 1].fire("contextmenu");
    app.nodes.get("cell-open-disassembly").fire("click");
    assert.equal(app.latest("disassemblyRead").params.source.field, "routine");
    await disassemblyReply(app, { address: row.routine });
});

await check("T-UI-CALLBACK-NAV null unknown and malformed callbacks never navigate or consume unrelated copy menus", async () =>
{
    for (const address of [null, "0x0000000000000000", "not-an-address", "0x10000000000000000"])
    {
        const app = await memoryApp();
        await openTable(app, "!callbacks", [{ kind: "ObjectCallbackRegistration", callbackType: "Object.Process",
            preRoutine: "0xffff800000001000", postRoutine: address }]);
        app.nodes.get("result-rows").children[0].children[headers(app).indexOf("Post callback")].fire("contextmenu");
        assert.equal(app.nodes.get("btn-open-memory").disabled, true);
        assert.equal(app.nodes.get("btn-disassemble").disabled, true);
        assert.equal(app.nodes.get("cell-open-memory").disabled, true);
        app.nodes.get("cell-copy-menu").fire("keydown", { key: "End" });
        assert.equal(app.focused(), app.nodes.get("cell-copy-row"));
        app.nodes.get("cell-open-memory").fire("click");
        app.nodes.get("btn-disassemble").fire("click");
        assert.equal(app.messages.some(request => ["memoryRead", "disassemblyRead"].includes(request.method)), false);
        await openTable(app, "ordinary", [{ flags: "0x1234" }]);
        app.nodes.get("result-rows").children[0].children[headers(app).indexOf("Flags")].fire("contextmenu");
        assert.equal(app.nodes.get("cell-open-memory").classList.contains("hidden"), true);
    }
});

await check("T-UI-CALLBACK-NAV Busy changed contexts and historical rows invalidate open address actions", async () =>
{
    for (const mode of ["busy", "context", "historical", "row-target"])
    {
        const app = await memoryApp();
        const row = { kind: "ObjectCallbackRegistration", callbackType: "Object.Process",
            preRoutine: "0xffff800000001000", postRoutine: "0xffff800000002000",
            ...(mode === "historical" ? { historical: true } : {}),
            ...(mode === "row-target" ? { target: { ...stamp, contextGeneration: "99" } } : {}) };
        await openTable(app, "!callbacks", [row]);
        app.nodes.get("result-rows").children[0].children[headers(app).indexOf("Post callback")].fire("contextmenu");
        if (["busy", "context"].includes(mode))
        {
            app.nodes.get("btn-refresh-status").fire("click");
            if (mode === "busy")
            {
                await app.reply("status", { ok: false, error: "EngineBusy" });
            }
            else
            {
                await processStatus(app, { ...stamp, contextGeneration: "99" });
            }
        }
        app.nodes.get("cell-open-disassembly").fire("click");
        app.nodes.get("btn-open-memory").fire("click");
        assert.equal(app.messages.some(request => ["memoryRead", "disassemblyRead"].includes(request.method)), false, mode);
    }
});

await check("T-UI-CALLBACK-NAV unavailable menu actions restore keyboard focus without stealing focus from valid copy actions", async () =>
{
    for (const choice of ["cell-copy-value", "cell-copy-row", "cell-open-memory", "cell-open-disassembly"])
    {
        const app = await memoryApp();
        await openTable(app, "!callbacks", [{ kind: "ObjectCallbackRegistration", callbackType: "Object.Process",
            preRoutine: "0xffff800000001000", postRoutine: "0xffff800000002000" }]);
        app.nodes.get("result-rows").children[0].children[headers(app).indexOf("Post callback")].fire("contextmenu");
        app.nodes.get(choice).focus();
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, stamp, { stopped: false });
        assert.equal(app.focused(), app.nodes.get(choice.startsWith("cell-open-") ? "cell-copy-value" : choice));
        assert.equal(app.nodes.get("cell-copy-menu").classList.contains("hidden"), false);
        app.nodes.get("cell-copy-menu").fire("keydown", { key: "End" });
        assert.equal(app.focused(), app.nodes.get("cell-copy-row"));
        app.nodes.get("cell-open-memory").fire("click");
        assert.equal(app.messages.some(item => ["memoryRead", "disassemblyRead"].includes(item.method)), false);
    }
});

await check("T-UI-CALLBACK-NAV the selected phase survives sorting and switching retained result tabs", async () =>
{
    const app = await memoryApp();
    const rows = [
        { kind: "ObjectCallbackRegistration", callbackType: "Object.Process", preRoutine: "0xffff800000003000", postRoutine: "0xffff800000004000" },
        { kind: "ObjectCallbackRegistration", callbackType: "Object.Thread", preRoutine: "0xffff800000001000", postRoutine: "0xffff800000002000" }
    ];
    await openTable(app, "!callbacks", rows, { id: "callback-phase-a" });
    app.nodes.get("result-rows").children[0].fire("click");
    app.nodes.get("callback-address").value = "postRoutine";
    app.nodes.get("callback-address").fire("change");
    sortHeader(app, "Routine / Pre");
    assert.equal(app.nodes.get("callback-address").value, "postRoutine");
    await openTable(app, "ordinary", [{ address: "0x1234", addressSpace: "virtual" }], { id: "callback-phase-b" });
    await openTable(app, "!callbacks", rows, { id: "callback-phase-a" });
    assert.equal(app.nodes.get("callback-address").value, "postRoutine");
    app.nodes.get("btn-open-memory").fire("click");
    assert.equal(app.latest("memoryRead").params.source.index, "0");
    assert.equal(app.latest("memoryRead").params.expression, rows[0].postRoutine);
    await memoryReply(app, Array(64).fill(0), { address: rows[0].postRoutine });
});

await check("T-UI-FOLLOW a new stop reveals Disassembly once and marks the actual IP instead of a selected frame", async () =>
{
    const app = await memoryApp();
    app.nodes.get("disassembly-count").value = "16";
    const retained = app.nodes.get("result-title").textContent;
    assert.equal(app.messages.some(item => item.method === "disassemblyRead"), false);
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { stopped: false, canControlExecution: false });
    const stopped = { ...stamp, stopEpoch: "3", contextGeneration: "4",
        contextIdentity: { implicitProcess: "0xffff800000002000", scopeInstruction: "0xffff800000003001" } };
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stopped, { instructionPointer: "0xffff800000003000" });
    assert.equal(app.nodes.get("memory").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("tab-disassembly").getAttribute("aria-selected"), "true");
    assert.equal(app.latest("disassemblyRead").params.expression, "@$ip");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("disassemblyRead").params.expectedStamp)), stopped);
    await disassemblyReply(app, { address: "0xffff800000003000", instructionPointer: "0xffff800000003000" });
    const rows = app.nodes.get("disassembly-rows").children;
    assert.equal(rows[0].classList.contains("current-ip"), true);
    assert.equal(rows[1].classList.contains("current-ip"), false);
    assert.equal(rows[0].classList.contains("selected"), true);
    assert.equal(app.nodes.get("result-title").textContent, retained);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stopped, { instructionPointer: "0xffff800000003000" });
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, 1);
    const next = { ...stopped, stopEpoch: "4", contextGeneration: "5" };
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, next, { instructionPointer: "0xffff800000004000" });
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, 2,
        "A stop between polls must be followed even when no running status was observed");
});

await check("T-UI-FOLLOW forwarded execution keeps tracking a stop after host context invalidation", async () =>
{
    const app = await disassemblyApp();
    app.enter("g");
    await app.reply("classify", { ok: true, result: { write: false } });
    const current = { ...stamp, targetGeneration: "2", stopEpoch: "9", contextGeneration: "10" };
    await app.reply("execute", { ok: true, result: { ok: true, currentTarget: current, output: "Stopped" } });
    await processStatus(app, current, { instructionPointer: "0xffff800000003000" });
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, 1,
        "Host invalidation must not hide an execution stop between polls");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("disassemblyRead").params.expectedStamp)), current);
});

await check("T-UI-FOLLOW manual browsing disables following and saved Off survives reopening without target reads", async () =>
{
    const saved = new Map();
    const storage = { getItem: key => saved.get(key) || null, setItem: (key, value) => saved.set(key, value) };
    const app = await disassemblyApp({ storage });
    app.nodes.get("disassembly-address").value = "test!Other";
    app.nodes.get("disassembly-address").fire("input");
    assert.equal(app.nodes.get("btn-disassembly-follow").getAttribute("aria-pressed"), "false");
    app.nodes.get("btn-disassembly-read").fire("click");
    await disassemblyReply(app);
    const reads = app.messages.filter(item => item.method === "disassemblyRead").length;
    const stopped = { ...stamp, stopEpoch: "9" };
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stopped, { instructionPointer: "0xffff800000003000" });
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, reads);
    const reopened = harness({ storage });
    await reopened.boot();
    assert.equal(reopened.nodes.get("btn-disassembly-follow").getAttribute("aria-pressed"), "false");
    assert.equal(reopened.messages.some(item => item.method === "disassemblyRead"), false);
    app.nodes.get("btn-disassembly-ip").fire("click");
    assert.equal(app.nodes.get("btn-disassembly-follow").getAttribute("aria-pressed"), "true");
    assert.equal(app.latest("disassemblyRead").params.expression, "@$ip");
});

await check("T-UI-FOLLOW an unavailable IP waits for a complete status at the same stop instead of losing the event", async () =>
{
    const app = await disassemblyApp();
    const stopped = { ...stamp, stopEpoch: "8" };
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stopped, { instructionPointer: null });
    assert.equal(app.messages.some(item => item.method === "disassemblyRead"), false);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stopped, contextGeneration: "20" }, { instructionPointer: "0xffff800000003000" });
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, 1);
    assert.equal(app.latest("disassemblyRead").params.expectedStamp.contextGeneration, "20");
});

await check("T-UI-FOLLOW queued stops wait for active work and Stop cancels the pending automatic read", async () =>
{
    for (const cancel of [false, true])
    {
        const app = await memoryApp();
        app.enter("other-command");
        await app.reply("classify", { ok: true, result: { write: false } });
        const request = app.latest("execute");
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, { ...stamp, stopEpoch: "8" }, { instructionPointer: "0xffff800000003000" });
        assert.equal(app.messages.some(item => item.method === "disassemblyRead"), false);
        if (cancel)
        {
            app.nodes.get("btn-cancel").fire("click");
        }
        await app.deliver(request, { ok: true, result: { output: "Done" } });
        assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, cancel ? 0 : 1);
    }
});

await check("T-UI-FOLLOW obsolete or disabled automatic pages cannot overwrite a newer debugger context", async () =>
{
    for (const boundary of ["running", "off", "stop", "newer", "busy"])
    {
        const app = await disassemblyApp();
        app.nodes.get("btn-disassembly-read").fire("click");
        await disassemblyReply(app);
        const previous = app.nodes.get("disassembly-rows").children[0];
        const target = { ...stamp, stopEpoch: "7" };
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, target, { instructionPointer: "0xffff800000003000" });
        const request = app.latest("disassemblyRead");
        await app.deliver(request, { ok: true, result: { resultId: "late-follow", rowCount: "16",
            data: { commandId: "u", status: "Success", target } } });
        if (boundary === "off")
        {
            app.nodes.get("btn-disassembly-follow").fire("click");
        }
        else if (boundary === "stop")
        {
            app.nodes.get("btn-cancel").fire("click");
        }
        else if (boundary === "busy")
        {
            app.nodes.get("btn-refresh-status").fire("click");
            await app.reply("status", { ok: false, error: "EngineBusy" });
            app.nodes.get("btn-refresh-status").fire("click");
            await processStatus(app, target, { instructionPointer: "0xffff800000003000" });
        }
        else
        {
            app.nodes.get("btn-refresh-status").fire("click");
            await processStatus(app, boundary === "newer" ? { ...target, stopEpoch: "8" } : target,
                { stopped: boundary === "newer", instructionPointer: boundary === "newer" ? "0xffff800000004000" : null });
        }
        await app.reply("resultPage", { ok: true, result: { resultId: "late-follow", collection: "rows", offset: "0",
            next: "16", total: "16", complete: true, rows: instructionRows(16, "0xffff800000003000") } });
        assert.equal(app.nodes.get("disassembly-rows").children[0], previous, boundary);
        assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length,
            ["newer", "busy"].includes(boundary) ? 3 : 2, boundary);
    }
});

await check("T-UI-EXECUTION header continues with Inspect hidden and breaks only after confirmed running status", async () =>
{
    const app = await memoryApp();
    app.nodes.get("btn-disassembly-follow").fire("click");
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("prompt").value = "unsent command";
    const toggle = app.nodes.get("btn-execution-toggle");
    assert.equal(toggle.disabled, false);
    assert.equal(toggle.dataset.action, "continue");
    toggle.fire("click");
    toggle.fire("click");
    assert.equal(app.messages.filter(item => item.method === "debuggerAction").length, 1);
    assert.equal(app.latest("debuggerAction").params.operation, "go");
    assert.equal(toggle.disabled, true);
    assert.equal(app.nodes.get("execution-toggle-label").textContent, "Continuing...");
    const running = { ...stamp, stopEpoch: "9" };
    await app.reply("debuggerAction", { ok: true, result: { ok: true, operation: "go", status: {
        connected: true, stopped: false, target: running, canControlExecution: false, canBreakExecution: true } } });
    await processStatus(app, running, { stopped: false, canControlExecution: false, canBreakExecution: true });
    assert.equal(toggle.disabled, false);
    assert.equal(toggle.dataset.action, "break");
    assert.equal(app.nodes.get("memory").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("prompt").value, "unsent command");
    assert.equal(app.messages.some(item => item.method === "disassemblyRead"), false);
    toggle.fire("click");
    toggle.fire("click");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("breakExecution").params.expectedStamp)), running);
    assert.equal(app.messages.filter(item => item.method === "breakExecution").length, 1);
    assert.equal(toggle.disabled, true);
    assert.equal(app.nodes.get("execution-toggle-label").textContent, "Breaking...");
    await app.reply("breakExecution", { ok: true, result: { requested: true, completed: false } });
    await processStatus(app, running, { stopped: false, canControlExecution: false, canBreakExecution: true });
    assert.equal(toggle.disabled, true, "An interrupt receipt does not confirm a stop");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...running, stopEpoch: "10" });
    assert.equal(toggle.disabled, false);
    assert.equal(toggle.dataset.action, "continue");
    assert.equal(toggle.getAttribute("aria-busy"), "false");
    assert.equal(app.messages.some(item => item.method === "interrupt"), false, "Target Break must not cancel commands");
});

await check("T-UI-EXECUTION confirmed running status permits Break before a delayed Continue receipt", async () =>
{
    const app = await memoryApp();
    app.nodes.get("btn-disassembly-follow").fire("click");
    app.nodes.get("btn-memory-close").fire("click");
    const toggle = app.nodes.get("btn-execution-toggle");
    toggle.fire("click");
    const action = app.latest("debuggerAction");
    const previousStatus = app.latest("status");
    app.advanceTime(3000);
    assert.notEqual(app.latest("status"), previousStatus, "Execution receipt must not block status observation");
    const running = { ...stamp, stopEpoch: "9" };
    await processStatus(app, running, { stopped: false, canControlExecution: false, canBreakExecution: true });
    assert.equal(toggle.disabled, false, "Confirmed running state must unlock Break before the Continue receipt");
    assert.equal(toggle.dataset.action, "break");
    toggle.fire("click");
    await app.reply("breakExecution", { ok: true, result: { requested: true, completed: false } });
    await processStatus(app, running, { stopped: false, canControlExecution: false, canBreakExecution: true });
    const beforeStop = app.latest("status");
    app.advanceTime(500);
    assert.notEqual(app.latest("status"), beforeStop, "Pending Break must keep observing while Continue receipt is delayed");
    const stopped = { ...running, stopEpoch: "10" };
    await processStatus(app, stopped);
    assert.equal(app.nodes.get("execution-toggle-label").textContent, "Continuing...",
        "New execution remains blocked until the original operation settles");
    await app.deliver(action, { ok: true, result: { ok: true, operation: "go", status: {
        connected: true, stopped: false, target: running, canControlExecution: false, canBreakExecution: true } } });
    assert.equal(toggle.dataset.action, "continue", "Late running receipt must not replace a newer stop");
    assert.equal(toggle.disabled, false);
    assert.equal(app.nodes.get("memory").classList.contains("hidden"), true);
    assert.equal(app.messages.filter(item => item.method === "debuggerAction").length, 1);
    assert.equal(app.messages.filter(item => item.method === "breakExecution").length, 1);
    assert.equal(app.messages.some(item => item.method === "interrupt"), false);
});

await check("T-UI-EXECUTION F5 works outside Disassembly without changing drafts and ignores modified or repeated keys", async () =>
{
    const app = await memoryApp();
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("prompt").value = "retained draft";
    for (const modifiers of [{ shiftKey: true }, { ctrlKey: true }, { metaKey: true }, { altKey: true }, { repeat: true },
        { defaultPrevented: true }, { isComposing: true }])
    {
        app.documentListeners.get("keydown")({ key: "F5", preventDefault: noop, ...modifiers });
    }
    assert.equal(app.messages.some(item => item.method === "debuggerAction"), false);
    app.documentListeners.get("keydown")({ key: "F5", preventDefault: noop });
    assert.equal(app.latest("debuggerAction").params.operation, "go");
    assert.equal(app.nodes.get("prompt").value, "retained draft");
    assert.equal(app.nodes.get("memory").classList.contains("hidden"), true);
});

await check("T-UI-EXECUTION header refuses unknown disconnected dump local-kernel and unsupported target states", async () =>
{
    for (const overrides of [{ connected: false }, { stopped: false, canBreakExecution: false },
        { dumpFile: true }, { localKernel: true }, { canControlExecution: false }])
    {
        const app = await memoryApp();
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, stamp, overrides);
        assert.equal(app.nodes.get("btn-execution-toggle").disabled, true, JSON.stringify(overrides));
        app.nodes.get("btn-execution-toggle").fire("click");
        assert.equal(app.messages.some(item => ["debuggerAction", "breakExecution"].includes(item.method)), false);
    }
    const app = await memoryApp();
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "EngineBusy" });
    assert.equal(app.nodes.get("btn-execution-toggle").disabled, true);
    app.nodes.get("btn-execution-toggle").fire("click");
    assert.equal(app.messages.some(item => ["debuggerAction", "breakExecution"].includes(item.method)), false);
});

await check("T-UI-EXECUTION Break does not wait for or cancel a command and ignores old status and late receipts", async () =>
{
    const app = await memoryApp();
    app.nodes.get("btn-disassembly-follow").fire("click");
    app.enter("stack");
    await app.reply("classify", { ok: true, result: { write: false } });
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { stopped: false, canBreakExecution: true, canControlExecution: false });
    assert.equal(app.nodes.get("btn-execution-toggle").disabled, false);
    app.nodes.get("btn-refresh-status").fire("click");
    const stale = app.latest("status");
    app.nodes.get("btn-execution-toggle").fire("click");
    assert.equal(app.nodes.get("btn-cancel").disabled, false, "Existing command must remain owned and cancellable");
    await app.deliver(stale, { ok: true, result: { connected: true, stopped: true, canControlExecution: true, target: stamp } });
    assert.equal(app.nodes.get("execution-toggle-label").textContent, "Breaking...");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stamp, stopEpoch: "10" });
    await app.reply("breakExecution", { ok: false, error: "late receipt" });
    assert.equal(app.nodes.get("execution-toggle-label").textContent, "Continue");
    assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true);
    assert.equal(app.messages.some(item => item.method === "interrupt"), false);
});

await check("T-UI-EXECUTION failed and unconfirmed Break requests stay visible without automatic replay", async () =>
{
    for (const mode of ["failure", "pending", "timeout"])
    {
        const app = await memoryApp();
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, stamp, { stopped: false, canBreakExecution: true, canControlExecution: false });
        app.nodes.get("btn-execution-toggle").fire("click");
        if (mode === "timeout")
        {
            const timer = [...app.timers.keys()].find(id => app.timerDelays.get(id) === 8000);
            assert.ok(timer);
            app.timers.get(timer)();
            await settle();
        }
        else
        {
            await app.reply("breakExecution", mode === "failure" ? { ok: false, error: "Break unavailable" } :
                { ok: true, result: { requested: true, completed: false } });
            if (mode === "pending")
            {
                const timer = [...app.timers.keys()].find(id => app.timerDelays.get(id) === 10000);
                assert.ok(timer);
                app.timers.get(timer)();
            }
        }
        assert.match(app.nodes.get("workspace-feedback-text").textContent, /Break unavailable|unconfirmed|timeout/);
        assert.equal(app.messages.filter(item => item.method === "breakExecution").length, 1);
    }
});

await check("T-UI-EXECUTION buttons and unmodified shortcuts submit one bound action and follow a completed step", async () =>
{
    for (const [control, key, operation] of [["over", "F10", "step-over"], ["into", "F11", "step-into"], ["continue", "F5", "go"]])
    {
        const app = await disassemblyApp();
        assert.equal(app.nodes.get("btn-debug-" + control).disabled, false);
        app.documentListeners.get("keydown")({ key, preventDefault: noop });
        assert.equal(app.latest("debuggerAction").params.operation, operation);
        assert.deepEqual(JSON.parse(JSON.stringify(app.latest("debuggerAction").params.expectedStamp)), stamp);
        app.nodes.get("btn-debug-" + control).fire("click");
        assert.equal(app.messages.filter(item => item.method === "debuggerAction").length, 1);
        const target = { ...stamp, stopEpoch: "9" };
        await app.reply("debuggerAction", { ok: true, result: { ok: true, operation, status: {
            connected: true, stopped: true, canControlExecution: true, target, instructionPointer: "0xffff800000003000" } } });
        assert.equal(app.latest("disassemblyRead").params.expression, "@$ip");
        await processStatus(app, target, { instructionPointer: "0xffff800000003000" });
        await disassemblyReply(app, { address: "0xffff800000003000", instructionPointer: "0xffff800000003000" });
        assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true);
        assert.equal(app.nodes.get("btn-debug-" + control).disabled, false);
        for (const modifiers of [{ shiftKey: true }, { repeat: true }, { defaultPrevented: true }, { altKey: true }])
        {
            app.documentListeners.get("keydown")({ key, preventDefault: noop, ...modifiers });
        }
        assert.equal(app.messages.filter(item => item.method === "debuggerAction").length, 1);
    }
});

await check("T-UI-EXECUTION a late action receipt cannot replace newer stopped running or Busy status", async () =>
{
    for (const latest of ["stopped", "running", "busy"])
    {
        const app = await disassemblyApp();
        app.nodes.get("btn-debug-over").fire("click");
        const current = { ...stamp, stopEpoch: "4", contextGeneration: "5" };
        app.nodes.get("btn-refresh-status").fire("click");
        if (latest === "busy")
        {
            await app.reply("status", { ok: false, error: "EngineBusy" });
        }
        else
        {
            await processStatus(app, current, { stopped: latest === "stopped", canControlExecution: latest === "stopped",
                instructionPointer: latest === "stopped" ? "0xffff800000003000" : null });
        }
        await app.reply("debuggerAction", { ok: true, result: { ok: true, operation: "step-over", status: {
            connected: true, stopped: true, canControlExecution: true, target: { ...stamp, stopEpoch: "3" },
            instructionPointer: "0xffff800000002000" } } });
        const reads = app.messages.filter(item => item.method === "disassemblyRead");
        assert.equal(reads.length, latest === "stopped" ? 1 : 0, latest);
        if (latest === "stopped")
        {
            assert.deepEqual(JSON.parse(JSON.stringify(reads[0].params.expectedStamp)), current);
        }
        else
        {
            assert.equal(app.nodes.get("prompt").disabled, true, latest);
        }
        assert.equal(app.messages.filter(item => item.method === "debuggerAction").length, 1);
    }
});

await check("T-UI-EXECUTION failed or uncertain actions stay visible without replay and unsupported contexts refuse clicks", async () =>
{
    for (const reason of ["EngineBusy", "Outcome unknown"])
    {
        const app = await disassemblyApp();
        app.nodes.get("btn-debug-over").fire("click");
        await app.reply("debuggerAction", { ok: false, error: reason });
        assert.match(app.nodes.get("workspace-feedback-text").textContent, new RegExp(reason));
        assert.equal(feedbackTimers(app).length, 0);
        await processStatus(app);
        assert.equal(app.messages.filter(item => item.method === "debuggerAction").length, 1);
    }
    const cancelled = await disassemblyApp();
    cancelled.nodes.get("btn-debug-over").fire("click");
    cancelled.nodes.get("btn-cancel").fire("click");
    await cancelled.reply("debuggerAction", { ok: true, result: { ok: true, operation: "step-over", status: {
        connected: true, stopped: true, canControlExecution: true, target: { ...stamp, stopEpoch: "10" },
        instructionPointer: "0xffff800000003000" } } });
    assert.equal(cancelled.messages.some(item => item.method === "disassemblyRead"), false,
        "Stop must suppress automatic reads after an execution action completes");
    for (const overrides of [{ stopped: false }, { dumpFile: true, canControlExecution: false },
        { localKernel: true, canControlExecution: false }, { canControlExecution: false }])
    {
        const app = await disassemblyApp();
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, stamp, overrides);
        assert.equal(app.nodes.get("btn-debug-into").disabled, true);
        app.nodes.get("btn-debug-into").fire("click");
        assert.equal(app.messages.some(item => item.method === "debuggerAction"), false);
    }
});

await check("T-UI-PROCESS-PANEL all three tabs retain their snapshots and process search beside Results", async () =>
{
    const app = await memoryApp();
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(65));
    app.nodes.get("memory-rows").children[1].fire("click");
    app.nodes.get("tab-disassembly").fire("click");
    app.nodes.get("disassembly-count").value = "16";
    app.nodes.get("btn-disassembly-read").fire("click");
    await disassemblyReply(app);
    app.nodes.get("disassembly-rows").children[1].fire("click");
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app);
    app.nodes.get("process-filter").value = "process256";
    app.nodes.get("process-filter").fire("input");
    app.nodes.get("process-rows").children[0].fire("click");
    const reads = app.messages.filter(item => ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length;
    for (const tab of ["tab-memory-view", "tab-disassembly", "tab-processes"])
    {
        app.nodes.get(tab).fire("click");
    }
    await processStatus(app);
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("btn-memory-panel").fire("click");
    await processStatus(app);
    assert.equal(app.messages.filter(item => ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length, reads);
    assert.equal(app.nodes.get("process-filter").value, "process256");
    assert.match(app.nodes.get("process-name").textContent, /process256/);
    assert.equal(app.nodes.get("memory-rows").children[1].getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("disassembly-rows").children[1].getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("result-title").textContent, "retained-result");
    assert.equal(app.nodes.get("evidence").classList.contains("hidden"), false);
    assert.equal(app.nodes.has("tab-results"), false);
});

await check("T-UI-PROCESS-PANEL hidden and inactive lists do not collect on context changes", async () =>
{
    for (const inactive of ["hide", "memory", "disassembly"])
    {
        const app = await memoryApp();
        showProcesses(app);
        await processStatus(app);
        await collectProcessPages(app, processRows.slice(0, 2));
        if (inactive === "hide")
        {
            app.nodes.get("btn-memory-close").fire("click");
        }
        else
        {
            app.nodes.get(inactive === "memory" ? "tab-memory-view" : "tab-disassembly").fire("click");
        }
        app.nodes.get("btn-refresh-status").fire("click");
        const changed = { ...stamp, contextGeneration: "7" };
        await processStatus(app, changed);
        assert.equal(app.messages.filter(item => item.method === "execute").length, 1);
        assert.equal(app.nodes.get("process-rows").children.length, 2);
        showProcesses(app);
        await processStatus(app, changed);
        assert.equal(app.messages.filter(item => item.method === "execute").length, 2);
        await collectProcessPages(app, processRows.slice(0, 2), { target: changed });
    }
});

await check("T-UI-PROCESS-PANEL pending refreshes finish without reopening or selecting a hidden view", async () =>
{
    for (const destination of ["hide", "memory", "disassembly"])
    {
        const app = await memoryApp();
        showProcesses(app);
        await processStatus(app);
        if (destination === "hide")
        {
            app.nodes.get("btn-memory-close").fire("click");
        }
        else
        {
            app.nodes.get(destination === "memory" ? "tab-memory-view" : "tab-disassembly").fire("click");
        }
        await collectProcessPages(app, processRows.slice(0, 2));
        assert.equal(app.nodes.get("memory").classList.contains("hidden"), destination === "hide");
        if (destination !== "hide")
        {
            assert.equal(app.nodes.get("tab-processes").getAttribute("aria-selected"), "false");
        }
        assert.equal(app.nodes.get("evidence").classList.contains("hidden"), false);
        assert.equal(app.nodes.get("process-rows").children.length, 2);
        assert.equal(app.messages.some(item => item.method === "interrupt"), false);
    }
});

await check("T-UI-PROCESS-PANEL detail actions retain the wide panel, reveal narrow Results and respect a newer tab", async () =>
{
    for (const mode of ["wide", "overlay", "changed-tab"])
    {
        const app = await memoryApp();
        app.nodes.get("workspace-split").clientWidth = mode === "wide" ? 1600 : 600;
        showProcesses(app);
        await processStatus(app);
        await collectProcessPages(app, processRows.slice(0, 2));
        app.nodes.get("process-rows").children[1].fire("click");
        app.nodes.get("btn-process-details").fire("click");
        if (mode === "changed-tab")
        {
            app.nodes.get("tab-memory-view").fire("click");
            app.nodes.get("tab-memory-view").focus();
        }
        await app.reply("processAction", { ok: true, result: { resultId: "detail-result", rowCount: "0", outputLength: "0",
            data: { commandId: "!process", status: "Success", target: stamp } } });
        await app.reply("outputChunk", { ok: true, result: { resultId: "detail-result", offset: "0", next: "0", complete: true, text: "" } });
        await processStatus(app);
        assert.equal(app.nodes.get("result-title").textContent, "!process");
        assert.equal(app.nodes.get("memory").classList.contains("hidden"), mode === "overlay");
        assert.equal(app.focused(), app.nodes.get(mode === "changed-tab" ? "tab-memory-view" : "result-table"));
        assert.match(app.nodes.get("process-name").textContent, /process1/);
        assert.equal(app.latest("processAction").params.index, "1");
    }
});

await check("T-UI-PROCESS-PANEL manual copy restores the selected right tab or its hidden toggle", async () =>
{
    const app = await memoryApp({ clipboard: { writeText: () => Promise.reject(new Error("Denied")) } });
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, processRows.slice(0, 2));
    for (const destination of ["processes", "memory", "disassembly", "hide"])
    {
        showProcesses(app);
        await processStatus(app);
        app.nodes.get("process-rows").children[1].children[2].fire("click");
        await settle();
        if (destination === "hide")
        {
            app.nodes.get("btn-memory-close").fire("click");
        }
        else
        {
            app.nodes.get(destination === "processes" ? "tab-processes" : destination === "memory" ? "tab-memory-view" : "tab-disassembly").fire("click");
        }
        app.nodes.get("btn-copy-close").fire("click");
        assert.equal(app.focused(), app.nodes.get(destination === "hide" ? "btn-memory-panel" :
            destination === "processes" ? "process-grid" : destination + "-grid"));
    }
});

await check("T-UI-PROCESS-PANEL four-tab keyboard navigation and saved process tab retain one active tab", async () =>
{
    const saved = new Map([["kndbgx.memory-panel", JSON.stringify({ visible: false, width: 640, tab: "processes" })]]);
    const app = harness({ storage: { getItem: key => saved.get(key), setItem: (key, value) => saved.set(key, value) } });
    await app.boot();
    assert.equal(app.nodes.get("tab-processes").getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("memory").classList.contains("hidden"), true);
    assert.equal(app.messages.some(item => item.method === "execute"), false);
    app.nodes.get("btn-memory-panel").fire("click");
    await processStatus(app);
    await collectProcessPages(app, processRows.slice(0, 2));
    for (const [from, key, to] of [["tab-processes", "ArrowLeft", "tab-registers"], ["tab-registers", "ArrowRight", "tab-processes"],
        ["tab-processes", "ArrowRight", "tab-memory-view"], ["tab-memory-view", "End", "tab-registers"], ["tab-registers", "Home", "tab-processes"]])
    {
        app.nodes.get(from).fire("keydown", { key });
        assert.equal(app.nodes.get(to).getAttribute("aria-selected"), "true");
        assert.equal(app.focused(), app.nodes.get(to));
        assert.equal(["tab-processes", "tab-memory-view", "tab-disassembly", "tab-registers"].filter(id =>
            app.nodes.get(id).getAttribute("aria-selected") === "true").length, 1);
    }
    app.nodes.get("tab-processes").fire("keydown", { key: "ArrowRight", isComposing: true });
    assert.equal(app.nodes.get("tab-processes").getAttribute("aria-selected"), "true");
    assert.equal(JSON.parse(saved.get("kndbgx.memory-panel")).tab, "processes");
    assert.equal(app.messages.filter(item => item.method === "execute").length, 1);
});

await check("T-UI-DISASSEMBLY tabs preserve independent snapshots, selections and the main result without reading", async () =>
{
    const app = await memoryApp();
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(65));
    app.nodes.get("memory-rows").children[1].fire("click");
    app.nodes.get("tab-memory-view").fire("keydown", { key: "ArrowRight" });
    assert.equal(app.nodes.get("tab-disassembly").getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("memory-view").classList.contains("hidden"), true);
    assert.equal(app.messages.some(item => item.method === "disassemblyRead"), false);
    app.nodes.get("disassembly-count").value = "16";
    app.nodes.get("btn-disassembly-read").fire("click");
    await disassemblyReply(app);
    app.nodes.get("disassembly-rows").children[1].fire("click");
    app.nodes.get("tab-disassembly").fire("keydown", { key: "Home" });
    assert.equal(app.nodes.get("tab-processes").getAttribute("aria-selected"), "true");
    app.nodes.get("tab-memory-view").fire("click");
    assert.equal(app.nodes.get("memory-rows").children[1].getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("memory-rows").children[0].children[1].textContent, "41");
    app.nodes.get("tab-disassembly").fire("click");
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("btn-memory-panel").fire("click");
    assert.equal(app.nodes.get("disassembly-rows").children[1].getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("result-title").textContent, "retained-result");
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, 1);
    assert.equal(app.messages.filter(item => item.method === "memoryRead").length, 1);
});

await check("T-UI-DISASSEMBLY exact high addresses, decoded values, IP markers and keyboard copies survive tab changes", async () =>
{
    const copied = [];
    const app = await disassemblyApp({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return Promise.resolve();
    } } });
    const target = { ...stamp, contextIdentity: { implicitProcess: "0xffff800000002000", scopeInstruction: "0xfffffffffffff000" } };
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, target);
    app.nodes.get("disassembly-address").value = "test!Code";
    app.nodes.get("disassembly-address").fire("keydown", { key: "Enter" });
    assert.equal(app.latest("disassemblyRead").params.expression, "test!Code");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("disassemblyRead").params.expectedStamp)), target);
    const rows = await disassemblyReply(app, { address: "0xfffffffffffff000" });
    assert.equal(app.nodes.get("disassembly-address").value, rows[0].address);
    assert.equal(app.nodes.get("disassembly-rows").children[0].classList.contains("current-ip"), true);
    assert.equal(app.nodes.get("disassembly-grid").getAttribute("aria-rowcount"), "17");
    app.nodes.get("disassembly-grid").fire("keydown", { key: "End" });
    const last = app.nodes.get("disassembly-rows").children[15];
    last.children[3].fire("keydown", { key: "Enter" });
    await settle();
    assert.equal(copied.at(-1), rows[15].bytes);
    assert.equal(app.focused(), last.children[3]);
    app.nodes.get("tab-memory-view").fire("click");
    assert.equal(app.focused(), app.nodes.get("tab-memory-view"));
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, 1);
});

await check("T-UI-DISASSEMBLY next uses decoded boundaries and previous view restores captured data without a read", async () =>
{
    const app = await disassemblyApp();
    app.nodes.get("btn-disassembly-read").fire("click");
    const first = await disassemblyReply(app);
    app.nodes.get("btn-disassembly-next").fire("click");
    assert.equal(app.latest("disassemblyRead").params.expression, first.at(-1).nextAddress);
    await disassemblyReply(app, { address: first.at(-1).nextAddress });
    const reads = app.messages.filter(item => item.method === "disassemblyRead").length;
    app.nodes.get("btn-disassembly-back").fire("click");
    assert.equal(app.nodes.get("disassembly-address").value, first[0].address);
    assert.equal(app.nodes.get("disassembly-rows").children[0].children[2].textContent, first[0].instructionText);
    assert.equal(app.nodes.get("btn-disassembly-back").disabled, true);
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, reads);
    app.nodes.get("disassembly-address").value = "0x1000";
    app.nodes.get("disassembly-address").fire("input");
    assert.equal(app.nodes.get("btn-disassembly-next").disabled, true);
});

await check("T-UI-DISASSEMBLY invalid pages and instruction sequences retain the previous view", async () =>
{
    for (const failure of ["page", "sequence", "bytes", "space", "text"])
    {
        const app = await disassemblyApp();
        app.nodes.get("btn-disassembly-read").fire("click");
        await disassemblyReply(app);
        const previous = app.nodes.get("disassembly-rows").children[0];
        app.nodes.get("btn-disassembly-read").fire("click");
        await app.reply("disassemblyRead", { ok: true, result: { resultId: "bad-code", rowCount: "16",
            data: { commandId: "u", status: "Success", target: stamp } } });
        const rows = instructionRows(16);
        if (failure === "sequence")
        {
            rows[1].address = rows[0].address;
        }
        if (failure === "bytes")
        {
            rows[0].bytes = "9090";
        }
        if (failure === "space")
        {
            rows[0].addressSpace = "physical";
        }
        if (failure === "text")
        {
            rows[0].instructionText = "";
        }
        await app.reply("resultPage", { ok: true, result: { resultId: "bad-code", collection: "rows", offset: "0",
            total: "16", next: failure === "page" ? "0" : "16", complete: true, rows: failure === "page" ? [] : rows } });
        assert.equal(app.nodes.get("disassembly-rows").children[0], previous);
        assert.equal(app.nodes.get("btn-cancel").disabled, true);
        assert.ok(app.nodes.get("disassembly-notice").textContent);
        assert.equal(app.nodes.get("btn-disassembly-next").disabled, true);
    }
});

await check("T-UI-DISASSEMBLY Stop during execution or page retrieval retains data and hiding never reopens the panel", async () =>
{
    for (const stage of ["execution", "pages"])
    {
        const app = await disassemblyApp();
        app.nodes.get("btn-disassembly-read").fire("click");
        await disassemblyReply(app);
        const previous = app.nodes.get("disassembly-rows").children[0];
        app.nodes.get("btn-disassembly-read").fire("click");
        const execution = app.latest("disassemblyRead");
        const result = { ok: true, result: { resultId: "pending-code", rowCount: "16", data: { commandId: "u", status: "Success", target: stamp } } };
        if (stage === "pages")
        {
            await app.deliver(execution, result);
        }
        app.nodes.get("btn-cancel").fire("click");
        app.nodes.get("btn-memory-close").fire("click");
        if (stage === "execution")
        {
            await app.deliver(execution, result);
        }
        else
        {
            await app.reply("resultPage", { ok: true, result: { resultId: "pending-code", collection: "rows", offset: "0",
                total: "16", next: "16", complete: true, rows: instructionRows(16) } });
        }
        assert.equal(app.nodes.get("disassembly-rows").children[0], previous);
        assert.equal(app.nodes.get("memory").classList.contains("hidden"), true);
        assert.equal(app.nodes.get("btn-cancel").disabled, true);
        assert.match(app.nodes.get("disassembly-notice").textContent, /cancelled/);
        assert.equal(app.nodes.get("disassembly-address-history").children.length, 2);
        assert.equal(app.nodes.get("disassembly-address-history").children[1].textContent, "@$ip");
    }
});

await check("T-UI-DISASSEMBLY stale replies and unavailable or empty decoding never replace a captured view", async () =>
{
    for (const failure of ["stale", "empty", "unavailable", "wrong-command"])
    {
        const app = await disassemblyApp();
        app.nodes.get("btn-disassembly-read").fire("click");
        await disassemblyReply(app);
        const previous = app.nodes.get("disassembly-rows").children[0];
        app.nodes.get("btn-disassembly-read").fire("click");
        await app.reply("disassemblyRead", { ok: true, result: { resultId: "invalid-code", rowCount: failure === "empty" ? "0" : "16",
            data: { commandId: failure === "wrong-command" ? "uf" : "u", status: failure === "unavailable" ? "Unavailable" : "Success",
                target: failure === "stale" ? { ...stamp, contextGeneration: "99" } : stamp } } });
        assert.equal(app.nodes.get("disassembly-rows").children[0], previous);
        assert.equal(app.nodes.get("btn-cancel").disabled, true);
        assert.ok(app.nodes.get("disassembly-notice").textContent);
    }
});

await check("T-UI-DISASSEMBLY partial prefixes and changed contexts keep explicit limits without automatic reads", async () =>
{
    const app = await disassemblyApp();
    app.nodes.get("btn-disassembly-read").fire("click");
    await disassemblyReply(app, { rows: instructionRows(3), partial: true });
    assert.equal(app.nodes.get("disassembly-rows").children.length, 3);
    assert.match(app.nodes.get("disassembly-summary").textContent, /3 instructions \/ partial/);
    assert.match(app.nodes.get("disassembly-notice").textContent, /decoded prefix/);
    assert.equal(app.nodes.get("btn-disassembly-next").disabled, true);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...stamp, contextGeneration: "100" });
    assert.match(app.nodes.get("disassembly-notice").textContent, /context changed/);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { stopped: false });
    assert.equal(app.nodes.get("btn-disassembly-read").disabled, true);
    assert.equal(app.nodes.get("btn-disassembly-ip").disabled, true);
    assert.equal(app.nodes.get("disassembly-rows").children.length, 3);
    assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length, 1);
});

await check("T-UI-DISASSEMBLY malformed expressions are refused and the active panel tab restores without reading", async () =>
{
    const app = await disassemblyApp();
    for (const expression of ["", " ", "@$ip;g", '"@$ip"', "@$ip\ng", "@$ip\\", "{g}"])
    {
        app.nodes.get("disassembly-address").value = expression;
        app.nodes.get("btn-disassembly-read").fire("click");
    }
    assert.equal(app.messages.some(item => item.method === "disassemblyRead"), false);
    const saved = new Map([["kndbgx.memory-panel", JSON.stringify({ visible: true, width: 640, tab: "disassembly" })]]);
    const restored = harness({ storage: { getItem: key => saved.get(key) || null, setItem: (key, value) => saved.set(key, value) } });
    await restored.boot();
    assert.equal(restored.nodes.get("tab-disassembly").getAttribute("aria-selected"), "true");
    assert.equal(restored.nodes.get("memory-view").classList.contains("hidden"), true);
    assert.equal(restored.messages.some(item => item.method === "disassemblyRead" || item.method === "memoryRead"), false);
    restored.nodes.get("tab-memory-view").fire("click");
    assert.equal(JSON.parse(saved.get("kndbgx.memory-panel")).tab, "memory");
});

await check("T-UI-DISASSEMBLY clipboard refusal restores focus to the selected panel tab or its toggle", async () =>
{
    const app = await disassemblyApp({ clipboard: { writeText: () => Promise.reject(new Error("Denied")) } });
    app.nodes.get("btn-disassembly-read").fire("click");
    await disassemblyReply(app);
    app.nodes.get("disassembly-rows").children[0].children[2].fire("click");
    await settle();
    assert.equal(app.nodes.get("copy-text").value, "int3");
    app.nodes.get("tab-memory-view").fire("click");
    app.nodes.get("btn-copy-close").focus();
    app.nodes.get("btn-copy-close").fire("click");
    assert.equal(app.focused(), app.nodes.get("memory-grid"));
    app.nodes.get("tab-disassembly").fire("click");
    app.nodes.get("disassembly-rows").children[0].children[2].fire("click");
    await settle();
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("btn-copy-close").focus();
    app.nodes.get("btn-copy-close").fire("click");
    assert.equal(app.focused(), app.nodes.get("btn-memory-panel"));
});

await check("T-UI-MEMORY-PANEL visibility is independent of Results and Processes and preserves the memory snapshot", async () =>
{
    const app = await memoryApp();
    assert.equal(app.nodes.get("evidence").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("evidence").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("btn-memory-panel").getAttribute("aria-expanded"), "true");
    assert.equal(app.messages.some(request => request.method === "memoryRead"), false);
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(65));
    app.nodes.get("memory-rows").children[1].fire("click");
    app.nodes.get("memory-address").focus();
    app.nodes.get("btn-memory-close").fire("click");
    assert.equal(app.nodes.get("memory").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("memory-splitter").classList.contains("hidden"), true);
    assert.equal(app.focused(), app.nodes.get("btn-memory-panel"));
    showProcesses(app);
    assert.equal(app.nodes.get("tab-processes").getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("processes").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("memory").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("memory-rows").children[1].getAttribute("aria-selected"), "true");
    assert.equal(app.nodes.get("memory-address").value, "0xffff800000001000");
    assert.equal(app.messages.filter(request => request.method === "memoryRead").length, 1);
});

await check("T-UI-MEMORY-PANEL hiding an active read does not cancel, discard or reopen it", async () =>
{
    const app = await memoryApp();
    app.nodes.get("btn-memory-read").fire("click");
    app.nodes.get("btn-memory-close").fire("click");
    assert.equal(app.messages.some(request => request.method === "interrupt"), false);
    await memoryReply(app, Array(64).fill(66));
    assert.equal(app.nodes.get("memory").classList.contains("hidden"), true);
    assert.equal(app.nodes.get("memory-rows").children[0].children[1].textContent, "42");
    app.documentListeners.get("keydown")({ key: "m", ctrlKey: true, preventDefault: noop });
    assert.equal(app.nodes.get("memory").classList.contains("hidden"), false);
    assert.equal(app.messages.filter(request => request.method === "memoryRead").length, 1);
});

function memoryEvidenceFixture(bytes, options = {})
{
    const address = options.address || "0xffff800000001000";
    const read = bytes.filter(value => value !== null).length;
    return { schema: "kndbgx.memory-read.v1", address, addressSpace: options.space || "virtual", length: String(bytes.length),
        read: String(read), mapping: "Unobserved", unreadableCause: "Unknown",
        capture: { kind: options.kind || "KernelRemote", class: "1", qualifier: "0", dumpFlags: null,
            typeQueryHresult: "0x0000000000000000" },
        attempts: [{ address, requested: String(bytes.length), read: String(read), status: read === bytes.length ? "Success" : "Partial",
            nativeError: { domain: "HRESULT", code: "0x0000000000000000" } }] };
}

function memoryEvidenceText(app)
{
    return app.nodes.get("memory-evidence-facts").children.map(node => node.textContent).join(" / ") + " / " +
        app.nodes.get("memory-evidence-ranges").children.map(node => node.textContent).join(" / ");
}

await check("T-UI-MEMORY-EVIDENCE partial bytes expose saved native ranges without another request", async () =>
{
    const app = await memoryApp();
    const bytes = [...Array(7).fill(65), ...Array(57).fill(null)];
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, bytes, { evidence: memoryEvidenceFixture(bytes) });
    const count = app.messages.length;
    for (const key of [{ key: "Enter", repeat: true }, { key: "Enter", isComposing: true },
        { key: "Enter", target: app.nodes.get("memory-rows").children[0].children[1], repeat: true }])
    {
        app.nodes.get("memory-grid").fire("keydown", key);
        assert.equal(app.nodes.get("memory-evidence").classList.contains("hidden"), true,
            "A repeated, composing or cell key must not activate grid details");
    }
    app.nodes.get("memory-rows").children[0].children[8].fire("click");
    assert.equal(app.nodes.get("memory-evidence").classList.contains("hidden"), false);
    assert.match(memoryEvidenceText(app), /7 read \/ 9 unavailable \/ 16 requested/);
    assert.match(memoryEvidenceText(app), /7\/64 bytes, Partial.*Unavailable: 0xffff800000001007.*HRESULT 0x0000000000000000/);
    assert.match(app.nodes.get("memory-evidence-cause").textContent, /Cause: Unknown/);
    assert.equal(app.nodes.get("memory-rows").children[0].children[1].textContent, "41");
    assert.equal(app.messages.length, count);
    app.nodes.get("memory-evidence").fire("keydown", { key: "Escape" });
    assert.equal(app.focused(), app.nodes.get("btn-memory-evidence"));
    app.nodes.get("memory-grid").fire("keydown", { key: "Enter" });
    assert.equal(app.nodes.get("memory-evidence").classList.contains("hidden"), false);
    assert.equal(app.messages.length, count);
    const firstFact = app.nodes.get("memory-evidence-facts").children[0];
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app);
    assert.equal(app.nodes.get("memory-evidence-facts").children[0], firstFact,
        "Unchanged status must not replace evidence nodes or disturb reading position");
});

await check("T-UI-MEMORY-EVIDENCE failed refresh and changed context keep old evidence separate", async () =>
{
    const app = await memoryApp();
    const bytes = [...Array(7).fill(65), ...Array(57).fill(null)];
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, bytes, { evidence: memoryEvidenceFixture(bytes, { kind: "KernelDump" }) });
    app.nodes.get("btn-memory-evidence").fire("click");
    assert.match(app.nodes.get("memory-evidence-cause").textContent, /Dump origin .*unconfirmed/);
    app.nodes.get("memory-address").value = "missing!expression";
    app.nodes.get("btn-memory-read").fire("click");
    await app.reply("memoryRead", { ok: false, error: "Expression unavailable" });
    await processStatus(app, { ...stamp, contextGeneration: "2" });
    assert.match(app.nodes.get("memory-evidence-attempt").textContent, /missing!expression.*Expression unavailable/);
    assert.match(app.nodes.get("memory-evidence-summary").textContent, /previous or unconfirmed context/);
    assert.match(memoryEvidenceText(app), /Kernel dump/);
    assert.equal(app.nodes.get("memory-rows").children[0].children[1].textContent, "41");
    assert.equal(app.nodes.get("btn-memory-next").disabled, true);
});

await check("T-UI-MEMORY-EVIDENCE missing or mismatched metadata cannot fabricate a native explanation", async () =>
{
    const bytes = [...Array(7).fill(65), ...Array(57).fill(null)];
    for (const mutate of [() => undefined, data => ({ ...data, address: "0xffff800000009000" }),
        data => ({ ...data, read: "64" }), data => ({ ...data, unreadableCause: "PagedOut" }),
        data => ({ ...data, attempts: [{ ...data.attempts[0], read: "8" }] }),
        data => ({ ...data, attempts: [{ ...data.attempts[0], requested: 64 }] })])
    {
        const app = await memoryApp();
        app.nodes.get("btn-memory-read").fire("click");
        await memoryReply(app, bytes, { evidence: mutate(memoryEvidenceFixture(bytes)) });
        app.nodes.get("btn-memory-evidence").fire("click");
        assert.match(memoryEvidenceText(app), /saved diagnostics unavailable or inconsistent/);
        assert.equal(app.nodes.get("memory-evidence-ranges").children.length, 0);
        assert.equal(app.nodes.get("memory-rows").children[0].children[1].textContent, "41");
    }
});

await check("T-UI-MEMORY-EVIDENCE physical zero and wholly failed reads remain inspectable", async () =>
{
    const app = await memoryApp();
    const bytes = Array(64).fill(null);
    const options = { address: "0x0000000000000000", space: "physical" };
    const evidence = memoryEvidenceFixture(bytes, options);
    evidence.attempts[0].status = "Unavailable";
    evidence.attempts[0].nativeError.code = "0x0000000080004005";
    app.nodes.get("memory-space").value = "physical";
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, bytes, { ...options, evidence });
    app.nodes.get("btn-memory-evidence").fire("click");
    assert.match(memoryEvidenceText(app), /Physical; independent of the selected process/);
    assert.match(memoryEvidenceText(app), /0 read \/ 64 unavailable/);
    assert.match(memoryEvidenceText(app), /HRESULT 0x0000000080004005/);
});

async function inspectorApp(storage)
{
    const app = harness({ storage });
    await app.boot();
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("result-content").clientWidth = 1400;
    app.nodes.get("btn-inspector").fire("click");
    app.windowEvent("resize");
    return app;
}

await check("T-UI-INSPECTOR keyboard and pointer resizing preserve cancellation and never read the target", async () =>
{
    const saved = new Map();
    const app = await inspectorApp({ getItem: key => saved.get(key), setItem: (key, value) => saved.set(key, value) });
    const splitter = app.nodes.get("inspector-splitter");
    assert.equal(splitter.getAttribute("aria-valuenow"), "296");
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 1000 });
    app.documentListeners.get("pointerup")({ pointerId: 7, clientX: 1000, preventDefault: noop });
    assert.equal(saved.get("kndbgx.inspector-width"), "null");
    splitter.fire("keydown", { key: "ArrowLeft" });
    assert.equal(splitter.getAttribute("aria-valuenow"), "312");
    splitter.fire("keydown", { key: "ArrowRight", shiftKey: true });
    assert.equal(splitter.getAttribute("aria-valuenow"), "248");
    splitter.fire("keydown", { key: "Home" });
    assert.equal(splitter.getAttribute("aria-valuenow"), "240");
    splitter.fire("keydown", { key: "End" });
    assert.equal(splitter.getAttribute("aria-valuenow"), "800");
    for (const event of [{ button: 2 }, { button: 0, isPrimary: false }, { button: 0, clientX: NaN }])
    {
        splitter.fire("pointerdown", { pointerId: 7, clientX: 1000, ...event });
        assert.equal(app.nodes.get("root").classList.contains("inspector-resizing"), false);
    }
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 1000 });
    app.documentListeners.get("pointermove")({ pointerId: 8, clientX: 1100, preventDefault: noop });
    assert.equal(splitter.getAttribute("aria-valuenow"), "800");
    app.documentListeners.get("pointermove")({ pointerId: 7, clientX: 1100, preventDefault: noop });
    assert.equal(splitter.getAttribute("aria-valuenow"), "700");
    app.documentListeners.get("pointercancel")({ pointerId: 7 });
    assert.equal(splitter.getAttribute("aria-valuenow"), "800");
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 1000 });
    app.documentListeners.get("pointermove")({ pointerId: 7, clientX: 1100, preventDefault: noop });
    app.documentListeners.get("keydown")({ key: "Escape", preventDefault: noop });
    assert.equal(splitter.getAttribute("aria-valuenow"), "800");
    assert.equal(app.nodes.get("root").classList.contains("inspector-resizing"), false);
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 1000 });
    app.documentListeners.get("pointerup")({ pointerId: 7, clientX: 1200, preventDefault: noop });
    assert.equal(splitter.getAttribute("aria-valuenow"), "600");
    assert.equal(saved.get("kndbgx.inspector-width"), "600");
    splitter.fire("dblclick", { button: 0 });
    assert.equal(splitter.getAttribute("aria-valuenow"), "296");
    assert.equal(saved.get("kndbgx.inspector-width"), "null");
    assert.equal(app.messages.some(request => ["execute", "memoryRead", "disassemblyRead"].includes(request.method)), false);
});

await check("T-UI-INSPECTOR constrained layout and interrupted drags retain preferred width and release focus", async () =>
{
    const saved = new Map([["kndbgx.inspector-width", "800"]]);
    const app = await inspectorApp({ getItem: key => saved.get(key), setItem: (key, value) => saved.set(key, value) });
    const splitter = app.nodes.get("inspector-splitter");
    app.nodes.get("result-content").clientWidth = 900;
    app.windowEvent("resize");
    assert.equal(splitter.getAttribute("aria-valuenow"), "574");
    assert.equal(saved.get("kndbgx.inspector-width"), "800");
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 1000 });
    app.documentListeners.get("pointermove")({ pointerId: 7, clientX: 900, preventDefault: noop });
    app.documentListeners.get("pointerup")({ pointerId: 7, clientX: 900, preventDefault: noop });
    assert.equal(splitter.getAttribute("aria-valuenow"), "574");
    assert.equal(saved.get("kndbgx.inspector-width"), "800");
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 1000 });
    app.documentListeners.get("pointermove")({ pointerId: 7, clientX: 1100, preventDefault: noop });
    app.nodes.get("btn-memory-panel").fire("click");
    assert.equal(splitter.classList.contains("hidden"), true);
    assert.equal(app.nodes.get("inspector").style.flexBasis, "");
    assert.equal(app.nodes.get("root").classList.contains("inspector-resizing"), false);
    assert.equal(app.focused(), app.nodes.get("btn-inspector"));
    assert.equal(saved.get("kndbgx.inspector-width"), "800");
    app.nodes.get("result-content").clientWidth = 1400;
    app.nodes.get("btn-memory-close").fire("click");
    assert.equal(splitter.getAttribute("aria-valuenow"), "800");
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 1000 });
    app.documentListeners.get("pointermove")({ pointerId: 7, clientX: 1100, preventDefault: noop });
    app.nodes.get("btn-inspector").fire("click");
    assert.equal(splitter.classList.contains("hidden"), true);
    assert.equal(saved.get("kndbgx.inspector-width"), "800");
    app.nodes.get("btn-inspector").fire("click");
    assert.equal(splitter.getAttribute("aria-valuenow"), "800");
    for (const end of [() => app.windowEvent("blur"), () => splitter.fire("lostpointercapture")])
    {
        splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 1000 });
        app.documentListeners.get("pointermove")({ pointerId: 7, clientX: 1100, preventDefault: noop });
        end();
        assert.equal(app.nodes.get("root").classList.contains("inspector-resizing"), false);
    }
    assert.equal(saved.get("kndbgx.inspector-width"), "600");
    splitter.setPointerCapture = () =>
    {
        throw new Error("Unavailable");
    };
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 1000 });
    assert.equal(app.nodes.get("root").classList.contains("inspector-resizing"), false);
    splitter.fire("keydown", { key: "ArrowLeft" });
    assert.equal(splitter.getAttribute("aria-valuenow"), "616");
});

await check("T-UI-INSPECTOR saved widths reject malformed values and resizing works without storage", async () =>
{
    for (const [value, expected] of [["480", "480"], ["480".padEnd(32), "480"], ["480.5", "481"],
        ["480".padEnd(33), "296"], [null, "296"], ["null", "296"], ["true", "296"], ["[]", "296"],
        ['"480"', "296"], ["{}", "296"], ["239", "296"], ["801", "296"], ["invalid", "296"]])
    {
        const app = await inspectorApp({ getItem: key => key === "kndbgx.inspector-width" ? value : null, setItem: noop });
        assert.equal(app.nodes.get("inspector-splitter").getAttribute("aria-valuenow"), expected);
    }
    const denied = () =>
    {
        throw new Error("Denied");
    };
    const app = await inspectorApp({ getItem: denied, setItem: denied });
    app.nodes.get("inspector-splitter").fire("keydown", { key: "End" });
    assert.equal(app.nodes.get("inspector-splitter").getAttribute("aria-valuenow"), "800");
});

await check("T-UI-MEMORY-PANEL keyboard and pointer resizing clamp widths and cancel without touching the target", async () =>
{
    const saved = new Map();
    const app = await memoryApp({ storage: { getItem: key => saved.get(key) || null, setItem: (key, value) => saved.set(key, value) } });
    app.nodes.get("workspace-split").clientWidth = 1600;
    const splitter = app.nodes.get("memory-splitter");
    splitter.fire("keydown", { key: "ArrowLeft" });
    assert.equal(splitter.getAttribute("aria-valuenow"), "536");
    splitter.fire("keydown", { key: "ArrowRight", shiftKey: true });
    assert.equal(splitter.getAttribute("aria-valuenow"), "472");
    splitter.fire("keydown", { key: "End" });
    assert.equal(splitter.getAttribute("aria-valuenow"), "1000");
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 800 });
    app.documentListeners.get("pointermove")({ pointerId: 8, clientX: 900, preventDefault: noop });
    assert.equal(splitter.getAttribute("aria-valuenow"), "1000");
    app.documentListeners.get("pointermove")({ pointerId: 7, clientX: 900, preventDefault: noop });
    assert.equal(splitter.getAttribute("aria-valuenow"), "900");
    app.documentListeners.get("pointercancel")({ pointerId: 7 });
    assert.equal(splitter.getAttribute("aria-valuenow"), "1000");
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 800 });
    app.documentListeners.get("pointermove")({ pointerId: 7, clientX: 3000, preventDefault: noop });
    assert.equal(splitter.getAttribute("aria-valuenow"), "280");
    app.documentListeners.get("keydown")({ key: "Escape", preventDefault: noop });
    assert.equal(splitter.getAttribute("aria-valuenow"), "1000");
    assert.equal(app.nodes.get("root").classList.contains("memory-resizing"), false);
    splitter.fire("pointerdown", { button: 0, pointerId: 7, clientX: 800 });
    app.documentListeners.get("pointermove")({ pointerId: 7, clientX: 1000, preventDefault: noop });
    app.documentListeners.get("pointerup")({ pointerId: 7 });
    assert.equal(JSON.parse(saved.get("kndbgx.memory-panel")).width, 800);
    assert.equal(app.messages.some(request => request.method === "memoryRead" || request.method === "execute"), false);
});

await check("T-UI-MEMORY-PANEL small-window clamping does not replace the preferred width", async () =>
{
    const app = await memoryApp();
    const splitter = app.nodes.get("memory-splitter");
    app.nodes.get("workspace-split").clientWidth = 1600;
    splitter.fire("keydown", { key: "End" });
    app.nodes.get("workspace-split").clientWidth = 600;
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("btn-memory-panel").fire("click");
    assert.equal(app.nodes.get("root").classList.contains("memory-overlay"), true);
    assert.equal(splitter.getAttribute("aria-valuenow"), "576");
    app.nodes.get("workspace-split").clientWidth = 1600;
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("btn-memory-panel").fire("click");
    assert.equal(app.nodes.get("root").classList.contains("memory-overlay"), false);
    assert.equal(splitter.getAttribute("aria-valuenow"), "1000");
});

await check("T-UI-MEMORY-PANEL stored layout validates types and survives blocked storage", async () =>
{
    const hidden = JSON.stringify({ visible: false, width: 480 });
    for (const [value, visible, width, tab = "memory"] of [
        [null, true, "520"],
        [JSON.stringify({ visible: true, width: 480 }), true, "480"],
        [hidden, false, "480"],
        [hidden.padEnd(128), false, "480"],
        [hidden.padEnd(129), true, "520"],
        [JSON.stringify({ width: 480 }), true, "480"],
        [JSON.stringify({ visible: null, tab: "disassembly", width: 480 }), true, "480", "disassembly"],
        [JSON.stringify({ visible: false, tab: "disassembly", width: 480 }), false, "480", "disassembly"],
        [JSON.stringify({ visible: "true", width: -1 }), true, "520"],
        [JSON.stringify({ visible: "false" }), true, "520"],
        ["null", true, "520"], ["false", true, "520"], ["0", true, "520"], ["[]", true, "520"],
        ["invalid", true, "520"], [" ".repeat(129), true, "520"]
    ])
    {
        const app = harness({ storage: { getItem: key => key === "kndbgx.memory-panel" ? value : null, setItem: noop } });
        await app.boot();
        assert.equal(app.nodes.get("btn-memory-panel").getAttribute("aria-expanded"), String(visible));
        assert.equal(app.nodes.get("memory-splitter").getAttribute("aria-valuenow"), width);
        assert.equal(app.nodes.get("tab-" + tab + (tab === "memory" ? "-view" : "")).getAttribute("aria-selected"), "true");
        assert.equal(app.messages.some(request => ["execute", "memoryRead", "disassemblyRead"].includes(request.method)), false);
    }
    const app = await memoryApp({ storage: { getItem: () =>
    {
        throw new Error("Denied");
    }, setItem: () =>
    {
        throw new Error("Denied");
    } } });
    assert.equal(app.nodes.get("btn-memory-panel").getAttribute("aria-expanded"), "true");
    app.nodes.get("memory-splitter").fire("keydown", { key: "Home" });
    app.nodes.get("btn-memory-close").fire("click");
    assert.equal(app.nodes.get("btn-memory-panel").getAttribute("aria-expanded"), "false");
});

await check("T-UI-MEMORY-PANEL clipboard fallback returns to the correct visible panel", async () =>
{
    const app = await memoryApp({ clipboard: { writeText: () => Promise.reject(new Error("Denied")) } });
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(65));
    app.nodes.get("memory-rows").children[0].children[0].fire("click");
    await settle();
    app.nodes.get("btn-copy-close").fire("click");
    assert.equal(app.focused(), app.nodes.get("memory-grid"));
    app.nodes.get("memory-rows").children[0].children[0].fire("click");
    await settle();
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("btn-copy-close").fire("click");
    assert.equal(app.focused(), app.nodes.get("btn-memory-panel"));
});

await check("T-UI-MEMORY-PANEL manual copy from Results returns to the still-visible Results after a panel tab switch", async () =>
{
    const app = await memoryApp({ clipboard: { writeText: () => Promise.reject(new Error("Denied")) } });
    app.nodes.get("result-rows").children[0].children[1].fire("click");
    await settle();
    assert.equal(app.focused(), app.nodes.get("copy-text"));
    showProcesses(app);
    app.nodes.get("btn-copy-close").focus();
    app.nodes.get("btn-copy-close").fire("click");
    assert.equal(app.focused(), app.nodes.get("result-table"));
    assert.equal(app.nodes.get("copy-fallback").classList.contains("hidden"), true);
});

await check("T-UI-MEMORY-PANEL hiding, resizing and cancelling refill a taller process viewport", async () =>
{
    for (const action of ["hide", "resize", "cancel"])
    {
        const app = harness();
        await app.boot();
        showProcesses(app);
        await processStatus(app);
        app.nodes.get("process-view").clientHeight = 200;
        await collectProcessPages(app);
        assert.equal(app.nodes.get("process-rows").children.length, 24);
        const splitter = app.nodes.get("memory-splitter");
        if (action === "cancel")
        {
            splitter.fire("pointerdown", { button: 0, pointerId: 1, clientX: 600 });
            app.documentListeners.get("pointermove")({ pointerId: 1, clientX: 500, preventDefault: noop });
        }
        app.nodes.get("process-view").clientHeight = 1000;
        const before = app.messages.filter(request => request.method === "execute" || request.method === "memoryRead").length;
        if (action === "hide")
        {
            app.nodes.get("btn-memory-close").fire("click");
            app.nodes.get("btn-memory-panel").fire("click");
        }
        else if (action === "resize")
        {
            splitter.fire("keydown", { key: "Home" });
        }
        else
        {
            app.documentListeners.get("keydown")({ key: "Escape", preventDefault: noop });
        }
        assert.ok(app.nodes.get("process-rows").children.length >= 36);
        assert.ok(app.nodes.get("process-rows").children.length <= 128);
        assert.equal(app.messages.filter(request => request.method === "execute" || request.method === "memoryRead").length, before);
    }
});

await check("T-UI-MEMORY independent paged bytes preserve unknowns, little-endian values and exact addresses", async () =>
{
    const copied = [];
    const app = await memoryApp({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return Promise.resolve();
    } } });
    assert.equal(app.messages.some(item => item.method === "memoryRead"), false, "Opening Memory read the target automatically");
    app.nodes.get("memory-address").value = "nt!Example + 10";
    app.nodes.get("memory-address").fire("keydown", { key: "Enter" });
    assert.equal(app.latest("memoryRead").params.expression, "nt!Example + 10");
    assert.equal(app.latest("memoryRead").params.length, "64");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("memoryRead").params.expectedStamp)), stamp);
    const bytes = Array.from({ length: 64 }, (_, index) => index);
    bytes[5] = null;
    await memoryReply(app, bytes);
    assert.match(app.nodes.get("memory-summary").textContent, /63 of 64 bytes readable/);
    assert.equal(app.nodes.get("result-title").textContent, "retained-result");
    assert.equal(app.nodes.get("memory-rows").children.length, 4);
    const first = app.nodes.get("memory-rows").children[0];
    assert.equal(first.children[1].textContent, "00");
    assert.equal(first.children[6].textContent, "??");
    assert.equal(first.children[6].children.length, 0, "Unknown bytes exposed a numeric copy action");
    first.children[0].fire("click");
    await settle();
    assert.equal(copied.at(-1), "0xffff800000001000");
    app.nodes.get("memory-format").value = "8";
    app.nodes.get("memory-format").fire("change");
    const qwords = app.nodes.get("memory-rows").children[0];
    assert.equal(qwords.children[1].textContent, "??".repeat(8));
    assert.equal(qwords.children[2].textContent, "0f0e0d0c0b0a0908");
    qwords.children[2].fire("click");
    await settle();
    assert.equal(copied.at(-1), "0x0f0e0d0c0b0a0908");
    const reads = app.messages.filter(item => item.method === "memoryRead").length;
    app.nodes.get("btn-memory-close").fire("click");
    app.nodes.get("btn-memory-panel").fire("click");
    await processStatus(app);
    assert.equal(app.messages.filter(item => item.method === "memoryRead").length, reads);
    assert.equal(app.nodes.get("memory-rows").children[0].children[2].textContent, "0f0e0d0c0b0a0908");
});

await check("T-UI-MEMORY invalid pages, cancellation and failed expressions preserve the previous view", async () =>
{
    const app = await memoryApp();
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(65));
    for (const corrupt of ["sequence", "space", "value", "cancel"])
    {
        app.nodes.get("btn-memory-read").fire("click");
        assertCommandActivity(app, true, "Reading memory");
        await app.reply("memoryRead", { ok: true, result: { resultId: "broken", rowCount: "4",
            data: { commandId: "db", status: "Success", target: stamp } } });
        const rows = memoryRows(Array(64).fill(66));
        if (corrupt === "sequence")
        {
            rows[1].address = rows[0].address;
        }
        else if (corrupt === "space")
        {
            rows[0].addressSpace = "physical";
        }
        else if (corrupt === "value")
        {
            rows[0].bytes[0] = 256;
        }
        else
        {
            app.nodes.get("btn-cancel").fire("click");
        }
        await app.reply("resultPage", { ok: true, result: { resultId: "broken", collection: "rows", offset: "0",
            rows, next: "4", total: "4", complete: true } });
        await processStatus(app);
        assert.equal(app.nodes.get("memory-rows").children[0].children[1].textContent, "41");
        assert.match(app.nodes.get("memory-notice").textContent, /Invalid|cancelled/);
        assert.equal(app.nodes.get("btn-memory-next").disabled, true);
        assert.equal(app.nodes.get("btn-cancel").disabled, true);
        assert.equal(app.nodes.get("memory-address-history").children.length, 2);
        assert.equal(app.nodes.get("memory-address-history").children[1].textContent, "[Virtual] @rip");
    }
    app.nodes.get("btn-memory-read").fire("click");
    await app.reply("memoryRead", { ok: true, result: { resultId: "invalid-expression", rowCount: "0", error: "InvalidInput",
        data: { commandId: "db", status: "InvalidInput", target: stamp } } });
    await processStatus(app);
    assert.equal(app.nodes.get("memory-rows").children[0].children[1].textContent, "41");
    assert.match(app.nodes.get("memory-notice").textContent, /InvalidInput/);
});

await check("T-UI-MEMORY range navigation stays within 64-bit bounds and uses the displayed address space", async () =>
{
    const app = await memoryApp();
    app.nodes.get("memory-space").value = "physical";
    app.nodes.get("memory-address").value = "0xffffffffffffffc0";
    app.nodes.get("btn-memory-read").fire("click");
    assert.equal(app.latest("memoryRead").params.expression, "0xffffffffffffffc0");
    assert.equal(app.latest("memoryRead").params.space, "physical");
    await memoryReply(app, Array(64).fill(0), { address: "0xffffffffffffffc0", space: "physical" });
    assert.equal(app.nodes.get("btn-memory-next").disabled, true);
    assert.equal(app.nodes.get("btn-memory-prev").disabled, false);
    app.nodes.get("btn-memory-prev").fire("click");
    assert.equal(app.latest("memoryRead").params.expression, "0xffffffffffffff80");
    assert.equal(app.latest("memoryRead").params.space, "physical");
    await memoryReply(app, Array(64).fill(0), { address: "0xffffffffffffff80", space: "physical" });
    app.nodes.get("memory-address").value = "0";
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(null), { address: "0", space: "physical" });
    assert.equal(app.nodes.get("btn-memory-prev").disabled, true);
    assert.equal(app.nodes.get("btn-memory-next").disabled, false);
    assert.match(app.nodes.get("memory-summary").textContent, /0 of 64 bytes readable/);
    app.nodes.get("memory-space").value = "virtual";
    app.nodes.get("memory-space").fire("change");
    assert.equal(app.nodes.get("btn-memory-next").disabled, true, "Draft space change reused an old physical snapshot");
});

await check("T-UI-MEMORY malformed input and IME never execute; changed context stays explicit without auto-reading", async () =>
{
    const app = await memoryApp();
    for (const text of ["", "nt;g", '"@rip"', "nt\nL20", "nt\u0000hidden"])
    {
        app.nodes.get("memory-address").value = text;
        app.nodes.get("btn-memory-read").fire("click");
    }
    app.nodes.get("memory-address").value = "@rip";
    app.nodes.get("memory-address").fire("keydown", { key: "Enter", isComposing: true });
    assert.equal(app.messages.some(item => item.method === "memoryRead"), false);
    const before = { ...stamp, contextIdentity: { implicitProcess: "0xffff800000000001" } };
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, before);
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(0), { target: before });
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, { ...before, contextGeneration: "4", contextIdentity: { implicitProcess: "0xffff800000000002" } });
    assert.match(app.nodes.get("memory-summary").textContent, /previous snapshot/);
    assert.match(app.nodes.get("memory-context").textContent, /0xffff800000000001/);
    assert.equal(app.nodes.get("btn-memory-next").disabled, true);
    assert.equal(app.messages.filter(item => item.method === "memoryRead").length, 1);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, before, { stopped: false });
    assert.equal(app.nodes.get("btn-memory-read").disabled, true);
    assert.equal(app.nodes.get("memory-rows").children.length, 4);
});

await check("T-UI-CURRENT-PROCESS status polling updates every tab without using selected result rows", async () =>
{
    const copied = [];
    const app = harness({ clipboard: { writeText: text =>
    {
        copied.push(text);
        return Promise.resolve();
    } } });
    await app.boot();
    app.nodes.get("btn-memory-close").fire("click");
    const first = { ...stamp, contextIdentity: { implicitProcess: "0xffff800000001000" } };
    const second = { ...stamp, contextGeneration: "4", contextIdentity: { implicitProcess: "0xffff800000002000" } };
    for (const [target, image, pid] of [[first, "System", "4"], [second, "<literal>&.exe", "0"]])
    {
        const polling = [...app.timers].find(([id]) => app.timerDelays.get(id) === 3000);
        assert.ok(polling, "Results tab has no periodic status refresh");
        polling[1]();
        await processStatus(app, target, { currentProcess: { image, pid, eprocess: target.contextIdentity.implicitProcess } });
        assert.equal(app.nodes.get("current-process-image").textContent, image);
        assert.equal(app.nodes.get("current-process-pid").textContent, pid);
        assert.equal(app.nodes.get("current-process-eprocess").textContent, target.contextIdentity.implicitProcess);
        app.nodes.get("copy-current-eprocess").fire("click");
        await settle();
        assert.equal(copied.at(-1), target.contextIdentity.implicitProcess);
        await openTable(app, "historical-process", [{ image: "old.exe", pid: "99", eprocess: "0x1000" }]);
        assert.equal(app.nodes.get("current-process-image").textContent, image);
    }
    app.nodes.get("btn-memory-panel").fire("click");
    await processStatus(app, second, { currentProcess: { image: "current.exe", pid: "12", eprocess: second.contextIdentity.implicitProcess } });
    assert.equal(app.nodes.get("current-process-image").textContent, "current.exe");
    assert.equal(app.nodes.get("current-process-bar").classList.contains("hidden"), false);
});

await check("T-UI-CURRENT-PROCESS unavailable fields, running targets and mismatched contexts never reuse old identities", async () =>
{
    const app = harness();
    await app.boot();
    const target = { ...stamp, contextIdentity: { implicitProcess: "0xffff800000001000" } };
    const currentProcess = { image: "System", pid: "4", eprocess: target.contextIdentity.implicitProcess };
    for (const overrides of [{ currentProcess }, { currentProcess: { ...currentProcess, image: null, pid: null } },
        { currentProcess: { ...currentProcess, eprocess: "0xffff800000002000" } },
        { stopped: false, currentProcess }, { connected: false, currentProcess }])
    {
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, target, overrides);
        const complete = overrides.currentProcess === currentProcess && !Object.hasOwn(overrides, "stopped") && !Object.hasOwn(overrides, "connected");
        assert.equal(app.nodes.get("current-process-image").textContent, complete ? "System" : "Unavailable");
        assert.equal(app.nodes.get("copy-current-pid").disabled, !complete);
    }
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, target, { currentProcess });
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "EngineBusy" });
    assert.equal(app.nodes.get("current-process-eprocess").textContent, currentProcess.eprocess);
    assert.equal(app.nodes.get("copy-current-eprocess").disabled, false);
    assert.match(app.nodes.get("current-process-notice").textContent, /Debugger busy; showing last checked process/);
    assert.match(app.nodes.get("status").textContent, /debugger busy/);
    assert.equal(app.nodes.get("btn-stack").disabled, true);
    assert.equal(app.nodes.get("btn-memory-read").disabled, true);
    assert.equal(app.nodes.get("btn-process-refresh").disabled, true);
    assert.ok(!app.nodes.get("memory-notice").textContent.includes("disconnected"));
    assert.ok(!app.nodes.get("process-notice").textContent.includes("disconnected"));
    app.enter("stack");
    assert.equal(app.messages.some(message => message.method === "execute"), false);
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, target, { currentProcess });
    assert.equal(app.nodes.get("btn-stack").disabled, false);
    assert.equal(app.nodes.get("btn-memory-read").disabled, false);
    assert.equal(app.nodes.get("current-process-notice").textContent, "");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, target, { connected: false, currentProcess });
    assert.equal(app.nodes.get("current-process-eprocess").textContent, "Unavailable");
    assert.equal(app.nodes.get("current-process-notice").textContent, "No target");
});

function libraryHeaders(app)
{
    return app.nodes.get("catalog").querySelectorAll(".catalog-group-toggle");
}

function libraryGroup(app, name)
{
    const header = libraryHeaders(app).find(item => item.dataset.group === name);
    const children = app.nodes.get("catalog").children;
    return { header, list: children[children.indexOf(header) + 1] };
}

await check("T-UI-LIBRARY group folding and both sort orders survive a new document without execution", async () =>
{
    const saved = new Map();
    const storage = { getItem: key => saved.get(key) || null, setItem: (key, value) => saved.set(key, value) };
    const groups = {
        Session: [{ name: "version", synopsis: "Version", support: "Stable" }],
        Code: [{ name: "uf", synopsis: "Function", support: "Stable" }],
        Debugger: [
            { name: "zeta", synopsis: "Last", support: "Experimental" },
            { name: "!beta", synopsis: "Second", support: "Stable" },
            { name: "Alpha", synopsis: "First", support: "Stable" },
            { name: ".alpha", synopsis: "Also first", support: "Experimental" }
        ]
    };
    const app = harness({ storage });
    await app.boot(groups);
    const names = list => list.querySelectorAll(".cmd-item").map(item => item.children.find(child => child.className === "name").textContent);
    assert.deepEqual(libraryHeaders(app).map(item => item.dataset.group), ["Debugger", "Code", "Session"]);
    assert.deepEqual(names(libraryGroup(app, "Debugger").list), ["!beta", "Alpha", "zeta", ".alpha"]);
    const { header, list } = libraryGroup(app, "Debugger");
    header.focus();
    header.fire("click");
    assert.equal(header.getAttribute("aria-expanded"), "false");
    assert.equal(header.getAttribute("aria-controls"), list.id);
    assert.equal(list.classList.contains("hidden"), true);
    assert.equal(app.focused(), header, "Folding replaced the focused group header");
    libraryGroup(app, "Code").header.fire("click");
    assert.equal(app.nodes.get("catalog-count").textContent, "6 / 6");
    const prompt = app.nodes.get("prompt");
    prompt.value = "unfinished draft";
    const order = app.nodes.get("library-sort");
    order.value = "alphabetical";
    order.fire("change");
    assert.deepEqual(libraryHeaders(app).map(item => item.dataset.group), ["Code", "Debugger", "Session"]);
    assert.deepEqual(names(libraryGroup(app, "Debugger").list), [".alpha", "Alpha", "!beta", "zeta"]);
    assert.equal(libraryGroup(app, "Debugger").header.getAttribute("aria-expanded"), "false");
    assert.equal(prompt.value, "unfinished draft");
    const reopened = harness({ storage });
    await reopened.boot(groups);
    assert.equal(reopened.nodes.get("library-sort").value, "alphabetical");
    assert.deepEqual(libraryHeaders(reopened).map(item => item.dataset.group), ["Code", "Debugger", "Session"]);
    for (const name of ["Code", "Debugger"])
    {
        assert.equal(libraryGroup(reopened, name).list.classList.contains("hidden"), true);
    }
    assert.equal(libraryGroup(reopened, "Session").list.classList.contains("hidden"), false);
    reopened.nodes.get("library-sort").value = "default";
    reopened.nodes.get("library-sort").fire("change");
    assert.deepEqual(libraryHeaders(reopened).map(item => item.dataset.group), ["Debugger", "Code", "Session"]);
    assert.deepEqual(names(libraryGroup(reopened, "Debugger").list), ["!beta", "Alpha", "zeta", ".alpha"]);
    assert.equal(JSON.parse(saved.get("kndbgx.command-library")).sort, "default");
    for (const workspace of [app, reopened])
    {
        assert.equal(workspace.messages.some(item => ["classify", "execute", "debuggerAction"].includes(item.method)), false);
    }
});

await check("T-UI-LIBRARY search unfolds matches temporarily and selected-command reveal saves the expansion", async () =>
{
    let saved = JSON.stringify({ version: 1, sort: "default", collapsed: ["Kernel"] });
    const app = harness({ storage: { getItem: key => key === "kndbgx.command-library" ? saved : null,
        setItem: (key, value) =>
        {
            if (key === "kndbgx.command-library")
            {
                saved = value;
            }
        } } });
    await app.boot({ Kernel: [{ name: "!callbacks", synopsis: "Callbacks", support: "Experimental" }],
        Debugger: [{ name: "stack", synopsis: "Frames", support: "Stable" }] });
    assert.equal(libraryGroup(app, "Kernel").list.classList.contains("hidden"), true);
    const filter = app.nodes.get("filter");
    filter.value = "callbacks";
    filter.fire("input");
    assert.equal(libraryGroup(app, "Kernel").header.getAttribute("aria-expanded"), "true");
    assert.equal(app.nodes.get("catalog-count").textContent, "1 / 2");
    libraryGroup(app, "Kernel").header.fire("click");
    assert.equal(libraryGroup(app, "Kernel").list.classList.contains("hidden"), true);
    assert.deepEqual(JSON.parse(saved).collapsed, ["Kernel"], "Search changed the saved group state");
    filter.value = "call";
    filter.fire("input");
    assert.equal(libraryGroup(app, "Kernel").list.classList.contains("hidden"), false);
    filter.value = "";
    filter.fire("input");
    assert.equal(libraryGroup(app, "Kernel").list.classList.contains("hidden"), true);
    const prompt = app.nodes.get("prompt");
    prompt.value = "!callbacks";
    prompt.fire("input");
    app.nodes.get("selected-command").fire("click");
    assert.equal(libraryGroup(app, "Kernel").list.classList.contains("hidden"), false);
    assert.deepEqual(JSON.parse(saved).collapsed, []);
    assert.equal(app.focused().dataset.command, "callbacks");
    assert.equal(prompt.value, "!callbacks");
    libraryHeaders(app).forEach(header => header.fire("click"));
    assert.equal(app.nodes.get("catalog-count").textContent, "2 / 2");
    assert.equal(app.nodes.get("catalog").children.length, 4, "Collapsed groups were replaced by an empty-state message");
    filter.value = "no-such-command";
    filter.fire("input");
    assert.equal(libraryHeaders(app).length, 0);
    assert.equal(app.nodes.get("catalog").children[0].textContent, "No matching commands");
    assert.equal(app.messages.some(item => ["classify", "execute", "debuggerAction"].includes(item.method)), false);
});

await check("T-UI-LIBRARY malformed or blocked storage keeps local folding and sorting usable", async () =>
{
    const groups = { Kernel: [{ name: "!callbacks", synopsis: "Callbacks", support: "Stable" }] };
    for (const value of [null, "null", "[]", "false", "1", "invalid", " ".repeat(16385),
        JSON.stringify({ version: 2, sort: "alphabetical", collapsed: ["Kernel"] }),
        JSON.stringify({ version: 1, sort: true, collapsed: "Kernel" }),
        JSON.stringify({ version: 1, sort: "default", collapsed: Array(129).fill("Kernel") })])
    {
        const app = harness({ storage: { getItem: key => key === "kndbgx.command-library" ? value : null, setItem: noop } });
        await app.boot(groups);
        assert.equal(app.nodes.get("library-sort").value, "default");
        assert.equal(libraryGroup(app, "Kernel").header.getAttribute("aria-expanded"), "true");
    }
    const app = harness({ storage: { getItem: () =>
    {
        throw new Error("Denied");
    }, setItem: () =>
    {
        throw new Error("Denied");
    } } });
    await app.boot(groups);
    libraryGroup(app, "Kernel").header.fire("click");
    app.nodes.get("library-sort").value = "alphabetical";
    app.nodes.get("library-sort").fire("change");
    assert.equal(libraryGroup(app, "Kernel").header.getAttribute("aria-expanded"), "false");
    libraryGroup(app, "Kernel").header.fire("click");
    assert.equal(libraryGroup(app, "Kernel").list.classList.contains("hidden"), false);
    assert.equal(app.nodes.get("library-sort").value, "alphabetical");
    assert.equal(app.nodes.get("library-sort").disabled, false);
    app.nodes.get("btn-library-pin").fire("click");
    assert.equal(app.nodes.get("btn-library-pin").getAttribute("aria-pressed"), "true");
    app.nodes.get("btn-library-pin").fire("click");
    assert.equal(app.nodes.get("btn-library-pin").getAttribute("aria-pressed"), "false");
    assert.equal(app.messages.some(item => ["classify", "execute", "debuggerAction"].includes(item.method)), false);
});

await check("T-UI-LIBRARY saving boundary-size preferences drops obsolete groups without losing current state", async () =>
{
    const names = Array.from({ length: 127 }, (_, index) => String(index).padStart(3, "0") + "x".repeat(122));
    names.push("Kernel");
    const settings = { version: 1, sort: "default", collapsed: names };
    let remaining = 16384 - JSON.stringify(settings).length;
    for (let index = 0; index < 127 && remaining > 0; ++index)
    {
        const extra = Math.min(128 - names[index].length, remaining);
        names[index] += "x".repeat(extra);
        remaining -= extra;
    }
    let saved = JSON.stringify(settings);
    assert.equal(saved.length, 16384);
    assert.ok(names.every(name => name.length <= 128));
    const storage = { getItem: key => key === "kndbgx.command-library" ? saved : null, setItem: (key, value) =>
    {
        if (key === "kndbgx.command-library")
        {
            saved = value;
        }
    } };
    const groups = { Kernel: [{ name: "!callbacks", synopsis: "Callbacks", support: "Stable" }] };
    const app = harness({ storage });
    await app.boot(groups);
    assert.equal(libraryGroup(app, "Kernel").list.classList.contains("hidden"), true);
    app.nodes.get("library-sort").value = "alphabetical";
    app.nodes.get("library-sort").fire("change");
    assert.ok(saved.length <= 16384, "Saving produced a preference that the next document rejects");
    assert.deepEqual(JSON.parse(saved).collapsed, ["Kernel"]);
    const reopened = harness({ storage });
    await reopened.boot(groups);
    assert.equal(reopened.nodes.get("library-sort").value, "alphabetical");
    assert.equal(libraryGroup(reopened, "Kernel").list.classList.contains("hidden"), true);
    assert.equal(reopened.messages.some(item => ["classify", "execute", "debuggerAction"].includes(item.method)), false);
});

await check("T-UI-LIBRARY every registered command and alias remains searchable in either order with all groups folded", async () =>
{
    const contract = JSON.parse(fs.readFileSync(new URL("../docs/command-contract.json", import.meta.url), "utf8"));
    const groups = {};
    const expected = [];
    for (const command of contract)
    {
        for (const name of [command.name, ...command.aliases])
        {
            (groups[command.group] ||= []).push({ name, synopsis: command.summary, grammar: command.grammar, support: command.support });
            expected.push(name);
        }
    }
    const app = harness();
    await app.boot(groups);
    const items = () => app.nodes.get("catalog").querySelectorAll(".cmd-item");
    const nameOf = item => item.children.find(child => child.className === "name").textContent;
    for (const order of ["alphabetical", "default"])
    {
        app.nodes.get("library-sort").value = order;
        app.nodes.get("library-sort").fire("change");
        assert.deepEqual(items().map(nameOf).sort(), [...expected].sort());
        libraryHeaders(app).filter(header => header.getAttribute("aria-expanded") === "true").forEach(header => header.fire("click"));
        assert.equal(app.nodes.get("catalog-count").textContent, expected.length + " / " + expected.length);
        for (const name of expected)
        {
            app.nodes.get("filter").value = name;
            app.nodes.get("filter").fire("input");
            const item = items().find(item => nameOf(item) === name);
            assert.ok(item, "Missing library command: " + name);
            item.fire("click");
            assert.equal(app.nodes.get("prompt").value, name);
        }
        app.nodes.get("filter").value = "";
        app.nodes.get("filter").fire("input");
        assert.equal(libraryHeaders(app).every(header => header.getAttribute("aria-expanded") === "false"), true);
    }
    assert.equal(app.messages.some(item => ["classify", "execute", "debuggerAction"].includes(item.method)), false);
});

function setPrompt(app, value, cursor = value.length)
{
    const prompt = app.nodes.get("prompt");
    prompt.value = value;
    prompt.setSelectionRange(cursor, cursor);
    prompt.fire("input");
}

await check("T-UI-COMPLETION required parameters appear as ghost text and Tab fills a draft with editable fields", async () =>
{
    const app = harness();
    await app.boot({ Dumps: [{ name: "dump-pe", synopsis: "Save a module", grammar: "dump-pe <module|address> <path>", support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    setPrompt(app, "dump-pe nt old-file");
    const pending = app.latest("complete");
    setPrompt(app, "dump-pe");
    assert.equal(prompt.value, "dump-pe", "Displaying a recommendation edited the input");
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("prompt-ghost-prefix").textContent, "dump-pe");
    assert.equal(app.nodes.get("prompt-ghost-suffix").textContent, " <module|address> <path>");
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.value, "dump-pe <module|address> <path>");
    assert.equal(prompt.value.slice(prompt.selectionStart, prompt.selectionEnd), "<module|address>");
    assert.equal(app.nodes.get("btn-run").disabled, true);
    prompt.fire("keydown", { key: "Enter" });
    assert.equal(app.messages.some(item => item.method === "classify"), false);
    const replaceField = text =>
    {
        const start = prompt.selectionStart;
        const value = prompt.value.slice(0, start) + text + prompt.value.slice(prompt.selectionEnd);
        setPrompt(app, value, start + text.length);
    };
    replaceField("nt");
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.value.slice(prompt.selectionStart, prompt.selectionEnd), "<path>");
    await app.deliver(pending, { ok: true, result: { items: ["dump-pe nt old-file /unexpected"] } });
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
    replaceField('"C:\\saved module.bin"');
    assert.equal(prompt.value, 'dump-pe nt "C:\\saved module.bin"');
    assert.equal(app.nodes.get("btn-run").disabled, false);
    let trapped = false;
    prompt.fire("keydown", { key: "Tab", preventDefault()
    {
        trapped = true;
    } });
    assert.equal(trapped, false, "Finishing a parameter template trapped keyboard focus");
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
    prompt.fire("keydown", { key: "Enter" });
    assert.equal(app.latest("classify").params.command, 'dump-pe nt "C:\\saved module.bin"');
});

await check("T-UI-COMPLETION parameter templates preserve aliases typed values and literal alternatives", async () =>
{
    const contract = JSON.parse(fs.readFileSync(new URL("../docs/command-contract.json", import.meta.url), "utf8"));
    const commands = contract.flatMap(command => [command.name, ...command.aliases].map(name => ({
        name, synopsis: command.summary, grammar: command.grammar, support: command.support
    })));
    const app = harness();
    await app.boot({ Commands: commands });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    for (const [value, expected] of [
        ["irp", "irp <hex-address>"], ["  IRP ", "  IRP <hex-address>"],
        ["e", "e <address> <value...>"], ["navigate p", "navigate pa <address>"],
        ["bugcheck-decode 1f2 1", "bugcheck-decode 1f2 1 <p2> <p3> <p4>"],
        ["f", "f <address> L<bytes> <byte...|quoted-ascii>"], ["raw --a", "raw --ack-effects <command>"],
        ["!diff C:\\before ", "!diff C:\\before <after-directory>"], ["triage ha", "triage hang"]
    ])
    {
        setPrompt(app, value);
        assert.equal(app.nodes.get("prompt-ghost-suffix").textContent, expected.slice(value.length), value);
        assert.equal(prompt.value, value);
    }
    for (const value of ["ln", "uf", "!callbacks", "irp nt!Routine", 'dump-pe "a b" ', "irp; g", ".echo ",
        "navigate other ", "navigate P", "triage HA", "raw --A"])
    {
        setPrompt(app, value);
        assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true, value);
    }
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
});

await check("T-UI-COMPLETION option prefixes never consume required positional fields", async () =>
{
    const app = harness();
    await app.boot({ Commands: [
        { name: "dump-raw", grammar: "dump-raw <address> <length> <path> [/phys]", synopsis: "Save memory", support: "Stable" },
        { name: "!diff", grammar: "!diff <before-directory> <after-directory> [/cross-session]", synopsis: "Compare", support: "Stable" }
    ] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    for (const [prefix, completed] of [["dump-raw /p", "dump-raw /phys"], ["!diff /cross-s", "!diff /cross-session"]])
    {
        setPrompt(app, prefix);
        assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true,
            "An option was counted as a positional parameter: " + prefix);
        assert.equal(app.latest("complete").params.prefix, prefix);
        await app.reply("complete", { ok: true, result: { items: [completed] } });
        prompt.fire("keydown", { key: "Tab" });
        assert.equal(prompt.value, completed);
        setPrompt(app, completed + " ");
        assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
        await app.reply("complete", { ok: true, result: { items: [] } });
    }
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
});

await check("T-UI-COMPLETION accepting an option retains unresolved template fields", async () =>
{
    const app = harness();
    await app.boot({ Dumps: [
        { name: "dump-raw", grammar: "dump-raw <address> <length> <path> [/phys]", synopsis: "Save memory", support: "Stable" }
    ] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    setPrompt(app, "dump-raw");
    prompt.fire("keydown", { key: "Tab" });
    const draft = prompt.value;
    setPrompt(app, draft + " /p");
    await app.reply("complete", { ok: true, result: { items: [draft + " /phys"] } });
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.value, draft + " /phys");
    assert.equal(app.nodes.get("btn-run").disabled, true, "Option completion lost the unresolved draft binding");
    prompt.fire("keydown", { key: "Enter" });
    assert.equal(prompt.value.slice(prompt.selectionStart, prompt.selectionEnd), "<address>");
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
});

await check("T-UI-COMPLETION inline ghost follows suggestion selection scrolling focus and execution availability", async () =>
{
    const app = harness();
    await app.boot({ Session: [{ name: "help", synopsis: "Help", grammar: "help [command|ui]", support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    setPrompt(app, "help u");
    await app.reply("complete", { ok: true, result: { items: ["help ui", "help uf"] } });
    assert.equal(app.nodes.get("prompt-ghost-suffix").textContent, "i");
    prompt.fire("keydown", { key: "ArrowDown" });
    assert.equal(app.nodes.get("prompt-ghost-suffix").textContent, "f");
    prompt.scrollLeft = 28;
    prompt.fire("scroll");
    assert.equal(app.nodes.get("prompt-ghost-text").style.transform, "translateX(-28px)");
    prompt.fire("keydown", { key: "ArrowLeft" });
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
    prompt.setSelectionRange(2, 2);
    prompt.fire("keyup", { key: "ArrowLeft" });
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
    setPrompt(app, "help u");
    const old = app.latest("complete");
    prompt.fire("blur");
    await app.deliver(old, { ok: true, result: { items: ["help ui"] } });
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
    setPrompt(app, "help u");
    await app.reply("complete", { ok: true, result: { items: ["help ui"] } });
    prompt.fire("compositionstart");
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
    prompt.fire("compositionend");
    await app.reply("complete", { ok: true, result: { items: ["help ui"] } });
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: true, result: { connected: true, stopped: false, target: stamp } });
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
    assert.equal(prompt.disabled, true);
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
});

await check("T-UI-COMPLETION template fields allow focus escape while incomplete and never turn a caret move into a fill", async () =>
{
    const app = harness();
    await app.boot({ Kernel: [{ name: "irp", synopsis: "IRP", grammar: "irp <hex-address>", support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    setPrompt(app, "irp");
    prompt.fire("keydown", { key: "Tab" });
    let trapped = false;
    for (const event of [{ key: "Tab" }, { key: "Tab", shiftKey: true }, { key: "Tab", ctrlKey: true }])
    {
        prompt.fire("keydown", { ...event, preventDefault()
        {
            trapped = true;
        } });
    }
    assert.equal(trapped, false);
    assert.equal(app.nodes.get("btn-run").disabled, true);
    prompt.fire("keydown", { key: "Escape" });
    assert.equal(app.nodes.get("btn-run").disabled, true);
    prompt.fire("keydown", { key: "Enter" });
    assert.equal(app.messages.some(item => item.method === "classify"), false);
    setPrompt(app, "irp", 1);
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.value, "irp");
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
    setPrompt(app, "irp");
    prompt.fire("keydown", { key: "Escape" });
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
});

const symbolItems = [
    { symbol: "nt!KeBugCheckEx", address: "0xfffff80312345678", kind: "symbol" },
    { symbol: "nt!KeBugCheck2", address: "0xfffff80322345678", kind: "symbol" }
];

await check("T-UI-SYMBOLS live recommendations show addresses and Tab never executes", async () =>
{
    const app = harness();
    await app.boot({ Code: [{ name: "u", grammar: "u [address] [L<count>]", symbolParameters: [0], support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    setPrompt(app, "u nt!KeBug");
    app.advanceTime(179);
    assert.equal(app.messages.some(item => item.method === "completeSymbols"), false);
    app.advanceTime(1);
    assert.equal(app.latest("completeSymbols").params.prefix, "u nt!KeBug");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("completeSymbols").params.expectedStamp)), stamp);
    await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
    assert.equal(app.nodes.get("prompt-ghost-suffix").textContent, "CheckEx");
    assert.equal(app.nodes.get("suggest").children[0].children[0].textContent, symbolItems[0].address);
    assertCommandActivity(app, false);
    prompt.fire("keydown", { key: "ArrowDown" });
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.value, "u nt!KeBugCheck2");
    let trapped = false;
    prompt.fire("keydown", { key: "Tab", preventDefault()
    {
        trapped = true;
    } });
    assert.equal(trapped, false, "Accepted symbols trapped forward focus navigation");
    assert.equal(app.messages.some(item => ["classify", "execute", "debuggerAction"].includes(item.method)), false);
});

await check("T-UI-SYMBOLS completing a middle operand preserves the suffix and unresolved fields", async () =>
{
    const app = harness();
    await app.boot({ Dumps: [{ name: "dump-pe", grammar: "dump-pe <module|address> <path>", symbolParameters: [0], support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    setPrompt(app, "dump-pe");
    prompt.fire("keydown", { key: "Tab" });
    setPrompt(app, "dump-pe nt!KeBug <path>", "dump-pe nt!KeBug".length);
    prompt.fire("select");
    app.advanceTime(180);
    assert.equal(app.latest("completeSymbols").params.prefix, "dump-pe nt!KeBug");
    assert.equal(app.latest("completeSymbols").params.suffix, " <path>");
    await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
    assert.equal(app.nodes.get("prompt-ghost").classList.contains("hidden"), true);
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.value, "dump-pe nt!KeBugCheckEx <path>");
    assert.equal(prompt.value.slice(prompt.selectionStart, prompt.selectionEnd), "<path>");
    assert.equal(app.nodes.get("btn-run").disabled, true);
    prompt.fire("keydown", { key: "Enter" });
    assert.equal(app.messages.some(item => item.method === "classify"), false);
});

await check("T-UI-SYMBOLS coalesced requests use the newest prefix and pending Tab accepts once", async () =>
{
    const app = harness();
    await app.boot({ Code: [{ name: "u", grammar: "u [address]", symbolParameters: [0], support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    setPrompt(app, "u nt!Ke");
    app.advanceTime(180);
    const first = app.latest("completeSymbols");
    setPrompt(app, "u nt!KeB");
    app.advanceTime(180);
    setPrompt(app, "u nt!KeBug");
    app.advanceTime(180);
    assert.equal(app.messages.filter(item => item.method === "completeSymbols").length, 1);
    await app.deliver(first, { ok: true, result: { target: stamp, items: symbolItems } });
    assert.equal(app.nodes.get("suggest").classList.contains("hidden"), true);
    assert.equal(app.latest("completeSymbols").params.prefix, "u nt!KeBug");
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(app.messages.filter(item => item.method === "completeSymbols").length, 2);
    await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
    assert.equal(prompt.value, "u nt!KeBugCheckEx");
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
});

await check("T-UI-SYMBOLS stale context focus composition Escape and Busy reject late results", async () =>
{
    for (const boundary of ["context", "blur", "ime", "escape", "busy", "selection"])
    {
        const app = harness();
        await app.boot({ Code: [{ name: "u", grammar: "u [address]", symbolParameters: [0], support: "Stable" }] });
        const prompt = app.nodes.get("prompt");
        prompt.focus();
        setPrompt(app, "u nt!KeBug");
        prompt.fire("keydown", { key: "Tab" });
        const request = app.latest("completeSymbols");
        if (boundary === "context" || boundary === "busy")
        {
            app.nodes.get("btn-refresh-status").fire("click");
            await app.reply("status", { ok: true, result: { connected: true, stopped: boundary !== "busy",
                target: { ...stamp, contextGeneration: "99" } } });
        }
        else if (boundary === "blur")
        {
            prompt.fire("blur");
        }
        else if (boundary === "ime")
        {
            prompt.fire("compositionstart");
        }
        else if (boundary === "selection")
        {
            prompt.setSelectionRange(2, 3);
            prompt.fire("select");
        }
        else
        {
            prompt.fire("keydown", { key: "Escape" });
        }
        await app.deliver(request, { ok: true, result: { target: stamp, items: symbolItems } });
        assert.equal(prompt.value, "u nt!KeBug", boundary);
        assert.equal(app.nodes.get("suggest").classList.contains("hidden"), true, boundary);
    }
});

await check("T-UI-SYMBOLS malformed replies and non-address slots never invent operands", async () =>
{
    const app = harness();
    await app.boot({ Commands: [
        { name: "dt", grammar: "dt <type> [address]", symbolParameters: [1], support: "Stable" },
        { name: "dump-raw", grammar: "dump-raw <address> <length> <path> [/phys]", symbolParameters: [0],
            completionOptions: [{ name: "/phys", takesValue: false }], support: "Stable" },
        { name: "driver-audit", grammar: "driver-audit <path>", symbolParameters: [], support: "Stable" }
    ] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    for (const input of ["dt nt!_EP", "dump-raw /phys nt!Ke", "dump-raw 0xffff", "driver-audit C:\\bin\\driver", 'dt "type" nt!Ke'])
    {
        setPrompt(app, input);
        app.advanceTime(180);
    }
    assert.equal(app.messages.some(item => item.method === "completeSymbols"), false);
    const oversized = "dt nt!_EPROCESS nt!Ke " + "a".repeat(32768);
    setPrompt(app, oversized, "dt nt!_EPROCESS nt!Ke".length);
    app.advanceTime(180);
    assert.equal(app.messages.some(item => item.method === "completeSymbols"), false);
    for (const invalid of [null, { symbol: "nt!KeBug;g", address: "0x1", kind: "symbol" },
        { symbol: "nt!KeBugCheckEx", address: "9007199254740993", kind: "symbol" }])
    {
        setPrompt(app, "dt nt!_EPROCESS nt!KeBug");
        app.advanceTime(180);
        await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: [invalid] } });
        assert.equal(app.nodes.get("suggest").classList.contains("hidden"), true);
        assert.equal(prompt.value, "dt nt!_EPROCESS nt!KeBug");
    }
});

await check("T-UI-SYMBOLS a physical option after the caret excludes virtual symbols", async () =>
{
    const app = harness();
    await app.boot({ Dumps: [{ name: "dump-raw", grammar: "dump-raw <address> <length> <path> [/phys]",
        symbolParameters: [0], completionOptions: [{ name: "/phys", takesValue: false }], support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    for (const input of ["dump-raw nt!KeBug 100 out.bin /phys", 'dump-raw nt!KeBug 100 "C:\\out file.bin" /PHYS'])
    {
        setPrompt(app, input, "dump-raw nt!KeBug".length);
        prompt.fire("keydown", { key: "Tab" });
        app.advanceTime(180);
        assert.equal(prompt.value, input);
    }
    assert.equal(app.messages.some(item => item.method === "completeSymbols"), false);
    assert.equal(app.messages.some(item => item.method === "execute" || item.method === "classify"), false);
    const virtual = 'dump-raw nt!KeBug 100 "C:\\folder /phys data.bin"';
    setPrompt(app, virtual, "dump-raw nt!KeBug".length);
    app.advanceTime(180);
    assert.equal(app.latest("completeSymbols").params.suffix, ' 100 "C:\\folder /phys data.bin"');
    await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.value, 'dump-raw nt!KeBugCheckEx 100 "C:\\folder /phys data.bin"');
});

await check("T-UI-SYMBOLS optional lookup failures preserve required parameter completion", async () =>
{
    for (const failure of ["EngineBusy", "QueueFullOrClosing", "timeout"])
    {
        const app = harness();
        await app.boot({ Dumps: [{ name: "dump-pe", grammar: "dump-pe <module|address> <path>",
            symbolParameters: [0], support: "Stable" }] });
        const prompt = app.nodes.get("prompt");
        prompt.focus();
        setPrompt(app, "dump-pe nt!KeBug");
        prompt.fire("keydown", { key: "Tab" });
        if (failure === "timeout")
        {
            app.advanceTime(8000);
            await settle();
        }
        else
        {
            await app.reply("completeSymbols", { ok: false, error: failure });
        }
        assert.equal(prompt.value, "dump-pe nt!KeBug <path>", failure);
        assert.equal(prompt.value.slice(prompt.selectionStart, prompt.selectionEnd), "<path>", failure);
        assert.equal(app.nodes.get("btn-run").disabled, true, failure);
        prompt.fire("keydown", { key: "Enter" });
        assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false, failure);
    }
    for (const boundary of ["blur", "escape"])
    {
        const app = harness();
        await app.boot({ Dumps: [{ name: "dump-pe", grammar: "dump-pe <module|address> <path>",
            symbolParameters: [0], support: "Stable" }] });
        const prompt = app.nodes.get("prompt");
        prompt.focus();
        setPrompt(app, "dump-pe nt!KeBug");
        prompt.fire("keydown", { key: "Tab" });
        prompt.fire(boundary === "blur" ? "blur" : "keydown", { key: "Escape" });
        await app.reply("completeSymbols", { ok: false, error: "EngineBusy" });
        assert.equal(prompt.value, "dump-pe nt!KeBug", boundary);
        assert.equal(app.nodes.get("suggest").classList.contains("hidden"), true, boundary);
    }
});

await check("T-UI-SYMBOLS expired optional reads acknowledge late receipts without applying them", async () =>
{
    const app = harness();
    await app.boot({ Code: [{ name: "u", grammar: "u [address]", symbolParameters: [0], support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    setPrompt(app, "u nt!KeBug");
    prompt.fire("keydown", { key: "Tab" });
    const request = app.latest("completeSymbols");
    app.advanceTime(8000);
    await settle();
    await app.deliver(request, { uiGeneration: "old", operationId: "old-operation", ok: true,
        result: { target: stamp, items: symbolItems } });
    assert.equal(app.messages.some(item => item.method === "operationAck"), false);
    await app.deliver(request, { operationId: "expired-symbol-operation", ok: true,
        result: { target: stamp, items: symbolItems } });
    assert.equal(app.latest("operationAck")?.params.operationId, "expired-symbol-operation");
    assert.equal(prompt.value, "u nt!KeBug");
    assert.equal(app.nodes.get("suggest").classList.contains("hidden"), true);
    assertCommandActivity(app, false);
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
});

await check("T-UI-ADDRESS-HISTORY memory expressions and spaces survive reopening and use the current context", async () =>
{
    const saved = new Map();
    const storage = { getItem: key => saved.get(key) || null, setItem: (key, value) => saved.set(key, value) };
    const app = await memoryApp({ storage });
    assert.equal(app.nodes.get("memory-address-history").disabled, true);
    app.nodes.get("memory-address").value = "  nt!Example + 10  ";
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(1));
    assert.equal(app.nodes.get("memory-address").value, "0xffff800000001000");
    app.nodes.get("memory-address").value = "0x1234";
    app.nodes.get("memory-space").value = "physical";
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(2), { address: "0x1234", space: "physical" });
    const stored = JSON.parse(saved.get("kndbgx.address-history"));
    assert.deepEqual(stored.memory, [{ expression: "0x1234", space: "physical" }, { expression: "nt!Example + 10", space: "virtual" }]);
    assert.deepEqual(stored.disassembly, []);
    const reopened = await memoryApp({ storage });
    const history = reopened.nodes.get("memory-address-history");
    assert.equal(reopened.messages.some(item => item.method === "memoryRead" || item.method === "disassemblyRead"), false);
    assert.equal(history.children[1].textContent, "[Physical] 0x1234");
    assert.equal(history.children[2].textContent, "[Virtual] nt!Example + 10");
    const current = { ...stamp, contextGeneration: "22", stopEpoch: "23" };
    reopened.nodes.get("btn-refresh-status").fire("click");
    await processStatus(reopened, current);
    reopened.nodes.get("memory-space").value = "physical";
    history.value = "1";
    history.fire("change");
    assert.equal(reopened.latest("memoryRead").params.expression, "nt!Example + 10");
    assert.equal(reopened.latest("memoryRead").params.space, "virtual");
    assert.deepEqual(JSON.parse(JSON.stringify(reopened.latest("memoryRead").params.expectedStamp)), current);
    assert.equal(history.value, "");
    assert.equal(history.disabled, true);
    await memoryReply(reopened, Array(64).fill(3), { target: current });
    assert.equal(history.disabled, false);
    assert.equal(JSON.parse(saved.get("kndbgx.address-history")).memory[0].expression, "nt!Example + 10");
});

await check("T-UI-ADDRESS-HISTORY disassembly restores expressions independently and history selection pauses Follow IP", async () =>
{
    const saved = new Map();
    const storage = { getItem: key => saved.get(key) || null, setItem: (key, value) => saved.set(key, value) };
    const app = await disassemblyApp({ storage });
    app.nodes.get("disassembly-address").value = "test!Code + 2";
    app.nodes.get("btn-disassembly-read").fire("click");
    await disassemblyReply(app);
    assert.equal(app.nodes.get("disassembly-address").value, "0xffff800000001000");
    assert.deepEqual(JSON.parse(saved.get("kndbgx.address-history")).disassembly,
        [{ expression: "test!Code + 2", space: "virtual" }]);
    const reopened = await disassemblyApp({ storage });
    assert.equal(reopened.messages.some(item => item.method === "memoryRead" || item.method === "disassemblyRead"), false);
    assert.equal(reopened.nodes.get("memory-address-history").disabled, true);
    const history = reopened.nodes.get("disassembly-address-history");
    assert.equal(history.children[1].textContent, "test!Code + 2");
    reopened.nodes.get("btn-refresh-status").fire("click");
    await processStatus(reopened, stamp, { instructionPointer: "0xffff800000001000" });
    const stored = saved.get("kndbgx.address-history");
    reopened.nodes.get("btn-disassembly-follow").fire("click");
    await disassemblyReply(reopened);
    assert.equal(saved.get("kndbgx.address-history"), stored, "Automatic Follow IP polluted recent addresses");
    history.value = "0";
    history.fire("change");
    assert.equal(reopened.latest("disassemblyRead").params.expression, "test!Code + 2");
    assert.equal(reopened.nodes.get("btn-disassembly-follow").getAttribute("aria-pressed"), "false");
    await disassemblyReply(reopened);
    assert.equal(saved.get("kndbgx.address-history"), stored, "Selecting an existing entry created a duplicate");
});

await check("T-UI-ADDRESS-HISTORY bounds and deduplication preserve exact expressions and address spaces", async () =>
{
    const entries = Array.from({ length: 22 }, (_, index) => ({ expression: "test!Address" + index, space: "virtual" }));
    const saved = new Map([["kndbgx.address-history", JSON.stringify({ version: 1, memory: [entries[0], ...entries], disassembly: [] })]]);
    const storage = { getItem: key => saved.get(key) || null, setItem: (key, value) => saved.set(key, value) };
    const app = await memoryApp({ storage });
    const history = app.nodes.get("memory-address-history");
    assert.equal(history.children.length, 21);
    assert.equal(history.children[20].textContent, "[Virtual] test!Address19");
    app.nodes.get("memory-address").value = "test!Newest";
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(1));
    app.nodes.get("memory-address").value = "test!Address4";
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(2));
    let stored = JSON.parse(saved.get("kndbgx.address-history")).memory;
    assert.equal(stored.length, 20);
    assert.equal(stored[0].expression, "test!Address4");
    assert.equal(stored[1].expression, "test!Newest");
    assert.equal(stored.some(item => item.expression === "test!Address19"), false);
    app.nodes.get("memory-space").value = "physical";
    app.nodes.get("memory-address").value = "test!Address4";
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(3), { space: "physical" });
    stored = JSON.parse(saved.get("kndbgx.address-history")).memory;
    assert.deepEqual(stored.slice(0, 2), [{ expression: "test!Address4", space: "physical" }, { expression: "test!Address4", space: "virtual" }]);
});

await check("T-UI-ADDRESS-HISTORY malformed and unavailable storage cannot execute or break local history", async () =>
{
    const invalid = ["{bad", "x".repeat(65537), JSON.stringify({ version: 2, memory: [{ expression: "nt", space: "virtual" }] })];
    for (const value of invalid)
    {
        const app = await memoryApp({ storage: { getItem: key => key === "kndbgx.address-history" ? value : null, setItem: noop } });
        assert.equal(app.nodes.get("memory-address-history").disabled, true);
        assert.equal(app.messages.some(item => item.method === "memoryRead" || item.method === "disassemblyRead"), false);
    }
    const corrupt = JSON.stringify({ version: 1, memory: [null, {}, { expression: "nt;g", space: "virtual" },
        { expression: "\"nt\"", space: "virtual" }, { expression: "a".repeat(1025), space: "virtual" },
        { expression: "nt", space: "invalid" }, { expression: "nt\n", space: "virtual" }], disassembly: [
        { expression: "nt", space: "physical" }] });
    const app = await memoryApp({ storage: { getItem: key => key === "kndbgx.address-history" ? corrupt : null,
        setItem: () =>
        {
            throw new Error("Storage denied");
        } } });
    assert.equal(app.nodes.get("memory-address-history").disabled, true);
    assert.equal(app.nodes.get("disassembly-address-history").disabled, true);
    app.nodes.get("memory-address").value = "test!LocalOnly";
    app.nodes.get("btn-memory-read").fire("click");
    await memoryReply(app, Array(64).fill(1));
    assert.equal(app.nodes.get("memory-address-history").children[1].textContent, "[Virtual] test!LocalOnly");
    assert.equal(app.nodes.get("memory-address-history").disabled, false);
    const blocked = await memoryApp({ storage: { getItem: () =>
    {
        throw new Error("Storage denied");
    }, setItem: () =>
    {
        throw new Error("Storage denied");
    } } });
    blocked.nodes.get("btn-memory-read").fire("click");
    await memoryReply(blocked, Array(64).fill(1));
    assert.equal(blocked.nodes.get("memory-address-history").children[1].textContent, "[Virtual] @rip");
});

await check("T-UI-ADDRESS-HISTORY failures do not add entries and blocked or hidden selection cannot navigate", async () =>
{
    for (const view of ["memory", "disassembly"])
    {
        const stored = JSON.stringify({ version: 1, memory: [{ expression: "test!Memory", space: "virtual" }],
            disassembly: [{ expression: "test!Code", space: "virtual" }] });
        const storage = { getItem: key => key === "kndbgx.address-history" ? stored : null, setItem: noop };
        const app = view === "memory" ? await memoryApp({ storage }) : await disassemblyApp({ storage });
        const input = app.nodes.get(view + "-address");
        input.value = "test!Failed";
        app.nodes.get("btn-" + view + "-read").fire("click");
        const history = app.nodes.get(view + "-address-history");
        assert.equal(history.disabled, true);
        const before = app.messages.length;
        history.value = "0";
        history.fire("change");
        assert.equal(app.messages.length, before);
        assert.equal(input.value, "test!Failed");
        await app.reply(view === "memory" ? "memoryRead" : "disassemblyRead", { ok: false, error: "Unavailable" });
        await processStatus(app);
        assert.equal(history.children.length, 2);
        assert.equal(history.children[1].textContent.includes("Failed"), false);
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, stamp, { stopped: false });
        assert.equal(history.disabled, true);
        history.value = "0";
        history.fire("change");
        assert.equal(input.value, "test!Failed");
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app);
        app.nodes.get("btn-memory-close").fire("click");
        history.value = "0";
        history.fire("change");
        assert.equal(input.value, "test!Failed");
    }
});

function setInspectionAddress(app, view, value, cursor = value.length)
{
    const input = app.nodes.get(view + "-address");
    input.focus();
    input.value = value;
    input.setSelectionRange(cursor, cursor);
    input.fire("input");
    return input;
}

async function inspectionSymbolApp(view)
{
    const app = harness();
    await app.boot({ Code: [{ name: "u", grammar: "u [address]", symbolParameters: [0], support: "Stable" }] });
    if (view === "disassembly")
    {
        app.nodes.get("tab-disassembly").fire("click");
    }
    return app;
}

function assertNoInspectionRead(app)
{
    assert.equal(app.messages.some(item => ["memoryRead", "disassemblyRead", "debuggerAction", "classify", "execute"].includes(item.method)), false);
}

await check("T-UI-ADDRESS-SYMBOLS both inspectors show exact addresses and complete without reading", async () =>
{
    for (const view of ["memory", "disassembly"])
    {
        const app = await inspectionSymbolApp(view);
        app.nodes.get("prompt").value = "retained command draft";
        const input = setInspectionAddress(app, view, "nt!KeBug");
        app.advanceTime(179);
        assert.equal(app.messages.some(item => item.method === "completeSymbols"), false);
        app.advanceTime(1);
        assert.equal(app.latest("completeSymbols").params.prefix, "u nt!KeBug");
        assert.equal(app.latest("completeSymbols").params.suffix, "");
        await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
        assert.equal(app.nodes.get(view + "-symbol-suggest").children[0].children[0].textContent, symbolItems[0].address);
        assert.equal(app.nodes.get(view + "-address-ghost-suffix").textContent, "CheckEx");
        input.fire("keydown", { key: "ArrowDown" });
        assert.equal(app.nodes.get(view + "-address-ghost-suffix").textContent, "Check2");
        input.fire("keydown", { key: "Tab" });
        assert.equal(input.value, "nt!KeBugCheck2");
        assert.equal(input.getAttribute("aria-expanded"), "false");
        let trapped = false;
        input.fire("keydown", { key: "Tab", preventDefault()
        {
            trapped = true;
        } });
        assert.equal(trapped, false);
        assert.equal(app.nodes.get("prompt").value, "retained command draft");
        assertNoInspectionRead(app);
        input.fire("keydown", { key: "Enter" });
        assert.equal(app.latest(view === "memory" ? "memoryRead" : "disassemblyRead").params.expression, "nt!KeBugCheck2");
    }
});

await check("T-UI-ADDRESS-SYMBOLS an empty caret prefix stays idle until the caret reaches the symbol", async () =>
{
    for (const view of ["memory", "disassembly"])
    {
        const app = await inspectionSymbolApp(view);
        const input = setInspectionAddress(app, view, "nt!KeBug", 0);
        app.advanceTime(180);
        assert.equal(app.messages.some(item => item.method === "completeSymbols"), false);
        assert.equal(app.nodes.get(view + "-symbol-suggest").classList.contains("hidden"), true);
        input.fire("keydown", { key: "End" });
        input.setSelectionRange(input.value.length, input.value.length);
        input.fire("keyup", { key: "End" });
        app.advanceTime(180);
        assert.equal(app.latest("completeSymbols").params.prefix, "u nt!KeBug");
        await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
        assert.equal(app.nodes.get(view + "-symbol-suggest").classList.contains("hidden"), false);
        assert.equal(input.value, "nt!KeBug");
        assertNoInspectionRead(app);
    }
});

await check("T-UI-ADDRESS-SYMBOLS pending Tab preserves expression suffixes and supports pointer acceptance", async () =>
{
    for (const view of ["memory", "disassembly"])
    {
        const app = await inspectionSymbolApp(view);
        const input = setInspectionAddress(app, view, "  nt!KeBug+0x10", "  nt!KeBug".length);
        input.fire("keydown", { key: "Tab" });
        assert.equal(app.latest("completeSymbols").params.prefix, "u   nt!KeBug");
        assert.equal(app.latest("completeSymbols").params.suffix, " +0x10");
        await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
        assert.equal(input.value, "  nt!KeBugCheckEx+0x10");
        assert.equal(input.selectionStart, "  nt!KeBugCheckEx".length);
        assert.equal(app.nodes.get(view + "-address-ghost").classList.contains("hidden"), true);
        setInspectionAddress(app, view, "nt!KeBug");
        app.advanceTime(180);
        await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
        app.nodes.get(view + "-symbol-suggest").children[1].fire("mousedown", { button: 0 });
        assert.equal(input.value, "nt!KeBugCheck2");
        assertNoInspectionRead(app);
    }
});

await check("T-UI-ADDRESS-SYMBOLS one queue separates identical prefixes from different input owners", async () =>
{
    const app = await inspectionSymbolApp("memory");
    const memory = setInspectionAddress(app, "memory", "nt!KeBug");
    memory.fire("keydown", { key: "Tab" });
    const old = app.latest("completeSymbols");
    app.nodes.get("tab-disassembly").fire("click");
    const code = setInspectionAddress(app, "disassembly", "nt!KeBug");
    code.fire("keydown", { key: "Tab" });
    assert.equal(app.messages.filter(item => item.method === "completeSymbols").length, 1);
    await app.deliver(old, { ok: true, result: { target: stamp, items: symbolItems } });
    assert.equal(app.messages.filter(item => item.method === "completeSymbols").length, 2);
    assert.equal(memory.value, "nt!KeBug");
    assert.equal(code.value, "nt!KeBug");
    await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
    assert.equal(code.value, "nt!KeBugCheckEx");
    assert.equal(memory.value, "nt!KeBug");
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    setPrompt(app, "u nt!KeBug");
    prompt.fire("keydown", { key: "Tab" });
    await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
    assert.equal(prompt.value, "u nt!KeBugCheckEx");
    assert.equal(code.value, "nt!KeBugCheckEx");
    assertNoInspectionRead(app);
});

await check("T-UI-ADDRESS-SYMBOLS stale focus caret composition panel and debugger changes invalidate pending fills", async () =>
{
    for (const view of ["memory", "disassembly"])
    {
        for (const boundary of ["context", "symbols", "stop", "blur", "window", "selection", "escape", "ime", "hidden", "panel", "tab", "busy", "disconnect"])
        {
            const app = await inspectionSymbolApp(view);
            const input = setInspectionAddress(app, view, "nt!KeBug");
            input.fire("keydown", { key: "Tab" });
            const request = app.latest("completeSymbols");
            if (["context", "symbols", "stop", "busy", "disconnect"].includes(boundary))
            {
                app.nodes.get("btn-refresh-status").fire("click");
                const changed = { ...stamp, [boundary === "symbols" ? "symbolGeneration" : boundary === "stop" ? "stopEpoch" : "contextGeneration"]: "99" };
                await app.reply("status", boundary === "disconnect" ? { ok: false, error: "Disconnected" } :
                    { ok: true, result: { connected: true, stopped: boundary !== "busy", target: changed } });
            }
            else if (boundary === "selection")
            {
                input.setSelectionRange(1, 2);
                input.fire("select");
            }
            else if (boundary === "hidden")
            {
                app.visibility(true);
            }
            else if (boundary === "window")
            {
                app.windowEvent("blur");
            }
            else if (boundary === "panel")
            {
                app.nodes.get("btn-memory-close").fire("click");
            }
            else if (boundary === "tab")
            {
                app.nodes.get(view === "memory" ? "tab-disassembly" : "tab-memory-view").fire("click");
            }
            else if (boundary === "ime")
            {
                input.fire("compositionstart");
                input.fire("keydown", { key: "Enter" });
                app.documentListeners.get("keydown")({ key: "F10", preventDefault: noop });
            }
            else
            {
                input.fire(boundary === "blur" ? "blur" : "keydown", { key: "Escape" });
            }
            await app.deliver(request, { ok: true, result: { target: stamp, items: symbolItems } });
            assert.equal(input.value, "nt!KeBug", view + ":" + boundary);
            assert.equal(app.nodes.get(view + "-symbol-suggest").classList.contains("hidden"), true, view + ":" + boundary);
            assert.equal(app.nodes.get(view + "-address-ghost").classList.contains("hidden"), true, view + ":" + boundary);
            assertNoInspectionRead(app);
        }
    }
});

await check("T-UI-ADDRESS-SYMBOLS physical mode excludes virtual symbols and numeric registers stay manual", async () =>
{
    const app = await inspectionSymbolApp("memory");
    const input = setInspectionAddress(app, "memory", "nt!KeBug");
    input.fire("keydown", { key: "Tab" });
    const pending = app.latest("completeSymbols");
    app.nodes.get("memory-space").value = "physical";
    app.nodes.get("memory-space").fire("change");
    await app.deliver(pending, { ok: true, result: { target: stamp, items: symbolItems } });
    assert.equal(input.value, "nt!KeBug");
    assert.equal(app.nodes.get("memory-symbol-suggest").classList.contains("hidden"), true);
    const before = app.messages.filter(item => item.method === "completeSymbols").length;
    for (const value of ["nt!KeBugC", "KeBug", "nt!"])
    {
        setInspectionAddress(app, "memory", value).fire("keydown", { key: "Tab" });
        app.advanceTime(180);
    }
    app.nodes.get("memory-space").value = "virtual";
    app.nodes.get("memory-space").fire("change");
    for (const value of ["0xfffff80312345678", "@rip", "@$ip", "nt!KeBug+10", '"nt!KeBug"', "nt!KeBug;g"])
    {
        setInspectionAddress(app, "memory", value).fire("keydown", { key: "Tab" });
        app.advanceTime(180);
    }
    assert.equal(app.messages.filter(item => item.method === "completeSymbols").length, before);
    assertNoInspectionRead(app);
});

await check("T-UI-ADDRESS-SYMBOLS failed and empty lookups allow focus escape and discard expired suggestions", async () =>
{
    for (const view of ["memory", "disassembly"])
    {
        for (const outcome of ["error", "empty", "timeout"])
        {
            const app = await inspectionSymbolApp(view);
            const input = setInspectionAddress(app, view, "nt!KeBug");
            input.fire("keydown", { key: "Tab" });
            const request = app.latest("completeSymbols");
            if (outcome === "timeout")
            {
                app.advanceTime(8000);
                await settle();
                await app.deliver(request, { ok: true, operationId: "expired-inspection", result: { target: stamp, items: symbolItems } });
                assert.equal(app.latest("operationAck").params.operationId, "expired-inspection");
            }
            else
            {
                await app.reply("completeSymbols", outcome === "error" ? { ok: false, error: "EngineBusy" } :
                    { ok: true, result: { target: stamp, items: [] } });
            }
            let trapped = false;
            input.fire("keydown", { key: "Tab", preventDefault()
            {
                trapped = true;
            } });
            assert.equal(trapped, false, view + ":" + outcome);
            assert.equal(input.value, "nt!KeBug");
            assertNoInspectionRead(app);
        }
    }
});

await check("T-UI-ADDRESS-SYMBOLS refocusing or clicking retries a settled lookup without editing the prefix", async () =>
{
    for (const view of ["memory", "disassembly"])
    {
        for (const outcome of ["error", "empty", "timeout"])
        {
            for (const trigger of ["focus", "click"])
            {
                const app = await inspectionSymbolApp(view);
                const input = setInspectionAddress(app, view, "nt!KeBug");
                input.fire("keydown", { key: "Tab" });
                if (outcome === "timeout")
                {
                    app.advanceTime(8000);
                    await settle();
                }
                else
                {
                    await app.reply("completeSymbols", outcome === "error" ? { ok: false, error: "EngineBusy" } :
                        { ok: true, result: { target: stamp, items: [] } });
                }
                let trapped = false;
                input.fire("keydown", { key: "Tab", preventDefault()
                {
                    trapped = true;
                } });
                assert.equal(trapped, false);
                const before = app.messages.filter(item => item.method === "completeSymbols").length;
                if (trigger === "focus")
                {
                    input.fire("blur");
                    input.focus();
                }
                input.fire(trigger);
                app.advanceTime(180);
                assert.equal(app.messages.filter(item => item.method === "completeSymbols").length, before + 1,
                    view + ":" + outcome + ":" + trigger);
                await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
                input.fire("keydown", { key: "Tab" });
                assert.equal(input.value, "nt!KeBugCheckEx");
                assertNoInspectionRead(app);
            }
        }
    }
});

await check("T-UI-ADDRESS-SYMBOLS secondary pointer buttons cannot accept a recommendation", async () =>
{
    for (const view of ["memory", "disassembly"])
    {
        const app = await inspectionSymbolApp(view);
        const input = setInspectionAddress(app, view, "nt!KeBug");
        app.advanceTime(180);
        await app.reply("completeSymbols", { ok: true, result: { target: stamp, items: symbolItems } });
        for (const button of [1, 2])
        {
            let prevented = false;
            app.nodes.get(view + "-symbol-suggest").children[0].fire("mousedown", { button, preventDefault()
            {
                prevented = true;
            } });
            assert.equal(prevented, false, view + ":" + button);
            assert.equal(input.value, "nt!KeBug", view + ":" + button);
            assert.equal(app.nodes.get(view + "-symbol-suggest").classList.contains("hidden"), false);
        }
        app.nodes.get(view + "-symbol-suggest").children[1].fire("mousedown", { button: 0 });
        assert.equal(input.value, "nt!KeBugCheck2");
        assertNoInspectionRead(app);
    }
});

await check("T-UI-COMPLETION grammar search, argument completion and workspace help share the command catalog", async () =>
{
    const app = harness();
    await app.boot({ Kernel: [
        { name: "!threads", synopsis: "current thread or selected process", grammar: "!threads [process|ethread:ADDRESS]", support: "Experimental" },
        { name: "!vad", synopsis: "current process VADs", grammar: "!vad [process] [/exec]", support: "Experimental" },
        { name: "help", synopsis: "command and workspace help", grammar: "help [command|ui]", support: "Stable" }
    ] });
    const prompt = app.nodes.get("prompt");
    prompt.focus();
    prompt.value = "!THREADS et";
    prompt.fire("input");
    assert.ok(app.nodes.get("command-hint").textContent.includes("!threads [process|ethread:ADDRESS]"));
    assert.equal(app.latest("complete").params.prefix, "!THREADS et");
    await app.reply("complete", { ok: true, result: { items: ["!THREADS ethread:"] } });
    prompt.fire("keydown", { key: "Tab" });
    assert.equal(prompt.value, "!THREADS ethread:");
    assert.equal(app.messages.some(item => item.method === "execute" || item.method === "classify"), false);
    app.nodes.get("filter").value = "ethread";
    app.nodes.get("filter").fire("input");
    assert.equal(app.nodes.get("catalog-count").textContent, "1 / 3");
    prompt.value = "help u";
    prompt.fire("keydown", { key: "Tab" });
    await app.reply("complete", { ok: true, result: { items: ["help ui"] } });
    assert.equal(prompt.value, "help ui");
    app.enter(":help");
    assert.equal(app.latest("classify").params.command, "help ui");
    await app.reply("classify", { ok: true, result: { write: false } });
    assert.equal(app.latest("execute").params.command, "help ui");
});

await check("T-UI-COMPLETION optional symbol addresses retain grammar and never insert a fabricated operand", async () =>
{
    const contract = JSON.parse(fs.readFileSync(new URL("../docs/command-contract.json", import.meta.url), "utf8"));
    const commands = contract.filter(command => ["ln", "uf", "help"].includes(command.name)).map(command => ({
        name: command.name, synopsis: command.summary, grammar: command.grammar, support: command.support
    }));
    const app = harness();
    await app.boot({ Commands: commands });
    const prompt = app.nodes.get("prompt");
    for (const name of ["ln", "uf"])
    {
        prompt.focus();
        prompt.value = name.toUpperCase();
        prompt.fire("input");
        prompt.fire("keydown", { key: "Tab" });
        assert.equal(prompt.value, name);
        assert.ok(app.nodes.get("command-hint").textContent.includes(name + " [address]"));
        assert.ok(app.nodes.get("command-hint").textContent.includes("current instruction"));
        prompt.value = name + " ";
        prompt.fire("input");
        await app.reply("complete", { ok: true, result: { items: [] } });
        assert.equal(prompt.value, name + " ");
        assert.equal(app.nodes.get("suggest").classList.contains("hidden"), true);
    }
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
});

await check("T-UI-COMPLETION late responses, IME, focus and caret changes never replace a draft", async () =>
{
    const app = harness();
    await app.boot({ Session: [{ name: "help", synopsis: "help", support: "Stable" }] });
    const prompt = app.nodes.get("prompt");
    for (const change of ["input", "escape", "blur", "ime", "caret"])
    {
        prompt.focus();
        prompt.value = "help u";
        prompt.selectionStart = prompt.selectionEnd = prompt.value.length;
        prompt.fire("keydown", { key: "Tab" });
        const request = app.latest("complete");
        if (change === "input")
        {
            prompt.value = "help !threads";
            prompt.fire("input");
        }
        else if (change === "escape")
        {
            prompt.fire("keydown", { key: "Escape" });
        }
        else if (change === "blur")
        {
            prompt.fire("blur");
        }
        else if (change === "ime")
        {
            prompt.fire("compositionstart");
        }
        else
        {
            prompt.selectionStart = prompt.selectionEnd = 2;
        }
        const unchanged = prompt.value;
        await app.deliver(request, { ok: true, result: { items: ["help ui"] } });
        assert.equal(prompt.value, unchanged, change + " was overwritten by an old completion");
        assert.equal(app.nodes.get("suggest").classList.contains("hidden"), true);
        if (change === "ime")
        {
            prompt.value = "";
            prompt.fire("compositionend");
        }
    }
    assert.equal(app.messages.some(item => item.method === "classify" || item.method === "execute"), false);
});

await check("T-UI-WINDBG completion updates target before the next input and rejects older status", async () =>
{
    for (const ok of [true, false])
    {
        const app = harness();
        await app.boot();
        app.nodes.get("btn-refresh-status").fire("click");
        const olderStatus = app.latest("status");
        const changed = { ...stamp, targetGeneration: "3", contextGeneration: "5" };
        app.enter(".echo first");
        await app.reply("classify", { ok: true, result: { write: false, opaque: true } });
        await app.reply("execute", { ok: true, result: { ok, currentTarget: changed,
            resultId: "first-windbg", rowCount: "0", outputLength: "6", data: { commandId: "windbg", target: stamp } } });
        await app.deliver(olderStatus, { ok: true, result: { connected: true, stopped: true, target: stamp } });
        await app.reply("outputChunk", { ok: true, result: {
            resultId: "first-windbg", offset: "0", next: "6", complete: true, text: "first\n"
        } });
        assert.equal(app.nodes.get("prompt").disabled, true, "WinDbg completion unlocked input before checking its new execution state");
        const classifications = app.messages.filter(message => message.method === "classify").length;
        app.enter(".echo second");
        assert.equal(app.messages.filter(message => message.method === "classify").length, classifications);
        await processStatus(app, changed, { stopped: false });
        assert.equal(app.nodes.get("prompt").disabled, true);
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, changed);
        app.enter(".echo second");
        await app.reply("classify", { ok: true, result: { write: false, opaque: true } });
        assert.equal(app.latest("execute").expectedTargetGeneration, "3", "Next WinDbg command used the invalidated target generation");
        assert.equal(app.messages.filter(message => message.method === "execute").length, 2, "A command was automatically replayed");
    }
});

await check("T-UI-PALETTE exact command names and aliases precede fuzzy and description matches", async () =>
{
    const contract = JSON.parse(fs.readFileSync(new URL("../docs/command-contract.json", import.meta.url), "utf8"));
    const commands = contract.flatMap(command => [command.name, ...command.aliases].map(name => ({
        name, synopsis: command.summary, grammar: command.grammar, support: command.support
    })));
    const app = harness();
    await app.boot({ Commands: commands });
    for (const command of commands)
    {
        app.nodes.get("btn-palette").fire("click");
        const input = app.nodes.get("palette-input");
        input.value = command.name.toUpperCase();
        input.fire("input");
        const first = app.nodes.get("palette-results").children[0];
        assert.equal(first.children[1].textContent, command.name, command.name + " lost to a weaker match");
        input.fire("keydown", { key: "Enter" });
        assert.equal(app.nodes.get("prompt").value, command.name);
    }
    assert.equal(app.messages.some(message => message.method === "classify" || message.method === "execute"), false);
});

await check("T-UI-REVIEW process details supersede an older pending result-open response", async () =>
{
    const app = harness();
    await app.boot();
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, processRows.slice(0, 2));
    app.nodes.get("process-rows").children[1].fire("click");
    app.nodes.get("result-id-input").value = "older-result";
    app.nodes.get("btn-result-load").fire("click");
    const older = app.latest("resultInfo");
    app.nodes.get("btn-process-details").fire("click");
    await app.reply("processAction", { ok: true, result: { resultId: "newer-process-detail", rowCount: "0", outputLength: "0",
        data: { commandId: "!process", status: "Success", target: stamp } } });
    await app.reply("outputChunk", { ok: true, result: { resultId: "newer-process-detail", offset: "0", next: "0", complete: true, text: "" } });
    await processStatus(app);
    await app.deliver(older, { ok: true, result: { resultId: "older-result", rowCount: "0", outputLength: "0",
        data: { commandId: "older-command", status: "Success", target: stamp } } });
    assert.equal(app.nodes.get("result-title").textContent, "!process");
    assert.equal(app.nodes.get("result-load-status").textContent, "");
    assert.match(app.nodes.get("process-name").textContent, /process1/);
});

await check("T-UI-REVIEW Stop during process page delivery does not interrupt a completed engine request", async () =>
{
    const app = harness();
    await app.boot();
    showProcesses(app);
    await processStatus(app);
    await collectProcessPages(app, processRows.slice(0, 2));
    app.nodes.get("btn-process-refresh").fire("click");
    await app.reply("execute", { ok: true, result: { resultId: "page-delivery", rowCount: "2",
        data: { commandId: "!dml_proc", status: "Success", target: stamp } } });
    const interrupts = app.messages.filter(item => item.method === "interrupt").length;
    app.nodes.get("btn-cancel").fire("click");
    await app.reply("resultPage", { ok: true, result: { resultId: "page-delivery", collection: "rows", offset: "0",
        next: "2", total: "2", complete: true, rows: processRows.slice(2, 4) } });
    await processStatus(app);
    assert.equal(app.messages.filter(item => item.method === "interrupt").length, interrupts);
    assert.match(app.nodes.get("process-notice").textContent, /cancelled/);
    assert.equal(app.nodes.get("process-rows").children[0].children[0].textContent, "0");
    assert.equal(app.nodes.get("btn-cancel").disabled, true);
});

await check("T-UI-BREAKPOINT-NOTIFY only new breakpoint stops notify and failed reads remain retryable", async () =>
{
    const app = harness();
    await app.boot();
    const prompt = app.nodes.get("prompt");
    prompt.value = "unfinished command";
    prompt.focus();
    const hit = { type: "0x0000000000000001", breakpointId: "7", address: "0xffff800000004000", description: "Breakpoint 7 hit" };
    const stopped = { connected: true, stopped: true, target: { ...stamp, stopEpoch: "3" }, lastEvent: hit, breakpointSequence: "1" };
    const status = async value =>
    {
        app.nodes.get("btn-refresh-status").fire("click");
        await app.reply("status", { ok: true, result: value });
    };
    const visible = () => !app.nodes.get("breakpoint-toast").classList.contains("hidden");
    assert.equal(visible(), false);
    await status({ ...stopped, target: stamp, breakpointSequence: "0" });
    await status({ ...stopped, lastEvent: null });
    assert.equal(visible(), false);
    await status(stopped);
    assert.equal(visible(), true);
    assert.equal(app.nodes.get("breakpoint-toast-title").textContent, "Breakpoint #7 hit");
    assert.match(app.nodes.get("breakpoint-toast-detail").textContent, /0xffff800000004000/);
    assert.equal(app.focused(), prompt);
    assert.equal(prompt.value, "unfinished command");
    app.nodes.get("btn-breakpoint-toast-dismiss").fire("click");
    await status(stopped);
    await status({ ...stopped, target: { ...stopped.target, contextGeneration: "10", symbolGeneration: "11" } });
    assert.equal(visible(), false, "Repeated status and context changes must not repeat a dismissed hit");
    await status({ ...stopped, target: { ...stamp, stopEpoch: "4" }, lastEvent: { type: "0x2", code: "0x80000003" } });
    assert.equal(visible(), false, "A manual break exception must not be called a configured breakpoint hit");
    await status({ ...stopped, target: { ...stamp, stopEpoch: "5" }, breakpointSequence: "2" });
    assert.equal(visible(), true, "The same breakpoint can hit again at the next stop");
    app.nodes.get("btn-refresh-status").fire("click");
    await app.reply("status", { ok: false, error: "EngineBusy" });
    assert.equal(app.nodes.get("btn-breakpoint-event").disabled, true);
    await status({ ...stopped, target: { ...stamp, stopEpoch: "5" }, breakpointSequence: "2" });
    assert.equal(app.nodes.get("btn-breakpoint-event").disabled, false);
    await status({ ...stopped, stopped: false, breakpointSequence: "2" });
    assert.equal(visible(), false);
    await status({ ...stopped, target: { ...stamp, stopEpoch: "6" }, breakpointSequence: "3" });
    assert.equal(visible(), true);
    await status({ ...stopped, target: { ...stamp, targetGeneration: "2", stopEpoch: "7" }, breakpointSequence: "3" });
    assert.equal(visible(), false, "Switching target establishes a baseline");
    await status({ ...stopped, dumpFile: true });
    await status({ ...stopped, dumpFile: true, target: { ...stamp, stopEpoch: "8" } });
    assert.equal(visible(), false);
    await status({ connected: false });
    assert.equal(visible(), false);
    assert.equal(app.messages.some(item => item.method === "execute" || item.method === "debuggerAction"), false);
});

await check("T-UI-BREAKPOINT-NOTIFY current settings never masquerade as event IP and missing addresses stay unknown", async () =>
{
    const app = harness();
    await app.boot();
    const initial = { connected: true, stopped: true, target: stamp, breakpointSequence: "0" };
    const status = async value =>
    {
        app.nodes.get("btn-refresh-status").fire("click");
        await app.reply("status", { ok: true, result: value });
    };
    await status(initial);
    await status({ ...initial, target: { ...stamp, stopEpoch: "3" }, breakpointSequence: "1", lastEvent:
        { type: "0x1", breakpointId: "2", address: null, configuredAddress: "0xffff800000001008" } });
    assert.equal(app.nodes.get("breakpoint-toast-detail").textContent, "Current BP setting address: 0xffff800000001008");
    await status({ ...initial, target: { ...stamp, stopEpoch: "4" }, breakpointSequence: "2", lastEvent:
        { type: "0x1", breakpointId: "2", address: null, configuredAddress: null } });
    assert.equal(app.nodes.get("breakpoint-toast-detail").textContent, "Event IP unavailable");
    assert.equal(app.messages.some(item => item.method === "execute" || item.method === "debuggerAction"), false);
});

await check("T-UI-BREAKPOINT-NOTIFY an unavailable observer cannot turn an old event into a new hit", async () =>
{
    const app = harness();
    await app.boot();
    const hit = { type: "0x1", breakpointId: "0", address: "0xffff800000004000" };
    const initial = { connected: true, stopped: true, target: stamp, lastEvent: hit, breakpointSequence: "10" };
    const status = async value =>
    {
        app.nodes.get("btn-refresh-status").fire("click");
        await app.reply("status", { ok: true, result: value });
    };
    const visible = () => !app.nodes.get("breakpoint-toast").classList.contains("hidden");
    await status(initial);
    const unavailable = { ...initial, target: { ...stamp, targetGeneration: "2", stopEpoch: "3" }, breakpointSequence: null };
    await status(unavailable);
    await status({ ...unavailable, target: { ...unavailable.target, stopEpoch: "4" } });
    assert.equal(visible(), false, "A command invalidation with no observer must not redisplay the previous hit");
    await status({ ...unavailable, target: { ...unavailable.target, stopEpoch: "5" }, breakpointSequence: "11" });
    assert.equal(visible(), false, "Observer recovery establishes a baseline without replaying an unobserved hit");
    await status({ ...unavailable, target: { ...unavailable.target, stopEpoch: "6" }, breakpointSequence: "12" });
    assert.equal(visible(), true, "A newly observed hit after recovery must still notify");
    await status({ ...unavailable, target: { ...unavailable.target, stopEpoch: "7" }, breakpointSequence: undefined });
    assert.equal(visible(), false, "Missing observation data cannot keep an actionable stale notification");
});

await check("T-UI-BREAKPOINT-NOTIFY callback sequence separates real hits from command invalidation", async () =>
{
    const app = harness();
    await app.boot();
    const hit = { type: "0x1", breakpointId: "0", address: "0xffff800000004000" };
    const initial = { connected: true, stopped: true, target: stamp, lastEvent: hit, breakpointSequence: "10" };
    const status = async value =>
    {
        app.nodes.get("btn-refresh-status").fire("click");
        await app.reply("status", { ok: true, result: value });
    };
    const visible = () => !app.nodes.get("breakpoint-toast").classList.contains("hidden");
    await status(initial);
    await status({ ...initial, target: { ...stamp, stopEpoch: "7" } });
    assert.equal(visible(), false, "Engine status changes alone are not new hits");
    const next = { ...initial, target: { ...stamp, targetGeneration: "5", stopEpoch: "8" }, breakpointSequence: "11" };
    await status({ ...next, lastEvent: null });
    assert.equal(visible(), false);
    await status(next);
    assert.equal(visible(), true, "Forwarded execution can invalidate target generation and still produce a real hit");
    app.nodes.get("btn-breakpoint-toast-dismiss").fire("click");
    await status({ ...next, target: { ...next.target, stopEpoch: "12" } });
    assert.equal(visible(), false, "A command at the same hit must not repeat the notification");
    await status({ ...next, target: { ...next.target, stopEpoch: "12" }, breakpointSequence: "12" });
    assert.equal(visible(), true, "A delayed callback is noticed even after the stopped status was read");
});

const breakpointFixture = [
    { kind: "Breakpoint", id: "12", address: "0xffff800000001000", addressSpace: "virtual", enabled: true, type: "0", identity: "first-guid" },
    { kind: "Breakpoint", id: "5", address: "0xffff800000001001", addressSpace: "virtual", enabled: false, type: "0", identity: "second-guid" }
];

async function breakpointListReply(app, rows = breakpointFixture, options = {})
{
    const id = options.id || "breakpoint-list";
    await app.reply("execute", { ok: true, result: { ok: true, resultId: id, rowCount: String(rows.length), outputLength: "0",
        data: { commandId: "breakpoints", status: options.partial ? "Partial" : "Success", target: options.target || stamp } } });
    if (rows.length)
    {
        const first = app.latest("resultPage");
        const response = { ok: true, result: { resultId: id, collection: "rows", offset: "0", next: String(rows.length),
            total: String(rows.length), complete: true, rows } };
        await app.deliver(first, response);
        if (app.latest("resultPage") !== first && app.latest("resultPage").params.resultId === id)
        {
            await app.reply("resultPage", response);
        }
    }
    await processStatus(app, options.target || stamp);
}

function breakpointPreview(operation, target = stamp)
{
    return { ok: true, result: { ok: true, plan: { planId: "a".repeat(64), approvalToken: "b".repeat(64), operation,
        target, operand: "0x000000000000000c", original: "guid and configuration" } } };
}

function breakpointRowButtons(app)
{
    return app.nodes.get("result-rows").querySelectorAll(".breakpoint-row-toggle");
}

await check("T-UI-BREAKPOINT successful state changes stay silent while Add Delete and failures remain visible", async () =>
{
    for (const action of ["enable", "disable", "add", "remove", "enable-failed"])
    {
        const app = await memoryApp({ breakpointAuto: false });
        app.nodes.get("btn-breakpoints").fire("click");
        await breakpointListReply(app);
        const operation = "breakpoint-" + action.replace("-failed", "");
        if (action === "add")
        {
            app.nodes.get("breakpoint-address").value = "nt!Other";
            app.nodes.get("breakpoint-address").fire("input");
        }
        else
        {
            app.nodes.get("result-rows").children[action.startsWith("enable") ? 1 : 0].fire("click");
        }
        app.nodes.get("btn-breakpoint-" + action.replace("-failed", "")).fire("click");
        await app.reply("breakpointPlan", breakpointPreview(operation));
        if (action === "add" || action === "remove")
        {
            app.nodes.get("modal-confirm").fire("click");
        }
        if (action.endsWith("failed"))
        {
            await app.reply("breakpointApply", { ok: false, error: "Breakpoint identity changed" });
            assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), false);
            assert.match(app.nodes.get("workspace-feedback-text").textContent, /identity changed/);
            assert.equal(feedbackTimers(app).length, 0);
        }
        else
        {
            await app.reply("breakpointApply", { ok: true, result: { ok: true, status: {
                connected: true, stopped: true, canEditBreakpoints: true, target: stamp } } });
            await breakpointListReply(app);
            const silent = action === "enable" || action === "disable";
            assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), silent, action);
            assert.equal(feedbackTimers(app).length, silent ? 0 : 1, action);
        }
    }
});

await check("T-UI-BREAKPOINT a silent retry clears the preceding failure and still reports a new failure", async () =>
{
    const app = await memoryApp({ breakpointAuto: false });
    app.nodes.get("btn-breakpoints").fire("click");
    await breakpointListReply(app);
    for (const outcome of ["failure", "success", "new-failure"])
    {
        const action = outcome === "new-failure" ? "disable" : "enable";
        app.nodes.get("result-rows").children[1].fire("click");
        assert.equal(app.nodes.get("btn-breakpoint-" + action).disabled, false);
        app.nodes.get("btn-breakpoint-" + action).fire("click");
        assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true,
            "The preceding operation's feedback must be cleared when a new breakpoint action starts");
        await app.reply("breakpointPlan", breakpointPreview("breakpoint-" + action));
        if (outcome === "success")
        {
            await app.reply("breakpointApply", { ok: true, result: { ok: true, status: {
                connected: true, stopped: true, canEditBreakpoints: true, target: stamp } } });
            await breakpointListReply(app, breakpointFixture.map(row => ({ ...row, enabled: true })), { id: "retry-success" });
            assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), true);
        }
        else
        {
            await app.reply("breakpointApply", { ok: false, error: "Failure: " + outcome });
            assert.equal(app.nodes.get("workspace-feedback").classList.contains("hidden"), false);
            assert.equal(app.nodes.get("workspace-feedback-text").textContent, "Failure: " + outcome);
            app.nodes.get("btn-breakpoint-refresh").fire("click");
            await breakpointListReply(app, outcome === "new-failure" ? breakpointFixture.map(row => ({ ...row, enabled: true })) : breakpointFixture,
                { id: "refreshed-" + outcome });
        }
        assert.equal(feedbackTimers(app).length, 0);
    }
});

await check("T-UI-BREAKPOINT row states and actions keep original bindings after sorting and inventory reorder", async () =>
{
    const app = await memoryApp({ breakpointAuto: false });
    app.nodes.get("btn-breakpoints").fire("click");
    await breakpointListReply(app);
    assert.deepEqual(app.nodes.get("result-rows").querySelectorAll(".breakpoint-state-label").map(node => node.textContent),
        ["Enabled", "Disabled"]);
    assert.deepEqual(breakpointRowButtons(app).map(node => node.textContent), ["Disable", "Enable"]);
    columnHandle(app, "Enabled").fire("keydown", { key: "Home" });
    assert.equal(columnHandle(app, "Enabled").getAttribute("aria-valuemin"), "160");
    assert.equal(columnHandle(app, "Enabled").getAttribute("aria-valuenow"), "160");
    sortHeader(app, "ID");
    assert.deepEqual(originalOrder(app), [2, 1]);
    const detached = breakpointRowButtons(app)[0];
    sortHeader(app, "ID");
    const beforeDetached = app.messages.length;
    detached.fire("click");
    assert.equal(app.messages.length, beforeDetached, "A detached control from a previous sort must not act");
    sortHeader(app, "ID");
    const staleButton = breakpointRowButtons(app)[0];
    app.nodes.get("btn-disassembly-breakpoints").fire("click");
    await breakpointListReply(app, [...breakpointFixture].reverse(), { id: "new-inventory" });
    assert.equal(staleButton.disabled, false);
    let stopped = false;
    staleButton.fire("click", { stopPropagation()
    {
        stopped = true;
    } });
    assert.equal(stopped, true);
    assert.equal(app.latest("breakpointPlan").params.operation, "breakpoint-enable");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("breakpointPlan").params.source)), { resultId: "new-inventory", index: "0" });
    assert.equal(breakpointRowButtons(app).every(button => button.disabled), true);
    staleButton.fire("click");
    assert.equal(app.messages.filter(item => item.method === "breakpointPlan").length, 1);
    await app.reply("breakpointPlan", breakpointPreview("breakpoint-enable"));
    assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), true);
    assert.equal(app.messages.filter(item => item.method === "breakpointApply").length, 1);
    await app.reply("breakpointApply", { ok: true, result: { ok: true, status: {
        connected: true, stopped: true, canEditBreakpoints: true, target: stamp } } });
    await breakpointListReply(app, breakpointFixture.map(row => ({ ...row, enabled: true, identity: "changed-" + row.id })), { id: "changed-state" });
    assert.deepEqual(breakpointRowButtons(app).map(button => button.textContent), ["Disable", "Disable"]);
    const before = app.messages.length;
    staleButton.fire("click");
    assert.equal(app.messages.length, before, "Detached controls must not submit another result's action");
});

await check("T-UI-BREAKPOINT row actions refuse stale identity, historical rows, unsupported and failed refreshes", async () =>
{
    for (const boundary of ["running", "unavailable", "dump", "context", "identity", "historical", "refresh-error"])
    {
        const app = await memoryApp({ breakpointAuto: false });
        app.nodes.get("btn-breakpoints").fire("click");
        const rows = breakpointFixture.map(row => ({ ...row, historical: boundary === "historical" }));
        await breakpointListReply(app, rows);
        const button = breakpointRowButtons(app)[0];
        assert.ok(button);
        if (["running", "unavailable", "dump", "context"].includes(boundary))
        {
            app.nodes.get("btn-refresh-status").fire("click");
            if (boundary === "unavailable")
            {
                await app.reply("status", { ok: false, error: "EngineBusy" });
            }
            else
            {
                await processStatus(app, boundary === "context" ? { ...stamp, contextGeneration: "99" } : stamp,
                    { stopped: boundary !== "running", canEditBreakpoints: boundary !== "dump", dumpFile: boundary === "dump" });
            }
        }
        else if (boundary === "identity" || boundary === "refresh-error")
        {
            app.nodes.get("btn-disassembly-breakpoints").fire("click");
            if (boundary === "identity")
            {
                await breakpointListReply(app, rows.map(row => ({ ...row, identity: "reused-" + row.id })), { id: "reused" });
            }
            else
            {
                await app.reply("execute", { ok: false, error: "Cannot enumerate breakpoints" });
                await processStatus(app);
            }
        }
        assert.equal(button.disabled, true, boundary);
        if (boundary === "historical")
        {
            app.nodes.get("result-rows").children[0].fire("click");
            assert.equal(app.nodes.get("btn-breakpoint-disable").disabled, true);
            assert.equal(app.nodes.get("btn-breakpoint-remove").disabled, true);
        }
        const before = app.messages.length;
        button.fire("click");
        assert.equal(app.messages.length, before, boundary);
    }
});

await check("T-UI-BREAKPOINT state changes use the selected original row without a global switch or modal", async () =>
{
    const app = await memoryApp({ breakpointAuto: false });
    app.nodes.get("btn-breakpoints").fire("click");
    await breakpointListReply(app);
    assert.equal(app.nodes.get("breakpoint-tools").classList.contains("hidden"), false);
    assert.equal(app.nodes.get("btn-breakpoint-remove").disabled, true);
    app.nodes.get("result-rows").children[1].fire("click");
    assert.equal(app.nodes.get("btn-breakpoint-enable").disabled, false);
    assert.equal(app.nodes.get("btn-breakpoint-disable").disabled, true);
    app.nodes.get("btn-disassembly-breakpoints").fire("click");
    await breakpointListReply(app, [...breakpointFixture].reverse(), { id: "same-breakpoints-new-result" });
    assert.equal(app.nodes.get("btn-breakpoint-enable").disabled, false,
        "A new result ID for unchanged breakpoints invalidated the retained row selection");
    assert.equal(app.nodes.get("result-title").textContent, "breakpoints");
    app.nodes.get("btn-breakpoint-enable").fire("click");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("breakpointPlan").params.source)), { resultId: "same-breakpoints-new-result", index: "0" });
    await app.reply("breakpointPlan", breakpointPreview("breakpoint-enable"));
    assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), true);
    assert.equal(app.messages.filter(item => item.method === "breakpointApply").length, 1);
    assert.equal(app.latest("breakpointApply").params.planId, "a".repeat(64));
    await app.reply("breakpointApply", { ok: true, result: { ok: true, status: {
        connected: true, stopped: true, canEditBreakpoints: true, target: stamp } } });
    await breakpointListReply(app, breakpointFixture.map(row => ({ ...row, enabled: true })), { id: "updated-list" });
    app.nodes.get("result-rows").children[1].fire("click");
    assert.equal(app.nodes.get("btn-breakpoint-enable").disabled, true);
    assert.equal(app.nodes.get("btn-breakpoint-disable").disabled, false);
    assert.equal(app.nodes.get("result-title").textContent, "breakpoints");
    app.nodes.get("btn-disassembly-breakpoints").fire("click");
    await breakpointListReply(app, breakpointFixture.map(row => ({ ...row, enabled: true, identity: "replacement-" + row.id })),
        { id: "reused-ids" });
    assert.equal(app.nodes.get("btn-breakpoint-disable").disabled, true, "A reused ID remained bound to an older GUID/configuration");
    const before = app.messages.length;
    app.nodes.get("btn-breakpoint-disable").fire("click");
    assert.equal(app.messages.length, before);
});

await check("T-UI-BREAKPOINT cancel, Busy and late preview replies cannot apply a change", async () =>
{
    for (const boundary of ["cancel", "busy", "invalid-preview"])
    {
        const app = await memoryApp();
        app.nodes.get("btn-breakpoints").fire("click");
        await settle();
        app.nodes.get("breakpoint-address").value = "nt!Function + 10";
        app.nodes.get("breakpoint-address").fire("input");
        app.nodes.get("btn-breakpoint-add").fire("click");
        assert.equal(app.latest("breakpointPlan").params.expression, "nt!Function + 10");
        if (boundary === "busy")
        {
            app.nodes.get("btn-refresh-status").fire("click");
            await processStatus(app, stamp, { stopped: false });
            app.nodes.get("btn-refresh-status").fire("click");
            await processStatus(app);
        }
        const preview = breakpointPreview("breakpoint-add");
        if (boundary === "invalid-preview")
        {
            preview.result.plan.target = { ...stamp, contextGeneration: "99" };
        }
        await app.reply("breakpointPlan", preview);
        if (boundary === "cancel")
        {
            app.nodes.get("modal-cancel").fire("click");
        }
        app.nodes.get("modal-confirm").fire("click");
        assert.equal(app.messages.some(item => item.method === "breakpointApply"), false, boundary);
        assert.equal(app.latest("discardPlan").params.planId, "a".repeat(64));
        assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), true);
    }
});

await check("T-UI-BREAKPOINT running, dump and stale lists disable edits without losing the list", async () =>
{
    const app = await memoryApp({ breakpointAuto: false });
    app.nodes.get("btn-breakpoints").fire("click");
    await breakpointListReply(app);
    app.nodes.get("result-rows").children[0].fire("click");
    app.nodes.get("breakpoint-address").value = "nt!Function";
    for (const overrides of [{ stopped: false }, { canEditBreakpoints: false, dumpFile: true },
        { target: { ...stamp, contextGeneration: "99" } }])
    {
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, stamp, overrides);
        const before = app.messages.length;
        app.nodes.get("btn-breakpoint-remove").fire("click");
        assert.equal(app.messages.length, before);
        assert.equal(app.nodes.get("btn-breakpoint-remove").disabled, true);
        assert.equal(app.nodes.get("result-rows").children.length, 2);
    }
});

await check("T-UI-BREAKPOINT disassembly markers distinguish enabled, disabled and empty addresses with bound F9 actions", async () =>
{
    for (const [index, operation] of [[0, "breakpoint-disable"], [1, "breakpoint-enable"], [2, "breakpoint-add"]])
    {
        const app = await disassemblyApp({ breakpointAuto: false });
        app.nodes.get("btn-disassembly-read").fire("click");
        const request = app.latest("disassemblyRead");
        const rows = instructionRows(16);
        await app.deliver(request, { ok: true, result: { resultId: "code-bp", rowCount: "16",
            data: { commandId: "u", status: "Success", target: stamp } } });
        await app.reply("resultPage", { ok: true, result: { resultId: "code-bp", offset: "0", rows, complete: true } });
        await breakpointListReply(app);
        const code = app.nodes.get("disassembly-rows").children;
        const button = position => code[position].children[0].children[0];
        assert.equal(button(0).classList.contains("enabled"), true);
        assert.equal(button(1).classList.contains("disabled"), true);
        assert.equal(button(2).textContent, "+");
        assert.equal(app.nodes.get("result-title").textContent, "retained-result");
        code[index].fire("click");
        app.nodes.get("disassembly-grid").fire("keydown", { key: "F9" });
        assert.equal(app.latest("breakpointPlan").params.operation, operation);
        assert.equal(app.latest("breakpointPlan").params.source.index, String(index));
        await app.reply("breakpointPlan", breakpointPreview(operation));
        assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), index !== 2);
        assert.equal(app.messages.some(item => item.method === "breakpointApply"), index !== 2);
        assert.equal(app.latest("breakpointPlan").params.source.resultId, index === 2 ? "code-bp" : "breakpoint-list");
    }
});

await check("T-UI-BREAKPOINT stopped context changes or unavailable capability cannot offer or submit an obsolete preview", async () =>
{
    for (const boundary of ["planning-context", "approval-context", "planning-unavailable"])
    {
        const app = await memoryApp();
        app.nodes.get("btn-breakpoints").fire("click");
        await settle();
        app.nodes.get("breakpoint-address").value = "nt!Function";
        app.nodes.get("breakpoint-address").fire("input");
        app.nodes.get("btn-breakpoint-add").fire("click");
        if (boundary === "approval-context")
        {
            await app.reply("breakpointPlan", breakpointPreview("breakpoint-add"));
        }
        app.nodes.get("btn-refresh-status").fire("click");
        await processStatus(app, boundary === "planning-unavailable" ? stamp : { ...stamp, contextGeneration: "99" },
            { canEditBreakpoints: boundary !== "planning-unavailable" });
        if (boundary !== "approval-context")
        {
            await app.reply("breakpointPlan", breakpointPreview("breakpoint-add"));
            assert.equal(app.nodes.get("modal-backdrop").classList.contains("hidden"), true, boundary);
        }
        else
        {
            app.nodes.get("modal-confirm").fire("click");
        }
        assert.equal(app.messages.some(item => item.method === "breakpointApply"), false, boundary);
        assert.equal(app.latest("discardPlan").params.planId, "a".repeat(64));
    }
});

await check("T-UI-BREAKPOINT automatic decode refresh respects Stop and the applied debugger context", async () =>
{
    for (const boundary of ["stop", "stop-apply", "context", "busy-then-break", "refresh-failure", "unchanged"])
    {
        const app = await disassemblyApp({ breakpointAuto: false });
        app.nodes.get("btn-disassembly-read").fire("click");
        await disassemblyReply(app);
        await breakpointListReply(app);
        const previousHistory = app.nodes.get("disassembly-address-history").children.map(item => item.textContent);
        app.nodes.get("disassembly-rows").children[0].children[0].children[0].fire("click");
        await app.reply("breakpointPlan", breakpointPreview("breakpoint-disable"));
        const applyReads = app.messages.filter(item => item.method === "execute").length;
        if (boundary === "stop-apply")
        {
            app.nodes.get("btn-cancel").fire("click");
        }
        const appliedTarget = { ...stamp, contextGeneration: "4", stopEpoch: "3" };
        await app.reply("breakpointApply", { ok: true, result: { ok: true, status: {
            connected: true, stopped: true, canEditBreakpoints: true, target: appliedTarget } } });
        if (boundary === "stop-apply")
        {
            assert.equal(app.messages.filter(item => item.method === "execute").length, applyReads,
                "Stop during apply started a subsequent breakpoint read");
            continue;
        }
        const refresh = app.latest("execute");
        const reads = app.messages.filter(item => item.method === "disassemblyRead").length;
        if (boundary === "stop")
        {
            app.nodes.get("btn-cancel").fire("click");
        }
        else if (boundary === "context")
        {
            app.nodes.get("btn-refresh-status").fire("click");
            await processStatus(app, { ...appliedTarget, contextGeneration: "5" });
        }
        else if (boundary === "busy-then-break")
        {
            app.nodes.get("btn-refresh-status").fire("click");
            await processStatus(app, appliedTarget, { stopped: false });
            app.nodes.get("btn-refresh-status").fire("click");
            await processStatus(app, appliedTarget);
        }
        await app.deliver(refresh, boundary === "refresh-failure" ? { ok: false, error: "EngineBusy" } :
            { ok: true, result: { ok: true, resultId: "refreshed-breakpoints", rowCount: "0",
                data: { commandId: "breakpoints", status: "Success", target: appliedTarget } } });
        assert.equal(app.messages.filter(item => item.method === "disassemblyRead").length,
            reads + (boundary === "unchanged" ? 1 : 0), boundary + " started an unwanted automatic target read");
        if (boundary === "unchanged")
        {
            assert.deepEqual(JSON.parse(JSON.stringify(app.latest("disassemblyRead").params.expectedStamp)), appliedTarget);
            await disassemblyReply(app, { target: appliedTarget });
            await breakpointListReply(app, [], { id: "post-code-refresh", target: appliedTarget });
            assert.deepEqual(app.nodes.get("disassembly-address-history").children.map(item => item.textContent), previousHistory,
                "Breakpoint maintenance added a synthetic address visit");
        }
    }
});

await check("T-UI-BREAKPOINT Stop during retained page delivery does not interrupt a completed engine request", async () =>
{
    const app = await memoryApp({ breakpointAuto: false });
    app.nodes.get("btn-breakpoints").fire("click");
    await app.reply("execute", { ok: true, result: { ok: true, resultId: "pending-breakpoint-page", rowCount: "2",
        data: { commandId: "breakpoints", status: "Success", target: stamp } } });
    const interrupts = app.messages.filter(item => item.method === "interrupt").length;
    app.nodes.get("btn-cancel").fire("click");
    assert.equal(app.messages.filter(item => item.method === "interrupt").length, interrupts);
    await app.reply("resultPage", { ok: true, result: { resultId: "pending-breakpoint-page", offset: "0",
        rows: breakpointFixture, complete: true } });
    assert.equal(app.nodes.get("btn-cancel").disabled, true);
    assert.equal(app.nodes.get("result-title").textContent, "retained-result");
    assert.match(app.nodes.get("breakpoint-notice").textContent, /cancelled/);
});

async function registerApp()
{
    const app = await memoryApp();
    app.nodes.get("registers-view").children.push(app.nodes.get("registers-grid"));
    app.nodes.get("registers-grid").children.push(app.nodes.get("registers-rows"));
    app.nodes.get("tab-registers").fire("click");
    await processStatus(app);
    assert.equal(app.latest("execute").params.command, "registers");
    return app;
}

async function registerReply(app, target = stamp, value = "0xffff800000001000", options = {})
{
    const request = app.latest("execute");
    const id = "registers-" + request.requestId;
    const rows = options.rows || [{ kind: "Register", name: "rip", value,
        context: { engineProcessId: "0", engineThreadId: "1", processor: "0",
            targetContext: { pid: "424", tid: "428", image: "fixture.exe", processor: "0", source: "SelectedImplicitThread" } } },
        { kind: "Register", name: "xmm0", value: null, rawBytes: "00 11 22 33" },
        { kind: "Register", name: "unavailable", value: null, rawBytes: null }];
    await app.deliver(request, { ok: true, result: { resultId: id, rowCount: String(rows.length),
        data: { commandId: "registers", status: "Partial", target } } });
    await app.reply("resultPage", { ok: true, result: { resultId: id, collection: "rows", offset: "0",
        total: String(rows.length), next: String(rows.length), complete: true, rows } });
    await processStatus(app, target);
}

await check("T-UI-REGISTERS retained values, raw vectors, unknowns and filtering do not replace Results", async () =>
{
    const app = await registerApp();
    await registerReply(app);
    assert.equal(app.nodes.get("result-title").textContent, "retained-result");
    const rows = app.nodes.get("registers-rows").children;
    assert.equal(rows[0].children[1].textContent, "0xffff800000001000");
    assert.equal(rows[1].children[1].textContent, "00 11 22 33");
    assert.equal(rows[2].children[1].textContent, "Unavailable");
    assert.equal(app.nodes.get("registers-context").textContent, "fixture.exe / PID 424 / TID 428 / CPU 0");
    assert.match(app.nodes.get("registers-context").title, /Engine process ID: 0; engine thread ID: 1/);
    assert.match(app.nodes.get("registers-context").title, /Selected implicit thread/);
    assert.match(app.nodes.get("registers-notice").textContent, /Unknown values are not zero/);
    app.nodes.get("registers-filter").value = "xmm";
    app.nodes.get("registers-filter").fire("input");
    assert.equal(app.nodes.get("registers-rows").children.length, 1);
    assert.equal(app.messages.filter(item => item.method === "execute" && item.params.command === "registers").length, 1);
});

await check("T-UI-REGISTERS unknown and legacy identities stay unavailable while zero IDs remain known", async () =>
{
    for (const targetContext of [null, { pid: "0", tid: "0", image: "Idle" }, { pid: "424", tid: null }])
    {
        const app = await registerApp();
        await registerReply(app, stamp, "0x1", { rows: [{ kind: "Register", name: "rip", value: "0x1",
            context: { processId: "0", threadId: "1", processor: "0", targetContext } }] });
        const label = app.nodes.get("registers-context").textContent;
        assert.match(label, targetContext === null ? /PID Unavailable \/ TID Unavailable/ :
            targetContext.pid === "0" ? /Idle \/ PID 0 \/ TID 0/ : /PID 424 \/ TID Unavailable/);
        assert.doesNotMatch(label, /Debugger process|TID 1\b/);
        assert.match(label, /CPU 0/);
    }
});

await check("T-UI-REGISTERS identity and address-space changes reset comparisons despite identical engine IDs", async () =>
{
    for (const changed of ["tid", "implicitThread", "implicitProcess"])
    {
        const app = await registerApp();
        const context = { engineProcessId: "0", engineThreadId: "1", processor: "0",
            targetContext: { pid: "424", tid: "428", image: "fixture.exe" },
            target: { contextIdentity: { implicitThread: "0xffff800000001000", implicitProcess: "0xffff800000002000" } } };
        const row = { kind: "Register", name: "rip", value: "0x1", context };
        await registerReply(app, stamp, "0x1", { rows: [row] });
        const nextContext = JSON.parse(JSON.stringify(context));
        if (changed === "tid")
        {
            nextContext.targetContext.tid = "432";
        }
        else
        {
            nextContext.target.contextIdentity[changed] = "0xffff800000003000";
        }
        app.nodes.get("btn-registers-refresh").fire("click");
        await registerReply(app, stamp, "0x2", { rows: [{ ...row, value: "0x2", context: nextContext }] });
        assert.equal(app.nodes.get("registers-rows").children[0].children[2].textContent, "");
        app.nodes.get("btn-registers-refresh").fire("click");
        await registerReply(app, stamp, "0x3", { rows: [{ ...row, value: "0x3", context: nextContext }] });
        assert.equal(app.nodes.get("registers-rows").children[0].children[2].textContent, "Changed");
    }
});

await check("T-UI-REGISTERS typed registers and r snapshots preserve the Inspect capture and filter", async () =>
{
    const app = await registerApp();
    await registerReply(app);
    app.nodes.get("registers-filter").value = "rip";
    app.nodes.get("registers-filter").fire("input");
    const retained = app.nodes.get("registers-rows").children[0];
    for (const command of ["registers", "r"])
    {
        app.enter(command);
        await app.reply("classify", { ok: true, result: { write: false } });
        assert.equal(app.latest("execute").params.command, command);
        const id = "snapshot-" + command;
        await app.reply("execute", { ok: true, result: { resultId: id, command,
            rowCount: "1", outputLength: "0", data: { commandId: "registers", status: "Success", target: stamp } } });
        await app.reply("resultPage", { ok: true, result: { resultId: id, collection: "rows", offset: "0",
            complete: true, rows: [{ kind: "Register", name: "rip", value: "0xffff800000002000" }] } });
        await app.reply("outputChunk", { ok: true, result: { resultId: id, offset: "0", next: "0", complete: true, text: "" } });
        await processStatus(app);
        assert.equal(app.nodes.get("btn-results").getAttribute("aria-pressed"), "true");
        assert.equal(tableCell(app, 0, "Value"), "0xffff800000002000");
        assert.equal(app.nodes.get("tab-registers").getAttribute("aria-selected"), "true");
        assert.equal(app.nodes.get("registers-filter").value, "rip");
        assert.equal(app.nodes.get("registers-rows").children[0], retained);
        assert.equal(retained.children[1].textContent, "0xffff800000001000");
    }
});

await check("T-UI-REGISTERS stops refresh once, highlight changed values and refuse reads while running", async () =>
{
    const app = await registerApp();
    await registerReply(app);
    app.nodes.get("registers-scope").value = "all";
    app.nodes.get("registers-scope").fire("change");
    app.nodes.get("registers-rows").children[1].children[2].children[0].fire("click");
    assert.equal(app.nodes.get("registers-rows").children[0].children[0].textContent, "xmm0");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, stamp, { stopped: false, execStatus: "go" });
    assert.equal(app.nodes.get("btn-registers-refresh").disabled, true);
    assert.match(app.nodes.get("registers-notice").textContent, /previous capture/);
    const next = { ...stamp, stopEpoch: "3", contextGeneration: "5" };
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, next);
    await registerReply(app, next, "0xffff800000001004");
    assert.equal(app.nodes.get("registers-rows").children[0].children[0].textContent, "xmm0");
    assert.equal(app.nodes.get("registers-rows").children[0].children[2].textContent, "");
    assert.equal(app.nodes.get("registers-rows").children[1].children[0].textContent, "rip");
    assert.equal(app.nodes.get("registers-rows").children[1].children[2].textContent, "Changed");
    app.nodes.get("registers-scope").value = "changed";
    app.nodes.get("registers-scope").fire("change");
    assert.equal(app.nodes.get("registers-rows").children.length, 1);
    assert.equal(app.nodes.get("registers-rows").children[0].children[0].textContent, "rip");
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, next);
    assert.equal(app.messages.filter(item => item.method === "execute" && item.params.command === "registers").length, 2);
});

await check("T-UI-REGISTERS invalid pages, read failure and cancellation retain the previous capture", async () =>
{
    for (const failure of ["page", "execute", "cancel", "stale"])
    {
        const app = await registerApp();
        await registerReply(app);
        const previous = app.nodes.get("registers-rows").children[0];
        app.nodes.get("btn-registers-refresh").fire("click");
        if (failure === "execute")
        {
            await app.reply("execute", { ok: false, error: "Register engine unavailable" });
        }
        else
        {
            await app.reply("execute", { ok: true, result: { resultId: "pending-registers", rowCount: "1",
                data: { commandId: "registers", status: "Success", target: stamp } } });
            if (failure === "cancel")
            {
                app.nodes.get("btn-cancel").fire("click");
            }
            if (failure === "stale")
            {
                app.nodes.get("btn-refresh-status").fire("click");
                await processStatus(app, { ...stamp, stopEpoch: "4" }, { stopped: false });
            }
            await app.reply("resultPage", { ok: true, result: { resultId: "pending-registers", collection: "rows", offset: "0",
                total: "1", next: failure === "page" ? "0" : "1", complete: true,
                rows: [{ kind: "Register", name: "rip", value: "0x2222" }] } });
        }
        assert.equal(app.nodes.get("registers-rows").children[0], previous, failure);
        assert.ok(app.nodes.get("registers-notice").textContent);
    }
});

await check("T-UI-REGISTERS hidden panels do not collect until reopened and failed stops do not loop", async () =>
{
    const app = await registerApp();
    await app.reply("execute", { ok: false, error: "Unavailable" });
    await processStatus(app);
    assert.equal(app.messages.filter(item => item.method === "execute" && item.params.command === "registers").length, 1);
    app.nodes.get("tab-memory-view").fire("click");
    app.nodes.get("btn-refresh-status").fire("click");
    const next = { ...stamp, stopEpoch: "6" };
    await processStatus(app, next);
    assert.equal(app.messages.filter(item => item.method === "execute" && item.params.command === "registers").length, 1);
    app.nodes.get("tab-registers").fire("click");
    await processStatus(app, next);
    assert.equal(app.messages.filter(item => item.method === "execute" && item.params.command === "registers").length, 2);
});

const diagnosticTarget = { ...stamp, contextIdentity: { system: "0x0", process: "0x0", thread: "0x1",
    implicitProcess: "0xffff800000001000", implicitThread: "0xffff800000002000", effectiveArchitecture: "0x8664",
    scopeInstruction: "0xfffff80000101000", scopeStack: "0xffff800000003000", scopeFrame: "0xffff800000003010", scopeIndex: "0x0" } };
const diagnosticModule = { name: "nt", key: { base: "0xfffff80000000000", size: "1048576", timestamp: "123", checksum: "456" }, loadState: "Deferred" };

async function diagnosticApp()
{
    const app = harness();
    await app.reply("hello", { ok: true, result: { target: diagnosticTarget,
        capabilities: ["contextExplanation.v1", "symbolHealth.v1", "operationObservation.v1"] } });
    await app.reply("catalog", { ok: true, result: { groups: {} } });
    await processStatus(app, diagnosticTarget, { currentProcessor: "1", currentProcess: { image: "observed.exe", pid: "44",
        eprocess: diagnosticTarget.contextIdentity.implicitProcess } });
    return app;
}

function diagnosticText(app, id)
{
    return app.nodes.get(id).children.map(node => node.textContent).join("\n");
}

async function diagnosticModules(app)
{
    app.nodes.get("btn-context").fire("click");
    app.nodes.get("btn-context-symbols").fire("click");
    app.nodes.get("btn-symbol-modules").fire("click");
    await app.reply("symbolModules", { ok: true, result: { ok: true, target: diagnosticTarget, modules: [diagnosticModule],
        total: "1", nextCursor: "1", complete: true, unknown: "0" } });
    await processStatus(app, diagnosticTarget);
}

function diagnosticHealth(overrides = {})
{
    return { ok: true, target: diagnosticTarget, module: { ...diagnosticModule, loadState: "PDB" }, imageMatch: "Matched",
        pdbIdentity: { guid: "fixture-guid", age: "1" }, typeInformation: true, requestedType: { name: "_EPROCESS",
            field: "UniqueProcessId", state: "Available", size: "4096", fieldOffset: "0", nativeError: null },
        reloadDraft: ".reload /f nt", nativeError: null, metadataReason: "", ...overrides };
}

await check("T-UI-P0 Context and Symbols open from cache without an engine request", async () =>
{
    const app = await diagnosticApp();
    const requests = app.messages.length;
    app.nodes.get("btn-context").fire("click");
    assert.equal(app.messages.length, requests);
    const text = diagnosticText(app, "context-fields");
    assert.match(text, /observed\.exe \/ 44/);
    assert.match(text, /debugger ID, not OS TID/);
    assert.match(text, /Unknown.*external \.trap/);
    assert.match(text, /No row selected/);
    assert.equal(app.nodes.get("context-panel").classList.contains("hidden"), false);
    app.nodes.get("btn-context-symbols").fire("click");
    assert.equal(app.messages.length, requests);
    assert.equal(app.nodes.get("btn-symbol-inspect").disabled, true);
    app.nodes.get("btn-context-refresh").fire("click");
    assert.equal(app.messages.length, requests + 1);
    assert.equal(app.latest("status").method, "status");
});

await check("T-UI-P0 selected process remains distinct from observed address and register context", async () =>
{
    const app = await diagnosticApp();
    showProcesses(app);
    await processStatus(app, diagnosticTarget);
    await collectProcessPages(app, processRows.slice(0, 2), { target: diagnosticTarget });
    app.nodes.get("process-rows").children[1].fire("click");
    const reads = app.messages.filter(message => message.method === "processAction").length;
    app.nodes.get("btn-context").fire("click");
    const text = diagnosticText(app, "context-fields");
    assert.match(text, /process1\.exe/);
    assert.match(text, /Implicit EPROCESS 0xffff800000001000/);
    assert.match(text, /0xffff800000002000/);
    assert.match(text, /UI selection only/);
    assert.equal(app.messages.filter(message => message.method === "processAction").length, reads);
});

await check("T-UI-P0 legacy host lacks new symbol actions without weakening existing context browsing", async () =>
{
    const app = harness();
    await app.boot();
    app.nodes.get("btn-context").fire("click");
    app.nodes.get("btn-context-symbols").fire("click");
    assert.match(app.nodes.get("symbol-status").textContent, /does not advertise/);
    app.nodes.get("btn-symbol-modules").fire("click");
    assert.equal(app.messages.some(message => message.method === "symbolModules"), false);
});

await check("T-UI-P0 symbol inspection separates missing fields from PDB identity and only drafts reload", async () =>
{
    const app = await diagnosticApp();
    await diagnosticModules(app);
    assert.equal(app.nodes.get("btn-symbol-inspect").disabled, false);
    assert.match(diagnosticText(app, "symbol-fields"), /Deferred.*inventory observation/);
    app.nodes.get("symbol-type").value = "_EPROCESS";
    app.nodes.get("symbol-field").value = "Absent";
    app.nodes.get("btn-symbol-inspect").fire("click");
    assert.deepEqual(JSON.parse(JSON.stringify(app.latest("symbolHealth").params.moduleKey)), diagnosticModule.key);
    await app.reply("symbolHealth", { ok: true, result: diagnosticHealth({ requestedType: { name: "_EPROCESS", field: "Absent",
        state: "FieldUnavailable", size: "4096", fieldOffset: null, nativeError: "0x80004005" } }) });
    await processStatus(app, diagnosticTarget);
    const text = diagnosticText(app, "symbol-fields");
    assert.match(text, /Matched/);
    assert.match(text, /FieldUnavailable.*0x80004005/);
    assert.equal(app.nodes.get("btn-symbol-reload-draft").disabled, false);
    app.nodes.get("btn-symbol-reload-draft").fire("click");
    assert.equal(app.nodes.get("prompt").value, ".reload /f nt");
    assert.equal(app.messages.some(message => message.method === "execute" || message.method === "executePlan"), false);
});

await check("T-UI-P0 malformed module pages and expression-like types do not become live inspection", async () =>
{
    const app = await diagnosticApp();
    app.nodes.get("btn-context").fire("click");
    app.nodes.get("btn-context-symbols").fire("click");
    app.nodes.get("btn-symbol-modules").fire("click");
    await app.reply("symbolModules", { ok: true, result: { ok: true, target: diagnosticTarget,
        modules: [{ ...diagnosticModule, key: { ...diagnosticModule.key, base: 123 } }], total: "1", nextCursor: "1", complete: true, unknown: "0" } });
    await processStatus(app, diagnosticTarget);
    assert.match(app.nodes.get("symbol-status").textContent, /malformed/);
    assert.equal(app.nodes.get("btn-symbol-inspect").disabled, true);
    app.nodes.get("btn-symbol-modules").fire("click");
    await app.reply("symbolModules", { ok: true, result: { ok: true, target: diagnosticTarget, modules: [diagnosticModule],
        total: "1", nextCursor: "1", complete: true, unknown: "0" } });
    await processStatus(app, diagnosticTarget);
    app.nodes.get("symbol-type").value = "_EPROCESS;g";
    app.nodes.get("btn-symbol-inspect").fire("click");
    assert.match(app.nodes.get("symbol-status").textContent, /simple type/);
    assert.equal(app.messages.some(message => message.method === "symbolHealth"), false);
});

await check("T-UI-P0 module paging rejects duplicate identities and late symbol replies remain historical", async () =>
{
    const app = await diagnosticApp();
    await diagnosticModules(app);
    app.nodes.get("btn-symbol-inspect").fire("click");
    await app.reply("symbolHealth", { ok: true, result: diagnosticHealth() });
    await processStatus(app, diagnosticTarget);
    app.nodes.get("btn-symbol-inspect").fire("click");
    const pending = app.latest("symbolHealth");
    const next = { ...diagnosticTarget, contextGeneration: "9" };
    app.nodes.get("btn-refresh-status").fire("click");
    await processStatus(app, next);
    await app.deliver(pending, { ok: true, result: diagnosticHealth({ imageMatch: "Mismatched" }) });
    await processStatus(app, next);
    const text = diagnosticText(app, "symbol-fields");
    assert.match(text, /Historical/);
    assert.match(text, /Matched/);
    assert.doesNotMatch(text, /Mismatched/);
    assert.equal(app.nodes.get("btn-symbol-inspect").disabled, true);
    assert.equal(app.nodes.get("btn-symbol-reload-draft").disabled, true);
    app.nodes.get("btn-symbol-modules").fire("click");
    const page = { ok: true, target: next, modules: [diagnosticModule], total: "2", nextCursor: "1", complete: false, unknown: "0" };
    await app.reply("symbolModules", { ok: true, result: page });
    await app.reply("symbolModules", { ok: true, result: { ...page, nextCursor: "2", complete: true } });
    await processStatus(app, next);
    assert.match(app.nodes.get("symbol-status").textContent, /changed while paging/);
    assert.equal(app.nodes.get("btn-symbol-inspect").disabled, true);
});

await check("T-UI-P0 module inventory display limit holds across pages with unavailable entries", async () =>
{
    const app = await diagnosticApp();
    app.nodes.get("btn-context").fire("click");
    app.nodes.get("btn-context-symbols").fire("click");
    for (let batch = 0; batch < 9; ++batch)
    {
        app.nodes.get(batch === 0 ? "btn-symbol-modules" : "btn-symbol-more").fire("click");
        const pages = batch === 8 ? 1 : 8;
        for (let page = 0; page < pages; ++page)
        {
            const first = batch * 512 + page * 64;
            const next = first + 64;
            const modules = Array.from({ length: first === 0 ? 63 : 64 }, (_, offset) => ({ ...diagnosticModule,
                key: { ...diagnosticModule.key, base: "0x" + (0xffff800000000000n + BigInt(first + offset) * 1048576n).toString(16) } }));
            await app.reply("symbolModules", { ok: true, result: { ok: true, target: diagnosticTarget, modules,
                total: "4160", nextCursor: String(next), complete: next === 4160, unknown: first === 0 ? "1" : "0" } });
        }
        await processStatus(app, diagnosticTarget);
    }
    assert.equal(app.nodes.get("symbol-module").children.length, 4096);
    assert.equal(app.nodes.get("btn-symbol-more").disabled, true);
    assert.match(app.nodes.get("symbol-status").textContent, /4096-module display limit reached/);
});

await check("T-UI-P0 automatic inspection pause keeps context polling and explicit reads available", async () =>
{
    const app = await diagnosticApp();
    app.nodes.get("pause-inspection-reads").checked = true;
    app.nodes.get("pause-inspection-reads").fire("change");
    showProcesses(app);
    await processStatus(app, diagnosticTarget);
    app.nodes.get("tab-registers").fire("click");
    await processStatus(app, diagnosticTarget);
    assert.equal(app.messages.some(message => message.method === "execute"), false);
    assert.match(app.nodes.get("process-summary").textContent, /automatic reads paused/);
    assert.match(app.nodes.get("registers-summary").textContent, /Automatic reads are paused.*Use Refresh/);
    assert.equal(app.nodes.get("btn-disassembly-follow").textContent, "IP follow suspended");
    app.nodes.get("btn-disassembly-follow").fire("click");
    assert.equal(app.nodes.get("btn-disassembly-follow").textContent, "IP follow paused");
    app.nodes.get("btn-disassembly-follow").fire("click");
    assert.equal(app.nodes.get("btn-disassembly-follow").textContent, "IP follow suspended");
    assert.match(app.nodes.get("disassembly-summary").textContent, /automatic reads paused/);
    app.advanceTime(3000);
    await settle();
    assert.ok(app.latest("status"));
    await processStatus(app, diagnosticTarget);
    app.nodes.get("btn-registers-refresh").fire("click");
    assert.equal(app.latest("execute").params.command, "registers");
    await app.reply("execute", { ok: false, error: "Unavailable" });
    await processStatus(app, diagnosticTarget);
    assert.match(app.nodes.get("btn-context").textContent, /reads paused/);
});

await check("T-UI-P0 live Operations polling uses host receipts and preserves focusable rows while waiting", async () =>
{
    const app = await diagnosticApp();
    app.nodes.get("btn-operations").fire("click");
    const observation = { stage: "SymbolQuery", elapsedMs: "1000", stageElapsedMs: "800", sinceProgressMs: "700", cancelElapsedMs: null, waitReason: null };
    const record = { operationId: "7", requestId: "88", method: "symbolHealth", phase: "Running", delivery: "Pending", observation };
    await app.reply("operations", { ok: true, result: { records: [record], next: "7", complete: true } });
    await app.reply("operationStatus", { ok: true, result: record });
    const row = app.nodes.get("operations-list").children[0];
    assert.match(row.children[1].textContent, /Symbol API call.*elapsed 1.0s/);
    app.advanceTime(1500);
    await settle();
    assert.equal(app.latest("operationStatus").params.operationId, "7");
    await app.reply("operationStatus", { ok: true, result: { ...record, phase: "CancelRequested",
        observation: { ...observation, elapsedMs: "2500", cancelElapsedMs: "500" } } });
    assert.equal(app.nodes.get("operations-list").children[0], row);
    assert.match(row.children[1].textContent, /wait cause unconfirmed/);
    assert.match(row.children[1].textContent, /execution has not completed/);
    assert.equal(app.messages.some(message => message.method === "symbolHealth" || message.method === "execute"), false);
    app.nodes.get("btn-operations-close").fire("click");
    assert.equal([...app.timerDelays.values()].includes(1500), false);
});

await check("T-UI-P0 live Operations marks missing or mismatched receipts unknown", async () =>
{
    for (const failure of ["expired", "identity", "malformed"])
    {
        const app = await diagnosticApp();
        app.nodes.get("btn-operations").fire("click");
        const record = { operationId: "7", method: "symbolHealth", phase: "Running", observation: {
            stage: "SymbolQuery", elapsedMs: "1000", stageElapsedMs: "800", sinceProgressMs: "700" } };
        await app.reply("operations", { ok: true, result: { records: [record], next: "7", complete: true } });
        await app.reply("operationStatus", { ok: true, result: record });
        app.advanceTime(1500);
        await settle();
        await app.reply("operationStatus", failure === "expired" ? { ok: false, error: "OperationUnknownOrExpired" } :
            { ok: true, result: failure === "identity" ? { ...record, operationId: "8" } : {} });
        const row = app.nodes.get("operations-list").children[0];
        assert.match(row.children[0].textContent, /#7.*Unknown/, failure);
        assert.match(row.children[1].textContent, /unconfirmed/i, failure);
        assert.equal(row.classList.contains("unknown"), true, failure);
        assert.equal(app.messages.some(message => message.method === "execute" || message.method === "symbolHealth"), false);
    }
});

await check("T-UI-P0 live Operations acknowledges a terminal receipt only after displaying it", async () =>
{
    const app = await diagnosticApp();
    app.nodes.get("btn-operations").fire("click");
    const record = { operationId: "7", method: "symbolHealth", phase: "Running", delivery: "Pending",
        observation: { stage: "SymbolQuery", elapsedMs: "1000", stageElapsedMs: "800", sinceProgressMs: "700" } };
    await app.reply("operations", { ok: true, result: { records: [record], next: "7", complete: true } });
    await app.reply("operationStatus", { ok: true, result: record });
    let displayedAtAck = false;
    app.onPost(request =>
    {
        if (request.method === "operationAck")
        {
            displayedAtAck = /Completed/.test(app.nodes.get("operations-list").children[0].children[0].textContent);
        }
    });
    app.advanceTime(1500);
    await settle();
    await app.reply("operationStatus", { ok: true, result: { ...record, phase: "Completed", ok: true, outcome: "Success" } });
    assert.equal(app.latest("operationAck")?.params.operationId, "7");
    assert.equal(displayedAtAck, true);
    assert.doesNotMatch(app.nodes.get("operations-list").children[0].children[1].textContent, /Acknowledged/);
    await app.reply("operationAck", { ok: true, result: true });
    assert.match(app.nodes.get("operations-list").children[0].children[1].textContent, /Acknowledged/);
    assert.equal(app.messages.filter(message => message.method === "operationAck").length, 1);
});

await check("T-UI-P0 hiding Operations stops queued receipt queries", async () =>
{
    const app = await diagnosticApp();
    app.nodes.get("btn-operations").fire("click");
    const records = ["7", "8"].map(operationId => ({ operationId, method: "symbolHealth", phase: "Running" }));
    await app.reply("operations", { ok: true, result: { records, next: "8", complete: true } });
    await app.reply("operationStatus", { ok: true, result: records[0] });
    await app.reply("operationStatus", { ok: true, result: records[1] });
    app.advanceTime(1500);
    await settle();
    const queries = app.messages.filter(message => message.method === "operationStatus").length;
    app.visibility(true);
    await app.reply("operationStatus", { ok: true, result: records[0] });
    assert.equal(app.messages.filter(message => message.method === "operationStatus").length, queries);
});

await check("T-UI-ASYNC no unhandled rejections in fault scenarios", () =>
{
    assert.deepEqual(unhandled.map(error => error.message), []);
});

process.exitCode = failures ? 1 : 0;
