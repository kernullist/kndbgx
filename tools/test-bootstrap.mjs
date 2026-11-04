import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(root, "ui/index.html"), "utf8");
const script = fs.readFileSync(path.join(root, "ui/app.js"), "utf8");
let failures = 0;

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

async function boot(source)
{
    const tag = /<script\b[^>]*\bsrc="\/app.js"[^>]*><\/script>/.exec(source);
    assert.ok(tag, "app.js script tag missing");
    const visibleHtml = /\bdefer\b/.test(tag[0]) ? source : source.slice(0, tag.index);
    const nodes = new Map();
    const messages = [];
    let receive;
    const makeNode = () => ({
        textContent: "", value: "", className: "", children: [], style: {}, dataset: {}, attributes: {},
        classList: { add() {}, remove() {}, contains() { return true; } },
        addEventListener() {}, focus() {},
        getBoundingClientRect()
        {
            return { top: 0, bottom: 0, left: 0, right: 0, width: 0, height: 0 };
        },
        setAttribute(name, value)
        {
            this.attributes[name] = String(value);
        },
        getAttribute(name)
        {
            return this.attributes[name] ?? null;
        },
        appendChild(child) { this.children.push(child); },
        contains(child)
        {
            return child === this || this.children.some(item => item.contains(child));
        },
        querySelectorAll() { return []; }
    });
    for (const match of visibleHtml.matchAll(/\bid="([^"]+)"/g))
    {
        nodes.set(match[1], makeNode());
    }
    const document = {
        getElementById(id) { return nodes.get(id) ?? null; },
        createElement: makeNode,
        addEventListener() {}
    };
    const window = {
        chrome: { webview: { addEventListener(name, fn) { receive = fn; }, postMessage(m) { messages.push(m); } } },
        addEventListener() {}
    };
    vm.runInNewContext(script, { window, document, performance, setTimeout() { return 1; }, clearTimeout() {}, console });
    const hello = messages.find(m => m.method === "hello");
    if (hello) {
        receive({ data: { schema: "kndbgx.rpc.v3", requestId: hello.requestId,
            uiGeneration: "7", type: "completed", ok: true,
            result: { target: { sessionId: "fixture", targetGeneration: "1" } } } });
        await Promise.resolve();
        await Promise.resolve();
    }
    return messages;
}

await check("T-BOOT-01 product HTML sends startup requests exactly once", async () =>
{
    assert.deepEqual((await boot(html)).map(m => m.method).sort(), ["catalog", "hello", "status"]);
});

await check("T-BOOT-01 negative control detects original script order", async () =>
{
    const original = html.replace(/(<script\b[^>]*?)\sdefer\b/, "$1");
    let detected = false;
    try
    {
        detected = (await boot(original)).length !== 4;
    }
    catch
    {
        detected = true;
    }
    assert.ok(detected, "regression test did not detect premature bootstrap");
});

await check("T-BUILD-01 solution project blocks are balanced", () =>
{
    let open = false;
    let count = 0;
    for (const line of fs.readFileSync(path.join(root, "kndbgx.sln"), "utf8").split(/\r?\n/))
    {
        if (line.startsWith("Project("))
        {
            assert.equal(open, false, "nested project declaration");
            open = true;
            ++count;
        }
        if (line === "EndProject")
        {
            assert.equal(open, true, "unmatched EndProject");
            open = false;
        }
    }
    assert.equal(open, false, "unclosed project");
    assert.equal(count, 2);
});

process.exitCode = failures === 0 ? 0 : 1;
