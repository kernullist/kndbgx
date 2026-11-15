// Optional real-layout regression suite. Requires Playwright and Microsoft Edge.
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const evidence = process.argv[2] ? path.resolve(process.argv[2]) : null;

async function main()
{
    const server = http.createServer((request, response) =>
    {
        const name = request.url === "/" ? "index.html" : request.url.slice(1);
        if (!["index.html", "app.js", "app.css"].includes(name))
        {
            response.writeHead(404).end();
            return;
        }
        response.setHeader("Content-Type", name.endsWith("css") ? "text/css" : name.endsWith("js") ? "application/javascript" : "text/html");
        response.end(fs.readFileSync(path.join(root, "ui", name)));
    });
    let browser;
    let failures = 0;
    try
    {
        if (evidence)
        {
            fs.mkdirSync(evidence, { recursive: true });
        }
        await new Promise((resolve, reject) =>
        {
            server.once("error", reject);
            server.listen(0, "127.0.0.1", resolve);
        });
        browser = await chromium.launch({ channel: "msedge", headless: true });
        const context = await browser.newContext({ viewport: { width: 900, height: 720 } });
        await context.grantPermissions(["clipboard-read", "clipboard-write"]);
        const page = await context.newPage();
        const errors = [];
        page.on("pageerror", error => errors.push(error.message));
        const fixtureInit = (options = {}) =>
        {
            // Older feature scenarios exercise an explicitly expanded workspace.
            // Workspace UX scenarios below verify the new defaults independently.
            if (!options.adaptiveLayout)
            {
                if (!window.localStorage.getItem("kndbgx.workspace-layout"))
                {
                    window.localStorage.setItem("kndbgx.workspace-layout", JSON.stringify({ console: true, details: true }));
                }
                document.addEventListener("DOMContentLoaded", () =>
                {
                    document.querySelectorAll(".inspection-options, .address-history-menu").forEach(node => node.open = true);
                });
            }
            if (options.followExecution)
            {
                window.localStorage.setItem("kndbgx.disassembly-follow", "on");
                window.localStorage.setItem("kndbgx.memory-panel", JSON.stringify({ visible: true, width: 520, tab: "memory" }));
            }
            let receive;
            const stamp = { sessionId: "browser-fixture", targetGeneration: "1", stopEpoch: "1", contextGeneration: "1", symbolGeneration: "1" };
            const fields = Object.fromEntries(Array.from({ length: 32 }, (_, i) => ["field" + i, i]));
            window.knTestRequests = [];
            window.knTestOperationPolls = 0;
            window.knTestOperationOverrides = {};
            window.knTestInspectionEpoch = "0";
            window.knTestInspectionVisible = false;
            window.knTestInspectionStates = {};
            window.knTestHoldInspectionShow = options.holdInspectionShow === true;
            window.knTestPendingInspection = [];
            window.knTestFailInspectionAction = "";
            window.knTestReleaseInspection = () => window.knTestPendingInspection.splice(0).forEach(deliver => deliver());
            window.knTestCloseInspectionFrame = token =>
            {
                const request = window.knTestRequests.findLast(item => item.method === "inspectionWindow");
                token = token || request.params.token;
                const state = window.knTestInspectionStates[token] ||= { epoch: "0", visible: false };
                window.knTestInspectionEpoch = state.epoch = String(BigInt(state.epoch) + 1n);
                state.visible = false;
                window.knTestInspectionVisible = false;
                receive({ data: { schema: "kndbgx.rpc.v3", requestId: "", type: "inspectionHidden", uiGeneration: "7",
                    token, visibilityEpoch: state.epoch } });
            };
            window.knTestDockDrag = message => receive({ data: { schema: "kndbgx.rpc.v3", requestId: "",
                type: "inspectionDockDrag", uiGeneration: "7", visibilityEpoch: "0", destinationToken: "",
                destinationEpoch: "0", ...message } });
            const breakpointPlans = new Map();
            const resultCommands = new Map();
            let breakpointSequence = 0;
            window.knTestHoldStatus = options.holdStatus === true;
            window.knTestStopped = true;
            window.knTestLastEvent = options.lastEvent || null;
            window.knTestBreakpointSequence = options.breakpointSequence;
            window.knTestCurrentProcess = { image: "System", pid: "4", eprocess: "0xffff800000001000" };
            stamp.contextIdentity = { implicitProcess: window.knTestCurrentProcess.eprocess, scopeInstruction: "0xffff800000001000" };
            window.knTestInstructionPointer = stamp.contextIdentity.scopeInstruction;
            window.knTestBreak = address =>
            {
                window.knTestStopped = true;
                window.knTestInstructionPointer = address;
                stamp.stopEpoch = String(Number(stamp.stopEpoch) + 1);
                stamp.contextGeneration = String(Number(stamp.contextGeneration) + 1);
                stamp.contextIdentity.scopeInstruction = address;
                return JSON.parse(JSON.stringify(stamp));
            };
            const fixtures = {
                "!hiddenproc": options.processComparisonRows || [],
                "address-menus": [{ kind: "Module", name: "second", base: "0xffff800000003000" },
                    { kind: "Module", name: "first", base: "0xffff800000001000" }],
                "mixed-address-menu": [{ kind: "PageTranslation", va: "0xffff800000004000", pa: "0x0000000000000000",
                    flags: "0xffff800000008000" }],
                "foreign-address-menu": [{ kind: "Address", address: "0x0000000012340000", addressSpace: "virtual",
                    sourceFile: "sample.cpp", process: { eprocess: "0xffff800000002000" } }],
                "copy-only-address-menu": [{ kind: "Address", address: "0xffff800000003000", addressSpace: "virtual", sourceFile: "sample.cpp" }],
                stack: options.stack || [{ kind: "StackFrame", instruction: "0xffff800000001000", symbol: "sample!Frame" }],
                registers: options.registers || [{ kind: "Register", name: "rip", value: "0xffff800000001000" }],
                event: [{ kind: "LastEvent", description: "Fixture breakpoint" }],
                breakpoints: options.breakpoints || [],
                "!dml_proc": options.processes || Array.from({ length: 257 }, (_, i) => ({ kind: "Process", pid: String(i * 4), image: "process" + i + ".exe",
                    eprocess: "0xffff8000" + (0x1000 + i * 0x100).toString(16).padStart(8, "0"), dtb: "0x12345000",
                    createTime: "18446744073709551000" })),
                "!callbacks": options.callbackNavigation ? [
                    { kind: "RoutineObservation", callbackType: "Notify.Process", routine: "0xffff800000006000", symbol: "sample!Notify" },
                    { kind: "ObjectCallbackRegistration", callbackType: "Object.Process", preRoutine: "0xffff800000003000",
                        postRoutine: "0xffff800000004000", preSymbol: "sample!PreProcess", postSymbol: "sample!PostProcess" },
                    { kind: "ObjectCallbackRegistration", callbackType: "Object.Thread", preRoutine: "0xffff800000001000",
                        postRoutine: "0xffff800000002000", preSymbol: "sample!PreThread", postSymbol: "sample!PostThread" },
                    { kind: "ObjectCallbackRegistration", callbackType: "Object.Desktop", preRoutine: "0xffff800000005000",
                        postRoutine: "0x0000000000000000", preSymbol: "sample!PreDesktop", postSymbol: null, postSymbolSource: "NotRegistered" }
                ] : Array.from({ length: 300 }, (_, i) => ({ kind: "RoutineObservation", family: "ProcessNotify",
                    routine: "0xffff800000001008", module: "sample.sys", ownership: "KnownModule", ...fields,
                    message: "\uafc0\ubcf4 <&>\n".repeat(1000), flag: false, empty: "", unknown: null, nul: "before\u0000after",
                    ...(i >= 128 ? { laterField: i } : {}) })),
                "!msrcheck": [
                    { kind: "ProcessorRegister", cpu: "0", register: "LSTAR", value: "0xffff800000123456", registerSource: "CurrentProcessorMsr" },
                    { kind: "ProcessorRegister", cpu: "1", register: "LSTAR", value: null, registerSource: "CurrentProcessorMsr", unavailableReason: "ProcessorSwitchRequired" }
                ],
                "sort-fixture": Array.from({ length: 260 }, (_, i) => ({ kind: "Process", pid: String(260 - i),
                    image: "process" + (260 - i) + ".exe", eprocess: "0x" + (0xffffffffffffffffn - BigInt(i)).toString(16) })),
                "code-fixture": Array.from({ length: 3 }, (_, i) => ({ kind: "Symbol", symbol: "sample!Routine" + i,
                    address: "0xffff80000000100" + i * 4, addressSpace: "virtual" })),
                "db nt L10": [],
                "!hv": [],
                "help ui": [],
                "notice-fixture": []
            };
            const reply = (request, result) => queueMicrotask(() => receive({ data: {
                schema: "kndbgx.rpc.v3", requestId: request.requestId, type: "completed", uiGeneration: "7", ok: true,
                result: JSON.parse(JSON.stringify(result))
            } }));
            window.knTestHoldSymbols = options.holdSymbols === true;
            window.knTestSymbolError = options.symbolError || "";
            window.knTestPendingSymbols = [];
            window.knTestReleaseSymbols = () =>
            {
                const pending = window.knTestPendingSymbols.splice(0);
                pending.forEach(deliver => deliver());
            };
            window.knTestChangeContext = () =>
            {
                stamp.contextGeneration = String(Number(stamp.contextGeneration) + 1);
                window.knTestCurrentProcess = { image: "changed.exe", pid: "88", eprocess: "0xffff800000009000" };
                stamp.contextIdentity = { implicitProcess: window.knTestCurrentProcess.eprocess, scopeInstruction: "0xffff800000009000" };
            };
            window.chrome = window.chrome || {};
            window.chrome.webview = {
                addEventListener(name, callback)
                {
                    receive = callback;
                },
                postMessage(request)
                {
                    window.knTestRequests.push(request);
                    const params = request.params;
                    if (request.method === "resultTabs")
                    {
                        reply(request, { missing: [] });
                    }
                    else if (request.method === "status" && window.knTestBusy)
                    {
                        queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                            type: "completed", uiGeneration: "7", ok: false, error: "EngineBusy" } }));
                        return;
                    }
                    if (request.method === "status" && window.knTestStatusError)
                    {
                        queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                            type: "completed", uiGeneration: "7", ok: false, error: window.knTestStatusError } }));
                        return;
                    }
                    if (request.method === "hello" || request.method === "status")
                    {
                        const deliver = () => reply(request, { connected: true, kernelMode: true, stopped: window.knTestStopped,
                            canAttachProcess: window.knTestStopped, canEditBreakpoints: window.knTestStopped, execStatus: window.knTestStopped ? "break" : "go", target: stamp,
                            currentProcess: window.knTestCurrentProcess, canControlExecution: window.knTestStopped,
                            canBreakExecution: !window.knTestStopped,
                            capabilities: options.diagnostics ? ["contextExplanation.v1", "operationObservation.v1", "symbolHealth.v1"] : [],
                            currentProcessor: options.diagnostics ? "0" : undefined,
                            lastEvent: window.knTestLastEvent,
                            breakpointSequence: window.knTestBreakpointSequence,
                            instructionPointer: options.followExecution && window.knTestStopped ? window.knTestInstructionPointer : undefined });
                        if (request.method === "status" && window.knTestHoldStatus)
                        {
                            window.knTestReleaseStatus = deliver;
                        }
                        else
                        {
                            deliver();
                        }
                    }
                    else if (request.method === "symbolModules" && options.diagnostics)
                    {
                        reply(request, { ok: true, target: stamp, total: "1", unknown: "0", nextCursor: "1", complete: true,
                            modules: [{ name: "nt", loadState: "Deferred", key: { base: "0xffff800000001000",
                                size: "1048576", timestamp: "123", checksum: "456" } }] });
                    }
                    else if (request.method === "symbolHealth" && options.diagnostics)
                    {
                        reply(request, { ok: true, target: stamp, module: { key: params.moduleKey, name: "nt", loadState: "PDB" },
                            imageMatch: "Matched", pdbIdentity: { guid: "{11111111-2222-3333-4444-555555555555}", age: "1" },
                            typeInformation: true, requestedType: { name: params.typeName, field: params.fieldName,
                                state: params.fieldName ? "FieldUnavailable" : "NotRequested", size: "2048", fieldOffset: null,
                                nativeError: params.fieldName ? "0x80004005" : null }, reloadDraft: ".reload /f nt" });
                    }
                    else if (request.method === "inspectionWindow")
                    {
                        const inspection = window.knTestInspectionStates[params.token] ||= { epoch: "0", visible: false };
                        const deliver = () =>
                        {
                            if (["show", "restore", "hide", "recover"].includes(params.action) && params.visibilityEpoch !== undefined &&
                                params.visibilityEpoch !== inspection.epoch)
                            {
                                receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId, type: "completed", uiGeneration: "7",
                                    ok: false, error: "InspectionVisibilityChanged", result: { visibilityEpoch: inspection.epoch,
                                        visible: inspection.visible } } });
                                return;
                            }
                            if (window.knTestFailInspectionAction === params.action ||
                                window.knTestFailInspectionAction === "visible" && ["show", "restore"].includes(params.action))
                            {
                                const fail = () => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                                    type: "completed", uiGeneration: "7", ok: false, error: "InspectionWindowUnavailable" } });
                                if (window.knTestHoldInspectionErrors)
                                {
                                    window.knTestPendingInspection.push(fail);
                                }
                                else
                                {
                                    fail();
                                }
                                return;
                            }
                            if (["show", "restore", "hide", "close"].includes(params.action))
                            {
                                window.knTestInspectionVisible = ["show", "restore"].includes(params.action);
                                inspection.visible = window.knTestInspectionVisible;
                            }
                            reply(request, {});
                        };
                        if (window.knTestHoldInspectionShow && params.action === "show" ||
                            window.knTestHoldInspectionFocus && params.action === "focus-main")
                        {
                            window.knTestPendingInspection.push(deliver);
                        }
                        else
                        {
                            deliver();
                        }
                    }
                    else if (request.method === "catalog")
                    {
                        reply(request, { groups: options.catalog || { Kernel: [{ name: "!callbacks", synopsis: "Show callback routines", support: "Stable" },
                            { name: "!threads", synopsis: "Current thread or explicit process", grammar: "!threads [process|ethread:ADDRESS]", support: "Experimental" }],
                            Session: [{ name: "help", synopsis: "Command and workspace help", grammar: "help [command|ui]", support: "Stable" }],
                            Debugger: [{ name: "stack", synopsis: "Show the stack", grammar: "stack [decimal-frame-count]", support: "Stable" }] } });
                    }
                    else if (request.method === "complete")
                    {
                        reply(request, { items: (options.completions || ["help ui", "!threads ethread:"]).filter(item => item.startsWith(params.prefix)) });
                    }
                    else if (request.method === "completeSymbols")
                    {
                        const result = { target: JSON.parse(JSON.stringify(params.expectedStamp)), items: options.symbols || [] };
                        const deliver = () =>
                        {
                            const error = window.knTestSymbolError;
                            if (error)
                            {
                                queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                                    uiGeneration: "7", type: "completed", ok: false, error } }));
                            }
                            else
                            {
                                reply(request, result);
                            }
                        };
                        if (window.knTestHoldSymbols)
                        {
                            window.knTestPendingSymbols.push(deliver);
                        }
                        else
                        {
                            deliver();
                        }
                    }
                    else if (request.method === "classify")
                    {
                        if (window.knTestHoldClassification)
                        {
                            window.knTestFinishClassification = () => reply(request, { write: false });
                        }
                        else
                        {
                            reply(request, { write: false });
                        }
                    }
                    else if (request.method === "debuggerAction")
                    {
                        if (params.operation === "go")
                        {
                            window.knTestStopped = false;
                        }
                        else
                        {
                            window.knTestBreak("0x" + (BigInt(window.knTestInstructionPointer) + 1n).toString(16).padStart(16, "0"));
                        }
                        const result = { ok: true, operation: params.operation, status: { connected: true, stopped: window.knTestStopped,
                            canControlExecution: window.knTestStopped, canBreakExecution: !window.knTestStopped,
                            instructionPointer: window.knTestStopped ? window.knTestInstructionPointer : null,
                            target: JSON.parse(JSON.stringify(stamp)) } };
                        if (window.knTestHoldExecution)
                        {
                            window.knTestReleaseExecution = () => reply(request, result);
                        }
                        else
                        {
                            reply(request, result);
                        }
                    }
                    else if (request.method === "breakExecution")
                    {
                        reply(request, { requested: true, completed: false });
                        if (!window.knTestHoldBreak)
                        {
                            window.knTestBreak(window.knTestInstructionPointer);
                        }
                    }
                    else if (request.method === "breakpointPlan")
                    {
                        const row = params.source.resultId && fixtures[params.source.resultId][Number(params.source.index)];
                        const operand = params.operation === "breakpoint-add" ? row ? row.address : params.expression : row.id;
                        const planId = String(++breakpointSequence).padStart(64, "a");
                        const plan = { planId, approvalToken: "b".repeat(64), operation: params.operation, operand, original: "fixture configuration",
                            target: JSON.parse(JSON.stringify(stamp)) };
                        breakpointPlans.set(planId, plan);
                        reply(request, { ok: true, plan });
                    }
                    else if (request.method === "breakpointApply")
                    {
                        const plan = breakpointPlans.get(params.planId);
                        breakpointPlans.delete(params.planId);
                        if (!plan)
                        {
                            reply(request, { ok: false, error: "Expired plan" });
                            return;
                        }
                        if (plan.operation === "breakpoint-add")
                        {
                            fixtures.breakpoints.push({ kind: "Breakpoint", id: String(breakpointSequence), address: plan.operand,
                                addressSpace: "virtual", type: "0", enabled: true, identity: plan.planId });
                        }
                        else if (plan.operation === "breakpoint-remove")
                        {
                            fixtures.breakpoints = fixtures.breakpoints.filter(row => row.id !== plan.operand);
                        }
                        else
                        {
                            fixtures.breakpoints.find(row => row.id === plan.operand).enabled = plan.operation === "breakpoint-enable";
                        }
                        stamp.contextGeneration = String(Number(stamp.contextGeneration) + 1);
                        stamp.stopEpoch = String(Number(stamp.stopEpoch) + 1);
                        reply(request, { ok: true, status: { connected: true, stopped: true, kernelMode: true,
                            canEditBreakpoints: true, target: stamp, currentProcess: window.knTestCurrentProcess } });
                    }
                    else if (request.method === "discardPlan")
                    {
                        breakpointPlans.delete(params.planId);
                        reply(request, {});
                    }
                    else if (request.method === "memoryRead")
                    {
                        const source = params.source?.resultId && fixtures[params.source.resultId][Number(params.source.index)];
                        const address = source ? BigInt(params.source.path ? params.source.path.reduce((value, key) => value[key], source) :
                            source[params.source.field || "address"]) + BigInt(params.source.byteOffset || "0") :
                            /^0x[0-9a-f]+$/i.test(params.expression) || params.expression === "0" ?
                            BigInt(params.expression) : BigInt("0xffff800000001000");
                        const length = Number(params.length);
                        const id = "memory-" + request.requestId;
                        fixtures[id] = Array.from({ length: length / 16 }, (_, index) => ({ kind: "MemoryBytes",
                            address: "0x" + (address + BigInt(index * 16)).toString(16).padStart(16, "0"),
                            addressSpace: params.space,
                            bytes: Array.from({ length: 16 }, (_, byte) => options.memoryEvidence ?
                                (index * 16 + byte < 7 ? 0x80 + byte : null) :
                                index === 0 && byte === 5 ? null : (0x80 + index * 16 + byte) % 256) }));
                        const memoryEvidence = options.memoryEvidence ? { schema: "kndbgx.memory-read.v1",
                            address: "0x" + address.toString(16).padStart(16, "0"), addressSpace: params.space,
                            length: String(length), read: "7", mapping: "Unobserved", unreadableCause: "Unknown",
                            capture: { kind: "KernelRemote", class: "1", qualifier: "0", dumpFlags: null },
                            attempts: [{ address: "0x" + address.toString(16).padStart(16, "0"), requested: String(length), read: "7",
                                status: "Partial", nativeError: { domain: "HRESULT", code: "0x0000000080004005" } }] } : undefined;
                        reply(request, { resultId: id, rowCount: String(length / 16), data: {
                            commandId: params.space === "physical" ? "!db" : "db", status: "Partial", target: stamp,
                            analysis: { memoryRead: memoryEvidence } } });
                    }
                    else if (request.method === "disassemblyRead")
                    {
                        const source = params.source.resultId && fixtures[params.source.resultId][Number(params.source.index)];
                        const address = source ? BigInt(params.source.path ? params.source.path.reduce((value, key) => value[key], source) :
                            source[params.source.field || "address"]) + BigInt(params.source.byteOffset || "0") : /^0x[0-9a-f]+$/i.test(params.expression) ?
                            BigInt(params.expression) : BigInt(options.followExecution ? window.knTestInstructionPointer : "0xffff800000001000");
                        const count = Number(params.count);
                        const id = "disassembly-" + request.requestId;
                        fixtures[id] = Array.from({ length: count }, (_, index) => ({ kind: "Instruction",
                            address: "0x" + (address + BigInt(index * 4)).toString(16), addressSpace: "virtual",
                            nextAddress: "0x" + (address + BigInt(index * 4 + 4)).toString(16), bytes: "4883ec28",
                            instructionText: index === 1 ? "call sample!Worker (ffff8000`00002000)" : "sub rsp,28h",
                            symbol: "sample!Routine+0x" + (index * 4).toString(16) }));
                        reply(request, { resultId: id, rowCount: String(count), data: { commandId: "u", status: "Success", target: stamp },
                            instructionPointer: options.followExecution ? window.knTestInstructionPointer : undefined });
                    }
                    else if (request.method === "execute" || request.method === "resultInfo")
                    {
                        let id = params.command || params.resultId;
                        if (request.method === "resultInfo" && id === window.knTestMissingResultId)
                        {
                            queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                                type: "completed", uiGeneration: "7", ok: false, error: "ResultNotFound" } }));
                            return;
                        }
                        const forwardedExecution = request.method === "execute" && id === "g" && options.followExecution;
                        if (forwardedExecution)
                        {
                            fixtures.g = [];
                            stamp.targetGeneration = String(Number(stamp.targetGeneration) + 1);
                            stamp.symbolGeneration = String(Number(stamp.symbolGeneration) + 1);
                            window.knTestBreak("0xffff800000003000");
                        }
                        if (request.method === "execute" && id === "breakpoints")
                        {
                            id = "bp-list-" + request.requestId;
                            fixtures[id] = JSON.parse(JSON.stringify(fixtures.breakpoints));
                        }
                        if (request.method === "execute" && id === "event" && options.eventBreakpoints)
                        {
                            fixtures.event = [window.knTestLastEvent, ...fixtures.breakpoints];
                        }
                        if (request.method === "execute" && id === "registers")
                        {
                            fixtures.registers[0].value = window.knTestInstructionPointer;
                        }
                        if (options.uniqueToolbarResults && request.method === "execute" && id === "stack")
                        {
                            id = "stack-view-" + request.requestId;
                            fixtures[id] = fixtures.stack;
                        }
                        if (request.method === "execute" && options.uniqueCommands?.includes(id))
                        {
                            const command = id;
                            id = request.requestId + "-result";
                            fixtures[id] = fixtures[command] || [];
                            resultCommands.set(id, command);
                        }
                        const canonical = resultCommands.get(id) || (id.startsWith("bp-list-") ? "breakpoints" : id.startsWith("stack-view-") ? "stack" : id);
                        if (id === "!dml_proc" && window.knTestLargeProcessDetails)
                        {
                            Object.assign(fixtures[id][0], Object.fromEntries(Array.from({ length: 24 }, (_, index) =>
                                ["detail" + index, "Long retained process metadata ".repeat(8)])));
                        }
                        const noticeError = id === "notice-fixture" ? "Unresolved context <&> ".repeat(1000) + "END OF NOTICE" : "";
                        const result = { ok: !noticeError, resultId: id, command: canonical, rowCount: String(fixtures[id].length), findingCount: "0",
                            outputLength: id === "db nt L10" ? "29" : "0", data: { commandId: canonical, target: stamp,
                                status: noticeError ? "Unavailable" : id === "!msrcheck" ? "Partial" : "Success",
                                coverage: { complete: id !== "!msrcheck", unknownEntries: id === "!msrcheck" ? "1" : "0",
                                    stopReason: id === "!msrcheck" ? "FieldsOrOwnershipUnavailable" : "Complete" },
                                provenance: { source: id === "!msrcheck" ? "TargetRegisters:CurrentProcessorMsr" : options.sources?.[canonical] || "target" },
                                limitations: id === "!msrcheck" ? ["MSRs are read only on the selected event CPU. Other CPUs remain unknown."] : [] } };
                        if (canonical === "event" && options.eventBreakpoints)
                        {
                            result.data.analysis = { lastEvent: window.knTestLastEvent };
                        }
                        if (canonical === "stack" && options.stackContext)
                        {
                            result.data.analysis = { stackContext: options.stackContext };
                        }
                        if (canonical === "!hiddenproc" && options.processComparison)
                        {
                            result.data.analysis = { processComparison: options.processComparison };
                            result.data.status = "Partial";
                            result.data.coverage.complete = false;
                            result.data.coverage.unknownEntries = options.processComparison.indeterminate;
                            result.data.coverage.stopReason = "TargetCrossViewIncomplete";
                        }
                        if (forwardedExecution)
                        {
                            result.currentTarget = JSON.parse(JSON.stringify(stamp));
                        }
                        if (noticeError)
                        {
                            result.error = noticeError;
                            result.data.error = { message: noticeError };
                        }
                        if (request.method === "resultInfo" && window.knTestHoldResultInfo)
                        {
                            const captured = JSON.parse(JSON.stringify(result));
                            window.knTestReleaseResultInfo = () =>
                            {
                                window.knTestHoldResultInfo = false;
                                window.knTestReleaseResultInfo = null;
                                reply(request, captured);
                            };
                            return;
                        }
                        if (request.method === "execute" && canonical === "breakpoints" && window.knTestHoldBreakpointRead)
                        {
                            const captured = JSON.parse(JSON.stringify(result));
                            window.knTestFinishBreakpointRead = () =>
                            {
                                window.knTestHoldBreakpointRead = false;
                                window.knTestFinishBreakpointRead = null;
                                reply(request, captured);
                            };
                            return;
                        }
                        if (request.method === "execute" && id === "!dml_proc" && window.knTestHoldProcess)
                        {
                            queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                                type: "progress", uiGeneration: "7", ok: true } }));
                            window.knTestFinishProcess = cancelled =>
                            {
                                window.knTestFinishProcess = null;
                                if (cancelled)
                                {
                                    queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                                        type: "completed", uiGeneration: "7", ok: false, error: "Cancelled" } }));
                                }
                                else
                                {
                                    reply(request, result);
                                }
                            };
                        }
                        else
                        {
                            reply(request, result);
                        }
                    }
                    else if (request.method === "interrupt")
                    {
                        if (window.knTestFinishProcess && !window.knTestHoldInterrupt)
                        {
                            window.knTestFinishProcess(true);
                        }
                        reply(request, { requested: true });
                    }
                    else if (request.method === "operations" && options.operations)
                    {
                        const offset = Number(params.cursor);
                        const records = options.operations.slice(offset, offset + 16);
                        reply(request, window.knTestFailOperationPage === params.cursor ? null :
                            { records, next: String(offset + records.length), complete: offset + records.length === options.operations.length });
                    }
                    else if (request.method === "operationStatus" && options.operations)
                    {
                        const record = window.knTestOperationOverrides[params.operationId] ||
                            options.operations.find(item => item.operationId === params.operationId);
                        if (options.diagnostics && record && record.observation)
                        {
                            ++window.knTestOperationPolls;
                            record.observation.elapsedMs = String(window.knTestOperationPolls * 1500);
                        }
                        reply(request, record && record.unavailable ? { operationId: "different" } : record || {});
                    }
                    else if (request.method === "operationAck")
                    {
                        reply(request, true);
                    }
                    else if (request.method === "saveLog" && options.savedPath)
                    {
                        reply(request, { path: options.savedPath });
                    }
                    else if (request.method === "operationStatus" && window.knTestFinishProcess)
                    {
                        reply(request, { phase: "Running" });
                    }
                    else if (request.method === "resultPage")
                    {
                        if (window.knTestFailResultPage)
                        {
                            window.knTestFailResultPage = false;
                            queueMicrotask(() => receive({ data: { schema: "kndbgx.rpc.v3", requestId: request.requestId,
                                type: "completed", uiGeneration: "7", ok: false, error: "TransientPageFailure" } }));
                            return;
                        }
                        const rows = fixtures[params.resultId].slice(Number(params.offset), Number(params.offset) + 128);
                        const next = Number(params.offset) + rows.length;
                        const page = { resultId: params.resultId, collection: "rows", offset: params.offset, next: String(next),
                            total: String(fixtures[params.resultId].length), complete: next === fixtures[params.resultId].length, rows };
                        if (params.resultId === "address-menus" || params.resultId === "mixed-address-menu")
                        {
                            page.addressFields = rows.map(() => params.resultId === "address-menus" ?
                                [{ path: ["base"], space: "virtual", allowZero: false }] :
                                [{ path: ["va"], space: "virtual", allowZero: false }, { path: ["pa"], space: "physical", allowZero: true }]);
                        }
                        if (params.resultId === "foreign-address-menu" || params.resultId === "copy-only-address-menu")
                        {
                            page.addressFields = rows.map(() => params.resultId === "foreign-address-menu" ?
                                [{ path: ["address"], space: "virtual", allowZero: true, process: "0xffff800000002000" }] : []);
                        }
                        if (window.knTestHoldSortPage && params.offset === "0")
                        {
                            window.knTestReleaseSortPage = () =>
                            {
                                window.knTestHoldSortPage = false;
                                window.knTestReleaseSortPage = null;
                                reply(request, page);
                            };
                            return;
                        }
                        reply(request, page);
                    }
                    else if (request.method === "processAction")
                    {
                        const process = fixtures[params.resultId][Number(params.index)];
                        if (params.action === "attach")
                        {
                            stamp.contextGeneration = String(Number(stamp.contextGeneration) + 1);
                            stamp.contextIdentity = { implicitProcess: process.eprocess };
                            window.knTestCurrentProcess = process;
                            reply(request, { attached: true, process, connected: true, kernelMode: true, stopped: true,
                                canAttachProcess: true, execStatus: "break", target: stamp, currentProcess: process });
                        }
                        else
                        {
                            const id = "process-" + params.action;
                            fixtures[id] = [{ kind: "Thread", process, tid: "1234" }];
                            reply(request, { ok: true, resultId: id, command: "!" + params.action, rowCount: "1", findingCount: "0",
                                outputLength: "0", data: { commandId: "!" + params.action, target: stamp, status: "Success" } });
                        }
                    }
                    else if (request.method === "outputChunk")
                    {
                        reply(request, { resultId: params.resultId, offset: params.cursor, next: "29", complete: true, text: "[callbacks] literal <&> output\n" });
                    }
                    else
                    {
                        reply(request, { open: false });
                    }
                }
            };
        };
        await page.addInitScript(fixtureInit);
        await page.goto(`http://127.0.0.1:${server.address().port}/`);
        await page.waitForFunction(() => !document.getElementById("btn-palette").disabled);
        async function showProcesses(workspace)
        {
            if (await workspace.locator("#memory").isHidden())
            {
                await workspace.locator("#btn-memory-panel").click();
            }
            await workspace.locator("#tab-processes").click();
        }
        async function hideInspection(workspace)
        {
            if (await workspace.locator("#memory").isVisible())
            {
                await workspace.locator("#btn-memory-close").click();
            }
        }
        async function check(name, test)
        {
            if (process.env.KNDBGX_UI_TEST_FILTER && !name.includes(process.env.KNDBGX_UI_TEST_FILTER))
            {
                return;
            }
            try
            {
                await test();
                console.log("PASS " + name);
            }
            catch (error)
            {
                ++failures;
                console.error("FAIL " + name + ": " + error.stack);
                if (evidence)
                {
                    await page.screenshot({ path: path.join(evidence, "failure-" + failures + ".png") });
                }
            }
        }
        await check("T-UI-BROWSER crossview summary keeps all counts and interpretation visible at narrow widths", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 850 } });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true,
                    processComparison: { total: "3", matched: "1", mismatchCandidates: "1", indeterminate: "1" },
                    processComparisonRows: ["SameObservedIdentity", "CidOnlyReobserveCandidate", "IdentityUnknown"].map((observation, index) =>
                        ({ kind: "ProcessCrossView", pid: String(index + 4), observation,
                            activeList: { image: "fixture.exe" }, cidTable: { image: "fixture.exe" } })) });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                if (await workspace.locator("#memory").isVisible())
                {
                    await workspace.locator("#btn-memory-close").click();
                }
                await workspace.locator("#prompt").fill("!hiddenproc");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.getElementById("result-count").textContent.startsWith("Total 3 /"));
                for (const width of [1280, 900, 640])
                {
                    await workspace.setViewportSize({ width, height: 850 });
                    assert.equal(await workspace.locator("#result-count").textContent(),
                        "Total 3 / Matched 1 / Mismatch candidates 1 / Indeterminate 1");
                    assert.match(await workspace.locator("#process-comparison-note").textContent(),
                        /including matches.*not confirmed hidden processes.*incomplete.*cannot establish absence/);
                    for (const selector of ["#result-count", "#process-comparison-note", "#btn-save"])
                    {
                        await workspace.waitForFunction(selector =>
                        {
                            const element = document.querySelector(selector);
                            const rect = element.getBoundingClientRect();
                            const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
                            return rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight &&
                                element.scrollWidth <= element.clientWidth + 1 && element.scrollHeight <= element.clientHeight + 1 &&
                                (hit === element || element.contains(hit));
                        }, selector, { timeout: 3000 });
                    }
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "crossview-summary-" + width + ".png") });
                    }
                }
                await workspace.locator("#prompt").fill("registers");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.getElementById("process-comparison-note").classList.contains("hidden"));
                assert.equal(await workspace.locator("#result-count").textContent(), "1 rows / 0 findings");
            }
            finally
            {
                await local.close();
            }
        });
        async function reachableLastChoice()
        {
            return page.locator("#column-list").evaluate(list =>
            {
                list.scrollTop = list.scrollHeight;
                const input = list.lastElementChild.querySelector("input");
                const box = input.getBoundingClientRect();
                return document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2) === input;
            });
        }
        async function inspectorWorkspace(options = {})
        {
            const inspectorContext = await browser.newContext({ viewport: { width: 1920, height: 1000 } });
            const workspace = await inspectorContext.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            await workspace.addInitScript(fixtureInit, { callbackNavigation: true, ...options });
            await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
            await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
            await hideInspection(workspace);
            return { workspace, inspectorContext };
        }
        await check("T-UI-BROWSER workspace UX Operations remains usable with output off and never replays commands", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 850 } });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                const operations = Array.from({ length: 18 }, (_, i) => ({ operationId: String(i + 1), method: "execute",
                    phase: "Completed", ok: true, resultId: "stack", ...(i === 17 ? { unavailable: true } : {}) }));
                operations[0] = { operationId: "1", method: "saveLog", phase: "Completed", ok: true, path: "C:\\exports\\literal <&>.json" };
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true, operations, savedPath: "C:\\exports\\complete.json" });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#btn-console-output").click();
                await workspace.locator("#btn-operations").click();
                await workspace.waitForFunction(() => document.querySelectorAll(".operation-row").length === 18);
                assert.equal(await workspace.locator("#btn-console").getAttribute("aria-expanded"), "false");
                assert.match(await workspace.locator(".operation-row").first().textContent(), /Unknown.*identity/s);
                assert.match(await workspace.locator(".operation-row").last().textContent(), /literal <&>\.json/);
                const requests = await workspace.evaluate(() => window.knTestRequests);
                assert.equal(requests.filter(item => item.method === "operations").length, 2);
                assert.equal(requests.filter(item => item.method === "execute" || item.method === "saveLog").length, 0);
                assert.equal(requests.filter(item => item.method === "operationAck").length, 17);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "workspace-operations.png") });
                }
                await workspace.locator(".operation-row").nth(1).getByRole("button", { name: "Open result", exact: true }).click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "stack");
                await workspace.locator("#btn-save").click();
                await workspace.waitForFunction(() => document.getElementById("workspace-feedback-text").textContent.includes("complete.json"));
                assert.equal(await workspace.locator("#btn-console").getAttribute("aria-expanded"), "false");
                await workspace.locator("#result-info-toggle").click();
                assert.equal(await workspace.locator("#btn-result-export-path").isVisible(), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 0);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX review failed operation pagination retains the last confirmed list", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 850 } });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                const operations = Array.from({ length: 18 }, (_, i) => ({ operationId: String(i + 1), method: "execute",
                    phase: "Completed", ok: true, resultId: "stack" }));
                operations[17] = { operationId: "18", method: "saveLog", phase: "Completed", ok: true, path: "C:\\exports\\last-confirmed.json" };
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true, operations });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#btn-operations").click();
                await workspace.waitForFunction(() => document.querySelectorAll(".operation-row").length === 18);
                await workspace.evaluate(() => window.knTestFailOperationPage = "16");
                await workspace.locator("#btn-operations-refresh").click();
                await workspace.waitForFunction(() => !document.getElementById("btn-operations-refresh").disabled);
                assert.equal(await workspace.locator(".operation-row").count(), 18,
                    "a failed later page must not discard previously displayed outcomes");
                assert.match(await workspace.locator(".operation-row").first().textContent(), /last-confirmed\.json/);
                assert.match(await workspace.locator("#operations-status").textContent(), /could not be checked/);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    item.method === "execute" || item.method === "saveLog").length), 0);
                await workspace.evaluate(() => window.knTestFailOperationPage = "");
                await workspace.locator("#btn-operations-refresh").click();
                await workspace.waitForFunction(() => !document.getElementById("btn-operations-refresh").disabled);
                assert.equal(await workspace.locator(".operation-row").count(), 18);
                assert.doesNotMatch(await workspace.locator("#operations-status").textContent(), /could not be checked/);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX review full operation recovery acknowledges every displayed receipt", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 850 } });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                const operations = Array.from({ length: 128 }, (_, i) => ({ operationId: String(i + 1), method: "execute",
                    phase: "Completed", ok: true, resultId: "stack" }));
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true, operations });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#btn-operations").click();
                await workspace.waitForFunction(() => document.querySelectorAll(".operation-row").length === 128);
                await workspace.waitForFunction(() => window.knTestRequests.filter(item => item.method === "operationAck").length === 128,
                    null, { timeout: 3000 });
                assert.equal(await workspace.evaluate(() => new Set(window.knTestRequests.filter(item =>
                    item.method === "operationAck").map(item => item.params.operationId)).size), 128,
                    "recovery must not exhaust the bridge request limit and leave completed receipts unacknowledged");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    item.method === "execute" || item.method === "saveLog").length), 0);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX review process density keeps the scrolled viewport aligned", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 850 } });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#tab-processes").click();
                await workspace.locator("#process-rows [role=row]").first().waitFor();
                await workspace.locator("#process-view").evaluate(view => view.scrollTop = 100 * 28);
                await workspace.waitForFunction(() => document.querySelector("#process-rows [role=row]")?.dataset.processIndex === "92");
                await workspace.locator("#process-row-100").click();
                const selected = await workspace.locator("#process-name").textContent();
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                for (const [density, rowHeight] of [["comfortable", 34], ["compact", 28]])
                {
                    await workspace.locator("#workspace-layout-toggle").click();
                    await workspace.locator("#workspace-density").selectOption(density);
                    await workspace.locator("#workspace-layout-toggle").press("Escape");
                    const geometry = await workspace.evaluate(() =>
                    {
                        const view = document.getElementById("process-view");
                        const row = document.querySelector("#process-rows [role=row]");
                        return { height: row.getBoundingClientRect().height,
                            total: document.getElementById("process-spacer").getBoundingClientRect().height,
                            index: Number(row.dataset.processIndex),
                            top: row.getBoundingClientRect().top - view.getBoundingClientRect().top + view.scrollTop };
                    });
                    assert.equal(geometry.height, rowHeight);
                    assert.equal(geometry.total, 257 * rowHeight, "the scrollbar must cover every process at the current row height");
                    assert.ok(Math.abs(geometry.top - geometry.index * rowHeight) <= 1, JSON.stringify(geometry));
                    assert.equal(await workspace.locator("#process-name").textContent(), selected);
                    const details = await workspace.locator("#process-inspector").boundingBox();
                    const panel = await workspace.locator("#processes").boundingBox();
                    assert.ok(details.y >= panel.y && details.y + details.height <= panel.y + panel.height + 1,
                        "selected process details must remain inside the visible panel: " + JSON.stringify({ details, panel }));
                }
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), reads);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER Processes review short panes keep selected process actions reachable in every window mode", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ adaptiveLayout: true });
            try
            {
                await showProcesses(workspace);
                await workspace.locator("#process-rows [role=row]").first().waitFor();
                await workspace.locator("#process-grid").press("End");
                const selected = await workspace.locator("#process-name").textContent();
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                for (const [mode, width, height] of [["docked", 640, 480], ["independent", 400, 320], ["group", 360, 250]])
                {
                    const surface = mode === "docked" ? workspace : mode === "independent" ?
                        await detachInspectionView(workspace, "processes") : await detachInspection(workspace);
                    for (const density of ["comfortable", "compact"])
                    {
                        await workspace.setViewportSize({ width: 1280, height: 850 });
                        await workspace.locator("#workspace-layout-toggle").click();
                        await workspace.locator("#workspace-density").selectOption(density);
                        await workspace.locator("#workspace-layout-toggle").press("Escape");
                        await surface.setViewportSize({ width, height });
                        assert.equal(await surface.locator("#process-name").textContent(), selected);
                        for (const action of ["threads", "attach"])
                        {
                            await surface.locator("#btn-process-" + action).click({ trial: true, timeout: 2000 });
                        }
                    }
                    await surface.setViewportSize({ width: 1280, height: 850 });
                    if (mode !== "docked")
                    {
                        await surface.locator(mode === "group" ? "#btn-inspection-float" : "#btn-float-processes").click();
                        await workspace.locator("#processes").waitFor();
                    }
                    assert.equal(await workspace.locator("#process-name").textContent(), selected);
                }
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), reads);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX Stack retains captured identity through paging, sorting and context changes", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1440, height: 900 } });
            const workspace = await local.newPage();
            const stackErrors = [];
            workspace.on("pageerror", error => stackErrors.push(error.message));
            try
            {
                const stackContext = { engineProcessId: "0", engineThreadId: "1", processor: "1", targetContext:
                    { image: "captured.exe", pid: "424", tid: "428", processor: "1", source: "SelectedImplicitThread" } };
                const stack = Array.from({ length: 256 }, (_, index) => ({ kind: "StackFrame", index: String(index),
                    address: "0x" + (0xffff800000001000n + BigInt(index)).toString(16), symbol: "fixture!Frame" + index,
                    context: stackContext }));
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true, stack, stackContext });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await hideInspection(workspace);
                await workspace.locator("#btn-stack").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#result-rows [role='row']").length > 0);
                const label = "captured.exe / PID 424 / TID 428 / CPU 1";
                assert.equal(await workspace.locator("#stack-context").textContent(), label);
                assert.match(await workspace.locator("#stack-context").getAttribute("title"), /Engine process ID: 0; engine thread ID: 1/);
                await workspace.locator("#result-table").focus();
                await workspace.keyboard.press("End");
                await workspace.waitForFunction(() => document.getElementById("result-detail").textContent.includes('"index": "255"'));
                await workspace.locator("#table-head [role='columnheader']").filter({ hasText: /^Index$/ }).click();
                await workspace.waitForFunction(() => !document.getElementById("row-position").textContent.includes("Sorting"));
                assert.equal(await workspace.locator("#stack-context").textContent(), label);
                await workspace.evaluate(() => window.knTestChangeContext());
                await workspace.locator("#btn-refresh-status").click();
                await workspace.waitForFunction(() => document.getElementById("current-process-image").textContent === "changed.exe");
                assert.equal(await workspace.locator("#stack-context").textContent(), label);
                await workspace.locator("#btn-event").click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "event");
                assert.equal(await workspace.locator("#stack-summary").isVisible(), false);
                await workspace.locator("#result-open-toggle").click();
                await workspace.locator("#result-id-input").fill("stack");
                await workspace.locator("#btn-result-load").click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "stack");
                assert.equal(await workspace.locator("#stack-context").textContent(), label);
                await workspace.setViewportSize({ width: 760, height: 650 });
                assert.equal(await workspace.locator("#stack-context").evaluate(element => element.scrollWidth <= element.clientWidth), true);
                assert.deepEqual(stackErrors, []);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX Event separates the stop and preserves original row identity through paging and sorting", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1440, height: 900 } });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                const lastEvent = { kind: "LastEvent", type: "0x1", breakpointId: "259", address: null,
                    configuredAddress: "0xffff800000001103", configuredSymbol: "fixture!Stop+0x3", description: "Last stop 259",
                    engineProcessId: "0", engineThreadId: "1", targetContext:
                    { pid: "824", tid: "13144", image: "fixture.exe", processor: "1", source: "StoppedEventProcessor" } };
                const breakpoints = Array.from({ length: 260 }, (_, i) => ({ kind: "Breakpoint", id: String(i), enabled: true,
                    address: "0x" + (0xffff800000001000n + BigInt(i)).toString(16), symbol: "fixture!Stop" + i,
                    condition: "@rax == " + i, expression: "fixture" + i }));
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true, lastEvent, eventBreakpoints: true, breakpointSequence: "0", breakpoints });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await hideInspection(workspace);
                await workspace.locator("#btn-event").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#result-rows [role='row']").length > 0);
                assert.match(await workspace.locator("#result-count").textContent(), /260 breakpoint settings \/ 1 last stop/);
                assert.equal(await workspace.locator("#event-address").textContent(), "0xffff800000001103");
                assert.match(await workspace.locator("#event-context").textContent(), /Current BP setting address/);
                assert.doesNotMatch(await workspace.locator("#event-context").textContent(), /Event IP/);
                assert.match(await workspace.locator("#event-context").textContent(), /fixture.exe \/ PID 824 \/ TID 13144 \/ CPU 1/);
                assert.doesNotMatch(await workspace.locator("#event-context").textContent(), /Debugger process 0|thread 1\b/);
                assert.equal(await workspace.locator("#event-symbol").textContent(), "fixture!Stop+0x3");
                assert.match(await workspace.locator("#event-context").getAttribute("title"), /Engine process ID: 0; engine thread ID: 1/);
                assert.equal(await workspace.locator("#table-head [role='columnheader']").filter({ hasText: /^Symbol$/ }).count(), 1);
                assert.match(await workspace.locator("#result-rows").textContent(), /fixture!Stop0/);
                assert.equal(await workspace.locator("#result-rows").textContent().then(text => text.includes("Last stop 259")), false);
                await workspace.locator("#result-table").focus();
                await workspace.keyboard.press("End");
                await workspace.waitForFunction(() => document.getElementById("result-detail").textContent.includes('"id": "259"'));
                assert.match(await workspace.locator(".event-matched-breakpoint").textContent(), /@rax == 259/);
                await workspace.locator("#table-head [role='columnheader']").filter({ hasText: /^ID$/ }).click();
                await workspace.waitForFunction(() => document.querySelector("#table-head [aria-sort='ascending']"));
                await workspace.locator("#result-table").press("Home");
                await workspace.waitForFunction(() => document.getElementById("result-detail").textContent.includes('"id": "0"'));
                assert.equal(await workspace.evaluate(() => JSON.parse(document.getElementById("result-detail").textContent).condition), "@rax == 0");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 1);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "workspace-event.png") });
                }
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX Event preserves zero IDs and refuses legacy engine IDs as PID TID", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 760, height: 650 } });
            try
            {
                for (const targetContext of [null, { pid: "0", tid: "0", processor: "0", image: "Idle" }, { pid: "824", tid: null }])
                {
                    const workspace = await local.newPage();
                    const lastEvent = { kind: "LastEvent", type: "0x1", breakpointId: "0", processId: "0", threadId: "1", targetContext };
                    const breakpoints = [{ kind: "Breakpoint", id: "0", address: null, symbol: null, deferred: true,
                        expression: "missing!Routine", enabled: true }];
                    await workspace.addInitScript(fixtureInit, { adaptiveLayout: true, lastEvent, eventBreakpoints: true, breakpoints });
                    await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                    await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                    await hideInspection(workspace);
                    await workspace.locator("#btn-event").click();
                    await workspace.waitForFunction(() => document.querySelectorAll("#result-rows [role='row']").length > 0);
                    const text = await workspace.locator("#event-context").textContent();
                    assert.match(text, targetContext === null ? /PID Unavailable \/ TID Unavailable/ :
                        targetContext.pid === "0" ? /Idle \/ PID 0 \/ TID 0 \/ CPU 0/ : /PID 824 \/ TID Unavailable/);
                    assert.doesNotMatch(text, /TID 1\b|Debugger process/);
                    assert.equal(await workspace.locator("#event-symbol").isVisible(), false);
                    assert.match(await workspace.locator("#result-rows").textContent(), /missing!Routine \(deferred\)/);
                    await workspace.close();
                }
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX memory display changes preserve bytes and bound half-row addresses", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 850 } });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-memory-read").disabled);
                await workspace.locator("#btn-memory-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length === 16);
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length);
                await workspace.locator("#memory-row-width").selectOption("8");
                await workspace.locator("#memory-ascii").uncheck();
                assert.equal(await workspace.locator("#memory-rows .memory-row").count(), 32);
                assert.equal(await workspace.locator("#memory-head").textContent().then(text => text.includes("ASCII")), false);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length), reads);
                const address = workspace.locator("#memory-row-1 > span").first();
                assert.equal(await address.textContent(), "0xffff800000001008");
                await address.click({ button: "right" });
                await workspace.locator("#cell-open-disassembly").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows [role='row']").length > 0);
                const request = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "disassemblyRead"));
                assert.equal(request.params.source.index, "0");
                assert.equal(request.params.source.byteOffset, "8");
                assert.equal(await workspace.locator("#disassembly-rows [role='row']").first().textContent().then(text => text.includes("0xffff800000001008")), true);
                await workspace.locator("#tab-memory-view").click();
                assert.equal(await workspace.locator("#memory-row-0").textContent().then(text => text.includes("??")), true);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "workspace-memory.png") });
                }
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX register filters keep exact values and pin preferences", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 850 }, deviceScaleFactor: 2 });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true, registers: [{ kind: "Register", name: "rip", value: "0xffff800000001000",
                    context: { engineProcessId: "0", engineThreadId: "1", processor: "0", targetContext:
                        { image: "fixture.exe", pid: "424", tid: "428", processor: "0", source: "SelectedImplicitThread" } } },
                    { kind: "Register", name: "rax", value: "0xffffffffffffffff" }, { kind: "Register", name: "xmm0", rawBytes: "00ff".repeat(8) }] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#tab-registers").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#registers-rows .register-row").length === 3);
                const names = () => workspace.locator("#registers-rows .register-row > :first-child").allTextContents();
                assert.deepEqual(await names(), ["rip", "rax", "xmm0"]);
                await workspace.getByRole("button", { name: "Pin xmm0", exact: true }).click();
                assert.deepEqual(await names(), ["xmm0", "rip", "rax"]);
                await workspace.getByRole("button", { name: "Pin rax", exact: true }).click();
                assert.deepEqual(await names(), ["rax", "xmm0", "rip"]);
                assert.equal(await workspace.locator("#registers-context").textContent(), "fixture.exe / PID 424 / TID 428 / CPU 0");
                assert.match(await workspace.locator("#registers-context").getAttribute("title"), /Selected implicit thread.*Engine process ID: 0; engine thread ID: 1/);
                await workspace.locator("#registers-filter").fill("r");
                assert.deepEqual(await names(), ["rax", "rip"]);
                await workspace.locator("#registers-filter").fill("");
                await workspace.getByRole("button", { name: "Unpin rax", exact: true }).click();
                assert.deepEqual(await names(), ["xmm0", "rip", "rax"]);
                await workspace.getByRole("button", { name: "Unpin xmm0", exact: true }).click();
                assert.deepEqual(await names(), ["rip", "rax", "xmm0"]);
                await workspace.getByRole("button", { name: "Pin rax", exact: true }).click();
                await workspace.locator("#registers-scope").selectOption("pinned");
                assert.equal(await workspace.locator("#registers-rows .register-row").count(), 1);
                assert.match(await workspace.locator("#registers-rows").textContent(), /0xffffffffffffffff/);
                await workspace.locator("#registers-scope").selectOption("changed");
                assert.equal(await workspace.locator("#registers-rows .register-row").count(), 0);
                await workspace.locator("#registers-scope").selectOption("all");
                assert.deepEqual(await names(), ["rax", "rip", "xmm0"]);
                assert.match(await workspace.locator("#registers-rows").textContent(), /00ff00ff00ff00ff00ff00ff00ff00ff/);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 1);
                assert.deepEqual(await workspace.evaluate(() => JSON.parse(localStorage.getItem("kndbgx.register-pins"))), ["rax"]);
                await workspace.locator("#workspace-layout-toggle").click();
                await workspace.locator("#workspace-density").selectOption("comfortable");
                await workspace.locator("#workspace-layout-toggle").press("Escape");
                assert.ok((await workspace.locator("#registers-rows .register-row").first().boundingBox()).height >= 34);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "workspace-registers-dpi2.png") });
                }
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX command discovery retains aliases favorites route and provenance", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1440, height: 900 } });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                const registers = { synopsis: "Read registers", canonical: "registers", aliases: ["r"], support: "Stable", implementation: "native" };
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true, sources: { "!hv": "HostCpuid+TargetRegisters" }, catalog: {
                    Debugger: [{ ...registers, name: "registers" }, { ...registers, name: "r" },
                        { name: "eb", canonical: "eb", synopsis: "Write bytes", support: "Stable", requiresPreview: true },
                        { name: "!hv", canonical: "!hv", synopsis: "Host and target observations", support: "Experimental" }] } });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#btn-sidebar").click();
                assert.equal(await workspace.locator(".cmd-item").count(), 3);
                assert.match(await workspace.locator('.cmd-item[data-command="registers"]').textContent(), /Aliases: r/);
                await workspace.getByRole("button", { name: "Favorite registers", exact: true }).click();
                await workspace.locator("#library-favorites").check();
                assert.equal(await workspace.locator(".cmd-item").count(), 1);
                await workspace.locator("#library-favorites").uncheck();
                await workspace.locator("#filter").fill("r");
                assert.equal(await workspace.locator(".cmd-item").first().getAttribute("data-command"), "r");
                await workspace.locator(".cmd-item").first().click();
                assert.equal(await workspace.locator("#prompt").inputValue(), "r");
                assert.match(await workspace.locator("#command-hint").textContent(), /^KNDbgX/);
                assert.equal(await workspace.locator("#sidebar").isVisible(), false);
                assert.equal(await workspace.locator("#prompt").evaluate(element => element === document.activeElement), true);
                await workspace.locator("#prompt").fill(".echo direct");
                assert.match(await workspace.locator("#command-hint").textContent(), /^WinDbg direct \/ effects not classified/);
                await workspace.locator("#prompt").fill("eb 0x1000 01");
                assert.match(await workspace.locator("#command-hint").textContent(), /Change preview required/);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 0);
                await workspace.locator("#prompt").fill("!hv");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.getElementById("result-summary").textContent.startsWith("Host + target"));
                assert.deepEqual(await workspace.evaluate(() => JSON.parse(localStorage.getItem("kndbgx.command-favorites"))), ["registers"]);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX Windows can recover and dock a separate view without new reads", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 850 } });
            const workspace = await local.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#prompt").fill("unsent window draft");
                const opened = workspace.waitForEvent("popup");
                await workspace.locator("#btn-float-memory").click();
                const floating = await opened;
                await floating.locator("#memory-address").waitFor();
                await workspace.locator("#workspace-layout-toggle").click();
                assert.match(await workspace.locator("#workspace-windows").textContent(), /Memory \/ Floating/);
                await workspace.locator("#btn-layout-recover").click();
                await workspace.waitForFunction(() => window.knTestRequests.some(item => item.method === "inspectionWindow" && item.params.action === "recover"));
                await workspace.locator("#workspace-layout-toggle").click();
                await workspace.locator("#btn-layout-dock-all").click();
                await workspace.locator("#memory-address").waitFor();
                assert.equal(await workspace.locator("#prompt").inputValue(), "unsent window draft");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length), 0);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER workspace UX adaptive layout preserves usable tables and explicit preferences", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 800 } });
            try
            {
                await local.addInitScript(fixtureInit, { adaptiveLayout: true, registers: Array.from({ length: 100 }, (_, index) =>
                    ({ kind: "Register", name: "r" + index, value: "0x" + (0x1000 + index).toString(16) })) });
                await local.addInitScript(() =>
                {
                    if (!localStorage.getItem("kndbgx.memory-panel"))
                    {
                        localStorage.setItem("kndbgx.memory-panel", JSON.stringify({ visible: true, width: 660, tab: "registers" }));
                    }
                });
                const workspace = await local.newPage();
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#registers-rows .register-row").first().waitFor();
                await workspace.locator("#prompt").fill("registers");
                await workspace.locator("#prompt").press("Enter");
                await workspace.locator("#result-rows [role=row]").first().waitFor();
                assert.equal(await workspace.locator("#sidebar").isVisible(), false);
                assert.equal(await workspace.locator("#console-wrap").isVisible(), false);
                assert.equal(await workspace.locator("#inspector").isVisible(), false);
                const before = await workspace.locator("#result-view").boundingBox();
                assert.ok(before.width >= 560 && before.height >= 280, JSON.stringify(before));
                const registerViewport = await workspace.locator("#registers-grid").boundingBox();
                const registerRow = await workspace.locator("#registers-rows .register-row").first().boundingBox();
                assert.ok(registerViewport.height >= registerRow.height * 10, JSON.stringify({ registerViewport, registerRow }));
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.locator("#btn-sidebar").click();
                assert.equal(await workspace.locator("#sidebar").isVisible(), true);
                assert.deepEqual(await workspace.locator("#result-view").boundingBox(), before);
                await workspace.locator("#btn-library-close").click();
                await workspace.locator("#btn-inspector").click();
                assert.equal(await workspace.locator("#inspector").isVisible(), true);
                assert.equal((await workspace.locator("#result-view").boundingBox()).width, before.width);
                await workspace.locator("#btn-inspector-close").click();
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-inspector");
                await workspace.locator("#btn-console").click();
                assert.equal(await workspace.locator("#console-wrap").isVisible(), true);
                const settings = JSON.parse(await workspace.evaluate(() => localStorage.getItem("kndbgx.workspace-layout")));
                assert.equal(settings.console, true);
                assert.equal(settings.details, false);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), reads);
                const restored = await local.newPage();
                await restored.goto(`http://127.0.0.1:${server.address().port}/`);
                await restored.waitForFunction(() => !document.getElementById("prompt").disabled);
                assert.equal(await restored.locator("#console-wrap").isVisible(), true);
                assert.equal(await restored.locator("#inspector").isVisible(), false);
                await workspace.locator("#btn-console").click();
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "workspace-adaptive-1280.png") });
                }
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER library overlay selection reveals the command draft at desktop and narrow widths", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace({ adaptiveLayout: true });
            try
            {
                await workspace.locator("#btn-memory-panel").click();
                for (const width of [1280, 1024, 800, 360])
                {
                    await workspace.setViewportSize({ width, height: 800 });
                    await workspace.locator("#btn-sidebar").click();
                    assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("library-overlay")), true);
                    const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                    await workspace.locator('.command-favorite[aria-label="Favorite stack"]').click();
                    assert.equal(await workspace.locator("#sidebar").isVisible(), true);
                    await workspace.locator('.command-favorite[aria-label="Remove favorite stack"]').click();
                    const command = workspace.locator('.cmd-item[data-command="stack"]');
                    if (width === 1024)
                    {
                        await command.press("Enter");
                    }
                    else
                    {
                        await command.click();
                    }
                    assert.equal(await workspace.locator("#sidebar").isVisible(), false, "Overlay remains open at " + width);
                    assert.equal(await workspace.locator("#prompt").inputValue(), "stack");
                    assert.equal(await workspace.evaluate(() => document.activeElement.id), "prompt");
                    assert.equal(await workspace.locator("#prompt").evaluate(node =>
                    {
                        const box = node.getBoundingClientRect();
                        return document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2) === node;
                    }), true, "The selected command is obscured at " + width);
                    await workspace.locator("#btn-sidebar").click();
                    await workspace.locator(".kernel-workflows > summary").click();
                    await workspace.locator("#kernel-workflow").selectOption("triage crash");
                    assert.equal(await workspace.locator("#sidebar").isVisible(), false);
                    assert.equal(await workspace.locator("#prompt").inputValue(), "triage crash");
                    assert.equal(await workspace.evaluate(() => document.activeElement.id), "prompt");
                    assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                    assert.equal(JSON.parse(await workspace.evaluate(() => localStorage.getItem("kndbgx.workspace-layout"))).library, false);
                    await workspace.locator("#btn-sidebar").click();
                    await workspace.locator(".kernel-workflows > summary").click();
                    await workspace.locator("#btn-library-close").click();
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "library-draft-visible-" + width + ".png") });
                    }
                }
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER library pin preserves a left column and restores its preference after narrow layouts", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace({ adaptiveLayout: true });
            try
            {
                await workspace.setViewportSize({ width: 1280, height: 800 });
                await workspace.locator("#btn-memory-panel").click();
                await workspace.locator("#btn-sidebar").click();
                const pin = workspace.locator("#btn-library-pin");
                await pin.click();
                assert.equal(await pin.getAttribute("aria-pressed"), "true");
                assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("library-overlay")), false);
                const sidebar = await workspace.locator("#sidebar").boundingBox();
                const main = await workspace.locator("#main").boundingBox();
                assert.ok(main.x >= sidebar.x + sidebar.width - 1, "Pinned Library overlaps the workspace");
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.locator('.cmd-item[data-command="stack"]').click();
                assert.equal(await workspace.locator("#sidebar").isVisible(), true);
                assert.equal(await workspace.locator("#prompt").inputValue(), "stack");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "prompt");
                await workspace.keyboard.press("Control+b");
                assert.equal(await workspace.locator("#sidebar").isVisible(), false);
                await workspace.keyboard.press("Control+b");
                assert.equal(await pin.getAttribute("aria-pressed"), "true");
                await workspace.setViewportSize({ width: 800, height: 650 });
                await workspace.waitForFunction(() => document.getElementById("root").classList.contains("library-overlay"));
                assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("library-overlay")), true);
                assert.equal(await pin.getAttribute("aria-pressed"), "true");
                await workspace.setViewportSize({ width: 1280, height: 800 });
                await workspace.waitForFunction(() => !document.getElementById("root").classList.contains("library-overlay"));
                assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("library-overlay")), false);
                assert.equal(await workspace.locator("#prompt").inputValue(), "stack");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                await workspace.reload();
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                assert.equal(await pin.getAttribute("aria-pressed"), "true");
                assert.equal(await workspace.locator("#sidebar").isVisible(), true);
                assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("library-overlay")), false);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "library-pinned-1280.png") });
                }
                await pin.click();
                assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("library-overlay")), true);
                assert.equal(await workspace.locator("#sidebar").isVisible(), true);
                await pin.click();
                await workspace.locator("#workspace-layout-toggle").click();
                await workspace.locator("#btn-layout-auto").click();
                assert.equal(await pin.getAttribute("aria-pressed"), "false");
                assert.equal(await workspace.locator("#sidebar").isVisible(), false);
                assert.equal(JSON.parse(await workspace.evaluate(() => localStorage.getItem("kndbgx.workspace-layout"))).libraryPinned, false);
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER workspace UX density keeps virtual row selection and result menus accessible", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1280, height: 800 } });
            try
            {
                const workspace = await local.newPage();
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#btn-memory-close").click();
                await workspace.locator("#prompt").fill("sort-fixture");
                await workspace.locator("#prompt").press("Enter");
                await workspace.locator("#result-rows [role=row]").first().waitFor();
                await workspace.locator("#result-table").focus();
                await workspace.keyboard.press("End");
                await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("260"));
                const selected = await workspace.locator("#row-position").textContent();
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.locator("#workspace-layout-toggle").click();
                await workspace.locator("#workspace-density").selectOption("comfortable");
                await workspace.locator("#workspace-layout-toggle").press("Escape");
                await workspace.waitForFunction(() => document.querySelector("#result-rows [role=row]")?.getBoundingClientRect().height === 34);
                assert.equal(await workspace.locator("#row-position").textContent(), selected);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), reads);
                await workspace.locator("#result-open-toggle").click();
                assert.equal(await workspace.locator("#result-history").isVisible(), true);
                await workspace.locator("#result-id-input").fill("stack");
                await workspace.locator("#btn-result-load").click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "stack");
                await workspace.locator("#address-navigation-toggle").click();
                assert.equal(await workspace.locator("#btn-bookmarks").isVisible(), true);
                await workspace.locator("#address-navigation-toggle").press("Escape");
                assert.equal(await workspace.locator("#inspector").isVisible(), false);
                await workspace.setViewportSize({ width: 1024, height: 768 });
                await workspace.locator("#btn-memory-panel").click();
                await workspace.locator("#tab-registers").click();
                assert.ok((await workspace.locator("#result-view").boundingBox()).width >= 560);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "workspace-density-1024.png") });
                }
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER command history restores the unfinished draft and selection", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace({ catalog: { Debugger: [
                { name: "irp", grammar: "irp <hex-address>", synopsis: "Inspect an IRP", support: "Experimental" }
            ] } });
            try
            {
                const prompt = workspace.locator("#prompt");
                for (const command of ["status", "event"])
                {
                    await prompt.fill(command);
                    await prompt.press("Enter");
                    await workspace.waitForFunction(() => !document.getElementById("prompt").disabled &&
                        document.getElementById("btn-cancel").disabled);
                }
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await prompt.fill(".echo unfinished draft");
                await prompt.press("Escape");
                await prompt.press("ArrowDown");
                assert.equal(await prompt.inputValue(), ".echo unfinished draft", "Down at the newest entry cleared the draft");
                await prompt.evaluate(input => input.setSelectionRange(6, 16, "backward"));
                await prompt.press("ArrowUp");
                assert.equal(await prompt.inputValue(), "event");
                await prompt.press("ArrowUp");
                assert.equal(await prompt.inputValue(), "status");
                await prompt.press("ArrowDown");
                assert.equal(await prompt.inputValue(), "event");
                await prompt.press("ArrowDown");
                assert.equal(await prompt.inputValue(), ".echo unfinished draft");
                assert.deepEqual(await prompt.evaluate(input => [input.selectionStart, input.selectionEnd, input.selectionDirection]),
                    [6, 16, "backward"]);
                await prompt.press("ArrowUp");
                await prompt.fill(".echo edited history draft");
                await prompt.press("Escape");
                await prompt.press("ArrowUp");
                assert.equal(await prompt.inputValue(), "event", "Editing a recalled command must start a new history browse");
                await prompt.press("ArrowDown");
                assert.equal(await prompt.inputValue(), ".echo edited history draft");
                await prompt.fill("irp");
                await prompt.press("Tab");
                assert.equal(await prompt.inputValue(), "irp <hex-address>");
                await prompt.press("Escape");
                await prompt.press("ArrowUp");
                await prompt.press("ArrowDown");
                assert.equal(await prompt.inputValue(), "irp <hex-address>");
                assert.equal(await workspace.locator("#btn-run").isDisabled(), true);
                await prompt.press("Enter");
                assert.deepEqual(await prompt.evaluate(input => [input.selectionStart, input.selectionEnd]), [4, 17]);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER command history retains its draft when toolbar entries evict the recalled command", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace();
            try
            {
                const prompt = workspace.locator("#prompt");
                await prompt.fill(".echo oldest history entry");
                await prompt.press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.evaluate(async () =>
                {
                    const button = document.getElementById("btn-stack");
                    for (let index = 0; index < 199; ++index)
                    {
                        button.click();
                        await new Promise((resolve, reject) =>
                        {
                            const timeout = setTimeout(() => reject(new Error("Toolbar history setup did not complete")), 10000);
                            function settled()
                            {
                                if (!button.disabled && document.getElementById("btn-cancel").disabled)
                                {
                                    clearTimeout(timeout);
                                    resolve();
                                }
                                else
                                {
                                    requestAnimationFrame(settled);
                                }
                            }
                            settled();
                        });
                    }
                });
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    item.method === "execute" && item.params.command === "stack").length), 199);
                await prompt.fill(".echo retained cap draft");
                await prompt.press("Escape");
                await prompt.evaluate(input =>
                {
                    input.setSelectionRange(6, 18, "backward");
                    for (let index = 0; index < 200; ++index)
                    {
                        input.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true }));
                    }
                });
                assert.equal(await prompt.inputValue(), ".echo oldest history entry");
                for (const view of ["stack", "event"])
                {
                    await workspace.locator("#btn-" + view).click();
                    await workspace.waitForFunction(() => !document.getElementById("prompt").disabled &&
                        document.getElementById("btn-cancel").disabled);
                    assert.equal(await prompt.inputValue(), ".echo oldest history entry");
                }
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await prompt.press("ArrowUp");
                assert.equal(await prompt.inputValue(), ".echo oldest history entry");
                await prompt.press("ArrowDown");
                assert.equal(await prompt.inputValue(), "stack");
                await prompt.evaluate(input =>
                {
                    for (let index = 0; index < 200; ++index)
                    {
                        input.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowDown", bubbles: true }));
                    }
                });
                assert.equal(await prompt.inputValue(), ".echo retained cap draft");
                assert.deepEqual(await prompt.evaluate(input => [input.selectionStart, input.selectionEnd, input.selectionDirection]),
                    [6, 18, "backward"]);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER debugger toolbar views preserve the unfinished command draft", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace({ catalog: { Debugger: [
                { name: "irp", grammar: "irp <hex-address>", synopsis: "Inspect an IRP", support: "Experimental" }
            ] } });
            try
            {
                const prompt = workspace.locator("#prompt");
                await prompt.fill(".echo toolbar draft");
                await prompt.press("Escape");
                for (const screen of ["stack", "event", "breakpoints"])
                {
                    await workspace.locator("#btn-" + screen).click();
                    await workspace.waitForFunction(() => !document.getElementById("prompt").disabled &&
                        document.getElementById("btn-cancel").disabled);
                    assert.equal(await prompt.inputValue(), ".echo toolbar draft", screen + " discarded the draft");
                }
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    item.method === "execute" && item.params.command === ".echo toolbar draft")), false);
                await prompt.fill("irp");
                await prompt.press("Tab");
                await workspace.locator("#btn-event").click();
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled &&
                    document.getElementById("btn-cancel").disabled);
                assert.equal(await prompt.inputValue(), "irp <hex-address>");
                assert.equal(await workspace.locator("#btn-run").isDisabled(), true);
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER inspection toolbar keeps its open state and keyboard focus visible in forced colors", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                const launcher = workspace.getByRole("button", { name: "Inspect", exact: true });
                for (const colorScheme of ["light", "dark"])
                {
                    await workspace.setViewportSize({ width: colorScheme === "light" ? 1280 : 360, height: 800 });
                    await workspace.emulateMedia({ forcedColors: "active", reducedMotion: "reduce", colorScheme });
                    await hideInspection(workspace);
                    const closedBackground = await launcher.evaluate(node => getComputedStyle(node).backgroundColor);
                    await launcher.focus();
                    await launcher.press("Space");
                    await workspace.locator("#memory").waitFor({ state: "visible" });
                    assert.equal(await launcher.getAttribute("aria-expanded"), "true");
                    const appearance = await launcher.evaluate(node =>
                    {
                        const style = getComputedStyle(node);
                        return { background: style.backgroundColor, outline: style.outlineColor,
                            outlineStyle: style.outlineStyle, outlineWidth: parseFloat(style.outlineWidth),
                            labels: Array.from(node.querySelectorAll("span"), label =>
                            {
                                const text = getComputedStyle(label);
                                return { foreground: text.color, background: text.backgroundColor };
                            }) };
                    });
                    assert.notEqual(appearance.background, closedBackground, colorScheme + " hides the open state");
                    assert.notEqual(appearance.outline, appearance.background, colorScheme + " hides keyboard focus");
                    assert.equal(appearance.outlineStyle, "solid");
                    assert.ok(appearance.outlineWidth >= 2);
                    for (const label of appearance.labels)
                    {
                        assert.notEqual(label.foreground, label.background, colorScheme + " hides the button text");
                        assert.notEqual(label.foreground, appearance.background, colorScheme + " hides the button text");
                    }
                    const bounds = await launcher.boundingBox();
                    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= workspace.viewportSize().width);
                    assert.ok(await workspace.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
                    if (evidence)
                    {
                        await workspace.locator("#toolbar").screenshot({ path: path.join(evidence, "inspect-forced-colors-" + colorScheme + ".png") });
                    }
                    await launcher.press("Control+m");
                    await workspace.locator("#memory").waitFor({ state: "hidden" });
                    assert.equal(await launcher.getAttribute("aria-expanded"), "false");
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER docked inspection keeps result controls inside their panel without overlap", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace();
            try
            {
                await workspace.setViewportSize({ width: 1266, height: 822 });
                await workspace.locator("#btn-memory-panel").click();
                await workspace.locator("#tab-disassembly").click();
                for (let step = 0; step < 5; ++step)
                {
                    await workspace.locator("#memory-splitter").press("ArrowLeft");
                }
                for (const width of [1266, 1400])
                {
                    await workspace.setViewportSize({ width, height: 822 });
                    const geometry = await workspace.evaluate(() =>
                    {
                        const rect = selector =>
                        {
                            const box = document.querySelector(selector).getBoundingClientRect();
                            return { left: box.left, right: box.right, top: box.top, bottom: box.bottom };
                        };
                        return { panel: rect("#workspace-primary"), head: rect("#evidence > .evidence-head"),
                            meta: rect("#evidence > .evidence-meta"), content: rect("#result-content"),
                            controls: ["#btn-save", "#columns-toggle", "#btn-inspector"].map(rect) };
                    });
                    for (const control of geometry.controls)
                    {
                        assert.ok(control.left >= geometry.panel.left && control.right <= geometry.panel.right,
                            "Result control is clipped by the docked inspection panel at " + width);
                    }
                    assert.ok(geometry.head.bottom <= geometry.meta.top + 1, "Result heading overlaps metadata");
                    assert.ok(geometry.controls.slice(1).every(control => control.bottom <= geometry.content.top + 1),
                        "Result table covers wrapped metadata controls");
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "docked-result-controls-" + width + ".png") });
                    }
                }
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER Inspector divider drag keyboard and reset preserve result selection without target reads", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace();
            try
            {
                await workspace.locator("#prompt").fill("!callbacks");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 4 && document.getElementById("btn-cancel").disabled);
                await workspace.locator(".result-row").nth(1).click();
                const selected = await workspace.locator("#result-detail").textContent();
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length);
                const splitter = workspace.getByRole("separator", { name: "Row details width", exact: true });
                assert.equal(await splitter.getAttribute("aria-valuenow"), "296");
                await splitter.click();
                assert.equal(await workspace.evaluate(() => localStorage.getItem("kndbgx.inspector-width")), "null",
                    "Focusing the divider must preserve the responsive default");
                let box = await splitter.boundingBox();
                await workspace.mouse.move(box.x + box.width / 2, box.y + 80);
                await workspace.mouse.down();
                await workspace.mouse.move(box.x + box.width / 2 - 180, box.y + 80, { steps: 8 });
                await workspace.mouse.up();
                assert.equal(await splitter.getAttribute("aria-valuenow"), "476");
                assert.equal((await workspace.locator("#inspector").boundingBox()).width, 476);
                await splitter.press("ArrowLeft");
                assert.equal(await splitter.getAttribute("aria-valuenow"), "492");
                await splitter.press("Shift+ArrowRight");
                assert.equal(await splitter.getAttribute("aria-valuenow"), "428");
                box = await splitter.boundingBox();
                await workspace.mouse.move(box.x + box.width / 2, box.y + 80);
                await workspace.mouse.down();
                await workspace.mouse.move(box.x - 100, box.y + 80, { steps: 5 });
                await workspace.keyboard.press("Escape");
                await workspace.mouse.up();
                assert.equal(await splitter.getAttribute("aria-valuenow"), "428");
                assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("inspector-resizing")), false);
                await splitter.press("Home");
                assert.equal(await splitter.getAttribute("aria-valuenow"), "240");
                await splitter.press("End");
                assert.equal(await splitter.getAttribute("aria-valuenow"), "800");
                assert.ok((await workspace.locator("#result-table").boundingBox()).width >= 320);
                assert.equal(await workspace.locator("#result-detail").textContent(), selected);
                assert.equal(await workspace.locator("#result-title").textContent(), "!callbacks");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length), reads);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "inspector-expanded.png") });
                }
                await splitter.dblclick();
                assert.equal(await splitter.getAttribute("aria-valuenow"), "296");
                assert.equal(await workspace.evaluate(() => localStorage.getItem("kndbgx.inspector-width")), "null");
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER Inspector width persists through hide compact layout and document recreation", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace();
            try
            {
                const splitter = workspace.locator("#inspector-splitter");
                await splitter.press("End");
                for (let step = 0; step < 10; ++step)
                {
                    await splitter.press("ArrowRight");
                }
                assert.equal(await splitter.getAttribute("aria-valuenow"), "640");
                const activeColor = await workspace.locator("#btn-inspector").evaluate(node => getComputedStyle(node).backgroundColor);
                await workspace.locator("#btn-inspector").click();
                await workspace.mouse.move(0, 0);
                assert.equal(await splitter.isHidden(), true);
                assert.equal(await workspace.locator("#inspector").isHidden(), true);
                assert.equal(await workspace.locator("#btn-inspector").getAttribute("aria-expanded"), "false");
                await workspace.waitForFunction(() => getComputedStyle(document.getElementById("btn-inspector")).backgroundColor === "rgba(0, 0, 0, 0)");
                assert.notEqual(await workspace.locator("#btn-inspector").evaluate(node => getComputedStyle(node).backgroundColor), activeColor);
                await workspace.locator("#btn-inspector").click();
                await workspace.mouse.move(0, 0);
                assert.equal(await workspace.locator("#btn-inspector").getAttribute("aria-expanded"), "true");
                await workspace.waitForFunction(color => getComputedStyle(document.getElementById("btn-inspector")).backgroundColor === color, activeColor);
                assert.equal(await workspace.locator("#btn-inspector").evaluate(node => getComputedStyle(node).backgroundColor), activeColor);
                assert.equal(await splitter.getAttribute("aria-valuenow"), "640");
                await workspace.emulateMedia({ forcedColors: "active", reducedMotion: "reduce" });
                const buttonAppearance = () => workspace.locator("#btn-inspector").evaluate(node =>
                {
                    const style = getComputedStyle(node);
                    return [style.backgroundColor, style.color, style.borderColor, style.outlineStyle, style.outlineWidth];
                });
                const contrastActive = await buttonAppearance();
                await workspace.locator("#btn-inspector").click();
                await workspace.mouse.move(0, 0);
                assert.notDeepEqual(await buttonAppearance(), contrastActive, "Inspector state must remain visible in forced colors");
                await workspace.locator("#btn-inspector").click();
                await workspace.mouse.move(0, 0);
                assert.deepEqual(await buttonAppearance(), contrastActive);
                await workspace.emulateMedia({ forcedColors: "none", reducedMotion: "no-preference" });
                await workspace.setViewportSize({ width: 1100, height: 900 });
                await workspace.waitForFunction(() => Number(document.getElementById("inspector-splitter").getAttribute("aria-valuenow")) < 640);
                assert.ok((await workspace.locator("#result-table").boundingBox()).width >= 320);
                assert.equal(await workspace.evaluate(() => localStorage.getItem("kndbgx.inspector-width")), "640");
                await splitter.click();
                assert.equal(await workspace.evaluate(() => localStorage.getItem("kndbgx.inspector-width")), "640",
                    "A click on the constrained divider must not replace the preferred width");
                await workspace.setViewportSize({ width: 1920, height: 1000 });
                await workspace.waitForFunction(() => document.getElementById("inspector-splitter").getAttribute("aria-valuenow") === "640");
                await workspace.locator("#btn-memory-panel").click();
                await workspace.locator("#memory-splitter").press("End");
                await splitter.waitFor({ state: "hidden" });
                assert.equal(await workspace.locator("#inspector").evaluate(node => node.style.flexBasis), "");
                assert.equal((await workspace.locator("#inspector").boundingBox()).width, Math.min(380, (await workspace.locator("#result-content").boundingBox()).width));
                await workspace.locator("#btn-memory-close").click();
                assert.equal(await splitter.getAttribute("aria-valuenow"), "640");
                for (const size of [{ width: 650, height: 800 }, { width: 1920, height: 500 }])
                {
                    const box = await splitter.boundingBox();
                    await workspace.mouse.move(box.x + box.width / 2, box.y + 80);
                    await workspace.mouse.down();
                    await workspace.mouse.move(box.x + 100, box.y + 80, { steps: 5 });
                    await workspace.setViewportSize(size);
                    await splitter.waitFor({ state: "hidden" });
                    await workspace.waitForFunction(() => document.activeElement.id === "btn-inspector" &&
                        document.getElementById("inspector").style.flexBasis === "");
                    await workspace.mouse.up();
                    assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("inspector-resizing")), false);
                    assert.equal(await workspace.locator("#inspector").evaluate(node => node.style.flexBasis), "");
                    assert.equal(await workspace.evaluate(() => localStorage.getItem("kndbgx.inspector-width")), "640");
                    const panel = await workspace.locator("#inspector").boundingBox();
                    assert.ok(panel.x >= 0 && panel.x + panel.width <= size.width);
                    await workspace.setViewportSize({ width: 1920, height: 1000 });
                    await splitter.waitFor({ state: "visible" });
                    assert.equal(await splitter.getAttribute("aria-valuenow"), "640");
                }
                await workspace.reload();
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                assert.equal(await splitter.getAttribute("aria-valuenow"), "640");
                assert.equal((await workspace.locator("#inspector").boundingBox()).width, 640);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => ["execute", "memoryRead", "disassemblyRead"].includes(item.method))), false);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "inspector-restored.png") });
                }
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER library groups support keyboard folding and preserve ordering across close and reopen", async () =>
        {
            const libraryContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
            const contract = JSON.parse(fs.readFileSync(path.join(root, "docs/command-contract.json"), "utf8"));
            const catalog = {};
            const expected = [];
            for (const command of contract)
            {
                for (const name of [command.name, ...command.aliases])
                {
                    (catalog[command.group] ||= []).push({ name, synopsis: command.summary, grammar: command.grammar,
                        support: command.support, modes: command.targetModes });
                    expected.push(name);
                }
            }
            async function openLibrary()
            {
                const workspace = await libraryContext.newPage();
                await workspace.addInitScript(fixtureInit, { catalog });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("library-sort").disabled);
                if (await workspace.locator("#sidebar").isHidden())
                {
                    await workspace.locator("#btn-sidebar").click();
                }
                return workspace;
            }
            const header = (workspace, group) => workspace.locator(".catalog-group-toggle").filter({ hasText: group + " /" });
            const isFolded = (workspace, group) => header(workspace, group).evaluate(button =>
                document.getElementById(button.getAttribute("aria-controls")).classList.contains("hidden"));
            try
            {
                let workspace = await openLibrary();
                assert.equal(await workspace.locator("#catalog-count").textContent(), expected.length + " / " + expected.length);
                assert.equal(await workspace.locator(".catalog-group-toggle").first().getAttribute("data-group"), "Kernel Analysis");
                await workspace.locator("#prompt").fill("unfinished library draft");
                await header(workspace, "Code").focus();
                await header(workspace, "Code").press("Enter");
                assert.equal(await isFolded(workspace, "Code"), true);
                assert.equal(await header(workspace, "Code").evaluate(node => document.activeElement === node), true);
                await header(workspace, "Code").press("Space");
                assert.equal(await isFolded(workspace, "Code"), false);
                await header(workspace, "Code").press("Enter");
                await header(workspace, "Kernel").click();
                await workspace.locator("#library-sort").selectOption("alphabetical");
                assert.deepEqual(await workspace.locator(".catalog-group-toggle").evaluateAll(nodes => nodes.map(node => node.dataset.group)),
                    ["Code", "Debugger", "Dumps", "Files", "Jobs", "Kernel", "Kernel Analysis", "Memory", "Results", "Session", "Symbols"]);
                assert.deepEqual(await header(workspace, "Debugger").evaluate(button =>
                    Array.from(document.getElementById(button.getAttribute("aria-controls")).querySelectorAll(".name"), node => node.textContent)),
                    ["back", "bl", "bookmark", "bookmarks", "breakpoints", "debug-approve", "debug-plan", "event", "forward", "history", "k", "navigate", "r", "registers", "source", "stack"]);
                assert.deepEqual((await workspace.locator(".cmd-item .name").allTextContents()).sort(), [...expected].sort());
                assert.equal(await workspace.locator("#prompt").inputValue(), "unfinished library draft");
                assert.equal(await isFolded(workspace, "Kernel"), true);
                assert.equal(await isFolded(workspace, "Code"), true);
                if (evidence)
                {
                    await workspace.locator("#catalog").evaluate(node => node.scrollTop = 0);
                    await workspace.screenshot({ path: path.join(evidence, "library-alphabetical.png") });
                }
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["classify", "execute", "debuggerAction"].includes(item.method))), false);
                await workspace.close();
                workspace = await openLibrary();
                assert.equal(await workspace.locator("#library-sort").inputValue(), "alphabetical");
                assert.equal(await isFolded(workspace, "Code"), true);
                assert.equal(await isFolded(workspace, "Kernel"), true);
                await header(workspace, "Code").focus();
                await workspace.keyboard.press("Tab");
                assert.equal(await header(workspace, "Debugger").evaluate(node => document.activeElement === node), true,
                    "A collapsed command remained in the keyboard tab order");
                await workspace.locator("#prompt").fill("!callbacks");
                await workspace.locator("#selected-command").click();
                assert.equal(await isFolded(workspace, "Kernel"), false);
                assert.equal(await workspace.locator(".cmd-item.active").evaluate(node => document.activeElement === node), true);
                await workspace.locator("#library-sort").selectOption("default");
                assert.equal(await workspace.locator(".catalog-group-toggle").first().getAttribute("data-group"), "Kernel Analysis");
                assert.equal(await isFolded(workspace, "Code"), true);
                await workspace.reload();
                await workspace.waitForFunction(() => !document.getElementById("library-sort").disabled);
                assert.equal(await workspace.locator("#library-sort").inputValue(), "default");
                assert.equal(await isFolded(workspace, "Code"), true);
                assert.equal(await isFolded(workspace, "Kernel"), false);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["classify", "execute", "debuggerAction"].includes(item.method))), false);
            }
            finally
            {
                await libraryContext.close();
            }
        });
        await check("T-UI-BROWSER library filtering reveals folded matches and sort controls remain reachable in a narrow window", async () =>
        {
            const libraryContext = await browser.newContext({ viewport: { width: 800, height: 650 } });
            try
            {
                const workspace = await libraryContext.newPage();
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("library-sort").disabled);
                await workspace.locator("#btn-sidebar").click();
                const header = workspace.locator('.catalog-group-toggle[data-group="Kernel"]');
                await header.click();
                assert.equal(await header.getAttribute("aria-expanded"), "false");
                const preference = await workspace.evaluate(() => localStorage.getItem("kndbgx.command-library"));
                await workspace.locator("#filter").fill("callbacks");
                assert.equal(await header.getAttribute("aria-expanded"), "true");
                assert.equal(await workspace.locator('.cmd-item[data-command="callbacks"]').isVisible(), true);
                await header.press("Space");
                assert.equal(await header.getAttribute("aria-expanded"), "false");
                assert.equal(await workspace.evaluate(() => localStorage.getItem("kndbgx.command-library")), preference);
                await workspace.locator("#filter").fill("");
                assert.equal(await header.getAttribute("aria-expanded"), "false");
                await workspace.locator("#filter").fill("no-such-command");
                assert.equal(await workspace.locator("#catalog-count").textContent(), "0 / 4");
                assert.equal(await workspace.locator("#catalog").textContent(), "No matching commands");
                await workspace.locator("#filter").fill("");
                await workspace.locator("#library-sort").selectOption("alphabetical");
                assert.equal(await workspace.locator("#library-sort").evaluate(node =>
                {
                    const box = node.getBoundingClientRect();
                    return document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2) === node;
                }), true);
                await workspace.locator("#prompt").fill("!callbacks");
                await workspace.locator("#selected-command").click();
                assert.equal(await header.getAttribute("aria-expanded"), "true");
                assert.equal(await workspace.locator('.cmd-item[data-command="callbacks"]').isVisible(), true);
                await workspace.emulateMedia({ forcedColors: "active" });
                await header.focus();
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "library-forced-colors.png") });
                }
                assert.equal(await header.evaluate(node => getComputedStyle(node, "::before").borderRightStyle), "solid");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["classify", "execute", "debuggerAction"].includes(item.method))), false);
            }
            finally
            {
                await libraryContext.close();
            }
        });
        await check("T-UI-BROWSER short library drawers retain fully reachable group buttons commands and sorting", async () =>
        {
            const libraryContext = await browser.newContext({ viewport: { width: 800, height: 350 } });
            try
            {
                const workspace = await libraryContext.newPage();
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("library-sort").disabled);
                await workspace.locator("#btn-sidebar").click();
                for (const viewport of [{ width: 800, height: 350 }, { width: 360, height: 400 }])
                {
                    await workspace.setViewportSize(viewport);
                    const header = workspace.locator('.catalog-group-toggle[data-group="Debugger"]');
                    await header.scrollIntoViewIfNeeded();
                    assert.equal(await header.evaluate(node =>
                    {
                        const box = node.getBoundingClientRect();
                        const list = document.getElementById("catalog").getBoundingClientRect();
                        return box.top >= list.top && box.bottom <= list.bottom && box.top >= 52 && box.bottom <= window.innerHeight - 27 &&
                            document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2) === node;
                    }), true, "The drawer clipped its group header at " + JSON.stringify(viewport));
                    await header.click();
                    assert.equal(await header.getAttribute("aria-expanded"), "false");
                    await header.press("Space");
                    assert.equal(await header.getAttribute("aria-expanded"), "true");
                    const command = workspace.locator('.cmd-item[data-command="stack"]');
                    await command.click();
                    assert.equal(await workspace.locator("#prompt").inputValue(), "stack");
                    await workspace.locator("#btn-sidebar").click();
                    await workspace.locator("#library-sort").selectOption("alphabetical");
                    assert.equal(await workspace.locator("#library-sort").inputValue(), "alphabetical");
                    await workspace.locator("#filter").fill("callbacks");
                    await workspace.locator('.cmd-item[data-command="callbacks"]').click();
                    assert.equal(await workspace.locator("#prompt").inputValue(), "!callbacks");
                    await workspace.locator("#btn-sidebar").click();
                    await workspace.locator("#filter").fill("");
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "library-short-" + viewport.width + ".png") });
                    }
                }
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["classify", "execute", "debuggerAction"].includes(item.method))), false);
            }
            finally
            {
                await libraryContext.close();
            }
        });
        await check("T-UI-BROWSER inline parameter recommendations fill selected fields without executing an incomplete draft", async () =>
        {
            const completionContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
            try
            {
                const workspace = await completionContext.newPage();
                await workspace.addInitScript(fixtureInit, { catalog: { Dumps: [
                    { name: "dump-pe", grammar: "dump-pe <module|address> <path>", synopsis: "Save a module", support: "Stable" }
                ] } });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await workspace.locator("#prompt").fill("dump-pe");
                assert.equal(await workspace.locator("#prompt-ghost").isVisible(), true);
                assert.equal(await workspace.locator("#prompt-ghost-suffix").textContent(), " <module|address> <path>");
                assert.equal(await workspace.locator("#prompt").inputValue(), "dump-pe");
                assert.equal(await workspace.locator("#prompt").getAttribute("aria-autocomplete"), "both");
                assert.equal(await workspace.locator("#prompt-ghost").getAttribute("aria-hidden"), "true");
                const alignment = await workspace.locator("#prompt").evaluate(input =>
                {
                    const style = getComputedStyle(input);
                    const measure = document.createElement("canvas").getContext("2d");
                    measure.font = style.font;
                    const expected = input.getBoundingClientRect().left + parseFloat(style.borderLeftWidth) + parseFloat(style.paddingLeft) +
                        measure.measureText(input.value).width - input.scrollLeft;
                    const suffix = document.getElementById("prompt-ghost-suffix").getBoundingClientRect();
                    return { offset: Math.abs(suffix.left - expected), top: suffix.top, bottom: suffix.bottom,
                        inputTop: input.getBoundingClientRect().top, inputBottom: input.getBoundingClientRect().bottom };
                });
                assert.ok(alignment.offset < 1, "Ghost text is misaligned: " + JSON.stringify(alignment));
                assert.ok(alignment.top >= alignment.inputTop && alignment.bottom <= alignment.inputBottom);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "parameter-ghost.png") });
                }
                await workspace.locator("#prompt").press("Tab");
                const selected = () => workspace.locator("#prompt").evaluate(input => input.value.slice(input.selectionStart, input.selectionEnd));
                assert.equal(await selected(), "<module|address>");
                assert.equal(await workspace.locator("#btn-run").isDisabled(), true);
                await workspace.locator("#prompt").press("Escape");
                await workspace.locator("#prompt").press("Enter");
                assert.equal(await selected(), "<module|address>");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "classify")), false);
                await workspace.keyboard.insertText("nt");
                await workspace.locator("#prompt").press("Tab");
                assert.equal(await selected(), "<path>");
                await workspace.keyboard.insertText('"C:\\Evidence\\module dump.bin"');
                assert.equal(await workspace.locator("#prompt").inputValue(), 'dump-pe nt "C:\\Evidence\\module dump.bin"');
                assert.equal(await workspace.locator("#btn-run").isEnabled(), true);
                await workspace.locator("#prompt").press("Tab");
                assert.equal(await workspace.locator("#btn-run").evaluate(node => node === document.activeElement), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["classify", "execute", "debuggerAction"].includes(item.method))), false);
            }
            finally
            {
                await completionContext.close();
            }
        });
        await check("T-UI-BROWSER option completion preserves required template fields and execution guards", async () =>
        {
            const completionContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
            try
            {
                const workspace = await completionContext.newPage();
                await workspace.addInitScript(fixtureInit, { completions: [
                    "dump-raw /phys", "dump-raw <address> <length> <path> /phys"
                ], catalog: { Dumps: [
                    { name: "dump-raw", grammar: "dump-raw <address> <length> <path> [/phys]", synopsis: "Save memory", support: "Stable" }
                ] } });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                const prompt = workspace.locator("#prompt");
                await prompt.fill("dump-raw /p");
                await workspace.waitForFunction(() => document.getElementById("prompt-ghost-suffix").textContent === "hys");
                await prompt.press("Tab");
                assert.equal(await prompt.inputValue(), "dump-raw /phys");
                await prompt.fill("dump-raw");
                await prompt.press("Tab");
                const draft = await prompt.inputValue();
                await prompt.press("End");
                await workspace.keyboard.insertText(" /p");
                await workspace.waitForFunction(() => document.getElementById("prompt-ghost-suffix").textContent === "hys");
                await prompt.press("Tab");
                assert.equal(await prompt.inputValue(), draft + " /phys");
                assert.equal(await workspace.locator("#btn-run").isDisabled(), true);
                await prompt.press("Enter");
                assert.equal(await prompt.evaluate(input => input.value.slice(input.selectionStart, input.selectionEnd)), "<address>");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["classify", "execute", "debuggerAction"].includes(item.method))), false);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "parameter-option-unresolved.png") });
                }
            }
            finally
            {
                await completionContext.close();
            }
        });
        await check("T-UI-BROWSER inline completion tracks scrolling caret movement contrast mode and Busy", async () =>
        {
            const completionContext = await browser.newContext({ viewport: { width: 360, height: 650 } });
            try
            {
                const workspace = await completionContext.newPage();
                await workspace.addInitScript(fixtureInit, { completions: ["help ui", "help uf"], catalog: { Commands: [
                    { name: "bugcheck-decode", grammar: "bugcheck-decode <hex-code> <p1> <p2> <p3> <p4>", synopsis: "Decode", support: "Stable" },
                    { name: "help", grammar: "help [command|ui]", synopsis: "Help", support: "Stable" }
                ] } });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                const value = "bugcheck-decode " + "a".repeat(80) + " " + "b".repeat(80);
                await workspace.locator("#prompt").fill(value);
                assert.equal(await workspace.locator("#prompt-ghost").isVisible(), true);
                assert.equal(await workspace.locator("#prompt-ghost-suffix").textContent(), " <p2> <p3> <p4>");
                const scroll = await workspace.locator("#prompt").evaluate(input =>
                {
                    input.scrollLeft = input.scrollWidth;
                    input.dispatchEvent(new Event("scroll"));
                    return input.scrollLeft;
                });
                assert.ok(scroll > 0);
                assert.equal(await workspace.locator("#prompt-ghost-text").evaluate(node => node.style.transform), "translateX(" + -scroll + "px)");
                await workspace.locator("#prompt").press("Home");
                assert.equal(await workspace.locator("#prompt-ghost").isHidden(), true);
                await workspace.locator("#prompt").press("End");
                assert.equal(await workspace.locator("#prompt-ghost").isVisible(), true);
                assert.equal(await workspace.locator("#prompt-input-wrap").evaluate(node =>
                {
                    const box = node.getBoundingClientRect();
                    return box.left >= 0 && box.right <= window.innerWidth;
                }), true);
                await workspace.locator("#prompt").fill("help u");
                await workspace.waitForFunction(() => document.getElementById("prompt-ghost-suffix").textContent === "i");
                await workspace.locator("#prompt").press("ArrowDown");
                assert.equal(await workspace.locator("#prompt-ghost-suffix").textContent(), "f");
                await workspace.locator("#prompt").press("Tab");
                assert.equal(await workspace.locator("#prompt").inputValue(), "help uf");
                await workspace.locator("#prompt").fill("bugcheck-decode");
                await workspace.emulateMedia({ forcedColors: "active" });
                assert.equal(await workspace.locator("#prompt-ghost-prefix").evaluate(node => getComputedStyle(node).visibility), "hidden");
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "parameter-ghost-narrow-contrast.png") });
                }
                await workspace.evaluate(() =>
                {
                    window.knTestStopped = false;
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => document.getElementById("prompt").disabled);
                assert.equal(await workspace.locator("#prompt-ghost").isHidden(), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["classify", "execute", "debuggerAction"].includes(item.method))), false);
            }
            finally
            {
                await completionContext.close();
            }
        });
        await check("T-UI-BROWSER debugger symbols display exact addresses and complete middle template operands", async () =>
        {
            const symbolContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
            try
            {
                const workspace = await symbolContext.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                await workspace.addInitScript(fixtureInit, { symbols: Array.from({ length: 24 }, (_, i) => ({
                    symbol: "nt!KeBugCheck" + i, address: "0xfffff803" + (0x12345000 + i * 16).toString(16), kind: "symbol"
                })), catalog: { Code: [
                    { name: "u", grammar: "u [address] [L<count>]", symbolParameters: [0], synopsis: "Disassemble", support: "Stable" },
                    { name: "dump-pe", grammar: "dump-pe <module|address> <path>", symbolParameters: [0], synopsis: "Save", support: "Stable" }
                ] } });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                const prompt = workspace.locator("#prompt");
                await prompt.fill("u nt!KeBug");
                await workspace.waitForFunction(() => document.querySelectorAll("#suggest .suggest-item").length === 24);
                assert.equal(await workspace.locator(".suggest-address").first().textContent(), "0xfffff80312345000");
                assert.equal(await workspace.locator("#prompt-ghost-suffix").textContent(), "Check0");
                for (let i = 0; i < 20; ++i)
                {
                    await prompt.press("ArrowDown");
                }
                assert.equal(await workspace.locator("#suggest").evaluate(node =>
                {
                    const active = node.querySelector(".active").getBoundingClientRect();
                    const box = node.getBoundingClientRect();
                    return active.top >= box.top && active.bottom <= box.bottom;
                }), true);
                await prompt.press("Tab");
                assert.equal(await prompt.inputValue(), "u nt!KeBugCheck20");
                await prompt.press("Tab");
                assert.equal(await workspace.locator("#btn-run").evaluate(node => node === document.activeElement), true);
                await prompt.fill("dump-pe");
                await prompt.press("Tab");
                await workspace.keyboard.insertText("nt!KeBug");
                await workspace.waitForFunction(() => document.querySelectorAll("#suggest .suggest-item").length === 24);
                assert.equal(await workspace.locator("#prompt-ghost").isHidden(), true);
                await prompt.press("Tab");
                assert.equal(await prompt.inputValue(), "dump-pe nt!KeBugCheck0 <path>");
                assert.equal(await prompt.evaluate(input => input.value.slice(input.selectionStart, input.selectionEnd)), "<path>");
                assert.equal(await workspace.locator("#btn-run").isDisabled(), true);
                await prompt.press("Enter");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["classify", "execute", "debuggerAction"].includes(item.method))), false);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "symbol-middle-template.png") });
                }
            }
            finally
            {
                await symbolContext.close();
            }
        });
        await check("T-UI-BROWSER delayed symbol Tab completion rejects context changes and Escape", async () =>
        {
            const symbolContext = await browser.newContext({ viewport: { width: 1100, height: 760 } });
            try
            {
                const workspace = await symbolContext.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                await workspace.addInitScript(fixtureInit, { holdSymbols: true,
                    symbols: [{ symbol: "nt!KeBugCheckEx", address: "0xfffff80312345678", kind: "symbol" }],
                    catalog: { Code: [{ name: "u", grammar: "u [address]", symbolParameters: [0], synopsis: "Code", support: "Stable" }] } });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                const prompt = workspace.locator("#prompt");
                await prompt.fill("u nt!KeBug");
                await workspace.waitForFunction(() => window.knTestPendingSymbols.length === 1);
                await prompt.press("Tab");
                await workspace.evaluate(() =>
                {
                    window.knTestChangeContext();
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => document.getElementById("current-process-image").textContent === "changed.exe");
                await workspace.evaluate(() => window.knTestReleaseSymbols());
                assert.equal(await prompt.inputValue(), "u nt!KeBug");
                assert.equal(await workspace.locator("#suggest").isHidden(), true);
                await prompt.fill("u nt!KeBugC");
                await prompt.press("Tab");
                await workspace.waitForFunction(() => window.knTestPendingSymbols.length === 1);
                await prompt.press("Escape");
                await workspace.evaluate(() => window.knTestReleaseSymbols());
                assert.equal(await prompt.inputValue(), "u nt!KeBugC");
                assert.equal(await workspace.locator("#suggest").isHidden(), true);
                await prompt.fill("u nt!KeBugCh");
                await prompt.press("Tab");
                await workspace.waitForFunction(() => window.knTestPendingSymbols.length === 1);
                await workspace.evaluate(() => window.knTestReleaseSymbols());
                await workspace.waitForFunction(() => document.getElementById("prompt").value === "u nt!KeBugCheckEx");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["classify", "execute", "debuggerAction"].includes(item.method))), false);
            }
            finally
            {
                await symbolContext.close();
            }
        });
        await check("T-UI-BROWSER physical tails exclude symbols while quoted paths remain data", async () =>
        {
            const symbolContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
            try
            {
                const workspace = await symbolContext.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                await workspace.addInitScript(fixtureInit, { symbols: [
                    { symbol: "nt!KeBugCheckEx", address: "0xfffff80312345678", kind: "symbol" }
                ], catalog: { Dumps: [{ name: "dump-raw", grammar: "dump-raw <address> <length> <path> [/phys]",
                    symbolParameters: [0], completionOptions: [{ name: "/phys", takesValue: false }], support: "Stable" }] } });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                const prompt = workspace.locator("#prompt");
                const physical = 'dump-raw nt!KeBug 100 "out file.bin" /PHYS';
                await prompt.fill(physical);
                await prompt.evaluate(input =>
                {
                    input.setSelectionRange("dump-raw nt!KeBug".length, "dump-raw nt!KeBug".length);
                    input.dispatchEvent(new Event("input", { bubbles: true }));
                });
                await prompt.press("Tab");
                assert.equal(await prompt.inputValue(), physical);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "completeSymbols")), false);
                const virtual = 'dump-raw nt!KeBug 100 "C:\\folder /phys data.bin"';
                await prompt.fill(virtual);
                await prompt.evaluate(input =>
                {
                    input.setSelectionRange("dump-raw nt!KeBug".length, "dump-raw nt!KeBug".length);
                    input.dispatchEvent(new Event("input", { bubbles: true }));
                });
                await workspace.waitForFunction(() => document.querySelectorAll("#suggest .suggest-item").length === 1);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "completeSymbols").params.suffix),
                    ' 100 "C:\\folder /phys data.bin"');
                await prompt.press("Tab");
                assert.equal(await prompt.inputValue(), 'dump-raw nt!KeBugCheckEx 100 "C:\\folder /phys data.bin"');
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "classify" || item.method === "execute")), false);
            }
            finally
            {
                await symbolContext.close();
            }
        });
        await check("T-UI-BROWSER symbol lookup errors retain template completion without executing", async () =>
        {
            const symbolContext = await browser.newContext({ viewport: { width: 1100, height: 760 } });
            try
            {
                const workspace = await symbolContext.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                await workspace.addInitScript(fixtureInit, { symbolError: "EngineBusy", catalog: { Dumps: [
                    { name: "dump-pe", grammar: "dump-pe <module|address> <path>", symbolParameters: [0], support: "Stable" }
                ] } });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                const prompt = workspace.locator("#prompt");
                await prompt.fill("dump-pe nt!KeBug");
                await prompt.press("Tab");
                await workspace.waitForFunction(() => document.getElementById("prompt").value === "dump-pe nt!KeBug <path>");
                assert.equal(await prompt.evaluate(input => input.value.slice(input.selectionStart, input.selectionEnd)), "<path>");
                assert.equal(await workspace.locator("#btn-run").isDisabled(), true);
                await prompt.press("Enter");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "classify" || item.method === "execute")), false);
            }
            finally
            {
                await symbolContext.close();
            }
        });
        await check("T-UI-BROWSER inspector symbol lists support keyboard pointer expressions and narrow panels without reads", async () =>
        {
            const symbolContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
            try
            {
                const workspace = await symbolContext.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                await workspace.addInitScript(fixtureInit, { symbols: Array.from({ length: 24 }, (_, index) => ({
                    symbol: "nt!KeBugCheck" + index, address: "0xfffff803" + (0x12345000 + index * 16).toString(16), kind: "symbol"
                })) });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await workspace.locator("#prompt").fill("retained draft");
                for (const view of ["memory", "disassembly"])
                {
                    await workspace.locator(view === "memory" ? "#tab-memory-view" : "#tab-disassembly").click();
                    const input = workspace.locator("#" + view + "-address");
                    const list = workspace.locator("#" + view + "-symbol-suggest");
                    await input.fill("nt!KeBug");
                    await workspace.waitForFunction(view => document.querySelectorAll("#" + view + "-symbol-suggest .suggest-item").length === 24, view);
                    assert.equal(await list.locator(".suggest-address").first().textContent(), "0xfffff80312345000");
                    assert.equal(await workspace.locator("#" + view + "-address-ghost-suffix").textContent(), "Check0");
                    for (let index = 0; index < 20; ++index)
                    {
                        await input.press("ArrowDown");
                    }
                    assert.equal(await list.evaluate(node =>
                    {
                        const active = node.querySelector(".active").getBoundingClientRect();
                        const box = node.getBoundingClientRect();
                        return active.top >= box.top && active.bottom <= box.bottom;
                    }), true);
                    await input.press("Tab");
                    assert.equal(await input.inputValue(), "nt!KeBugCheck20");
                    await input.press("Tab");
                    assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-" + view + "-read");
                    await input.fill("nt!KeBug");
                    await list.waitFor({ state: "visible" });
                    await list.locator(".suggest-item").nth(1).click();
                    assert.equal(await input.inputValue(), "nt!KeBugCheck1");
                    await input.fill("nt!KeBug+0x20");
                    await input.evaluate(node =>
                    {
                        node.setSelectionRange("nt!KeBug".length, "nt!KeBug".length);
                        node.dispatchEvent(new Event("input", { bubbles: true }));
                    });
                    await input.press("Tab");
                    await workspace.waitForFunction(view => document.getElementById(view + "-address").value === "nt!KeBugCheck0+0x20", view);
                    await workspace.setViewportSize({ width: 360, height: 480 });
                    await workspace.waitForFunction(() => document.getElementById("root").classList.contains("memory-overlay"));
                    // Replacement through fill can leave the caret at zero during a resize.
                    await input.press("Control+a");
                    await input.pressSequentially("nt!KeBug");
                    assert.deepEqual(await input.evaluate(node => [node.value, node.selectionStart, node.selectionEnd]),
                        ["nt!KeBug", "nt!KeBug".length, "nt!KeBug".length]);
                    await list.waitFor({ state: "visible" });
                    await list.scrollIntoViewIfNeeded();
                    const bounds = await list.boundingBox();
                    assert.ok(bounds && bounds.x >= 0 && bounds.x + bounds.width <= 361 && bounds.width > 100);
                    for (let index = 0; index < 23; ++index)
                    {
                        await input.press("ArrowDown");
                    }
                    await input.press("Tab");
                    assert.equal(await input.inputValue(), "nt!KeBugCheck23");
                    const inputBounds = await input.boundingBox();
                    assert.ok(inputBounds && inputBounds.x >= 0 && inputBounds.y >= 0 && inputBounds.y + inputBounds.height <= 480);
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, view + "-symbols-narrow.png") });
                    }
                    await workspace.setViewportSize({ width: 1280, height: 900 });
                    await input.fill("nt!NothingMatches");
                    await input.press("Tab");
                    await input.press("Tab");
                    assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-" + view + "-read");
                }
                assert.equal(await workspace.locator("#prompt").inputValue(), "retained draft");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["memoryRead", "disassemblyRead", "debuggerAction", "execute", "classify"].includes(item.method))), false);
            }
            finally
            {
                await symbolContext.close();
            }
        });
        await check("T-UI-BROWSER inspector completions reject old owners physical mode and IME execution", async () =>
        {
            const symbolContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
            try
            {
                const workspace = await symbolContext.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                await workspace.addInitScript(fixtureInit, { holdSymbols: true,
                    symbols: [{ symbol: "nt!KeBugCheckEx", address: "0xfffff80312345678", kind: "symbol" }] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                const memory = workspace.locator("#memory-address");
                const code = workspace.locator("#disassembly-address");
                await memory.fill("nt!KeBug");
                await memory.press("Tab");
                await workspace.waitForFunction(() => window.knTestPendingSymbols.length === 1);
                await workspace.locator("#tab-disassembly").click();
                await code.fill("nt!KeBug");
                await code.press("Tab");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "completeSymbols").length), 1);
                await workspace.evaluate(() => window.knTestReleaseSymbols());
                await workspace.waitForFunction(() => window.knTestRequests.filter(item => item.method === "completeSymbols").length === 2 &&
                    window.knTestPendingSymbols.length === 1);
                assert.equal(await memory.inputValue(), "nt!KeBug");
                assert.equal(await code.inputValue(), "nt!KeBug");
                await workspace.evaluate(() => window.knTestReleaseSymbols());
                await workspace.waitForFunction(() => document.getElementById("disassembly-address").value === "nt!KeBugCheckEx");
                await workspace.locator("#tab-memory-view").click();
                await memory.fill("nt!KeBugC");
                await memory.press("Tab");
                await workspace.locator("#memory-space").selectOption("physical");
                await workspace.evaluate(() => window.knTestReleaseSymbols());
                assert.equal(await memory.inputValue(), "nt!KeBugC");
                assert.equal(await workspace.locator("#memory-symbol-suggest").isHidden(), true);
                const lookups = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "completeSymbols").length);
                await memory.fill("nt!KeBugCh");
                await memory.press("Tab");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "completeSymbols").length), lookups);
                await workspace.locator("#tab-disassembly").click();
                await code.fill("nt!KeBugC");
                await code.press("Tab");
                await code.dispatchEvent("compositionstart");
                await code.press("Enter");
                await code.press("F10");
                await workspace.evaluate(() => window.knTestReleaseSymbols());
                assert.equal(await code.inputValue(), "nt!KeBugC");
                assert.equal(await workspace.locator("#disassembly-symbol-suggest").isHidden(), true);
                await code.dispatchEvent("compositionend");
                await workspace.locator("#tab-memory-view").click();
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["memoryRead", "disassemblyRead", "debuggerAction", "execute", "classify"].includes(item.method))), false);
            }
            finally
            {
                await symbolContext.close();
            }
        });
        await check("T-UI-BROWSER inspector lookup retries preserve focus escape and secondary clicks keep drafts unchanged", async () =>
        {
            const symbolContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
            try
            {
                const workspace = await symbolContext.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                await workspace.addInitScript(fixtureInit, { symbols: [
                    { symbol: "nt!KeBugCheckEx", address: "0xfffff80312345678", kind: "symbol" },
                    { symbol: "nt!KeBugCheck2", address: "0xfffff80322345678", kind: "symbol" }
                ] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                for (const view of ["memory", "disassembly"])
                {
                    await workspace.locator(view === "memory" ? "#tab-memory-view" : "#tab-disassembly").click();
                    const input = workspace.locator("#" + view + "-address");
                    const list = workspace.locator("#" + view + "-symbol-suggest");
                    await workspace.evaluate(() =>
                    {
                        window.knTestSymbolError = "EngineBusy";
                    });
                    await input.fill("nt!KeBug");
                    await input.press("Tab");
                    await input.press("Tab");
                    assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-" + view + "-read");
                    const before = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "completeSymbols").length);
                    await workspace.evaluate(() =>
                    {
                        window.knTestSymbolError = "";
                    });
                    await input.click({ position: { x: 120, y: 16 } });
                    await list.waitFor({ state: "visible" });
                    assert.equal(await input.inputValue(), "nt!KeBug");
                    assert.ok(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "completeSymbols").length) > before);
                    for (const button of ["right", "middle"])
                    {
                        await list.locator(".suggest-item").first().click({ button });
                        assert.equal(await input.inputValue(), "nt!KeBug", view + ":" + button);
                        await input.press("Escape");
                        await input.click({ position: { x: 120, y: 16 } });
                        await list.waitFor({ state: "visible" });
                    }
                    await list.locator(".suggest-item").nth(1).click();
                    assert.equal(await input.inputValue(), "nt!KeBugCheck2");
                    await input.press("Tab");
                    assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-" + view + "-read");
                }
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["memoryRead", "disassemblyRead", "debuggerAction", "execute", "classify"].includes(item.method))), false);
            }
            finally
            {
                await symbolContext.close();
            }
        });
        await check("T-UI-BROWSER inspection address histories restore expressions and spaces across reload without automatic reads", async () =>
        {
            const historyContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
            try
            {
                const workspace = await historyContext.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await workspace.locator("#memory-size").selectOption("64");
                await workspace.locator("#memory-address").fill("nt!Example + 10");
                await workspace.locator("#memory-address").press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("btn-memory-read").disabled);
                await workspace.locator("#memory-space").selectOption("physical");
                await workspace.locator("#memory-address").fill("0x1234");
                await workspace.locator("#memory-address").press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("btn-memory-read").disabled);
                await workspace.locator("#tab-disassembly").click();
                await workspace.locator("#disassembly-count").selectOption("16");
                await workspace.locator("#disassembly-address").fill("nt!KeBugCheckEx+0x10");
                await workspace.locator("#disassembly-address").press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("btn-disassembly-read").disabled);
                await workspace.reload();
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["memoryRead", "disassemblyRead", "execute", "debuggerAction"].includes(item.method))), false);
                const codeHistory = workspace.locator("#disassembly-address-history");
                assert.equal(await codeHistory.locator("option").nth(1).textContent(), "nt!KeBugCheckEx+0x10");
                assert.equal(await workspace.locator("#memory-address-history option").count(), 3);
                await workspace.evaluate(() => window.knTestChangeContext());
                await workspace.locator("#btn-refresh-status").click();
                await workspace.waitForFunction(() => document.getElementById("current-process-image").textContent === "changed.exe");
                await codeHistory.selectOption("0");
                await workspace.waitForFunction(() => !document.getElementById("btn-disassembly-read").disabled);
                const codeRequest = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "disassemblyRead"));
                assert.equal(codeRequest.params.expression, "nt!KeBugCheckEx+0x10");
                assert.equal(codeRequest.params.expectedStamp.contextGeneration, "2");
                assert.equal(await workspace.locator("#btn-disassembly-follow").getAttribute("aria-pressed"), "false");
                assert.equal(await codeHistory.inputValue(), "");
                await workspace.locator("#tab-memory-view").click();
                const memoryHistory = workspace.locator("#memory-address-history");
                assert.equal(await memoryHistory.locator("option").nth(1).textContent(), "[Physical] 0x1234");
                await memoryHistory.selectOption("0");
                await workspace.waitForFunction(() => !document.getElementById("btn-memory-read").disabled);
                assert.equal(await workspace.locator("#memory-space").inputValue(), "physical");
                let request = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "memoryRead"));
                assert.equal(request.params.expression, "0x1234");
                assert.equal(request.params.space, "physical");
                await memoryHistory.selectOption("1");
                await workspace.waitForFunction(() => !document.getElementById("btn-memory-read").disabled);
                request = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "memoryRead"));
                assert.equal(request.params.expression, "nt!Example + 10");
                assert.equal(request.params.space, "virtual");
                assert.equal(await memoryHistory.locator("option").count(), 3);
                await workspace.locator("#memory-address").focus();
                await workspace.locator("#memory-address").press("Tab");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-memory-read");
                await workspace.keyboard.press("Tab");
                await workspace.keyboard.press("Tab");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "memory-address-history");
                await workspace.setViewportSize({ width: 360, height: 480 });
                for (const view of ["memory", "disassembly"])
                {
                    await workspace.locator(view === "memory" ? "#tab-memory-view" : "#tab-disassembly").click();
                    const history = workspace.locator("#" + view + "-address-history");
                    await history.scrollIntoViewIfNeeded();
                    const bounds = await history.boundingBox();
                    assert.ok(bounds && bounds.x >= 0 && bounds.x + bounds.width <= 361 && bounds.width > 100);
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, view + "-address-history-narrow.png") });
                    }
                }
            }
            finally
            {
                await historyContext.close();
            }
        });
        await check("T-UI-BROWSER closing others recovers the kept result after an adjacent open failed", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                const ids = [];
                for (let index = 0; index < 3; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                    ids.push(await workspace.locator("#result-history").inputValue());
                }
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.evaluate(id => { window.knTestMissingResultId = id; }, ids[1]);
                await workspace.locator("#result-tabs .result-tab-close").last().click();
                await workspace.waitForFunction(() => document.getElementById("result-notice-text").textContent.includes("expired or unavailable"));
                assert.equal(await workspace.locator("#result-tabs [role=tab]").count(), 2);
                assert.equal(await workspace.locator("#result-title").textContent(), "Debugger workspace");
                await workspace.evaluate(() => { window.knTestMissingResultId = ""; });
                await workspace.locator("#result-tabs [role=tab]").first().click({ button: "right" });
                await workspace.getByRole("menuitem", { name: "Close other tabs", exact: true }).click();
                await workspace.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
                assert.equal(await workspace.locator("#result-history").inputValue(), ids[0]);
                assert.equal(await workspace.locator("#result-tabs [role=tab]").count(), 1);
                assert.equal(await workspace.locator("#result-tabs [role=tab]").getAttribute("aria-selected"), "true");
                assert.equal(await workspace.locator("#result-title").textContent(), "db nt L10");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "tab-menu-recover-open.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER cancelling a result open through the tab menu clears visible loading status", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                const ids = [];
                for (let index = 0; index < 2; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                    ids.push(await workspace.locator("#result-history").inputValue());
                }
                await workspace.locator("#result-tabs [role=tab]").first().click();
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id, ids[0]);
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.locator("#result-open-toggle").click();
                await workspace.locator("#result-id-input").fill(ids[1]);
                await workspace.evaluate(() => { window.knTestHoldResultInfo = true; });
                await workspace.locator("#btn-result-load").click();
                await workspace.waitForFunction(() => typeof window.knTestReleaseResultInfo === "function");
                assert.equal(await workspace.locator("#result-load-status").textContent(), "Opening result...");
                await workspace.locator("#result-tabs [role=tab]").first().click({ button: "right" });
                await workspace.getByRole("menuitem", { name: "Close other tabs", exact: true }).click();
                assert.equal(await workspace.locator("#result-load-status").textContent(), "");
                await workspace.evaluate(() => window.knTestReleaseResultInfo());
                await workspace.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
                assert.equal(await workspace.locator("#result-tabs [role=tab]").count(), 1);
                assert.equal(await workspace.locator("#result-history").inputValue(), ids[0]);
                assert.equal(await workspace.locator("#result-load-status").textContent(), "");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "tab-menu-cancel-open.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER result tab menus close the clicked background tab others and all without replay", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["sort-fixture", "db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("sort-fixture");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("btn-stack").disabled && document.querySelectorAll(".result-row").length > 0);
                await workspace.getByRole("button", { name: "PID: Sort ascending by PID", exact: true }).click();
                await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID (ascending)"));
                await workspace.locator(".result-row").nth(20).click();
                await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).focus();
                await workspace.keyboard.press("End");
                await workspace.locator("#result-table").focus();
                await workspace.locator("#result-view").evaluate(view =>
                {
                    view.scrollTop = 560;
                    view.scrollLeft = 73;
                    view.dispatchEvent(new Event("scroll"));
                });
                const first = await workspace.locator("#result-history").inputValue();
                for (let index = 0; index < 2; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 2);
                }
                const active = await workspace.locator("#result-history").inputValue();
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.locator("#result-tabs [role=tab]").first().click({ button: "right" });
                assert.equal(await workspace.locator("#result-history").inputValue(), active);
                assert.equal(await workspace.locator("#result-tab-menu").isVisible(), true);
                const retention = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "resultTabs").length);
                await workspace.getByRole("menuitem", { name: "Close other tabs", exact: true }).click();
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id &&
                    document.getElementById("row-position").textContent === "Sorted by PID (ascending) / Row 21 of 260", first);
                assert.equal(await workspace.locator("#result-tabs [role=tab]").count(), 1);
                assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pid, "21");
                assert.deepEqual(await workspace.locator("#result-view").evaluate(view => ({ top: view.scrollTop, left: view.scrollLeft })),
                    { top: 560, left: 73 });
                assert.equal(await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).getAttribute("aria-valuenow"), "4096");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "resultTabs").length), retention + 1);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                await workspace.locator("#prompt").fill("db nt L10");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll("#result-tabs [role=tab]").length === 2 &&
                    !document.getElementById("btn-stack").disabled);
                const remaining = await workspace.locator("#result-history").inputValue();
                await workspace.locator("#prompt").fill("keep draft");
                const opens = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "resultInfo").length);
                await workspace.locator("#result-tabs [role=tab]").first().click({ button: "right" });
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tab-menu.png") });
                }
                await workspace.getByRole("menuitem", { name: "Close tab", exact: true }).click();
                assert.equal(await workspace.locator("#result-history").inputValue(), remaining);
                assert.equal(await workspace.locator("#result-tabs [role=tab]").count(), 1);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "resultInfo").length), opens);
                await workspace.locator("#result-tabs [role=tab]").first().click({ button: "right" });
                assert.equal(await workspace.getByRole("menuitem", { name: "Close other tabs", exact: true }).isDisabled(), true);
                await workspace.getByRole("menuitem", { name: "Close all tabs", exact: true }).click();
                assert.equal(await workspace.locator("#result-tabs").isVisible(), false);
                assert.equal(await workspace.locator("#result-title").textContent(), "Debugger workspace");
                assert.equal(await workspace.locator("#empty-title").textContent(), "Ready to inspect");
                assert.equal(await workspace.locator("#prompt").inputValue(), "keep draft");
                assert.equal(await workspace.locator("#result-table").evaluate(node => document.activeElement === node), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions + 1);
                assert.deepEqual(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "resultTabs").at(-1).params.resultIds), []);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER result tab menus support keyboard focus dismissal and a narrow viewport", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("db nt L10");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll("#result-tabs [role=tab]").length === 1 &&
                    !document.getElementById("btn-stack").disabled);
                await workspace.evaluate(() =>
                {
                    window.knTestMenuViewportReady = new Promise(resolve =>
                    {
                        window.addEventListener("resize", () => requestAnimationFrame(() => requestAnimationFrame(resolve)), { once: true });
                    });
                });
                await workspace.setViewportSize({ width: 360, height: 760 });
                await workspace.evaluate(() => window.knTestMenuViewportReady);
                const tab = workspace.locator("#result-tabs [role=tab]");
                const title = await tab.getAttribute("title");
                await tab.press("Shift+F10");
                const menu = workspace.locator("#result-tab-menu");
                assert.equal(await menu.isVisible(), true);
                assert.equal(await tab.getAttribute("title"), "");
                assert.equal(await workspace.locator("#result-tabs .result-tab-close").getAttribute("title"), "");
                const box = await menu.boundingBox();
                assert.ok(box.x >= 8 && box.y >= 8 && box.x + box.width <= 352 && box.y + box.height <= 752, JSON.stringify(box));
                await workspace.keyboard.press("ArrowDown");
                assert.equal(await workspace.locator("#result-tab-close-all").evaluate(node => document.activeElement === node), true);
                await workspace.keyboard.press("Home");
                assert.equal(await workspace.locator("#result-tab-close-current").evaluate(node => document.activeElement === node), true);
                await workspace.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
                assert.equal(await menu.isVisible(), true);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tab-menu-narrow.png") });
                }
                await workspace.keyboard.press("Escape");
                assert.equal(await menu.isVisible(), false);
                assert.equal(await tab.evaluate(node => document.activeElement === node), true);
                assert.equal(await tab.getAttribute("aria-expanded"), "false");
                assert.equal(await tab.getAttribute("title"), title);
                await tab.press("Shift+F10");
                await workspace.locator("#prompt").click();
                assert.equal(await menu.isVisible(), false);
                await tab.press("Shift+F10");
                await workspace.keyboard.press("Control+k");
                assert.equal(await menu.isVisible(), false);
                assert.equal(await workspace.locator("#palette").isVisible(), true);
                await workspace.keyboard.press("Escape");
                await tab.press("Shift+F10");
                await workspace.setViewportSize({ width: 420, height: 760 });
                await workspace.waitForFunction(() => document.getElementById("result-tab-menu").classList.contains("hidden"));
                await tab.press("Shift+F10");
                await workspace.keyboard.press("Enter");
                assert.equal(await workspace.locator("#result-tabs").isVisible(), false);
                assert.equal(await workspace.locator("#empty-title").textContent(), "Ready to inspect");
                assert.equal(await workspace.locator("#result-table").evaluate(node => document.activeElement === node), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 1);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER named repeated-command tabs retain sort selection viewports and identity through reorder and reopen", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.setViewportSize({ width: 1280, height: 900 });
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["sort-fixture"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                const ids = [];
                const names = ["Before", "After \uafc0\ubcf4"];
                for (let index = 0; index < 2; ++index)
                {
                    await workspace.locator("#prompt").fill("sort-fixture");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                    ids.push(await workspace.locator("#result-history").inputValue());
                    await workspace.getByRole("button", { name: "PID: Sort ascending by PID", exact: true }).click();
                    await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID (ascending)"));
                    if (index === 1)
                    {
                        await workspace.getByRole("button", { name: "PID: Sort descending by PID", exact: true }).click();
                        await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID (descending)"));
                    }
                    await workspace.locator("#result-table").focus();
                    await workspace.keyboard.press("Home");
                    for (let step = 0; step < (index === 0 ? 20 : 10); ++step)
                    {
                        await workspace.keyboard.press("ArrowDown");
                    }
                    assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pid, index === 0 ? "21" : "250");
                    await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).focus();
                    await workspace.keyboard.press("End");
                    await workspace.locator("#result-table").focus();
                    await workspace.locator("#result-view").evaluate((view, index) =>
                    {
                        view.scrollTop = index === 0 ? 560 : 280;
                        view.scrollLeft = index === 0 ? 73 : 131;
                        view.dispatchEvent(new Event("scroll"));
                    }, index);
                    const before = await workspace.evaluate(() =>
                    {
                        window.knTestRenameRows = document.getElementById("result-rows").firstChild;
                        return window.knTestRequests.filter(item => item.method !== "status").length;
                    });
                    await workspace.locator("#result-tabs [role=tab]").nth(index).dblclick();
                    const input = workspace.getByRole("textbox", { name: "Result tab name", exact: true });
                    assert.equal(await input.inputValue(), "sort-fixture");
                    assert.equal(await input.evaluate(node => node.selectionStart === 0 && node.selectionEnd === node.value.length), true);
                    await input.fill(names[index]);
                    if (evidence && index === 1)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "result-tab-rename-editor.png") });
                    }
                    await input.press("Enter");
                    assert.equal(await workspace.evaluate(() => window.knTestRenameRows === document.getElementById("result-rows").firstChild), true);
                    assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length), before);
                    assert.equal(await workspace.locator("#result-title").textContent(), "sort-fixture");
                    const tab = workspace.locator("#result-tabs [role=tab]").nth(index);
                    assert.equal(await tab.getAttribute("title"), names[index] + "\nsort-fixture / " + ids[index]);
                    assert.equal(await tab.getAttribute("aria-label"), names[index] + " / " + ids[index].slice(0, 8));
                    assert.equal(await tab.evaluate(node => document.activeElement === node), true);
                }
                await workspace.locator("#prompt").fill("keep rename draft");
                const last = await workspace.locator("#result-tabs [role=tab]").last().boundingBox();
                await dragResultTab(workspace, workspace.locator("#result-tabs [role=tab]").first(),
                    last.x + last.width - 2, last.y + last.height / 2);
                await workspace.mouse.up();
                assert.deepEqual(await workspace.locator(".result-tab-label").allTextContents(), [names[1], names[0]]);
                for (const [index, direction, pid, row, top, left] of [[0, "ascending", "21", 21, 560, 73], [1, "descending", "250", 11, 280, 131]])
                {
                    const tab = workspace.getByRole("tab", { name: names[index] + " / " + ids[index].slice(0, 8), exact: true });
                    await tab.click();
                    await workspace.waitForFunction(expected => document.getElementById("row-position").textContent === expected,
                        "Sorted by PID (" + direction + ") / Row " + row + " of 260");
                    assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pid, pid);
                    assert.deepEqual(await workspace.locator("#result-view").evaluate(view => ({ top: view.scrollTop, left: view.scrollLeft })), { top, left });
                    assert.equal(await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).getAttribute("aria-valuenow"), "4096");
                }
                assert.equal(await workspace.locator("#prompt").inputValue(), "keep rename draft");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 2);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tabs-named.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER tab name editing handles IME Escape blur reset literal text and a narrow viewport", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.setViewportSize({ width: 480, height: 720 });
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("db nt L10");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll("#result-tabs [role=tab]").length === 1 &&
                    !document.getElementById("btn-stack").disabled);
                const tab = workspace.locator("#result-tabs [role=tab]");
                await tab.press("F2");
                let input = workspace.getByRole("textbox", { name: "Result tab name", exact: true });
                await input.fill("\ud55c\uae00 \uad6c\ubd84 \ud83d\ude00");
                await input.dispatchEvent("compositionstart", { data: "\ubd84" });
                await input.press("Enter");
                assert.equal(await input.isVisible(), true);
                await input.dispatchEvent("compositionend", { data: "\ubd84" });
                await input.press("Enter");
                assert.equal(await tab.locator(".result-tab-label").textContent(), "\ud55c\uae00 \uad6c\ubd84 \ud83d\ude00");
                await tab.dblclick();
                input = workspace.getByRole("textbox", { name: "Result tab name", exact: true });
                await input.fill("discard this");
                await input.press("Escape");
                assert.equal(await tab.locator(".result-tab-label").textContent(), "\ud55c\uae00 \uad6c\ubd84 \ud83d\ude00");
                await tab.press("F2");
                input = workspace.getByRole("textbox", { name: "Result tab name", exact: true });
                await input.fill("  <img src=x onerror=alert(1)>  ");
                await workspace.locator("#prompt").click();
                assert.equal(await tab.locator(".result-tab-label").textContent(), "<img src=x onerror=alert(1)>");
                assert.equal(await workspace.locator("#result-tabs img").count(), 0);
                assert.equal(await workspace.locator("#prompt").evaluate(node => document.activeElement === node), true);
                await tab.press("F2");
                input = workspace.getByRole("textbox", { name: "Result tab name", exact: true });
                assert.equal(await input.getAttribute("maxlength"), "128");
                await input.fill("long ".repeat(25));
                const bounds = await input.boundingBox();
                assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 480);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tab-rename-narrow.png") });
                }
                await input.press("Tab");
                assert.equal(await workspace.locator(".result-tab-name").count(), 0);
                assert.equal(await workspace.locator(".result-tab-close").evaluate(node => document.activeElement === node), true);
                await tab.press("F2");
                input = workspace.getByRole("textbox", { name: "Result tab name", exact: true });
                await input.fill("   ");
                await input.press("Enter");
                assert.equal(await tab.locator(".result-tab-label").textContent(), "db nt L10");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 1);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER pending result replies retain the name editor and closing releases names without command replay", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                const ids = [];
                for (let index = 0; index < 2; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                    ids.push(await workspace.locator("#result-history").inputValue());
                }
                const first = workspace.locator(".result-tab").first();
                await workspace.evaluate(() => { window.knTestHoldResultInfo = true; });
                const before = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "resultInfo").length);
                await first.locator("[role=tab]").dblclick();
                const input = workspace.getByRole("textbox", { name: "Result tab name", exact: true });
                await input.fill("saved while loading");
                await workspace.waitForFunction(() => typeof window.knTestReleaseResultInfo === "function");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "resultInfo").length), before + 1);
                await workspace.evaluate(() => window.knTestReleaseResultInfo());
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id, ids[0]);
                assert.equal(await input.inputValue(), "saved while loading");
                assert.equal(await input.evaluate(node => document.activeElement === node), true);
                await input.press("Enter");
                await first.locator("[role=tab]").click({ button: "right" });
                await workspace.locator("#result-tab-menu").press("Escape");
                assert.equal(await first.locator("[role=tab]").getAttribute("title"), "saved while loading\ndb nt L10 / " + ids[0]);
                await first.locator("[role=tab]").press("F2");
                await workspace.getByRole("textbox", { name: "Result tab name", exact: true }).fill("closed draft");
                await first.locator(".result-tab-close").click();
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id, ids[1]);
                assert.equal(await workspace.locator(".result-tab-name").count(), 0);
                await workspace.locator("#result-open-toggle").click();
                await workspace.locator("#result-id-input").fill(ids[0]);
                await workspace.locator("#btn-result-load").click();
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id, ids[0]);
                assert.deepEqual(await workspace.locator(".result-tab-label").allTextContents(), ["db nt L10", "db nt L10"]);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 2);
            }
            finally
            {
                await workspace.close();
            }
        });

        await check("T-UI-BROWSER another tab's late metadata preserves the focused name draft and keyboard editing", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                const ids = [];
                for (let index = 0; index < 2; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                    ids.push(await workspace.locator("#result-history").inputValue());
                }
                await workspace.evaluate(() => { window.knTestHoldResultInfo = true; });
                const tabs = workspace.locator("#result-tabs [role=tab]");
                await tabs.first().click();
                await workspace.waitForFunction(() => typeof window.knTestReleaseResultInfo === "function");
                await tabs.last().press("F2");
                const input = workspace.getByRole("textbox", { name: "Result tab name", exact: true });
                await input.fill("unfinished \uad6c\ubd84");
                await workspace.evaluate(() => window.knTestReleaseResultInfo());
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id, ids[0]);
                assert.equal(await input.count(), 1, "Unrelated metadata removed the focused editor");
                assert.equal(await input.evaluate(node => document.activeElement === node), true);
                await input.press("End");
                await input.press("Space");
                await workspace.keyboard.type("complete");
                await input.press("Enter");
                assert.equal(await tabs.last().locator(".result-tab-label").textContent(), "unfinished \uad6c\ubd84 complete");
                assert.equal(await tabs.first().getAttribute("aria-selected"), "true");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 2);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tab-name-late-other.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER an active named result can retry a transient row failure without executing again", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["code-fixture"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.evaluate(() => { window.knTestFailResultPage = true; });
                await workspace.locator("#prompt").fill("code-fixture");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.getElementById("result-notice-text").textContent.includes("Rows unavailable") &&
                    !document.getElementById("btn-stack").disabled);
                const tab = workspace.locator("#result-tabs [role=tab]");
                await tab.press("F2");
                const input = workspace.getByRole("textbox", { name: "Result tab name", exact: true });
                await input.fill("retry named result");
                await input.press("Enter");
                const before = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "resultInfo").length);
                await tab.click();
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "resultInfo").length), before + 1,
                    "The active tab cannot retry its failed rows");
                await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 3 &&
                    !document.getElementById("result-notice-text").textContent.includes("Rows unavailable"));
                assert.equal(await tab.locator(".result-tab-label").textContent(), "retry named result");
                assert.equal(await workspace.locator("#result-title").textContent(), "code-fixture");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 1);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tab-name-row-retry.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });

        async function dragResultTab(workspace, tab, x, y)
        {
            const box = await tab.boundingBox();
            assert.ok(box);
            await workspace.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
            await workspace.mouse.down();
            await workspace.mouse.move(x, y, { steps: 12 });
        }
        await check("T-UI-BROWSER dragging repeated-command tabs preserves active and saved sort selection widths and viewports", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.setViewportSize({ width: 1280, height: 900 });
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["sort-fixture", "db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                const ids = [];
                for (let index = 0; index < 2; ++index)
                {
                    await workspace.locator("#prompt").fill("sort-fixture");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                    ids.push(await workspace.locator("#result-history").inputValue());
                    await workspace.getByRole("button", { name: "PID: Sort ascending by PID", exact: true }).click();
                    await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID (ascending)"));
                    if (index === 1)
                    {
                        await workspace.getByRole("button", { name: "PID: Sort descending by PID", exact: true }).click();
                        await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID (descending)"));
                    }
                    await workspace.locator("#result-table").focus();
                    await workspace.keyboard.press("Home");
                    for (let step = 0; step < (index === 0 ? 20 : 10); ++step)
                    {
                        await workspace.keyboard.press("ArrowDown");
                    }
                    assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pid, index === 0 ? "21" : "250");
                    await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).focus();
                    await workspace.keyboard.press("End");
                    await workspace.locator("#result-table").focus();
                    await workspace.locator("#result-view").evaluate((view, index) =>
                    {
                        view.scrollTop = index === 0 ? 560 : 280;
                        view.scrollLeft = index === 0 ? 73 : 131;
                        view.dispatchEvent(new Event("scroll"));
                    }, index);
                }
                await workspace.locator("#prompt").fill("db nt L10");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll("#result-tabs [role=tab]").length === 3 &&
                    !document.getElementById("btn-stack").disabled);
                ids.push(await workspace.locator("#result-history").inputValue());
                await workspace.locator("#prompt").fill("keep drag draft");
                const tabs = workspace.locator("#result-tabs [role=tab]");
                await workspace.evaluate(() => { window.knTestOriginalTabNodes = [...document.querySelectorAll("#result-tabs [role=tab]")]; });
                const requests = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length);
                const last = await tabs.last().boundingBox();
                await dragResultTab(workspace, tabs.first(), last.x + last.width - 4, last.y + last.height / 2);
                assert.equal(await workspace.locator(".result-tab.drag-source").count(), 1);
                assert.equal(await workspace.locator(".result-tab.drop-after").count(), 1);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tab-drag.png") });
                }
                await workspace.mouse.up();
                assert.equal(await workspace.evaluate(() => [...document.querySelectorAll("#result-tabs [role=tab]")]
                    .every((node, index) => node === window.knTestOriginalTabNodes[[1, 2, 0][index]])), true);
                assert.equal(await workspace.locator("#result-history").inputValue(), ids[2]);
                const front = await tabs.first().boundingBox();
                await dragResultTab(workspace, tabs.nth(1), front.x + 2, front.y + front.height / 2);
                await workspace.mouse.up();
                assert.equal(await workspace.evaluate(() => [...document.querySelectorAll("#result-tabs [role=tab]")]
                    .every((node, index) => node === window.knTestOriginalTabNodes[[2, 1, 0][index]])), true);
                assert.equal(await workspace.locator("#result-history").inputValue(), ids[2]);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length), requests);
                for (const [index, direction, pid, row, top, left] of [[0, "ascending", "21", 21, 560, 73], [1, "descending", "250", 11, 280, 131]])
                {
                    await workspace.getByRole("tab", { name: "sort-fixture / " + ids[index].slice(0, 8), exact: true }).click();
                    await workspace.waitForFunction(expected => document.getElementById("row-position").textContent === expected,
                        "Sorted by PID (" + direction + ") / Row " + row + " of 260");
                    assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pid, pid);
                    assert.deepEqual(await workspace.locator("#result-view").evaluate(view => ({ top: view.scrollTop, left: view.scrollLeft })), { top, left });
                    assert.equal(await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).getAttribute("aria-valuenow"), "4096");
                }
                const activeRows = await workspace.evaluate(() =>
                {
                    window.knTestActiveRows = document.getElementById("result-rows").firstChild;
                    return window.knTestRequests.filter(item => item.method !== "status").length;
                });
                const end = await tabs.last().boundingBox();
                await dragResultTab(workspace, tabs.nth(1), end.x + end.width - 2, end.y + end.height / 2);
                await workspace.mouse.up();
                assert.equal(await workspace.evaluate(() => window.knTestActiveRows === document.getElementById("result-rows").firstChild), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length), activeRows);
                assert.deepEqual(await workspace.locator("#result-view").evaluate(view => ({ top: view.scrollTop, left: view.scrollLeft })), { top: 280, left: 131 });
                assert.equal(await workspace.locator("#prompt").inputValue(), "keep drag draft");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 3);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER dragged pending tabs accept their response while Escape outside drops and keyboard moves remain usable", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.setViewportSize({ width: 1280, height: 900 });
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                const ids = [];
                for (let index = 0; index < 3; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                    ids.push(await workspace.locator("#result-history").inputValue());
                }
                const order = () => workspace.locator("#result-tabs [role=tab]").evaluateAll(nodes => nodes.map(node => node.getAttribute("aria-label")));
                const names = ids.map(id => "db nt L10 / " + id.slice(0, 8));
                await workspace.evaluate(() => { window.knTestHoldResultInfo = true; });
                const pending = workspace.getByRole("tab", { name: names[1], exact: true });
                await pending.click();
                await workspace.waitForFunction(() => typeof window.knTestReleaseResultInfo === "function");
                const requests = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length);
                const front = await workspace.locator("#result-tabs [role=tab]").first().boundingBox();
                await dragResultTab(workspace, pending, front.x + 2, front.y + front.height / 2);
                await workspace.mouse.up();
                assert.deepEqual(await order(), [names[1], names[0], names[2]]);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length), requests);
                assert.equal(await workspace.locator("#result-load-status").textContent(), "Opening result...");
                await workspace.evaluate(() => { window.knTestHoldResultInfo = false; window.knTestReleaseResultInfo(); });
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id, ids[1]);
                const last = await workspace.locator("#result-tabs [role=tab]").last().boundingBox();
                for (const cancel of ["escape", "outside", "palette"])
                {
                    await dragResultTab(workspace, pending, last.x + last.width - 2, last.y + last.height / 2);
                    if (cancel === "escape")
                    {
                        await workspace.keyboard.press("Escape");
                    }
                    else if (cancel === "outside")
                    {
                        await workspace.mouse.move(last.x, last.y + last.height + 40);
                    }
                    else
                    {
                        await workspace.keyboard.press("Control+k");
                        assert.equal(await workspace.locator("#palette").isVisible(), true);
                    }
                    await workspace.mouse.up();
                    if (cancel === "palette")
                    {
                        await workspace.keyboard.press("Escape");
                    }
                    assert.deepEqual(await order(), [names[1], names[0], names[2]]);
                    assert.equal(await workspace.locator(".drag-source, .drop-before, .drop-after").count(), 0);
                }
                await workspace.getByRole("tab", { name: names[2], exact: true }).click();
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id, ids[2]);
                await pending.click();
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id, ids[1]);
                await pending.press("Control+Shift+ArrowRight");
                assert.deepEqual(await order(), names);
                assert.equal(await pending.evaluate(node => node === document.activeElement), true);
                await pending.press("Control+Shift+ArrowLeft");
                assert.deepEqual(await order(), [names[1], names[0], names[2]]);
                assert.equal(await workspace.locator("#result-history").inputValue(), ids[1]);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 3);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER dragging at a narrow strip edge scrolls to hidden tabs in both directions", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.setViewportSize({ width: 460, height: 760 });
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                for (let index = 0; index < 8; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                }
                const order = () => workspace.locator("#result-tabs [role=tab]").evaluateAll(nodes => nodes.map(node => node.getAttribute("aria-label")));
                const original = await order();
                const active = await workspace.locator("#result-history").inputValue();
                const requests = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length);
                const strip = workspace.locator("#result-tabs");
                await strip.evaluate(node => { node.scrollLeft = 0; });
                const bounds = await strip.boundingBox();
                const source = workspace.getByRole("tab", { name: original[0], exact: true });
                await dragResultTab(workspace, source, bounds.x + bounds.width - 5, bounds.y + bounds.height / 2);
                await workspace.waitForFunction(() =>
                {
                    const strip = document.getElementById("result-tabs");
                    return strip.scrollLeft >= strip.scrollWidth - strip.clientWidth - 1;
                }, null, { timeout: 15000 });
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tab-drag-overflow.png") });
                }
                await workspace.mouse.up();
                assert.deepEqual(await order(), [...original.slice(1), original[0]]);
                await dragResultTab(workspace, source, bounds.x + 5, bounds.y + bounds.height / 2);
                await workspace.waitForFunction(() => document.getElementById("result-tabs").scrollLeft === 0, null, { timeout: 15000 });
                await workspace.mouse.up();
                assert.deepEqual(await order(), original);
                assert.equal(await workspace.locator("#result-history").inputValue(), active);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length), requests);
                assert.equal(await strip.evaluate(node => node.classList.contains("reordering")), false);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER edge scrolling progresses during continuous pointer movement and stops away from the edge", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.setViewportSize({ width: 460, height: 760 });
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                for (let index = 0; index < 8; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                }
                const strip = workspace.locator("#result-tabs");
                await strip.evaluate(node => { node.scrollLeft = 0; });
                const bounds = await strip.boundingBox();
                const active = await workspace.locator("#result-history").inputValue();
                const requests = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length);
                await dragResultTab(workspace, workspace.locator("#result-tabs [role=tab]").first(),
                    bounds.x + bounds.width - 5, bounds.y + bounds.height / 2);
                const initial = await strip.evaluate(node => node.scrollLeft);
                const startedAt = Date.now();
                let moves = 0;
                while (Date.now() - startedAt < 1000)
                {
                    await workspace.mouse.move(bounds.x + bounds.width - 5, bounds.y + bounds.height / 2 + moves % 2);
                    ++moves;
                }
                const progress = await strip.evaluate(node => node.scrollLeft);
                assert.ok(progress - initial >= 64, JSON.stringify({ moves, initial, progress }));
                await workspace.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
                const stopped = await strip.evaluate(node => node.scrollLeft);
                await workspace.waitForTimeout(100);
                assert.equal(await strip.evaluate(node => node.scrollLeft), stopped);
                await workspace.evaluate(() =>
                {
                    window.knTestMarkerBeforeScroll = document.querySelector("#result-tabs .drop-before, #result-tabs .drop-after");
                });
                await workspace.mouse.wheel(180, 0);
                await workspace.waitForFunction(left => document.getElementById("result-tabs").scrollLeft > left, stopped);
                await workspace.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
                assert.equal(await workspace.evaluate(() =>
                {
                    const marker = document.querySelector("#result-tabs .drop-before, #result-tabs .drop-after");
                    return marker !== null && marker !== window.knTestMarkerBeforeScroll;
                }), true, "Horizontal wheel scrolling must move the insertion marker to the new visible target");
                await workspace.keyboard.press("Escape");
                await workspace.mouse.up();
                assert.equal(await workspace.locator("#result-history").inputValue(), active);
                assert.equal(await workspace.locator(".drag-source, .drop-before, .drop-after").count(), 0);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length), requests);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tab-edge-motion.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER a short press released outside the tab cancels selection and the next click still works", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                for (let index = 0; index < 2; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                }
                const active = await workspace.locator("#result-history").inputValue();
                const tab = workspace.locator("#result-tabs [role=tab]").first();
                const box = await tab.boundingBox();
                const requests = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length);
                await workspace.mouse.move(box.x + box.width / 2, box.y + box.height - 2);
                await workspace.mouse.down();
                await workspace.mouse.move(box.x + box.width / 2, box.y + box.height + 2);
                await workspace.mouse.up();
                await workspace.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
                assert.equal(await workspace.locator("#result-history").inputValue(), active);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method !== "status").length), requests);
                assert.equal(await workspace.locator(".drag-source, .drop-before, .drop-after").count(), 0);
                await tab.click();
                await workspace.waitForFunction(id => document.getElementById("result-history").value !== id, active);
                assert.equal(await tab.getAttribute("aria-selected"), "true");
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER delayed sorted-tab restoration survives native scroll events and a newer viewport", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["sort-fixture", "db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("sort-fixture");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("btn-stack").disabled && document.querySelectorAll(".result-row").length > 0);
                await workspace.getByRole("button", { name: "PID: Sort ascending by PID", exact: true }).click();
                await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID (ascending)"));
                await workspace.getByRole("button", { name: "PID: Sort descending by PID", exact: true }).click();
                await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID (descending)"));
                await workspace.locator(".result-row").nth(20).click();
                await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).focus();
                await workspace.keyboard.press("End");
                await workspace.locator("#result-table").focus();
                await workspace.locator("#result-view").evaluate(view =>
                {
                    view.scrollTop = 560;
                    view.scrollLeft = 73;
                    view.dispatchEvent(new Event("scroll"));
                });
                await workspace.locator("#prompt").fill("db nt L10");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll("#result-tabs [role=tab]").length === 2 &&
                    !document.getElementById("btn-stack").disabled);
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                for (const changed of [false, true])
                {
                    if (changed)
                    {
                        await workspace.locator("#result-tabs [role=tab]").nth(1).click();
                        await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "db nt L10");
                    }
                    await workspace.evaluate(() => { window.knTestHoldSortPage = true; });
                    await workspace.locator("#result-tabs [role=tab]").first().click();
                    await workspace.waitForFunction(() => typeof window.knTestReleaseSortPage === "function");
                    await workspace.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
                    if (changed)
                    {
                        await workspace.locator("#result-view").evaluate(view =>
                        {
                            view.scrollTop = 840;
                            view.scrollLeft = 91;
                            view.dispatchEvent(new Event("scroll"));
                        });
                    }
                    await workspace.evaluate(() => window.knTestReleaseSortPage());
                    await workspace.waitForFunction(() => document.getElementById("row-position").textContent === "Sorted by PID (descending) / Row 21 of 260");
                    const viewport = await workspace.locator("#result-view").evaluate(view => ({ top: view.scrollTop, left: view.scrollLeft }));
                    assert.deepEqual(viewport, changed ? { top: 840, left: 91 } : { top: 560, left: 73 });
                    assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pid, "240");
                }
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tabs-delayed-sort.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER closing another background tab does not cancel a pending result switch", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                const ids = [];
                for (let index = 0; index < 3; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 1);
                    ids.push(await workspace.locator("#result-history").inputValue());
                }
                await workspace.locator("#result-tabs [role=tab]").first().click();
                await workspace.waitForFunction(id => document.getElementById("result-history").value === id, ids[0]);
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.evaluate(() => { window.knTestHoldResultInfo = true; });
                await workspace.locator("#result-tabs [role=tab]").nth(1).click();
                await workspace.waitForFunction(() => typeof window.knTestReleaseResultInfo === "function");
                await workspace.locator("#result-tabs .result-tab-close").nth(2).click();
                await workspace.evaluate(() => window.knTestReleaseResultInfo());
                await workspace.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
                assert.equal(await workspace.locator("#result-history").inputValue(), ids[1]);
                assert.equal(await workspace.locator("#result-tabs [role=tab]").count(), 2);
                assert.equal(await workspace.locator("#result-tabs [role=tab]").nth(1).getAttribute("aria-selected"), "true");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tabs-background-close.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER result tabs preserve independent sorting selection both scroll positions widths and draft", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["sort-fixture"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                const views = [];
                for (let index = 0; index < 2; ++index)
                {
                    await workspace.locator("#prompt").fill("sort-fixture");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled && document.querySelectorAll(".result-row").length > 0, index + 1);
                    await workspace.getByRole("button", { name: "PID: Sort ascending by PID", exact: true }).click();
                    await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID (ascending)"));
                    if (index)
                    {
                        await workspace.getByRole("button", { name: "PID: Sort descending by PID", exact: true }).click();
                        await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID (descending)"));
                    }
                    await workspace.locator(".result-row").first().click();
                    await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).focus();
                    await workspace.keyboard.press("End");
                    await workspace.locator("#result-view").evaluate((view, index) =>
                    {
                        view.scrollTop = index ? 560 : 840;
                        view.scrollLeft = index ? 90 : 180;
                        view.dispatchEvent(new Event("scroll"));
                    }, index);
                    views.push(await workspace.evaluate(() => ({ id: document.getElementById("result-history").value,
                        top: document.getElementById("result-view").scrollTop, left: document.getElementById("result-view").scrollLeft,
                        position: document.getElementById("row-position").textContent,
                        pid: JSON.parse(document.getElementById("result-detail").textContent).pid })));
                }
                assert.notEqual(views[0].id, views[1].id);
                await workspace.locator("#prompt").fill("next draft");
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                for (const before of views)
                {
                    await workspace.locator("#result-tabs [role=tab]").filter({ hasText: before.id.slice(0, 8) }).click();
                    await workspace.waitForFunction(before => document.getElementById("result-history").value === before.id &&
                        document.getElementById("row-position").textContent === before.position &&
                        document.getElementById("result-view").scrollLeft === before.left, before);
                    const after = await workspace.evaluate(() => ({ id: document.getElementById("result-history").value,
                        top: document.getElementById("result-view").scrollTop, left: document.getElementById("result-view").scrollLeft,
                        position: document.getElementById("row-position").textContent,
                        pid: JSON.parse(document.getElementById("result-detail").textContent).pid }));
                    assert.deepEqual(after, before);
                    assert.equal(await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).getAttribute("aria-valuenow"), "4096");
                }
                assert.equal(await workspace.locator("#prompt").inputValue(), "next draft");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tabs-independent.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER open tabs retain layouts beyond 32 results with narrow overflow and keyboard close", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueCommands: ["sort-fixture", "db nt L10"] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("sort-fixture");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("btn-stack").disabled && document.querySelectorAll(".result-row").length > 0);
                await workspace.getByRole("button", { name: "PID: Sort ascending by PID", exact: true }).click();
                await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID"));
                await workspace.locator(".result-row").first().click();
                await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).focus();
                await workspace.keyboard.press("End");
                for (let index = 0; index < 33; ++index)
                {
                    await workspace.locator("#prompt").fill("db nt L10");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(count => document.querySelectorAll("#result-tabs [role=tab]").length === count &&
                        !document.getElementById("btn-stack").disabled, index + 2);
                }
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.setViewportSize({ width: 360, height: 760 });
                await workspace.locator("#result-tabs [role=tab]").last().focus();
                await workspace.keyboard.press("Home");
                await workspace.waitForFunction(() => document.getElementById("row-position").textContent === "Sorted by PID (ascending) / Row 1 of 260");
                assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pid, "1");
                assert.equal(await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).getAttribute("aria-valuenow"), "4096");
                assert.ok(await workspace.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth &&
                    document.getElementById("result-tabs").scrollWidth > document.getElementById("result-tabs").clientWidth));
                await workspace.locator("#result-tabs [role=tab]").first().press("End");
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "db nt L10");
                await workspace.keyboard.press("Delete");
                await workspace.waitForFunction(() => document.querySelectorAll("#result-tabs [role=tab]").length === 33 &&
                    document.querySelector("#result-tabs [aria-selected=true]")?.id === document.activeElement.id);
                const box = await workspace.locator("#result-tabs [aria-selected=true]").boundingBox();
                assert.ok(box.x >= 0 && box.x + box.width <= 360, JSON.stringify(box));
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "result-tabs-narrow.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER Results returns from every toolbar screen with sorted rows selection scroll and widths intact", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("sort-fixture");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("btn-stack").disabled &&
                    document.querySelectorAll(".result-row").length > 0);
                await workspace.getByRole("button", { name: "PID: Sort ascending by PID", exact: true }).click();
                await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID"));
                await workspace.locator(".result-row").first().click();
                await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).focus();
                await workspace.keyboard.press("End");
                await workspace.locator("#result-view").evaluate(view =>
                {
                    view.scrollTop = 840;
                    view.scrollLeft = 180;
                    view.dispatchEvent(new Event("scroll"));
                });
                const before = await workspace.evaluate(() => ({ top: document.getElementById("result-view").scrollTop,
                    left: document.getElementById("result-view").scrollLeft, position: document.getElementById("row-position").textContent }));
                assert.ok(before.top > 0 && before.left > 0, JSON.stringify(before));
                for (const screen of ["stack", "breakpoints", "event"])
                {
                    await workspace.locator("#btn-" + screen).click();
                    await workspace.waitForFunction(screen => document.getElementById("btn-" + screen).getAttribute("aria-pressed") === "true" &&
                        !document.getElementById("btn-results").disabled, screen);
                }
                await workspace.locator("#prompt").fill("next draft");
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.locator("#btn-results").click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "sort-fixture" &&
                    document.getElementById("row-position").textContent.includes("Sorted by PID") &&
                    document.getElementById("result-view").scrollLeft > 0);
                const after = await workspace.evaluate(() => ({ top: document.getElementById("result-view").scrollTop,
                    left: document.getElementById("result-view").scrollLeft, position: document.getElementById("row-position").textContent }));
                assert.deepEqual(after, before);
                assert.equal(await workspace.getByRole("separator", { name: "Resize PID column", exact: true }).getAttribute("aria-valuenow"), "4096");
                assert.equal(await workspace.locator("#prompt").inputValue(), "next draft");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                assert.equal(await workspace.locator("#btn-results").getAttribute("aria-pressed"), "true");
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "results-return-sorted.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER Results stays reachable in a narrow toolbar and its saved output never reruns a command", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.setViewportSize({ width: 360, height: 760 });
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("db nt L10");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "db nt L10" &&
                    !document.getElementById("btn-event").disabled);
                await workspace.locator("#btn-event").click();
                await workspace.waitForFunction(() => !document.getElementById("btn-results").disabled);
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.locator("#btn-results").click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "db nt L10");
                await workspace.locator("#btn-empty-output").click();
                await workspace.waitForFunction(() => !document.getElementById("btn-event").disabled);
                assert.match(await workspace.locator("#output").textContent(), /\[saved output\] db nt L10/);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                const box = await workspace.locator("#btn-results").boundingBox();
                assert.ok(box.x >= 0 && box.x + box.width <= 360, JSON.stringify(box));
                assert.ok(await workspace.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "results-return-narrow.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER an open result tab retains its sort and source record beyond the layout cache", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit, { uniqueToolbarResults: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("sort-fixture");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("btn-stack").disabled &&
                    document.querySelectorAll(".result-row").length > 0);
                await workspace.getByRole("button", { name: "PID: Sort ascending by PID", exact: true }).click();
                await workspace.waitForFunction(() => document.getElementById("row-position").textContent.includes("Sorted by PID"));
                await workspace.locator(".result-row").first().click();
                assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pid, "1");
                for (let index = 0; index < 33; ++index)
                {
                    await workspace.locator("#btn-stack").click();
                    await workspace.waitForFunction(() => !document.getElementById("btn-stack").disabled);
                }
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.locator("#btn-results").click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "sort-fixture" &&
                    /Row \d/.test(document.getElementById("row-position").textContent));
                assert.equal(await workspace.locator("#row-position").textContent(), "Sorted by PID (ascending) / Row 1 of 260");
                assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pid, "1");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "results-return-evicted-selection.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER a late Results return cannot replace the breakpoint view behind an Add preview", async () =>
        {
            const workspace = await context.newPage();
            try
            {
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("sort-fixture");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => !document.getElementById("btn-breakpoints").disabled);
                await workspace.locator("#btn-breakpoints").click();
                await workspace.waitForFunction(() => !document.getElementById("btn-results").disabled);
                await workspace.evaluate(() => { window.knTestHoldResultInfo = true; });
                await workspace.locator("#btn-results").click();
                await workspace.waitForFunction(() => typeof window.knTestReleaseResultInfo === "function");
                if (!(await workspace.locator("#breakpoint-address").isVisible()))
                {
                    await workspace.locator("#breakpoint-create-toggle").click();
                }
                await workspace.locator("#breakpoint-address").fill("nt!ReviewFixture");
                await workspace.locator("#btn-breakpoint-add").click();
                await workspace.locator("#modal-backdrop").waitFor({ state: "visible" });
                await workspace.evaluate(() => window.knTestReleaseResultInfo());
                await workspace.waitForTimeout(100);
                assert.equal(await workspace.locator("#result-title").textContent(), "breakpoints");
                assert.equal(await workspace.locator("#btn-breakpoints").getAttribute("aria-pressed"), "true");
                assert.equal(await workspace.locator("#modal-backdrop").isVisible(), true);
                assert.match(await workspace.locator("#modal-preview").textContent(), /nt!ReviewFixture/);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "breakpointApply").length), 0);
                await workspace.locator("#modal-cancel").click();
                assert.equal(await workspace.locator("#btn-results").isEnabled(), true);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "results-return-obsolete-preview.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER Inspect is visible by default without target reads and an explicit Hide survives reopening", async () =>
        {
            assert.equal(await page.locator("#memory").isVisible(), true);
            assert.equal(await page.locator("#btn-memory-panel").getAttribute("aria-expanded"), "true");
            assert.equal(await page.locator("#tab-memory-view").getAttribute("aria-selected"), "true");
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item =>
                ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length), 0);
            await page.locator("#btn-memory-close").click();
            const restored = await context.newPage();
            try
            {
                await restored.addInitScript(fixtureInit);
                await restored.goto(`http://127.0.0.1:${server.address().port}/`);
                await restored.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                assert.equal(await restored.locator("#memory").isVisible(), false);
                assert.equal(await restored.locator("#btn-memory-panel").getAttribute("aria-expanded"), "false");
            }
            finally
            {
                await restored.close();
            }
        });
        await check("T-UI-BROWSER startup and failed status keep commands locked until the target state is known", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { holdStatus: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => typeof window.knTestReleaseStatus === "function");
                assert.equal(await workspace.locator("#prompt").isEnabled(), false);
                assert.equal(await workspace.locator("#btn-palette").isEnabled(), false);
                assert.equal(await workspace.locator("#command-phase").textContent(), "Waiting for target status");
                await workspace.evaluate(() =>
                {
                    document.getElementById("prompt").value = "!callbacks";
                    document.getElementById("prompt").dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
                    window.knTestStopped = false;
                    window.knTestHoldStatus = false;
                    window.knTestReleaseStatus();
                });
                await workspace.waitForFunction(() => document.getElementById("current-process-notice").textContent === "Target running");
                assert.equal(await workspace.locator("#prompt").isEnabled(), false);
                await workspace.evaluate(() =>
                {
                    window.knTestStatusError = "TransportError";
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => document.getElementById("status").textContent === "status failed");
                assert.equal(await workspace.locator("#prompt").isEnabled(), false);
                assert.equal(await workspace.locator("#btn-run").isEnabled(), false);
                assert.equal(await workspace.locator("#prompt").inputValue(), "!callbacks");
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "busy-status-unavailable.png") });
                }
                await workspace.evaluate(() =>
                {
                    window.knTestStatusError = null;
                    window.knTestStopped = true;
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                assert.equal(await workspace.locator("#btn-run").isEnabled(), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["classify", "execute", "executePlan"].includes(item.method)).length), 0);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER returning to break does not execute a classification from before Busy", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-stack").disabled);
                await workspace.evaluate(() =>
                {
                    window.knTestHoldClassification = true;
                });
                await workspace.locator("#prompt").fill("!callbacks");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => typeof window.knTestFinishClassification === "function");
                await workspace.evaluate(() =>
                {
                    window.knTestStopped = false;
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => document.getElementById("prompt").disabled);
                await workspace.evaluate(() =>
                {
                    window.knTestStopped = true;
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.evaluate(() =>
                {
                    window.knTestHoldClassification = false;
                    window.knTestFinishClassification();
                });
                await workspace.waitForFunction(() => document.getElementById("btn-cancel").disabled &&
                    document.getElementById("output").textContent.includes("command was not submitted"));
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 0);
                await workspace.locator("#prompt").fill("!callbacks");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "!callbacks");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 1);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER running and EngineBusy targets lock commands until polling observes a break", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-stack").disabled);
                await workspace.locator("#prompt").fill("!callbacks");
                await workspace.evaluate(() =>
                {
                    window.knTestStopped = false;
                });
                await workspace.waitForFunction(() => document.getElementById("prompt").disabled);
                assert.equal(await workspace.locator("#activity").textContent(), "Busy");
                assert.equal(await workspace.locator("#command-phase").textContent(), "Busy");
                assert.equal(await workspace.locator("#command-progress").isVisible(), true);
                assert.equal(await workspace.locator("#command-elapsed").textContent(), "");
                for (const id of ["btn-run", "kernel-workflow", "btn-stack", "btn-palette", "btn-empty-command"])
                {
                    assert.equal(await workspace.locator("#" + id).isEnabled(), false, id);
                }
                assert.equal(await workspace.locator("#btn-cancel").isEnabled(), false);
                await workspace.evaluate(() =>
                {
                    document.getElementById("prompt").dispatchEvent(new KeyboardEvent("keydown", { key: "Enter" }));
                    document.getElementById("btn-run").dispatchEvent(new MouseEvent("click"));
                    document.getElementById("btn-stack").dispatchEvent(new MouseEvent("click"));
                    document.querySelector(".cmd-item").click();
                });
                assert.equal(await workspace.locator("#prompt").inputValue(), "!callbacks");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["classify", "execute", "navigateResult", "interrupt"].includes(item.method)).length), 0);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "target-running-busy.png") });
                }
                await workspace.evaluate(() =>
                {
                    window.knTestStopped = true;
                    window.knTestBusy = true;
                });
                await workspace.waitForFunction(() => document.getElementById("status").textContent.includes("debugger busy"));
                assert.equal(await workspace.locator("#prompt").isEnabled(), false);
                await workspace.evaluate(() =>
                {
                    window.knTestBusy = false;
                    window.knTestStopped = false;
                });
                await workspace.waitForFunction(() => document.getElementById("status").textContent.includes("exec go"));
                assert.equal(await workspace.locator("#prompt").isEnabled(), false);
                await workspace.evaluate(() =>
                {
                    window.knTestStopped = true;
                });
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                assert.equal(await workspace.locator("#activity").textContent(), "Idle");
                assert.equal(await workspace.locator("#command-progress").isVisible(), false);
                assert.equal(await workspace.locator("#prompt").inputValue(), "!callbacks");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 0);
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "!callbacks");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 1);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER breakpoint management and instruction toggles share refreshed state", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("btn-breakpoints").disabled);
                assert.equal(await workspace.locator("#gate").count(), 0);
                assert.equal(await workspace.locator("#policy-status").count(), 0);
                await workspace.locator("#btn-breakpoints").click();
                await workspace.waitForFunction(() => document.getElementById("btn-cancel").disabled &&
                    document.getElementById("result-title").textContent === "breakpoints");
                if (!(await workspace.locator("#breakpoint-address").isVisible()))
                {
                    await workspace.locator("#breakpoint-create-toggle").click();
                }
                await workspace.locator("#breakpoint-address").fill("0xffff800000001004");
                await workspace.locator("#btn-breakpoint-add").click();
                await workspace.locator("#modal").waitFor({ state: "visible" });
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "breakpointApply")), false);
                await workspace.locator("#modal-cancel").click();
                assert.equal(await workspace.locator("#result-count").textContent(), "0 rows / 0 findings");
                await workspace.locator("#btn-breakpoint-add").click();
                await workspace.locator("#modal-confirm").click();
                await workspace.waitForFunction(() => document.getElementById("btn-cancel").disabled &&
                    document.querySelectorAll("#result-rows [role=row]").length === 1);
                await workspace.locator("#result-table").press("Home");
                await workspace.locator("#btn-breakpoint-disable").click();
                await workspace.waitForFunction(() => document.getElementById("btn-cancel").disabled);
                assert.equal(await workspace.locator("#modal-backdrop").isHidden(), true);
                if (await workspace.locator("#memory").isHidden())
                {
                    await workspace.locator("#btn-memory-panel").click();
                }
                await workspace.locator("#tab-disassembly").click();
                await workspace.locator("#disassembly-count").selectOption("16");
                await workspace.locator("#disassembly-address").fill("sample!Entry");
                await workspace.locator("#btn-disassembly-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .breakpoint-toggle.disabled").length === 1 &&
                    document.getElementById("btn-cancel").disabled);
                const recentAddresses = await workspace.evaluate(() => localStorage.getItem("kndbgx.address-history"));
                const marker = workspace.locator("#disassembly-rows .breakpoint-toggle").nth(1);
                assert.match(await marker.getAttribute("aria-label"), /Enable breakpoint/);
                await marker.click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .breakpoint-toggle.enabled").length === 1 &&
                    document.getElementById("btn-cancel").disabled);
                assert.equal(await workspace.evaluate(() => localStorage.getItem("kndbgx.address-history")), recentAddresses,
                    "Enabling a breakpoint added an internal refresh address to history");
                await workspace.locator("#disassembly-grid").press("Home");
                await workspace.locator("#disassembly-grid").press("ArrowDown");
                await workspace.locator("#disassembly-grid").press("F9");
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .breakpoint-toggle.disabled").length === 1 &&
                    document.getElementById("btn-cancel").disabled);
                assert.equal(await workspace.evaluate(() => localStorage.getItem("kndbgx.address-history")), recentAddresses,
                    "F9 added an internal refresh address to history");
                await workspace.setViewportSize({ width: 360, height: 720 });
                await marker.scrollIntoViewIfNeeded();
                const bounds = await marker.boundingBox();
                assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 360);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "disassembly-breakpoint-narrow.png") });
                }
                await workspace.setViewportSize({ width: 1280, height: 900 });
                await workspace.locator("#result-table").press("Home");
                await workspace.locator("#btn-breakpoint-remove").click();
                await workspace.locator("#modal-confirm").click();
                await workspace.waitForFunction(() => document.getElementById("result-count").textContent === "0 rows / 0 findings" &&
                    document.getElementById("btn-cancel").disabled);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "breakpointApply").length), 5);
                await hideInspection(workspace);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER breakpoint row controls show state and bind pointer and keyboard changes after sorting", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { breakpoints: [
                    { kind: "Breakpoint", id: "12", address: "0xffff800000001000", addressSpace: "virtual", type: "0", enabled: true, identity: "guid-12" },
                    { kind: "Breakpoint", id: "5", address: "0xffff800000001004", addressSpace: "virtual", type: "0", enabled: false, identity: "guid-5" }
                ] });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.locator("#btn-breakpoints").click();
                await workspace.waitForFunction(() => document.querySelectorAll(".breakpoint-row-toggle:not(:disabled)").length === 2);
                assert.deepEqual(await workspace.locator(".breakpoint-state-label").allTextContents(), ["Enabled", "Disabled"]);
                await workspace.locator('.table-sort[data-sort-key=\'["id"]\']').click();
                const enable = workspace.getByRole("button", { name: "Enable breakpoint 5", exact: true });
                assert.equal(await workspace.locator(".breakpoint-row-toggle").first().getAttribute("aria-label"), "Enable breakpoint 5");
                const resultScroll = await workspace.locator("#evidence").evaluate(node => node.scrollTop);
                await enable.click();
                await workspace.waitForFunction(() => document.getElementById("btn-cancel").disabled &&
                    document.querySelectorAll(".breakpoint-state-label.enabled").length === 2);
                assert.equal(await workspace.locator("#modal-backdrop").isHidden(), true);
                assert.equal(await workspace.locator("#evidence").evaluate(node => node.scrollTop), resultScroll,
                    "Row actions must not scroll the results heading out of view");
                assert.equal(await workspace.locator("#workspace-feedback").isHidden(), true);
                assert.deepEqual(await workspace.evaluate(() => {
                    const request = window.knTestRequests.find(item => item.method === "breakpointPlan");
                    return { operation: request.params.operation, index: request.params.source.index };
                }), { operation: "breakpoint-enable", index: "1" });
                const disable = workspace.getByRole("button", { name: "Disable breakpoint 5", exact: true });
                await workspace.locator("#result-table").press("End");
                assert.equal(await disable.getAttribute("tabindex"), "0");
                await disable.focus();
                await disable.press("Enter");
                await workspace.waitForFunction(() => document.getElementById("btn-cancel").disabled &&
                    document.querySelectorAll(".breakpoint-state-label.enabled").length === 1);
                assert.equal(await workspace.locator("#modal-backdrop").isHidden(), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "breakpointApply").length), 2);
                assert.equal(await workspace.locator("#workspace-feedback").isHidden(), true);
                const resize = workspace.locator('.table-resize[data-resize-key=\'["enabled"]\']');
                await resize.focus();
                await resize.press("Home");
                assert.equal(await resize.getAttribute("aria-valuenow"), "160");
                await workspace.setViewportSize({ width: 360, height: 720 });
                await enable.scrollIntoViewIfNeeded();
                const bounds = await enable.boundingBox();
                assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 360);
                assert.ok(bounds.height <= 28);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "breakpoint-row-controls-narrow.png") });
                }
                await workspace.evaluate(() =>
                {
                    window.knTestChangeContext();
                });
                await workspace.locator("#btn-refresh-status").click();
                await workspace.waitForFunction(() => [...document.querySelectorAll(".breakpoint-row-toggle")].every(button => button.disabled));
                assert.deepEqual(await workspace.locator(".breakpoint-state-label").allTextContents(), ["Enabled", "Disabled"]);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER breakpoint follow-up reads stop on cancellation or a changed address space", async () =>
        {
            for (const boundary of ["stop", "context"])
            {
                const workspace = await context.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                try
                {
                    await workspace.addInitScript(fixtureInit, { breakpoints: [{ kind: "Breakpoint", id: "7", address: "0xffff800000001000",
                        addressSpace: "virtual", enabled: true, type: "0", identity: "owned-fixture" }] });
                    await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                    await workspace.waitForFunction(() => !document.getElementById("btn-breakpoints").disabled);
                    if (await workspace.locator("#memory").isHidden())
                    {
                        await workspace.locator("#btn-memory-panel").click();
                    }
                    await workspace.locator("#tab-disassembly").click();
                    await workspace.locator("#disassembly-count").selectOption("16");
                    await workspace.locator("#btn-disassembly-read").click();
                    await workspace.waitForFunction(() => document.querySelector(".breakpoint-toggle.enabled") && document.getElementById("btn-cancel").disabled);
                    await workspace.evaluate(() => { window.knTestHoldBreakpointRead = true; });
                    await workspace.locator(".breakpoint-toggle.enabled").click();
                    await workspace.waitForFunction(() => typeof window.knTestFinishBreakpointRead === "function");
                    if (boundary === "stop")
                    {
                        await workspace.locator("#btn-cancel").click();
                    }
                    else
                    {
                        await workspace.evaluate(() => window.knTestChangeContext());
                        await workspace.locator("#btn-refresh-status").click();
                        await workspace.waitForFunction(() => document.getElementById("current-process-image").textContent === "changed.exe");
                    }
                    await workspace.evaluate(() => window.knTestFinishBreakpointRead());
                    await workspace.waitForFunction(() => document.getElementById("btn-cancel").disabled);
                    assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "disassemblyRead").length), 1, boundary);
                    assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "breakpointApply").length), 1);
                    assert.match(await workspace.locator("#disassembly-summary").textContent(), /previous snapshot/);
                    await hideInspection(workspace);
                }
                finally
                {
                    await workspace.close();
                }
            }
        });
        await hideInspection(page);
        await page.locator("#prompt").fill("!callbacks");
        await page.locator("#prompt").press("Enter");
        await page.waitForFunction(() => document.querySelectorAll(".result-row").length > 0);
        await page.locator("#columns-toggle").click();
        await check("T-UI-BROWSER column chooser remains usable in a short results pane", async () =>
        {
            assert.equal(await reachableLastChoice(), true, "The last column is clipped by the results pane");
        });
        if (evidence)
        {
            await page.screenshot({ path: path.join(evidence, "column-chooser.png") });
        }
        await check("T-UI-BROWSER discovering fields preserves chooser focus and scroll position", async () =>
        {
            await page.locator("#column-list input").nth(20).focus();
            const before = await page.locator("#column-list").evaluate(node => node.scrollTop);
            const focused = await page.evaluate(() => document.activeElement.dataset.columnKey);
            await page.locator("#result-view").evaluate(node =>
            {
                node.scrollTop = 200 * 28;
            });
            await page.waitForFunction(() => [...document.querySelectorAll("#column-list input")].some(node => node.dataset.columnKey === '["laterField"]'));
            assert.equal(await page.locator("#column-list").evaluate(node => node.scrollTop), before, "Schema discovery jumped the chooser scroll position");
            assert.equal(await page.evaluate(() => document.activeElement.dataset.columnKey), focused);
        });
        await check("T-UI-BROWSER chooser follows resize", async () =>
        {
            for (const size of [{ width: 900, height: 600 }, { width: 600, height: 480 }, { width: 360, height: 360 }, { width: 1600, height: 1000 }])
            {
                await page.setViewportSize(size);
                await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
                if (!await page.locator("#result-columns").evaluate(node => node.open))
                {
                    const anchor = await page.locator("#columns-toggle").boundingBox();
                    assert.ok(anchor.y > size.height || anchor.y + anchor.height < 0 ||
                        anchor.x > size.width || anchor.x + anchor.width < 0, "Resize closed a chooser with a visible anchor");
                    await page.locator("#columns-toggle").click();
                }
                assert.equal(await reachableLastChoice(), true, "Clipped after resize to " + JSON.stringify(size));
                if (evidence && size.width === 360)
                {
                    await page.screenshot({ path: path.join(evidence, "column-chooser-narrow.png") });
                }
            }
        });
        await check("T-UI-BROWSER chooser closes when its anchor scrolls offscreen and restores keyboard focus", async () =>
        {
            await page.setViewportSize({ width: 600, height: 480 });
            await page.locator("#column-list input").last().focus();
            await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
            await page.waitForFunction(() => !document.getElementById("result-columns").open);
            assert.equal(await page.evaluate(() => document.activeElement.id), "columns-toggle");
            await page.locator("#columns-toggle").click();
            await page.locator("#column-list input").last().focus();
            await page.keyboard.press("Escape");
            assert.equal(await page.evaluate(() => document.activeElement.id), "columns-toggle");
            assert.equal(await page.locator("#result-columns").evaluate(node => node.open), false);
        });
        await check("T-UI-BROWSER field changes and horizontal scroll keep headers aligned with exact cells", async () =>
        {
            await page.setViewportSize({ width: 900, height: 720 });
            await page.locator("#columns-toggle").click();
            await page.locator("#btn-columns-all").click();
            await page.keyboard.press("Escape");
            await page.locator("#result-view").evaluate(node =>
            {
                node.scrollLeft = 300;
            });
            await page.waitForFunction(() => document.querySelector("#table-head").style.transform === "translateX(-300px)");
            const deltas = await page.evaluate(() =>
            {
                const header = [...document.querySelectorAll("#table-head [role=columnheader]")];
                const cells = [...document.querySelectorAll(".result-row:first-child [role=gridcell]")];
                return header.map((node, index) =>
                {
                    const heading = node.getBoundingClientRect();
                    const cell = cells[index].getBoundingClientRect();
                    return [heading.left - cell.left, heading.width - cell.width];
                });
            });
            assert.ok(deltas.every(pair => pair.every(value => Math.abs(value) < 1)), JSON.stringify(deltas));
            await page.locator(".result-row").first().click();
            const selected = JSON.parse(await page.locator("#result-detail").textContent());
            assert.equal(selected.routine, "0xffff800000001008");
            assert.equal(selected.module, "sample.sys");
            assert.equal(selected.field31, 31);
        });
        if (evidence)
        {
            await page.screenshot({ path: path.join(evidence, "columns-table.png") });
        }
        await check("T-UI-BROWSER selected command stays highlighted after run, filter, resize and focus changes", async () =>
        {
            await page.setViewportSize({ width: 1600, height: 1000 });
            // Let the resize handler update the sidebar state before toggling it.
            await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
            if (await page.locator("#btn-sidebar").getAttribute("aria-expanded") !== "true")
            {
                await page.locator("#btn-sidebar").click();
            }
            assert.equal(await page.locator(".cmd-item.active").getAttribute("data-command"), "callbacks");
            await page.locator("#filter").fill("stack");
            assert.equal(await page.locator(".cmd-item.active").count(), 0);
            assert.equal(await page.locator("#selected-command").textContent(), "Selected: !callbacks");
            await page.locator("#selected-command").click();
            assert.equal(await page.locator(".cmd-item.active").getAttribute("aria-current"), "true");
            assert.equal(await page.locator(".cmd-item.active").evaluate(node => document.activeElement === node), true);
            await page.locator("#prompt").fill("stack");
            assert.equal(await page.locator(".cmd-item.active").getAttribute("data-command"), "stack");
            await page.locator("#prompt").fill("!callbacks");
            await page.locator("#prompt").press("Enter");
            await page.waitForFunction(() => document.querySelectorAll(".result-row").length > 0 && document.getElementById("btn-cancel").disabled);
            await page.locator("#result-table").focus();
            assert.equal(await page.locator(".cmd-item.active").getAttribute("data-command"), "callbacks");
            await page.emulateMedia({ forcedColors: "active" });
            const colors = await page.locator(".cmd-item.active").evaluate(node => ({ background: getComputedStyle(node).backgroundColor,
                name: getComputedStyle(node.querySelector(".name")).color }));
            assert.notEqual(colors.background, colors.name);
            await page.emulateMedia({ forcedColors: "none" });
        });
        await check("T-UI-BROWSER value clicks and Ctrl+C copy full values with the real Clipboard API", async () =>
        {
            await page.locator("#result-view").evaluate(view =>
            {
                view.scrollTop = 0;
                view.scrollLeft = 0;
                view.dispatchEvent(new Event("scroll"));
            });
            await page.waitForFunction(() => document.querySelector(".result-row")?.getAttribute("aria-rowindex") === "2");
            await page.locator(".result-row").first().click();
            await page.locator("#detail-fields [aria-label='Copy field message']").click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied field message.");
            assert.equal((await page.evaluate(() => navigator.clipboard.readText())).replace(/\r\n/g, "\n"), "\uafc0\ubcf4 <&>\n".repeat(1000));
            await page.locator("#detail-fields [aria-label='Copy field nul']").click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied field nul as a JSON string (embedded NUL).");
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), JSON.stringify("before\u0000after"));
            await page.locator("#btn-copy-row").click();
            await page.waitForFunction(() => /^Copied row .* as JSON\.$/.test(document.getElementById("copy-status").textContent));
            assert.equal(JSON.parse(await page.evaluate(() => navigator.clipboard.readText())).field31, 31);
            await page.locator("#result-table").focus();
            await page.evaluate(() => window.getSelection().removeAllRanges());
            await page.keyboard.press("Control+c");
            assert.equal(JSON.parse(await page.evaluate(() => navigator.clipboard.readText())).routine, "0xffff800000001008");
            await page.locator("#btn-copy-console").click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied displayed console text.");
            assert.ok((await page.evaluate(() => navigator.clipboard.readText())).replace(/\r\n/g, "\n").includes("[callbacks] literal <&> output\n"));
            await page.locator("#result-view").evaluate(node =>
            {
                node.scrollLeft = 0;
            });
            const moduleCell = page.locator(".result-row").first().locator("[role=gridcell]").filter({ hasText: /^sample\.sys$/ });
            await moduleCell.click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied value from row 1.");
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "sample.sys");
        });
        await check("T-UI-BROWSER cell copying supports pointer, keyboard, paging and full original values", async () =>
        {
            await page.locator("#columns-toggle").click();
            await page.locator("#btn-columns-all").click();
            await page.keyboard.press("Escape");
            const before = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
            const messageCopy = page.getByRole("gridcell", { name: "Copy Message, row 2", exact: true });
            await messageCopy.click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied value from row 2.");
            assert.equal((await page.evaluate(() => navigator.clipboard.readText())).replace(/\r\n/g, "\n"), "\uafc0\ubcf4 <&>\n".repeat(1000));
            assert.equal(await messageCopy.evaluate(node => document.activeElement === node), true, "Row selection stole cell focus");
            assert.equal(await page.locator(".result-row.selected").getAttribute("aria-rowindex"), "3");
            assert.equal(await page.locator(".result-row:not(.selected) .copyable").evaluateAll(nodes => nodes.every(node => node.tabIndex === -1)), true);
            await messageCopy.press("Escape");
            assert.equal(await page.evaluate(() => document.activeElement.id), "result-table");
            const sortKeys = await page.locator("#table-head .table-sort").evaluateAll(nodes => nodes.map(node => node.dataset.sortKey));
            for (const key of sortKeys)
            {
                await page.keyboard.press("Tab");
                assert.equal(await page.evaluate(() => document.activeElement.dataset.sortKey), key);
                await page.keyboard.press("Tab");
                assert.equal(await page.evaluate(() => document.activeElement.dataset.resizeKey), key);
                assert.equal(await page.evaluate(() => document.activeElement.getAttribute("role")), "separator");
            }
            await page.keyboard.press("Tab");
            const activeName = await page.evaluate(() => document.activeElement.getAttribute("aria-label"));
            assert.equal(activeName, await page.locator(".result-row.selected .copyable").first().getAttribute("aria-label"));
            const moduleCopy = page.getByRole("gridcell", { name: "Copy Module, row 2", exact: true });
            await moduleCopy.focus();
            await moduleCopy.press("Space");
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied value from row 2.");
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "sample.sys");
            await moduleCopy.press("ArrowDown");
            assert.equal(await page.evaluate(() => document.activeElement.id), "result-table");
            assert.equal(await page.locator(".result-row.selected").getAttribute("aria-rowindex"), "4");
            const routineCopy = page.getByRole("gridcell", { name: "Copy Routine, row 3", exact: true });
            await routineCopy.focus();
            await routineCopy.press("Enter");
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied value from row 3.");
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "0xffff800000001008");
            if (evidence)
            {
                await page.screenshot({ path: path.join(evidence, "cell-copy-keyboard.png") });
            }
            await page.locator("#result-view").evaluate(node =>
            {
                node.scrollTop = 200 * 28;
            });
            await page.waitForFunction(() => document.querySelector(".result-row").getAttribute("aria-rowindex") === "194");
            assert.equal(await page.evaluate(() => document.activeElement.id), "result-table", "Paging discarded keyboard focus");
            const laterCopy = page.getByRole("gridcell", { name: "Copy Later Field, row 201", exact: true });
            await laterCopy.click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied value from row 201.");
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "200");
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), before);
            await page.locator("#result-table").focus();
            await page.keyboard.press("Home");
            await page.waitForFunction(() => document.querySelector(".result-row.selected").getAttribute("aria-rowindex") === "2");
        });
        await check("T-UI-BROWSER context menus copy values and rows, restore focus and stay inside narrow viewports", async () =>
        {
            const cell = page.getByRole("gridcell", { name: "Copy Module, row 1", exact: true });
            const before = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
            await page.evaluate(() => navigator.clipboard.writeText("menu-unopened"));
            await cell.click({ button: "right" });
            await page.getByRole("menu", { name: "Copy options" }).waitFor();
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "menu-unopened");
            await page.getByRole("menuitem", { name: "Copy value", exact: true }).click();
            await page.waitForFunction(async () => await navigator.clipboard.readText() === "sample.sys");
            await cell.press("Shift+F10");
            await page.keyboard.press("ArrowDown");
            await page.keyboard.press("Enter");
            await page.waitForFunction(async () => (await navigator.clipboard.readText()).startsWith("{"));
            assert.equal(JSON.parse(await page.evaluate(() => navigator.clipboard.readText())).routine, "0xffff800000001008");
            assert.equal(await cell.evaluate(node => document.activeElement === node), true);
            const box = await cell.boundingBox();
            await cell.click();
            await page.waitForFunction(async () => await navigator.clipboard.readText() === "sample.sys");
            assert.deepEqual(await cell.boundingBox(), box, "Copy feedback shifted the table");
            assert.equal(await page.locator("#result-rows button, #detail-fields button").count(), 0);
            for (const width of [600, 360])
            {
                await page.setViewportSize({ width, height: 720 });
                await cell.click({ button: "right" });
                const menu = await page.locator("#cell-copy-menu").boundingBox();
                assert.ok(menu && menu.x >= 0 && menu.y >= 0 && menu.x + menu.width <= width && menu.y + menu.height <= 720);
                await page.keyboard.press("Escape");
                assert.equal(await cell.evaluate(node => document.activeElement === node), true);
            }
            await page.setViewportSize({ width: 900, height: 720 });
            await cell.click({ button: "right" });
            await page.locator("#result-view").evaluate(node =>
            {
                node.scrollTop = 200 * 28;
            });
            await page.waitForFunction(() => document.getElementById("cell-copy-menu").classList.contains("hidden"));
            await page.locator("#result-table").focus();
            await page.keyboard.press("Home");
            await page.waitForFunction(() => document.querySelector(".result-row.selected").getAttribute("aria-rowindex") === "2");
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), before);
        });
        await check("T-UI-BROWSER accessible copy controls expose the displayed value as well as the action", async () =>
        {
            const session = await page.context().newCDPSession(page);
            try
            {
                const tree = await session.send("Accessibility.getFullAXTree");
                for (const [label, value] of [["Copy Module, row 1", "sample.sys"], ["Copy current process name", "System"]])
                {
                    const node = tree.nodes.find(item => item.name && item.name.value === label && !item.ignored);
                    assert.ok(node && node.description && node.description.value.includes(value),
                        "Copy action hid its value from assistive technology: " + label);
                }
            }
            finally
            {
                await session.detach();
            }
        });
        await check("T-UI-BROWSER selected text takes precedence when another copyable value has focus", async () =>
        {
            try
            {
                await page.locator("#copy-current-eprocess").focus();
                await page.getByRole("gridcell", { name: "Copy Module, row 1", exact: true }).evaluate(node =>
                {
                    const range = document.createRange();
                    range.setStart(node.firstChild, 0);
                    range.setEnd(node.firstChild, 6);
                    window.getSelection().removeAllRanges();
                    window.getSelection().addRange(range);
                });
                assert.equal(await page.evaluate(() => window.getSelection().toString()), "sample");
                await page.keyboard.press("Control+c");
                assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "sample");
                await page.keyboard.press("Enter");
                await page.waitForFunction(async () => await navigator.clipboard.readText() === "0xffff800000001000");
            }
            finally
            {
                await page.evaluate(() => window.getSelection().removeAllRanges());
            }
        });
        await check("T-UI-BROWSER current-process menus close when their value changes or becomes unavailable", async () =>
        {
            const value = page.locator("#copy-current-image");
            try
            {
                await value.click({ button: "right" });
                await page.evaluate(() => document.getElementById("btn-refresh-status").click());
                await page.waitForFunction(() => !document.getElementById("current-process-notice").textContent);
                assert.equal(await page.locator("#cell-copy-menu").isVisible(), true, "Unchanged polling dismissed copy options");
                await page.evaluate(() =>
                {
                    window.knTestCurrentProcess.image = "ChangedProcess";
                    document.getElementById("btn-refresh-status").click();
                });
                await page.waitForFunction(() => document.getElementById("current-process-image").textContent === "ChangedProcess");
                assert.equal(await value.getAttribute("aria-description"), "ChangedProcess");
                assert.equal(await page.locator("#cell-copy-menu").isVisible(), false, "Menu retained the replaced process value");
                await value.click({ button: "right" });
                await page.evaluate(() =>
                {
                    window.knTestStopped = false;
                    document.getElementById("btn-refresh-status").click();
                });
                await page.waitForFunction(() => document.getElementById("copy-current-image").disabled);
                assert.equal(await value.getAttribute("aria-description"), "Unavailable");
                assert.equal(await page.locator("#cell-copy-menu").isVisible(), false, "Menu retained an unavailable identity");
                assert.equal(await page.evaluate(() => document.activeElement.id), "result-table");
            }
            finally
            {
                await page.keyboard.press("Escape");
                await page.evaluate(() =>
                {
                    window.knTestCurrentProcess.image = "System";
                    window.knTestStopped = true;
                    document.getElementById("btn-refresh-status").click();
                });
                await page.waitForFunction(() => document.getElementById("current-process-image").textContent === "System");
            }
        });
        await check("T-UI-BROWSER replacing a pending result dismisses Inspector copy options without losing keyboard focus", async () =>
        {
            await page.getByRole("gridcell", { name: "Copy Module, row 1", exact: true }).click();
            await page.locator("#prompt").fill("!callbacks");
            await page.evaluate(() =>
            {
                document.getElementById("btn-run").click();
                document.querySelector("#detail-fields [aria-label='Copy field module']").dispatchEvent(
                    new MouseEvent("contextmenu", { bubbles: true, cancelable: true }));
            });
            await page.waitForFunction(() => document.getElementById("btn-cancel").disabled &&
                document.querySelectorAll(".result-row").length > 0);
            assert.equal(await page.locator("#cell-copy-menu").isVisible(), false);
            assert.equal(await page.evaluate(() => document.activeElement.id), "result-table");
        });
        await check("T-UI-BROWSER denied clipboard focuses a full-value manual copy without executing a command", async () =>
        {
            await page.evaluate(() =>
            {
                window.knRealClipboardWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
                navigator.clipboard.writeText = () => Promise.reject(new Error("Denied for test"));
            });
            const before = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
            await page.getByRole("gridcell", { name: "Copy Message, row 1", exact: true }).click();
            await page.waitForFunction(() => document.activeElement.id === "copy-text");
            assert.equal(await page.locator("#copy-text").inputValue(), "\uafc0\ubcf4 <&>\n".repeat(1000));
            assert.equal(await page.locator("#copy-text").evaluate(node => node.selectionEnd - node.selectionStart), "\uafc0\ubcf4 <&>\n".repeat(1000).length);
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), before);
            await page.locator("#btn-copy-close").click();
            assert.equal(await page.locator("#copy-fallback").isVisible(), false);
            await page.evaluate(() =>
            {
                navigator.clipboard.writeText = window.knRealClipboardWrite;
            });
        });
        await check("T-UI-BROWSER Console Off survives reload, keeps results, and every control fits a narrow viewport", async () =>
        {
            await page.locator("#btn-console-output").click();
            await page.reload();
            await page.waitForFunction(() => !document.getElementById("prompt").disabled);
            assert.equal(await page.locator("#btn-console-output").getAttribute("aria-checked"), "false");
            await page.locator("#prompt").fill("!callbacks");
            await page.locator("#prompt").press("Enter");
            await page.waitForFunction(() => document.querySelectorAll(".result-row").length > 0 && document.getElementById("btn-cancel").disabled);
            assert.equal(await page.locator("#output").textContent(), "");
            assert.equal(await page.locator("#btn-save").isEnabled(), true);
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "outputChunk").length), 0);
            for (const width of [360, 600, 1600])
            {
                await page.setViewportSize({ width, height: width === 1600 ? 1000 : 600 });
                await page.locator("#btn-console-output").scrollIntoViewIfNeeded();
                assert.equal(await page.locator(".console-head").evaluate(node => node.scrollWidth <= node.clientWidth), true,
                    "Console controls overflow at width " + width);
                for (const id of ["btn-console", "btn-console-output", "btn-clear"])
                {
                    const box = await page.locator("#" + id).boundingBox();
                    assert.ok(box.x >= 0 && box.x + box.width <= width, id + " is outside the viewport");
                }
                if (evidence)
                {
                    await page.screenshot({ path: path.join(evidence, "clipboard-console-" + width + ".png") });
                }
            }
            await page.locator("#btn-console-output").click();
            assert.equal(await page.locator("#btn-console-output").getAttribute("aria-checked"), "true");
        });
        await check("T-UI-BROWSER collection details fit narrow windows and preserve useful CPU columns", async () =>
        {
            await page.setViewportSize({ width: 900, height: 720 });
            await page.locator("#prompt").fill("!msrcheck");
            await page.locator("#prompt").press("Enter");
            await page.waitForFunction(() => document.getElementById("result-title").textContent === "!msrcheck" && document.getElementById("btn-cancel").disabled);
            assert.match(await page.locator("#result-summary").textContent(), /Partial result/);
            assert.match(await page.locator("#result-notice").textContent(), /selected event CPU/);
            assert.deepEqual((await page.locator("#table-head [role=columnheader]").allTextContents()).slice(1, 4), ["CPU", "Register", "Value"]);
            for (const width of [360, 600, 1267])
            {
                await page.setViewportSize({ width, height: 720 });
                await page.locator("#result-info-toggle").click();
                const box = await page.locator("#result-info-popover").boundingBox();
                assert.ok(box.x >= 0 && box.x + box.width <= width, "Details overflow at width " + width);
                await page.locator("#btn-result-output").scrollIntoViewIfNeeded();
                await page.locator("#result-info-toggle").focus();
                await page.keyboard.press("Escape");
                assert.equal(await page.locator("#result-info").evaluate(node => node.open), false);
                if (evidence)
                {
                    await page.screenshot({ path: path.join(evidence, "result-summary-" + width + ".png") });
                }
            }
        });
        await check("T-UI-BROWSER View output opens saved text from an empty table without rerunning the command", async () =>
        {
            await page.locator("#btn-console-output").click();
            await page.locator("#prompt").fill("db nt L10");
            await page.locator("#prompt").press("Enter");
            await page.waitForFunction(() => document.getElementById("empty-title").textContent === "Text output" && document.getElementById("btn-cancel").disabled);
            const before = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
            await page.locator("#btn-empty-output").click();
            await page.waitForFunction(() => document.getElementById("btn-cancel").disabled && document.getElementById("output").textContent.includes("[saved output] db nt L10"));
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), before);
            assert.equal(await page.locator("#btn-console-output").getAttribute("aria-checked"), "true");
        });
        await check("T-UI-BROWSER opening a result menu closes the previous menu", async () =>
        {
            for (const id of ["result-info", "result-columns", "result-open"])
            {
                await page.locator("#" + id + " > summary").click();
                await page.waitForFunction(active => document.getElementById(active).open, id);
                assert.deepEqual(await page.locator("#evidence details[open]").evaluateAll(nodes => nodes.map(node => node.id)), [id]);
            }
            await page.locator("#result-open-toggle").focus();
            await page.keyboard.press("Escape");
            assert.equal(await page.locator("#evidence details[open]").count(), 0);
        });
        await check("T-UI-BROWSER process sorting covers all pages, keyboard headers and original action bindings", async () =>
        {
            const local = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
            const workspace = await local.newPage();
            const processErrors = [];
            workspace.on("pageerror", error => processErrors.push(error.message));
            try
            {
                const processes = Array.from({ length: 257 }, (_, index) => ({ kind: "Process", pid: String(257 - index),
                    image: "worker" + (257 - index) + ".exe", eprocess: "0x" + (0xffff800000001000n + BigInt(257 - index)).toString(16),
                    dtb: "0x" + (0x1000000000000000n + BigInt(257 - index)).toString(16),
                    createTime: String(18446744073709550000n + BigInt(257 - index)) }));
                await workspace.addInitScript(fixtureInit, { adaptiveLayout: true, processes });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await showProcesses(workspace);
                await workspace.waitForFunction(() => document.getElementById("process-summary").textContent.includes("257 shown") &&
                    !document.getElementById("btn-process-refresh").disabled);
                await workspace.locator(".process-row").first().click();
                const firstIndex = () => workspace.locator(".process-row").first().getAttribute("data-process-index");
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => ["execute", "resultPage", "processAction"].includes(item.method)).length);
                for (const key of ["pid", "image", "eprocess", "dtb", "createTime"])
                {
                    const button = workspace.locator("#process-sort-" + key);
                    await button.focus();
                    await workspace.keyboard.press("Enter");
                    assert.equal(await firstIndex(), "256", key + " ascending");
                    assert.equal(await workspace.locator("#process-column-" + key).getAttribute("aria-sort"), "ascending");
                    assert.match(await workspace.locator("#process-name").textContent(), /worker257.exe \/ PID 257/);
                    await workspace.keyboard.press("Space");
                    assert.equal(await firstIndex(), "0", key + " descending");
                    assert.equal(await workspace.locator("#process-column-" + key).getAttribute("aria-sort"), "descending");
                }
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => ["execute", "resultPage", "processAction"].includes(item.method)).length), reads);
                await workspace.locator("#process-sort-pid").focus();
                await workspace.keyboard.press("Enter");
                await workspace.locator("#process-grid").focus();
                await workspace.keyboard.press("Home");
                assert.match(await workspace.locator("#process-name").textContent(), /worker1.exe \/ PID 1/);
                await workspace.locator("#btn-process-threads").click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "!threads");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "processAction").params.index), "256");
                await workspace.setViewportSize({ width: 760, height: 650 });
                await showProcesses(workspace);
                await workspace.locator("#process-sort-createTime").focus();
                assert.equal(await workspace.locator("#process-sort-createTime").evaluate(button =>
                {
                    const bounds = button.getBoundingClientRect();
                    const view = document.getElementById("process-view").getBoundingClientRect();
                    return bounds.left >= view.left - 1 && bounds.right <= view.right + 1;
                }), true, "Keyboard focus must reveal the complete header in a narrow pane");
                await workspace.keyboard.press("Enter");
                assert.equal(await workspace.locator("#process-column-createTime").getAttribute("aria-sort"), "ascending");
                assert.deepEqual(processErrors, []);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER persistent process tab pages, filters and opens the selected process without losing the inventory", async () =>
        {
            await page.setViewportSize({ width: 1440, height: 1000 });
            const previousTitle = await page.locator("#result-title").textContent();
            await showProcesses(page);
            await page.waitForFunction(() => document.getElementById("process-summary").textContent.includes("257 shown / 257 collected / complete") &&
                document.getElementById("btn-cancel").disabled);
            assert.equal(await page.locator("#result-title").textContent(), previousTitle);
            assert.equal(await page.locator("#evidence").isVisible(), true);
            assert.ok(await page.locator(".process-row").count() <= 128);
            await page.locator("#process-grid").focus();
            await page.keyboard.press("End");
            assert.match(await page.locator("#process-name").textContent(), /process256.exe/);
            await page.locator("#process-filter").fill("process256");
            assert.equal(await page.locator(".process-row").count(), 1);
            await page.getByRole("gridcell", { name: "Copy EPROCESS for PID 1024", exact: true }).click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied EPROCESS from process 1024.");
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "0xffff800000011000");
            const count = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute" && item.params.command === "!dml_proc").length);
            await page.locator("#btn-process-threads").click();
            await page.waitForFunction(() => document.getElementById("result-title").textContent === "!threads" && document.getElementById("btn-cancel").disabled);
            assert.equal(await page.evaluate(() => window.knTestRequests.findLast(item => item.method === "processAction").params.index), "256");
            await showProcesses(page);
            assert.match(await page.locator("#process-name").textContent(), /process256.exe/);
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute" && item.params.command === "!dml_proc").length), count);
            await page.locator("#process-filter").fill("");
            await page.locator("#process-grid").focus();
            await page.keyboard.press("Home");
            if (evidence)
            {
                await page.screenshot({ path: path.join(evidence, "process-workspace.png") });
            }
        });
        await check("T-UI-BROWSER pending process collection keeps filtering and tabs responsive, cancels, and completes every page", async () =>
        {
            await page.evaluate(() =>
            {
                window.knTestHoldProcess = true;
            });
            await page.locator("#btn-process-refresh").click();
            await page.waitForFunction(() => typeof window.knTestFinishProcess === "function");
            await page.locator("#process-filter").fill("process256");
            assert.equal(await page.locator(".process-row").count(), 1);
            await hideInspection(page);
            assert.equal(await page.locator("#evidence").isVisible(), true);
            await showProcesses(page);
            assert.equal(await page.locator("#process-filter").inputValue(), "process256");
            await page.locator("#btn-cancel").click();
            await page.waitForFunction(() => document.getElementById("btn-cancel").disabled);
            assert.match(await page.locator("#process-summary").textContent(), /257 collected/);
            assert.equal(await page.locator(".process-row").count(), 1);
            await page.locator("#process-filter").fill("");
            await page.locator("#btn-process-refresh").click();
            await page.waitForFunction(() => typeof window.knTestFinishProcess === "function");
            await hideInspection(page);
            await page.evaluate(() =>
            {
                window.knTestHoldProcess = false;
                window.knTestFinishProcess(false);
            });
            await page.waitForFunction(() => document.getElementById("btn-cancel").disabled);
            await showProcesses(page);
            assert.match(await page.locator("#process-summary").textContent(), /257 shown \/ 257 collected \/ complete/);
            await page.locator("#process-grid").focus();
            await page.keyboard.press("End");
            assert.match(await page.locator("#process-name").textContent(), /process256.exe/);
            await page.keyboard.press("Home");
        });
        await check("T-UI-BROWSER process attach refreshes context and running targets disable actions", async () =>
        {
            await page.locator("#process-grid").focus();
            await page.keyboard.press("ArrowDown");
            const before = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "processAction" && item.params.action === "attach").length);
            await page.locator("#btn-process-attach").click();
            await page.waitForFunction(() => document.getElementById("workspace-feedback").textContent.includes("Address space attached: process1.exe") &&
                document.getElementById("btn-cancel").disabled && document.getElementById("process-attach-hint").textContent.includes("current process address space"));
            assert.equal(await page.locator("#tab-processes").getAttribute("aria-selected"), "true");
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "processAction" && item.params.action === "attach").length), before + 1);
            assert.equal(await page.locator("#result-notice").isVisible(), true);
            await page.locator("#btn-workspace-dismiss").focus();
            await page.keyboard.press("Enter");
            assert.equal(await page.locator("#workspace-feedback").isVisible(), false);
            assert.equal(await page.locator("#prompt").evaluate(node => node === document.activeElement), true);
            await page.locator("#btn-result-notice-dismiss").focus();
            await page.keyboard.press("Space");
            assert.equal(await page.locator("#result-notice").isVisible(), false);
            assert.equal(await page.locator("#result-table").evaluate(node => node === document.activeElement), true);
            await page.locator("#btn-refresh-status").click();
            await page.waitForFunction(() => !document.getElementById("btn-process-attach").disabled);
            assert.equal(await page.locator("#workspace-feedback").isVisible(), false);
            assert.equal(await page.locator("#result-notice").isVisible(), false);
            await page.locator("#btn-process-attach").click();
            await page.waitForFunction(() => document.getElementById("btn-cancel").disabled &&
                !document.getElementById("btn-process-attach").disabled);
            assert.equal(await page.locator("#workspace-feedback").isVisible(), true);
            assert.equal(await page.locator("#result-notice").isVisible(), true);
            await page.evaluate(() =>
            {
                window.knTestStopped = false;
            });
            await page.locator("#btn-refresh-status").click();
            await page.waitForFunction(() => document.getElementById("btn-process-attach").disabled);
            assert.match(await page.locator("#process-notice").textContent(), /Waiting for the target to stop/);
            assert.ok(await page.locator(".process-row").count() > 0);
            for (const width of [600, 360])
            {
                await page.setViewportSize({ width, height: 720 });
                await page.locator("#process-grid").focus();
                for (const key of ["pid", "image", "eprocess", "dtb", "createTime"])
                {
                    await page.keyboard.press("Tab");
                    assert.equal(await page.evaluate(() => document.activeElement.id), "process-sort-" + key);
                }
                const labels = await page.locator(".process-row.selected .copyable").evaluateAll(nodes => nodes.map(node => node.getAttribute("aria-label")));
                for (const label of labels)
                {
                    await page.keyboard.press("Tab");
                    assert.equal(await page.evaluate(() => document.activeElement.getAttribute("aria-label")), label,
                        "Horizontal scrolling removed the focused process cell");
                }
                await page.locator("#btn-process-attach").scrollIntoViewIfNeeded();
                const box = await page.locator("#process-inspector").boundingBox();
                assert.ok(box.x >= 0 && box.x + box.width <= width, "Process inspector overflows a narrow viewport");
                if (evidence)
                {
                    await page.screenshot({ path: path.join(evidence, "process-workspace-" + width + ".png") });
                }
            }
            await hideInspection(page);
            await page.evaluate(() =>
            {
                window.knTestStopped = true;
                document.getElementById("btn-refresh-status").click();
            });
            await page.waitForFunction(() => !document.getElementById("prompt").disabled);
        });
        await check("T-UI-BROWSER ordinary feedback expires automatically while drafts and focus survive", async () =>
        {
            const notices = await context.newPage();
            notices.on("pageerror", error => errors.push(error.message));
            try
            {
                await notices.addInitScript(fixtureInit);
                await notices.goto(`http://127.0.0.1:${server.address().port}/`);
                await notices.locator("#btn-console-output").click();
                assert.equal(await notices.locator("#workspace-feedback").isVisible(), true);
                await notices.locator("#prompt").fill("unsent draft");
                await notices.waitForFunction(() => document.getElementById("workspace-feedback").classList.contains("hidden"),
                    null, { timeout: 7000 });
                assert.equal(await notices.locator("#prompt").inputValue(), "unsent draft");
                assert.equal(await notices.locator("#prompt").evaluate(node => node === document.activeElement), true);
                assert.equal(await notices.evaluate(() => window.knTestRequests.some(item => item.method === "execute")), false);
            }
            finally
            {
                await notices.close();
            }
        });
        await check("T-UI-BROWSER focused feedback expiry keeps keyboard navigation available while Busy", async () =>
        {
            const notices = await context.newPage();
            notices.on("pageerror", error => errors.push(error.message));
            try
            {
                await notices.addInitScript(fixtureInit);
                await notices.goto(`http://127.0.0.1:${server.address().port}/`);
                await notices.locator("#btn-console-output").click();
                await notices.evaluate(() =>
                {
                    window.knTestBusy = true;
                    document.getElementById("btn-refresh-status").click();
                });
                await notices.waitForFunction(() => document.getElementById("prompt").disabled);
                await notices.locator("#btn-workspace-dismiss").focus();
                await notices.waitForFunction(() => document.getElementById("workspace-feedback").classList.contains("hidden"),
                    null, { timeout: 7000 });
                assert.equal(await notices.locator("#result-table").evaluate(node => node === document.activeElement), true);
                assert.equal(await notices.locator("#prompt").isDisabled(), true);
                assert.equal(await notices.evaluate(() => window.knTestRequests.some(item => item.method === "execute")), false);
            }
            finally
            {
                await notices.close();
            }
        });
        await check("T-UI-BROWSER notice dismissal stays reachable in narrow windows and preserves historical result status", async () =>
        {
            for (const width of [360, 600, 1440])
            {
                await page.setViewportSize({ width, height: 720 });
                await page.locator("#btn-console-output").click();
                await page.locator("#btn-console-output").click();
                for (const [banner, button] of [["workspace-feedback", "btn-workspace-dismiss"], ["result-notice", "btn-result-notice-dismiss"]])
                {
                    const outer = await page.locator("#" + banner).boundingBox();
                    const control = await page.locator("#" + button).boundingBox();
                    assert.ok(control && outer && control.x >= 0 && control.x + control.width <= width);
                    assert.ok(control.y >= outer.y && control.y + control.height <= outer.y + outer.height,
                        button + " is clipped at width " + width);
                }
                if (evidence)
                {
                    await page.screenshot({ path: path.join(evidence, "notice-dismiss-" + width + ".png") });
                }
            }
            await page.locator("#btn-result-notice-dismiss").click();
            await page.locator("#btn-workspace-dismiss").click();
            assert.equal(await page.locator("#result-notice").isVisible(), false);
            assert.equal(await page.locator("#workspace-feedback").isVisible(), false);
            assert.equal(await page.locator("#result-summary").evaluate(node => node.classList.contains("historical")), true);
        });
        await check("T-UI-BROWSER long failure notices scroll independently of Dismiss and retain empty-result evidence", async () =>
        {
            const notices = await context.newPage();
            try
            {
                await notices.addInitScript(fixtureInit);
                await notices.goto(`http://127.0.0.1:${server.address().port}/`);
                await notices.waitForFunction(() => !document.getElementById("btn-palette").disabled);
                await notices.locator("#btn-console-output").click();
                await notices.locator("#prompt").fill("notice-fixture");
                await notices.locator("#prompt").press("Enter");
                await notices.waitForFunction(() => document.getElementById("result-summary").textContent.includes("Unavailable") &&
                    document.getElementById("btn-cancel").disabled);
                for (const width of [360, 1440])
                {
                    await notices.setViewportSize({ width, height: 720 });
                    if (!(await notices.locator("#result-notice-details").evaluate(node => node.open)))
                    {
                        await notices.locator("#result-notice-summary").click();
                    }
                    for (const [banner, text, button] of [
                        ["workspace-feedback", "workspace-feedback-text", "btn-workspace-dismiss"],
                        ["result-notice", "result-notice-text", "btn-result-notice-dismiss"]
                    ])
                    {
                        assert.match(await notices.locator("#" + text).textContent(), /Unresolved context <&>/);
                        assert.equal(await notices.locator("#" + text + " *").count(), 0);
                        const scroll = await notices.locator("#" + text).evaluate(node =>
                        {
                            node.scrollTop = node.scrollHeight;
                            return { top: node.scrollTop, height: node.clientHeight, total: node.scrollHeight };
                        });
                        assert.ok(scroll.top > 0 && scroll.total > scroll.height);
                        const control = await notices.locator("#" + button).boundingBox();
                        const outer = await notices.locator("#" + banner).boundingBox();
                        assert.ok(control && outer && control.x >= 0 && control.x + control.width <= width);
                        assert.ok(control.y >= outer.y && control.y + control.height <= outer.y + outer.height);
                    }
                    if (evidence)
                    {
                        await notices.screenshot({ path: path.join(evidence, "notice-long-" + width + ".png") });
                    }
                }
                await notices.locator("#btn-workspace-dismiss").focus();
                await notices.keyboard.press("Space");
                assert.equal(await notices.locator("#prompt").evaluate(node => node === document.activeElement), true);
                assert.equal(await notices.locator("#result-notice").isVisible(), true);
                await notices.locator("#btn-result-notice-dismiss").focus();
                await notices.keyboard.press("Enter");
                assert.equal(await notices.locator("#result-table").evaluate(node => node === document.activeElement), true);
                assert.equal(await notices.locator("#result-notice").isVisible(), false);
                assert.match(await notices.locator("#result-summary").textContent(), /Unavailable \/ Current/);
                assert.equal(await notices.locator("#result-empty").isVisible(), true);
                assert.match(await notices.locator("#empty-message").textContent(), /Unresolved context/);
                await notices.locator("#result-info-toggle").click();
                assert.match(await notices.locator("#result-facts").textContent(), /Unresolved context/);
            }
            finally
            {
                await notices.close();
            }
        });
        await check("T-UI-BROWSER Memory panel reads expressions beside Results and copies exact little-endian values", async () =>
        {
            await page.setViewportSize({ width: 1440, height: 1000 });
            await page.evaluate(() =>
            {
                window.knTestStopped = true;
            });
            const title = await page.locator("#result-title").textContent();
            const before = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length);
            await page.locator("#btn-memory-panel").click();
            await page.locator("#tab-memory-view").click();
            await page.waitForFunction(() => !document.getElementById("btn-memory-read").disabled);
            assert.equal(await page.locator("#btn-memory-panel").getAttribute("aria-expanded"), "true");
            assert.equal(await page.locator("#evidence").isVisible(), true);
            assert.equal(await page.locator("#evidence").isVisible(), true);
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length), before);
            await page.locator("#memory-address").fill("nt!Example + 10");
            await page.locator("#memory-size").selectOption("64");
            await page.locator("#memory-address").press("Enter");
            await page.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length === 4 && document.getElementById("btn-cancel").disabled);
            assert.match(await page.locator("#memory-summary").textContent(), /63 of 64 bytes readable/);
            assert.equal(await page.locator("#result-title").textContent(), title);
            assert.equal(await page.locator("#memory-address").inputValue(), "0xffff800000001000");
            await page.getByRole("gridcell", { name: "Copy 8-bit value at 0xffff800000001000", exact: true }).click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent.startsWith("Copied 8-bit value"));
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "0x80");
            assert.equal(await page.getByRole("gridcell", { name: "Copy 8-bit value at 0xffff800000001005", exact: true }).count(), 0);
            for (const [width, value] of [["2", "8180"], ["4", "83828180"], ["8", "????????????????"]])
            {
                await page.locator("#memory-format").selectOption(width);
                assert.equal(await page.locator("#memory-rows .memory-row").first().locator("[role=gridcell]").nth(1).textContent(), value);
            }
            await page.getByRole("gridcell", { name: "Copy 64-bit value at 0xffff800000001008", exact: true }).click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent.startsWith("Copied 64-bit value"));
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "0x8f8e8d8c8b8a8988");
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length), before + 1,
                "Changing the display format reread the target");
            await page.locator("#btn-memory-next").click();
            await page.waitForFunction(() => document.getElementById("memory-address").value === "0xffff800000001040" && document.getElementById("btn-cancel").disabled);
            await page.locator("#btn-memory-prev").click();
            await page.waitForFunction(() => document.getElementById("memory-address").value === "0xffff800000001000" && document.getElementById("btn-cancel").disabled);
            await page.locator("#memory-format").selectOption("1");
            if (evidence)
            {
                await page.screenshot({ path: path.join(evidence, "memory-workspace.png") });
            }
        });
        await check("T-UI-BROWSER Memory values fit without per-cell buttons in every format", async () =>
        {
            for (const width of ["1", "2", "4", "8"])
            {
                await page.locator("#memory-format").selectOption(width);
                const collisions = await page.locator("#memory-rows .copyable").evaluateAll(cells => cells.flatMap(cell =>
                {
                    const text = document.createRange();
                    text.selectNode(cell.firstChild);
                    const textRight = text.getBoundingClientRect().right;
                    const cellRight = cell.getBoundingClientRect().right;
                    return textRight > cellRight ? [{ value: cell.firstChild.textContent, overlap: textRight - cellRight }] : [];
                }));
                assert.deepEqual(collisions, [], "Memory value overflows its cell for width " + width);
                assert.equal(await page.locator("#memory-rows button").count(), 0);
            }
            await page.locator("#memory-format").selectOption("1");
        });
        await check("T-UI-BROWSER Memory keyboard copying, narrow layouts and physical range selection stay usable", async () =>
        {
            for (const width of [600, 360])
            {
                await page.setViewportSize({ width, height: 900 });
                await page.locator("#memory-grid").focus();
                await page.keyboard.press("Home");
                const labels = await page.locator(".memory-row.selected .copyable").evaluateAll(nodes => nodes.map(node => node.getAttribute("aria-label")));
                for (const label of labels)
                {
                    await page.keyboard.press("Tab");
                    assert.equal(await page.evaluate(() => document.activeElement.getAttribute("aria-label")), label);
                }
                await page.keyboard.press("Escape");
                assert.equal(await page.evaluate(() => document.activeElement.id), "memory-grid");
                for (const id of ["memory-address", "memory-space", "memory-size", "btn-memory-read", "btn-memory-next"])
                {
                    await page.locator("#" + id).scrollIntoViewIfNeeded();
                    const box = await page.locator("#" + id).boundingBox();
                    assert.ok(box.x >= 0 && box.x + box.width <= width, id + " is outside the viewport");
                }
                if (evidence)
                {
                    await page.screenshot({ path: path.join(evidence, "memory-workspace-" + width + ".png") });
                }
            }
            await page.locator("#memory-space").selectOption("physical");
            assert.equal(await page.locator("#btn-memory-next").isEnabled(), false);
            await page.locator("#memory-address").fill("0");
            await page.locator("#btn-memory-read").click();
            await page.waitForFunction(() => document.getElementById("memory-address").value === "0x0000000000000000" && document.getElementById("btn-cancel").disabled);
            assert.match(await page.locator("#memory-context").textContent(), /Physical memory/);
            assert.equal(await page.locator("#btn-memory-prev").isEnabled(), false);
            assert.equal(await page.locator("#btn-memory-next").isEnabled(), true);
            const reads = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length);
            await page.locator("#btn-memory-close").click();
            await hideInspection(page);
            await page.locator("#btn-memory-panel").click();
            assert.equal(await page.locator("#memory-address").inputValue(), "0x0000000000000000");
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length), reads);
        });
        await check("T-UI-BROWSER Memory show/hide keeps the snapshot and result selection without reading again", async () =>
        {
            await page.setViewportSize({ width: 1920, height: 1000 });
            await page.waitForFunction(() => !document.getElementById("root").classList.contains("memory-overlay") &&
                document.getElementById("memory").getBoundingClientRect().right <= window.innerWidth);
            const bytes = await page.locator("#memory-rows").textContent();
            const title = await page.locator("#result-title").textContent();
            const reads = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length);
            const primary = await page.locator("#workspace-primary").boundingBox();
            const memory = await page.locator("#memory").boundingBox();
            assert.ok(primary.x + primary.width <= memory.x && memory.x + memory.width <= 1921,
                "Memory overlaps the primary workspace: " + JSON.stringify({ primary, memory }));
            await page.locator("#memory-grid").focus();
            await page.keyboard.press("Control+m");
            assert.equal(await page.locator("#memory").isVisible(), false);
            assert.equal(await page.locator("#memory-splitter").isVisible(), false);
            assert.equal(await page.evaluate(() => document.activeElement.id), "btn-memory-panel");
            assert.ok((await page.locator("#workspace-primary").boundingBox()).width > primary.width);
            await page.keyboard.press("Control+m");
            assert.equal(await page.locator("#memory-rows").textContent(), bytes);
            assert.equal(await page.locator("#result-title").textContent(), title);
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length), reads);
            if (evidence)
            {
                await page.screenshot({ path: path.join(evidence, "memory-right-panel.png") });
            }
        });
        await check("T-UI-BROWSER divider dragging, keyboard limits and Escape resize only the panel", async () =>
        {
            const splitter = page.locator("#memory-splitter");
            const before = Number(await splitter.getAttribute("aria-valuenow"));
            const reads = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length);
            let box = await splitter.boundingBox();
            await page.mouse.move(box.x + box.width / 2, box.y + 80);
            await page.mouse.down();
            await page.mouse.move(box.x - 117, box.y + 80, { steps: 5 });
            await page.mouse.up();
            assert.equal(Number(await splitter.getAttribute("aria-valuenow")), before + 120);
            await splitter.press("ArrowRight");
            assert.equal(Number(await splitter.getAttribute("aria-valuenow")), before + 104);
            box = await splitter.boundingBox();
            await page.mouse.move(box.x + box.width / 2, box.y + 80);
            await page.mouse.down();
            await page.mouse.move(box.x - 57, box.y + 80, { steps: 3 });
            await page.keyboard.press("Escape");
            await page.mouse.up();
            assert.equal(Number(await splitter.getAttribute("aria-valuenow")), before + 104);
            assert.equal(await page.locator("#root").evaluate(node => node.classList.contains("memory-resizing")), false);
            await splitter.press("Home");
            assert.equal(await splitter.getAttribute("aria-valuenow"), await splitter.getAttribute("aria-valuemin"));
            await splitter.press("End");
            assert.equal(await splitter.getAttribute("aria-valuenow"), await splitter.getAttribute("aria-valuemax"));
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "memoryRead").length), reads);
        });
        await check("T-UI-BROWSER saved panel layout reopens without reading and clamps narrow windows without losing width", async () =>
        {
            const preference = JSON.parse(await page.evaluate(() => localStorage.getItem("kndbgx.memory-panel")));
            const restored = await context.newPage();
            try
            {
                await restored.setViewportSize({ width: 1920, height: 1000 });
                await restored.addInitScript(fixtureInit);
                await restored.goto(`http://127.0.0.1:${server.address().port}/`);
                await restored.waitForFunction(() => document.getElementById("btn-memory-panel").getAttribute("aria-expanded") === "true");
                assert.equal(Number(await restored.locator("#memory-splitter").getAttribute("aria-valuenow")), preference.width);
                assert.equal(await restored.evaluate(() => window.knTestRequests.some(item => item.method === "memoryRead")), false);
                for (const width of [600, 360])
                {
                    await restored.setViewportSize({ width, height: 700 });
                    await restored.waitForFunction(() =>
                    {
                        const root = document.getElementById("root");
                        const frame = root.getBoundingClientRect();
                        const panel = document.getElementById("memory").getBoundingClientRect();
                        return root.classList.contains("memory-overlay") && Math.abs(panel.left - frame.left - 24) <= 1 &&
                            Math.abs(panel.right - frame.right) <= 1;
                    });
                    const panel = await restored.locator("#memory").boundingBox();
                    const close = await restored.locator("#btn-memory-close").boundingBox();
                    assert.ok(panel.x >= 0 && panel.x + panel.width <= width + 1);
                    assert.ok(close.x >= 0 && close.x + close.width <= width + 1 && close.y >= 0 && close.y + close.height <= 700);
                    assert.equal(JSON.parse(await restored.evaluate(() => localStorage.getItem("kndbgx.memory-panel"))).width, preference.width);
                }
                await restored.setViewportSize({ width: 1920, height: 1000 });
                await restored.waitForFunction(width => Number(document.getElementById("memory-splitter").getAttribute("aria-valuenow")) === width,
                    preference.width);
                if (evidence)
                {
                    await restored.screenshot({ path: path.join(evidence, "memory-restored-panel.png") });
                }
            }
            finally
            {
                await restored.close();
            }
            await page.locator("#btn-memory-close").click();
        });
        await check("T-UI-BROWSER Process panel fills its taller viewport after reopening, resizing or a window change without rereading", async () =>
        {
            for (const action of ["reopen", "resize", "window"])
            {
                const workspace = await context.newPage();
                try
                {
                    await workspace.setViewportSize({ width: 1920, height: 1400 });
                    await workspace.addInitScript(fixtureInit);
                    await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                    await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                    if (await workspace.locator("#memory").isHidden())
                    {
                        await workspace.locator("#btn-memory-panel").click();
                    }
                    await workspace.locator("#memory-splitter").press("End");
                    await showProcesses(workspace);
                    await workspace.waitForFunction(() => document.querySelectorAll(".process-row").length > 0 &&
                        document.getElementById("btn-cancel").disabled);
                    await workspace.locator("#process-filter").fill("");
                    const before = await workspace.evaluate(() => ({
                        rows: document.querySelectorAll(".process-row").length,
                        reads: window.knTestRequests.filter(item => item.method === "execute" || item.method === "memoryRead").length
                    }));
                    assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("memory-compact")), true);
                    if (action === "reopen")
                    {
                        await workspace.locator("#btn-memory-close").click();
                        await workspace.setViewportSize({ width: 1920, height: 1800 });
                        await workspace.locator("#btn-memory-panel").click();
                    }
                    else if (action === "resize")
                    {
                        await workspace.locator("#memory-splitter").press("Home");
                        await workspace.setViewportSize({ width: 1920, height: 1800 });
                    }
                    else
                    {
                        await workspace.locator("#process-grid").focus();
                        await workspace.keyboard.press("Home");
                        await workspace.locator(".process-row.selected .copyable").nth(3).focus();
                        await workspace.evaluate(() => { window.knTestFocusedProcessCell = document.activeElement.getAttribute("aria-label"); });
                        await workspace.setViewportSize({ width: 2560, height: 1800 });
                    }
                    await workspace.waitForFunction(() => document.getElementById("process-view").clientHeight > 700);
                    await workspace.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
                    const after = await workspace.evaluate(() => ({
                        rows: document.querySelectorAll(".process-row").length,
                        needed: Math.ceil(document.getElementById("process-view").clientHeight / 28),
                        reads: window.knTestRequests.filter(item => item.method === "execute" || item.method === "memoryRead").length
                    }));
                    assert.ok(after.rows >= after.needed && after.rows <= 128, JSON.stringify({ action, before, after }));
                    assert.equal(after.reads, before.reads);
                    if (action === "window")
                    {
                        assert.equal(await workspace.evaluate(() => document.activeElement.getAttribute("aria-label") === window.knTestFocusedProcessCell), true);
                    }
                }
                finally
                {
                    await workspace.close();
                }
            }
        });
        await check("T-UI-BROWSER process manual copy returns to the panel toggle after hiding the panel", async () =>
        {
            await showProcesses(page);
            await page.locator("#process-filter").fill("process1.exe");
            await page.evaluate(() =>
            {
                window.knRealClipboardWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
                navigator.clipboard.writeText = () => Promise.reject(new Error("Denied for test"));
            });
            try
            {
                await page.getByRole("gridcell", { name: "Copy Image for PID 4", exact: true }).click();
                await page.waitForFunction(() => document.activeElement.id === "copy-text");
                await hideInspection(page);
                await page.locator("#btn-copy-close").click();
                assert.equal(await page.evaluate(() => document.activeElement.id), "btn-memory-panel");
            }
            finally
            {
                await page.evaluate(() =>
                {
                    navigator.clipboard.writeText = window.knRealClipboardWrite;
                    const filter = document.getElementById("process-filter");
                    filter.value = "";
                    filter.dispatchEvent(new Event("input"));
                });
            }
        });
        await check("T-UI-BROWSER Current process polling preserves text selection and keyboard copy", async () =>
        {
            const selected = await page.locator("#current-process-eprocess").evaluate(node =>
            {
                const range = document.createRange();
                range.selectNodeContents(node);
                const selection = window.getSelection();
                selection.removeAllRanges();
                selection.addRange(range);
                return { value: selection.toString(), requests: window.knTestRequests.filter(item => item.method === "status").length };
            });
            assert.equal(selected.value, "0xffff800000001100");
            await page.waitForFunction(count => window.knTestRequests.filter(item => item.method === "status").length > count,
                selected.requests);
            assert.equal(await page.evaluate(() => window.getSelection().toString()), selected.value,
                "An unchanged status refresh destroyed the selected address");
            await page.keyboard.press("Control+c");
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), selected.value);
            await page.evaluate(() => window.getSelection().removeAllRanges());
        });
        await check("T-UI-BROWSER Current process strip does not cover the open command library", async () =>
        {
            await page.setViewportSize({ width: 800, height: 900 });
            await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
            if (await page.locator("#btn-sidebar").getAttribute("aria-expanded") !== "true")
            {
                await page.locator("#btn-sidebar").click();
            }
            try
            {
                assert.equal(await page.locator("#filter").evaluate(node =>
                {
                    const box = node.getBoundingClientRect();
                    return document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2) === node;
                }), true, "Current process strip intercepts clicks on the command filter");
                await page.locator("#filter").click();
                assert.equal(await page.locator("#filter").evaluate(node => node === document.activeElement), true);
            }
            finally
            {
                await page.keyboard.press("Control+b");
            }
        });
        await check("T-UI-BROWSER Current process stays visible across tabs and narrow-page scrolling with exact copy values", async () =>
        {
            assert.equal(await page.locator("#current-process-image").textContent(), "process1.exe");
            assert.equal(await page.locator("#current-process-pid").textContent(), "4");
            assert.equal(await page.locator("#current-process-eprocess").textContent(), "0xffff800000001100");
            for (const width of [1440, 600, 360])
            {
                await page.setViewportSize({ width, height: 900 });
                for (const tab of ["results", "processes", "memory"])
                {
                    if (tab === "results")
                    {
                        await hideInspection(page);
                    }
                    else
                    {
                        if (await page.locator("#memory").isHidden())
                        {
                            await page.locator("#btn-memory-panel").click();
                        }
                        await page.locator(tab === "processes" ? "#tab-processes" : "#tab-memory-view").click();
                    }
                    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
                    const box = await page.locator("#current-process-bar").boundingBox();
                    assert.ok(box.y >= 0 && box.y + box.height <= 900, "Current process strip scrolled outside the viewport");
                    for (const field of ["image", "pid", "eprocess"])
                    {
                        const value = await page.locator("#current-process-" + field).boundingBox();
                        assert.ok(value.x >= 0 && value.x + value.width <= width, "Current process field overflows: " + field);
                    }
                    if (tab === "memory")
                    {
                        await page.keyboard.press("Control+m");
                    }
                }
                if (evidence)
                {
                    await page.screenshot({ path: path.join(evidence, "current-process-" + width + ".png") });
                }
            }
            await page.locator("#copy-current-eprocess").click();
            await page.waitForFunction(() => document.getElementById("copy-status").textContent === "Copied current process eprocess.");
            assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "0xffff800000001100");
            await page.evaluate(() =>
            {
                window.knTestStopped = false;
            });
            await page.locator("#btn-refresh-status").click();
            await page.waitForFunction(() => document.getElementById("current-process-notice").textContent === "Target running");
            assert.equal(await page.locator("#current-process-image").textContent(), "Unavailable");
            assert.equal(await page.locator("#copy-current-eprocess").isEnabled(), false);
            await page.evaluate(() =>
            {
                window.knTestStopped = true;
                document.getElementById("btn-refresh-status").click();
            });
            await page.waitForFunction(() => !document.getElementById("prompt").disabled);
        });
        await check("T-UI-BROWSER registry grammar and argument completion edit drafts without executing them", async () =>
        {
            await page.setViewportSize({ width: 1200, height: 900 });
            const before = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
            await page.locator("#prompt").fill("!threads et");
            await page.locator("#suggest").waitFor({ state: "visible" });
            assert.ok((await page.locator("#command-hint").textContent()).includes("!threads [process|ethread:ADDRESS]"));
            await page.locator("#prompt").press("Tab");
            assert.equal(await page.locator("#prompt").inputValue(), "!threads ethread:");
            await page.locator("#prompt").fill("help u");
            await page.locator("#suggest").waitFor({ state: "visible" });
            await page.locator("#suggest .suggest-item").first().click();
            assert.equal(await page.locator("#prompt").inputValue(), "help ui");
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), before);
            await page.locator("#prompt").fill(":help");
            await page.locator("#prompt").press("Enter");
            await page.waitForFunction(() => window.knTestRequests.some(item => item.method === "execute" && item.params.command === "help ui"));
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), before + 1);
        });
        await check("T-UI-BROWSER EngineBusy retains identity and recovers actions after fresh status", async () =>
        {
            await page.evaluate(() =>
            {
                window.knTestStopped = true;
                window.knTestBusy = false;
            });
            await page.locator("#btn-refresh-status").click();
            await page.waitForFunction(() => !document.getElementById("btn-stack").disabled);
            const identity = await page.locator("#current-process-eprocess").textContent();
            await page.evaluate(() =>
            {
                window.knTestBusy = true;
            });
            await page.locator("#btn-refresh-status").click();
            await page.waitForFunction(() => document.getElementById("current-process-notice").textContent.includes("Debugger busy"));
            assert.equal(await page.locator("#current-process-eprocess").textContent(), identity);
            for (const id of ["btn-stack", "btn-memory-read", "btn-process-refresh"])
            {
                assert.equal(await page.locator("#" + id).isEnabled(), false);
            }
            assert.ok(!(await page.locator("#current-process-bar").textContent()).includes("No target"));
            if (evidence)
            {
                await page.screenshot({ path: path.join(evidence, "busy-last-known-target.png") });
            }
            await page.evaluate(() =>
            {
                window.knTestBusy = false;
            });
            await page.locator("#btn-refresh-status").click();
            await page.waitForFunction(() => !document.getElementById("btn-stack").disabled &&
                !document.getElementById("current-process-notice").textContent.includes("Debugger busy"));
            assert.equal(await page.locator("#current-process-eprocess").textContent(), identity);
        });
        await check("T-UI-BROWSER prompt activity stays visible without shifting input and respects reduced motion", async () =>
        {
            for (const width of [1440, 600, 360])
            {
                await page.setViewportSize({ width, height: 900 });
                await page.locator("#prompt").scrollIntoViewIfNeeded();
                const idleBox = await page.locator("#prompt").boundingBox();
                const idleArea = await page.locator("#command-area").boundingBox();
                await page.evaluate(() =>
                {
                    window.knTestHoldProcess = true;
                    window.knTestHoldInterrupt = true;
                });
                await page.locator("#prompt").fill("!dml_proc");
                await page.locator("#prompt").press("Enter");
                await page.waitForFunction(() => document.getElementById("command-phase").textContent === "Running");
                assert.equal(await page.locator("#command-progress").isVisible(), true);
                assert.equal(await page.locator("#command-hint").isVisible(), false);
                assert.deepEqual(await page.locator("#prompt").boundingBox(), idleBox, "Activity shifted the command input");
                assert.equal((await page.locator("#command-area").boundingBox()).height, idleArea.height,
                    "Activity resized the command area");
                assert.equal(await page.locator("#prompt-marker").evaluate(node => getComputedStyle(node).animationName), "command-spin");
                await page.emulateMedia({ reducedMotion: "reduce" });
                assert.equal(await page.locator("#prompt-marker").evaluate(node => getComputedStyle(node).animationName), "none");
                assert.equal(await page.locator("#command-progress").isVisible(), true);
                await page.emulateMedia({ reducedMotion: "no-preference" });
                const executions = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await page.locator("#prompt").fill("next draft");
                await page.locator("#prompt").press("Enter");
                assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
                await page.waitForFunction(minimum => parseFloat(document.getElementById("command-elapsed").textContent) >= minimum,
                    width === 1440 ? 4.5 : 1);
                assert.equal(await page.locator("#command-phase").textContent(), "Running");
                const progressBox = await page.locator("#command-progress").boundingBox();
                assert.ok(progressBox.x >= 0 && progressBox.x + progressBox.width <= width);
                if (evidence)
                {
                    await page.screenshot({ path: path.join(evidence, "command-running-" + width + ".png") });
                }
                if (width !== 1440)
                {
                    await page.locator("#btn-cancel").click();
                    await page.waitForFunction(() => document.getElementById("command-phase").textContent === "Cancelling");
                    assert.equal(await page.locator("#command-progress").isVisible(), true);
                    const interrupts = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "interrupt").length);
                    await page.locator("#btn-cancel").click();
                    assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "interrupt").length), interrupts,
                        "Repeated Stop submitted another interrupt while cancellation was pending");
                }
                await page.evaluate(cancelled =>
                {
                    window.knTestHoldProcess = false;
                    window.knTestHoldInterrupt = false;
                    window.knTestFinishProcess(cancelled);
                }, width !== 1440);
                await page.waitForFunction(() => document.getElementById("btn-cancel").disabled);
                assert.equal(await page.locator("#command-progress").isVisible(), false);
                assert.equal(await page.locator("#command-hint").isVisible(), true);
                assert.equal(await page.locator("#prompt-marker").evaluate(node => getComputedStyle(node).animationName), "none");
                assert.equal(await page.locator("#prompt").inputValue(), "next draft");
            }
        });
        await check("T-UI-BROWSER palette input stays in place as matches change and fits short windows", async () =>
        {
            for (const viewport of [{ width: 1440, height: 900 }, { width: 520, height: 360 }])
            {
                await page.setViewportSize(viewport);
                await page.locator("#btn-palette").click();
                const original = await page.locator("#palette-input").boundingBox();
                for (const query of ["help", "no-such-command-xyz", ""])
                {
                    await page.locator("#palette-input").fill(query);
                    const input = await page.locator("#palette-input").boundingBox();
                    assert.ok(Math.abs(input.y - original.y) < 1, "Filtering moved the input vertically");
                    for (const selector of ["#palette", "#palette-input", "#palette-close", "#palette-help"])
                    {
                        const box = await page.locator(selector).boundingBox();
                        assert.ok(box.x >= 0 && box.y >= 0 && box.x + box.width <= viewport.width + 1 &&
                            box.y + box.height <= viewport.height + 1, selector + " left the viewport");
                    }
                }
                const count = await page.locator("#palette-results .palette-item").count();
                for (let index = 0; index <= count; ++index)
                {
                    await page.locator("#palette-input").press("ArrowDown");
                    const input = await page.locator("#palette-input").boundingBox();
                    assert.ok(Math.abs(input.y - original.y) < 1, "Selection scrolling moved the input vertically");
                    assert.equal(await page.locator("#palette-results [aria-selected=true]").count(), 1);
                    assert.equal(await page.locator("#palette-input").evaluate(node => document.activeElement === node), true);
                }
                await page.keyboard.press("Escape");
            }
        });
        await check("T-UI-BROWSER header clicks sort every page and preserve exact 64-bit values", async () =>
        {
            await page.setViewportSize({ width: 1600, height: 1000 });
            await page.evaluate(() => window.scrollTo(0, 0));
            await hideInspection(page);
            await page.locator("#result-open-toggle").click();
            await page.locator("#result-id-input").fill("sort-fixture");
            await page.locator("#btn-result-load").click();
            await page.waitForFunction(() => document.getElementById("result-title").textContent === "sort-fixture" &&
                document.querySelectorAll(".result-row").length > 0);
            const before = await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
            const pid = page.locator('#table-head [data-sort-key=\'["pid"]\']');
            await pid.click();
            await page.waitForFunction(() => document.getElementById("row-position").textContent.startsWith("Sorted by PID (ascending)"));
            assert.equal(await page.locator(".result-row").first().locator(".row-index").textContent(), "260");
            assert.equal(await pid.locator("..").getAttribute("aria-sort"), "ascending");
            assert.ok(await page.locator(".result-row").count() <= 128);
            assert.ok(await page.evaluate(() => window.knTestRequests.some(item => item.method === "resultPage" &&
                item.params.resultId === "sort-fixture" && Number(item.params.offset) >= 256)));
            assert.equal(await page.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), before);
            const address = page.locator('#table-head [data-sort-key=\'["eprocess"]\']');
            await address.click();
            await page.waitForFunction(() => document.getElementById("row-position").textContent.startsWith("Sorted by EPROCESS (ascending)"));
            assert.equal(await page.locator(".result-row").first().locator(".row-address").textContent(), "0xfffffffffffffefc");
        });
        await check("T-UI-BROWSER Enter and Space toggle sorting and preserve header focus and selected source rows", async () =>
        {
            const address = page.locator('#table-head [data-sort-key=\'["eprocess"]\']');
            await address.press("Enter");
            assert.equal(await address.locator("..").getAttribute("aria-sort"), "descending");
            assert.equal(await address.evaluate(node => document.activeElement === node), true);
            assert.equal(await page.locator(".result-row").first().locator(".row-address").textContent(), "0xffffffffffffffff");
            await page.locator(".result-row").first().click();
            await address.focus();
            await address.press("Space");
            assert.equal(await address.locator("..").getAttribute("aria-sort"), "ascending");
            assert.equal(JSON.parse(await page.locator("#result-detail").textContent()).pid, "260");
            await page.locator("#btn-copy-row").click();
            await page.waitForFunction(async () => (await navigator.clipboard.readText()).startsWith("{"));
            assert.equal(JSON.parse(await page.evaluate(() => navigator.clipboard.readText())).eprocess, "0xffffffffffffffff");
            if (evidence)
            {
                await page.screenshot({ path: path.join(evidence, "sorted-table.png") });
            }
        });
        await check("T-UI-BROWSER focused sort headers stay visible and aligned in a narrow table", async () =>
        {
            await page.setViewportSize({ width: 600, height: 480 });
            const buttons = page.locator("#table-head .table-sort");
            for (let index = 0; index < await buttons.count(); ++index)
            {
                await buttons.nth(index).focus();
                const delta = await page.evaluate(() =>
                {
                    const index = [...document.querySelectorAll("#table-head button")].indexOf(document.activeElement);
                    const heading = document.activeElement.parentElement.getBoundingClientRect();
                    const cell = document.querySelector(".result-row").children[index].getBoundingClientRect();
                    const view = document.getElementById("result-view").getBoundingClientRect();
                    return { align: heading.left - cell.left, visible: heading.left >= view.left - 1 && heading.left < view.right,
                        outerScroll: document.getElementById("result-table").scrollLeft };
                });
                assert.ok(Math.abs(delta.align) < 1 && delta.visible && delta.outerScroll === 0, JSON.stringify(delta));
            }
            if (evidence)
            {
                await page.screenshot({ path: path.join(evidence, "sorted-table-narrow.png") });
            }
        });
        async function columnWorkspace()
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            await workspace.setViewportSize({ width: 1600, height: 1000 });
            await workspace.addInitScript(fixtureInit);
            await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
            await workspace.waitForFunction(() => !document.getElementById("btn-palette").disabled);
            await hideInspection(workspace);
            await workspace.locator("#result-open-toggle").click();
            await workspace.locator("#result-id-input").fill("sort-fixture");
            await workspace.locator("#btn-result-load").click();
            await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length > 0);
            return workspace;
        }
        await check("T-UI-BROWSER column dragging resizes headers and virtual rows without sorting or rereading the target", async () =>
        {
            const workspace = await columnWorkspace();
            try
            {
                const grip = workspace.locator('#table-head [data-resize-key=\'["pid"]\']');
                const header = grip.locator("..");
                await workspace.locator(".result-row").first().click();
                const selected = await workspace.locator("#result-detail").textContent();
                const requests = await workspace.evaluate(() => window.knTestRequests.length);
                const width = (await header.boundingBox()).width;
                const control = await grip.boundingBox();
                await workspace.mouse.move(control.x + control.width / 2, control.y + control.height / 2);
                await workspace.mouse.down();
                await workspace.mouse.move(control.x + control.width / 2 + 120, control.y + control.height / 2, { steps: 8 });
                await workspace.mouse.up();
                assert.ok(Math.abs((await header.boundingBox()).width - width - 120) < 1);
                assert.equal(await header.getAttribute("aria-sort"), "none");
                assert.equal(await workspace.locator("#result-detail").textContent(), selected);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.length), requests);
                await workspace.locator("#result-view").evaluate(node =>
                {
                    node.scrollTop = 200 * 28;
                });
                await workspace.waitForFunction(() => document.querySelector(".result-row").id === "observation-192");
                const alignment = await header.evaluate(node =>
                {
                    const row = document.querySelector(".result-row");
                    const cell = row.children[[...node.parentElement.children].indexOf(node)];
                    return { delta: node.getBoundingClientRect().left - cell.getBoundingClientRect().left,
                        width: cell.getBoundingClientRect().width, sameTemplate: row.style.gridTemplateColumns === node.parentElement.style.gridTemplateColumns };
                });
                assert.ok(Math.abs(alignment.delta) < 1 && alignment.sameTemplate);
                assert.ok(Math.abs(alignment.width - width - 120) < 1);
                await grip.dblclick();
                assert.ok(Math.abs((await header.boundingBox()).width - width) < 1);
                assert.equal(await header.getAttribute("aria-sort"), "none");
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "columns-resized.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER the stretched last column shrinks independently and Reset widths restores defaults", async () =>
        {
            const workspace = await columnWorkspace();
            try
            {
                const grip = workspace.locator("#table-head .table-resize").last();
                const cell = grip.locator("..");
                const width = (await cell.boundingBox()).width;
                const control = await grip.boundingBox();
                await workspace.mouse.move(control.x + control.width / 2, control.y + control.height / 2);
                await workspace.mouse.down();
                await workspace.mouse.move(control.x + control.width / 2 - 80, control.y + control.height / 2, { steps: 8 });
                await workspace.mouse.up();
                assert.ok(Math.abs((await cell.boundingBox()).width - width + 80) < 1);
                assert.equal(await workspace.locator("#table-head").evaluate(node => node.style.gridTemplateColumns.includes("minmax")), false);
                await workspace.locator("#columns-toggle").click();
                await workspace.locator("#btn-columns-widths").click();
                await workspace.locator("#columns-toggle").click();
                assert.ok(Math.abs((await cell.boundingBox()).width - width) < 1);
                assert.equal(await workspace.locator("#table-head").evaluate(node => node.style.gridTemplateColumns.includes("minmax")), true);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER column keyboard controls and Escape preserve selection and stay reachable in narrow windows", async () =>
        {
            const workspace = await columnWorkspace();
            try
            {
                await workspace.locator(".result-row").first().click();
                const selected = await workspace.locator("#result-detail").textContent();
                const grip = workspace.locator('#table-head [data-resize-key=\'["pid"]\']');
                const width = (await grip.locator("..").boundingBox()).width;
                const control = await grip.boundingBox();
                await workspace.mouse.move(control.x + control.width / 2, control.y + control.height / 2);
                await workspace.mouse.down();
                await workspace.mouse.move(control.x + control.width / 2 + 90, control.y + control.height / 2);
                await workspace.keyboard.press("Escape");
                await workspace.mouse.up();
                assert.ok(Math.abs((await grip.locator("..").boundingBox()).width - width) < 1);
                assert.equal(await workspace.locator("#root").evaluate(node => node.classList.contains("column-resizing")), false);
                for (const width of [600, 360])
                {
                    await workspace.setViewportSize({ width, height: 720 });
                    const last = workspace.locator("#table-head .table-resize").last();
                    await last.focus();
                    await last.press("End");
                    assert.equal(await last.getAttribute("aria-valuenow"), "4096");
                    await last.press("Home");
                    assert.equal(await last.getAttribute("aria-valuenow"), "64");
                    await last.press("Shift+ArrowRight");
                    assert.equal(await last.getAttribute("aria-valuenow"), "128");
                    const box = await last.boundingBox();
                    const viewport = await workspace.locator("#result-view").boundingBox();
                    assert.ok(box.x >= viewport.x && box.x + box.width <= viewport.x + viewport.width + 1);
                    assert.equal(await workspace.locator("#result-detail").textContent(), selected);
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "columns-keyboard-" + width + ".png") });
                    }
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER a rightmost scrolled column follows pointer displacement without scroll-clamp feedback", async () =>
        {
            const workspace = await columnWorkspace();
            try
            {
                await workspace.setViewportSize({ width: 600, height: 720 });
                const grip = workspace.locator("#table-head .table-resize").last();
                for (const steps of [1, 8])
                {
                    await grip.press("End");
                    const scroll = await workspace.locator("#result-view").evaluate(node => node.scrollLeft);
                    assert.ok(scroll > 0);
                    const initial = (await grip.locator("..").boundingBox()).width;
                    const control = await grip.boundingBox();
                    await workspace.mouse.move(control.x + control.width / 2, control.y + control.height / 2);
                    await workspace.mouse.down();
                    await workspace.mouse.move(control.x + control.width / 2 - 96, control.y + control.height / 2, { steps });
                    await workspace.mouse.up();
                    const actual = (await grip.locator("..").boundingBox()).width;
                    assert.ok(Math.abs(actual - initial + 96) < 1, JSON.stringify({ steps, initial, actual, expected: initial - 96 }));
                    assert.equal(await grip.locator("..").getAttribute("aria-sort"), "none");
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER cancelling a rightmost scrolled drag restores the viewport and visible keyboard focus", async () =>
        {
            const workspace = await columnWorkspace();
            try
            {
                await workspace.setViewportSize({ width: 600, height: 720 });
                const grip = workspace.locator("#table-head .table-resize").last();
                await grip.press("End");
                const initialScroll = await workspace.locator("#result-view").evaluate(node => node.scrollLeft);
                const initialWidth = (await grip.locator("..").boundingBox()).width;
                const control = await grip.boundingBox();
                await workspace.mouse.move(control.x + control.width / 2, control.y + control.height / 2);
                await workspace.mouse.down();
                await workspace.mouse.move(control.x + control.width / 2 - 96, control.y + control.height / 2);
                await workspace.keyboard.press("Escape");
                await workspace.mouse.up();
                const actualScroll = await workspace.locator("#result-view").evaluate(node => node.scrollLeft);
                assert.equal(actualScroll, initialScroll);
                assert.equal((await grip.locator("..").boundingBox()).width, initialWidth);
                assert.equal(await grip.evaluate(node => node === document.activeElement), true);
                const box = await grip.boundingBox();
                const viewport = await workspace.locator("#result-view").boundingBox();
                assert.ok(box.x >= viewport.x && box.x + box.width <= viewport.x + viewport.width + 1);
            }
            finally
            {
                await workspace.close();
            }
        });
        async function inspectionWorkspace()
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            await workspace.setViewportSize({ width: 1920, height: 1050 });
            await workspace.addInitScript(fixtureInit);
            await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
            if (await workspace.locator("#memory").isHidden())
            {
                await workspace.locator("#btn-memory-panel").click();
            }
            await workspace.locator("#tab-disassembly").click();
            await workspace.waitForFunction(() => !document.getElementById("btn-disassembly-read").disabled);
            return workspace;
        }
        async function floatingWorkspace(options = {})
        {
            const local = await browser.newContext({ viewport: { width: 1600, height: 900 } });
            const workspace = await local.newPage();
            workspace.setDefaultTimeout(8000);
            workspace.on("pageerror", error => errors.push(error.message));
            await workspace.addInitScript(fixtureInit, options);
            await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
            await workspace.waitForFunction(() => !document.getElementById("btn-inspection-float").disabled);
            return { local, workspace };
        }
        async function detachInspection(workspace)
        {
            const opened = workspace.waitForEvent("popup");
            await workspace.locator("#btn-inspection-float").click();
            const popup = await opened;
            popup.setDefaultTimeout(8000);
            popup.on("pageerror", error => errors.push(error.message));
            await popup.locator("#btn-inspection-float").filter({ hasText: "Dock" }).waitFor();
            return popup;
        }
        await check("T-UI-BROWSER floating review native close wins over an earlier queued show and permits a fresh reopen", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ holdInspectionShow: true });
            try
            {
                const popup = await detachInspection(workspace);
                await workspace.waitForFunction(() => window.knTestPendingInspection.length === 1);
                await workspace.evaluate(() =>
                {
                    window.knTestCloseInspectionFrame();
                    window.knTestReleaseInspection();
                });
                await popup.locator("#memory").waitFor({ state: "hidden" });
                assert.equal(await workspace.evaluate(() => window.knTestInspectionVisible), false);
                await workspace.evaluate(() => { window.knTestHoldInspectionShow = false; });
                await workspace.locator("#btn-memory-panel").click();
                await popup.locator("#memory").waitFor();
                assert.equal(await workspace.evaluate(() => window.knTestInspectionVisible), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER floating review an opening window cannot escape the command palette", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.evaluate(() =>
                {
                    const open = window.open;
                    window.open = function ()
                    {
                        const popup = open.apply(window, arguments);
                        const append = popup.document.head.appendChild.bind(popup.document.head);
                        popup.document.head.appendChild = function (node)
                        {
                            if (node.tagName === "LINK")
                            {
                                window.knTestReleaseStyles = () => append(node);
                                return node;
                            }
                            return append(node);
                        };
                        return popup;
                    };
                });
                const opened = workspace.waitForEvent("popup");
                await workspace.locator("#btn-inspection-float").click();
                const popup = await opened;
                await workspace.waitForFunction(() => typeof window.knTestReleaseStyles === "function");
                await workspace.locator("#btn-palette").click();
                await workspace.locator("#palette-backdrop").waitFor();
                await workspace.evaluate(() => window.knTestReleaseStyles());
                await workspace.waitForFunction(() => document.getElementById("btn-inspection-float")?.textContent === "Float group");
                assert.equal(popup.isClosed(), true);
                assert.equal(await workspace.locator("#memory").evaluate(node => node.closest("#root").inert), true);
                await workspace.keyboard.press("Escape");
                assert.equal(await workspace.locator("#memory").evaluate(node => node.closest("#root").inert), false);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER floating review a delayed clipboard refusal follows the moved source grid", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.locator("#tab-memory-view").click();
                await workspace.locator("#btn-memory-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length > 0 &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.evaluate(() => Object.defineProperty(navigator, "clipboard", { configurable: true,
                    value: { writeText: () => new Promise((resolve, reject) => { window.knTestRefuseClipboard = reject; }) } }));
                await workspace.locator("#memory-grid").press("Home");
                await workspace.locator(".memory-row.selected .copyable").first().press("Control+c");
                const popup = await detachInspection(workspace);
                await workspace.evaluate(() => window.knTestRefuseClipboard(new Error("delayed clipboard refusal")));
                await popup.locator("#copy-fallback").waitFor();
                assert.ok((await popup.locator("#copy-text").inputValue()).length > 0);
                assert.equal(await workspace.locator("#copy-fallback").count(), 0);
                await popup.locator("#btn-copy-close").click();
                await popup.evaluate(() => Object.defineProperty(navigator, "clipboard", { configurable: true,
                    value: { writeText: () => new Promise((resolve, reject) => { window.knTestRefuseClipboard = reject; }) } }));
                await popup.locator(".memory-row.selected .copyable").first().press("Control+c");
                await popup.locator("#btn-memory-close").click();
                await popup.evaluate(() => window.knTestRefuseClipboard(new Error("hidden panel clipboard refusal")));
                await workspace.locator("#copy-fallback").waitFor();
                assert.ok((await workspace.locator("#copy-text").inputValue()).length > 0);
                assert.equal(await popup.locator("#copy-fallback").count(), 0);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER floating review failed overlay visibility controls recover the panel to the main window", async () =>
        {
            for (const action of ["hide", "visible"])
            {
                const { local, workspace } = await floatingWorkspace();
                try
                {
                    const popup = await detachInspection(workspace);
                    await popup.locator("#memory-address").fill("nt!NtOpenFile");
                    if (action === "hide")
                    {
                        await workspace.evaluate(() => { window.knTestFailInspectionAction = "hide"; });
                    }
                    await workspace.locator("#btn-palette").click();
                    await workspace.locator("#palette-backdrop").waitFor();
                    if (action === "visible")
                    {
                        await workspace.evaluate(() => { window.knTestFailInspectionAction = "visible"; });
                        await workspace.keyboard.press("Escape");
                    }
                    await workspace.locator("#memory").waitFor();
                    assert.equal(await workspace.locator("#memory-address").inputValue(), "nt!NtOpenFile");
                    assert.equal(await workspace.locator("#memory").evaluate(node => node.closest("#root").inert), action === "hide");
                    assert.equal(popup.isClosed(), true);
                }
                finally
                {
                    await local.close();
                }
            }
        });
        await check("T-UI-BROWSER floating review a delayed focus acknowledgement cannot override a newer user gesture", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                const popup = await detachInspection(workspace);
                await workspace.evaluate(() => { window.knTestHoldInspectionFocus = true; });
                await popup.locator("#memory-address").press("Control+l");
                await workspace.waitForFunction(() => window.knTestPendingInspection.length === 1);
                await workspace.locator("#filter").click();
                await workspace.evaluate(() => window.knTestReleaseInspection());
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "filter");
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER floating review an obsolete visibility failure cannot undo a newer restore", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.evaluate(() =>
                {
                    window.knTestFailInspectionAction = "show";
                    window.knTestHoldInspectionErrors = true;
                });
                const popup = await detachInspection(workspace);
                await workspace.waitForFunction(() => window.knTestPendingInspection.length === 1);
                await workspace.evaluate(() => { window.knTestFailInspectionAction = ""; });
                await workspace.locator("#btn-palette").click();
                await workspace.locator("#palette-backdrop").waitFor();
                await workspace.keyboard.press("Escape");
                await workspace.evaluate(() => window.knTestReleaseInspection());
                assert.equal(await workspace.locator("#memory").count(), 0);
                assert.equal(await popup.locator("#memory").isVisible(), true);
                assert.equal(await workspace.evaluate(() => window.knTestInspectionVisible), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER floating inspection keeps the same nodes, drafts, selected process, snapshots and scroll on Dock", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.locator("#tab-memory-view").click();
                await workspace.locator("#memory-size").selectOption("1024");
                await workspace.locator("#btn-memory-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length === 64 &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#tab-disassembly").click();
                await workspace.locator("#btn-disassembly-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .disassembly-row").length > 0 &&
                    document.getElementById("btn-cancel").disabled);
                await showProcesses(workspace);
                await workspace.waitForFunction(() => document.getElementById("process-summary").textContent.includes("257 collected") &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#process-grid").press("End");
                await workspace.evaluate(() =>
                {
                    const ids = ["memory", "memory-rows", "disassembly-rows", "process-grid", "memory-address", "disassembly-address"];
                    window.knFloatNodes = ids.map(id => document.getElementById(id));
                    document.getElementById("memory-address").value = "nt!KeBugCheckEx+10";
                    document.getElementById("disassembly-address").value = "nt!NtCreateFile";
                    window.knFloatMarkup = [document.getElementById("memory-rows").innerHTML,
                        document.getElementById("disassembly-rows").innerHTML, document.getElementById("process-name").textContent];
                    window.knFloatReads = window.knTestRequests.filter(item => ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length;
                });
                const popup = await detachInspection(workspace);
                assert.equal(await workspace.locator("#memory").count(), 0);
                assert.equal(await workspace.locator("#btn-memory-panel").getAttribute("aria-controls"), null);
                assert.equal(await workspace.locator("#memory-splitter").isHidden(), true);
                assert.match(await popup.locator("#process-name").textContent(), /process256/);
                await popup.locator("#tab-memory-view").click();
                await popup.locator("#memory-grid").evaluate(node => { node.scrollTop = 300; node.scrollLeft = 20; });
                const scroll = await popup.locator("#memory-grid").evaluate(node => [node.scrollTop, node.scrollLeft]);
                assert.ok(scroll[0] > 0);
                assert.equal(await popup.locator("#memory-address").inputValue(), "nt!KeBugCheckEx+10");
                await popup.locator("#btn-inspection-float").click();
                await workspace.locator("#btn-inspection-float").filter({ hasText: "Float" }).waitFor();
                assert.equal(await workspace.locator("#btn-memory-panel").getAttribute("aria-controls"), "memory");
                assert.equal(await workspace.evaluate(() => window.knFloatNodes.every(node => node.ownerDocument === document &&
                    node === document.getElementById(node.id))), true);
                assert.deepEqual(await workspace.locator("#memory-grid").evaluate(node => [node.scrollTop, node.scrollLeft]), scroll);
                assert.deepEqual(await workspace.evaluate(() => [document.getElementById("memory-rows").innerHTML,
                    document.getElementById("disassembly-rows").innerHTML, document.getElementById("process-name").textContent]),
                    await workspace.evaluate(() => window.knFloatMarkup));
                assert.equal(await workspace.locator("#disassembly-address").inputValue(), "nt!NtCreateFile");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length === window.knFloatReads), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER address completion keeps read controls fixed and accepts the first click", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ symbols: [
                { symbol: "nt!NtCreateFile", address: "0xffff800000001000", kind: "symbol" }
            ] });
            try
            {
                await workspace.setViewportSize({ width: 1266, height: 822 });
                for (const floating of [false, true])
                {
                    const surface = floating ? await detachInspection(workspace) : workspace;
                    for (const view of ["memory", "disassembly"])
                    {
                        await surface.locator(view === "memory" ? "#tab-memory-view" : "#tab-disassembly").click();
                        const input = surface.locator("#" + view + "-address");
                        const read = surface.locator("#btn-" + view + "-read");
                        await read.waitFor();
                        const before = await read.boundingBox();
                        const method = view + "Read";
                        const count = await workspace.evaluate(method => window.knTestRequests.filter(item => item.method === method).length, method);
                        await input.fill("nt!NtCreateFile");
                        await surface.locator("#" + view + "-symbol-suggest").waitFor();
                        const after = await read.boundingBox();
                        assert.deepEqual(after, before, view + " read button moved when symbol suggestions appeared");
                        await surface.mouse.click(after.x + after.width / 2, after.y + after.height / 2);
                        await workspace.waitForFunction(({ method, count }) =>
                            window.knTestRequests.filter(item => item.method === method).length === count + 1, { method, count });
                        assert.equal(await surface.locator("#" + view + "-symbol-suggest").isHidden(), true);
                        await surface.waitForFunction(id => !document.getElementById(id).disabled, "btn-" + view + "-read");
                        await input.fill("nt!NtC");
                        await surface.locator("#" + view + "-symbol-suggest .suggest-item").first().click();
                        assert.equal(await input.inputValue(), "nt!NtCreateFile");
                        assert.equal(await workspace.evaluate(method => window.knTestRequests.filter(item => item.method === method).length, method), count + 1);
                    }
                }
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER floating address completion and manual clipboard fallback use the popup document", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ symbols: [{ symbol: "nt!NtCreateFile", address: "0xffff800000001000", kind: "symbol" }] });
            try
            {
                await workspace.locator("#tab-memory-view").click();
                const popup = await detachInspection(workspace);
                await popup.locator("#memory-address").fill("nt!NtC");
                await popup.locator("#memory-symbol-suggest").waitFor();
                await popup.locator("#memory-address").press("Tab");
                assert.equal(await popup.locator("#memory-address").inputValue(), "nt!NtCreateFile");
                await popup.locator("#btn-memory-read").click();
                await popup.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length > 0);
                await popup.evaluate(() => Object.defineProperty(navigator, "clipboard", {
                    configurable: true, value: { writeText: () => Promise.reject(new Error("fixture clipboard unavailable")) } }));
                await popup.locator("#memory-grid").press("Home");
                await popup.locator(".memory-row.selected .copyable").first().press("Control+c");
                await popup.locator("#copy-fallback").waitFor();
                assert.ok((await popup.locator("#copy-text").inputValue()).length > 0);
                assert.equal(await popup.locator("#copy-text").evaluate(node => node === document.activeElement), true);
                await popup.locator("#btn-copy-close").click();
                await popup.locator("#btn-inspection-float").click();
                await workspace.locator("#copy-fallback").waitFor({ state: "attached" });
                assert.equal(await workspace.locator("#copy-fallback").isHidden(), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER floating Follow IP routes F10 F11 once and locks controls while the target is running", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ followExecution: true });
            try
            {
                await workspace.locator("#tab-disassembly").click();
                await workspace.evaluate(() =>
                {
                    window.knTestBreak("0xffff800000001000");
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => document.querySelector("#disassembly-rows .current-ip"));
                const popup = await detachInspection(workspace);
                await popup.locator("#disassembly-grid").focus();
                await popup.keyboard.press("F10");
                await popup.waitForFunction(() => document.querySelector("#disassembly-rows .current-ip")?.textContent.includes("0xffff800000001001") &&
                    !document.getElementById("btn-debug-into").disabled);
                await popup.keyboard.press("F11");
                await popup.waitForFunction(() => document.querySelector("#disassembly-rows .current-ip")?.textContent.includes("0xffff800000001002") &&
                    !document.getElementById("btn-debug-into").disabled);
                assert.deepEqual(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "debuggerAction")
                    .map(item => item.params.operation)), ["step-over", "step-into"]);
                await popup.keyboard.press("F5");
                await workspace.waitForFunction(() => document.getElementById("prompt").disabled);
                assert.equal(await popup.locator("#btn-debug-over").isDisabled(), true);
                assert.equal(await popup.locator("#btn-disassembly-read").isDisabled(), true);
                assert.match(await popup.locator("#floating-inspection-status").textContent(), /running|Busy/i);
                if (evidence)
                {
                    await popup.screenshot({ path: path.join(evidence, "floating-inspect-busy.png") });
                }
                await workspace.locator("#btn-inspection-dock").click();
                assert.equal(await workspace.locator("#btn-debug-over").isDisabled(), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER floating F9 approval and command palette suspend the panel and restore focus after cancel", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.locator("#tab-disassembly").click();
                await workspace.locator("#btn-disassembly-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .disassembly-row").length > 0 &&
                    document.getElementById("btn-cancel").disabled);
                const popup = await detachInspection(workspace);
                await popup.locator("#disassembly-grid").focus();
                await popup.locator("#disassembly-grid").press("Home");
                await popup.keyboard.press("F9");
                await workspace.locator("#modal-backdrop").waitFor();
                assert.equal(await popup.locator("#memory").evaluate(node => node.inert), true);
                await workspace.locator("#modal-cancel").click();
                await popup.waitForFunction(() => !document.getElementById("memory").inert);
                await popup.locator("#disassembly-grid").focus();
                await popup.keyboard.press("Control+k");
                await workspace.locator("#palette-backdrop").waitFor();
                assert.equal(await popup.locator("#memory").evaluate(node => node.inert), true);
                await workspace.keyboard.press("Escape");
                await popup.waitForFunction(() => !document.getElementById("memory").inert);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "breakpointApply")), false);
                const controls = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "inspectionWindow").map(item => item.params.action));
                assert.ok(controls.filter(action => action === "hide").length >= 2 && controls.includes("focus-main"));
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER blocked floating window and failed styles keep the original docked panel usable", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.evaluate(() => { window.knSavedOpen = window.open; window.open = () => null; });
                await workspace.locator("#btn-inspection-float").click();
                assert.equal(await workspace.locator("#memory").isVisible(), true);
                assert.match(await workspace.locator("#workspace-feedback-text").textContent(), /could not be opened/);
                await workspace.evaluate(() => { window.open = window.knSavedOpen; });
                await local.route("**/app.css", route => route.abort());
                const opened = workspace.waitForEvent("popup");
                await workspace.locator("#btn-inspection-float").click();
                await opened;
                try
                {
                    await workspace.waitForFunction(() => /styles could not be loaded|did not become ready/.test(
                        document.getElementById("workspace-feedback-text").textContent), null, { timeout: 12000 });
                }
                catch (error)
                {
                    throw new Error("Styles failure did not restore the panel: " + await workspace.evaluate(() => JSON.stringify({
                        feedback: document.getElementById("workspace-feedback-text").textContent,
                        button: document.getElementById("btn-inspection-float")?.textContent,
                        controls: window.knTestRequests.filter(item => item.method === "inspectionWindow")
                    })));
                }
                assert.equal(await workspace.locator("#memory").isVisible(), true);
                assert.equal(await workspace.locator("#btn-inspection-float").isEnabled(), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER Processes lives in the right panel and four tabs retain data beside the selected Results row", async () =>
        {
            const workspace = await inspectionWorkspace();
            try
            {
                await workspace.locator("#result-open-toggle").click();
                await workspace.locator("#result-id-input").fill("code-fixture");
                await workspace.locator("#btn-result-load").click();
                await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 3);
                await workspace.locator(".result-row").first().click();
                const selected = await workspace.locator("#result-detail").textContent();
                await workspace.locator("#disassembly-count").selectOption("16");
                await workspace.locator("#btn-disassembly-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .disassembly-row").length === 16 &&
                    document.getElementById("btn-cancel").disabled);
                const code = await workspace.locator("#disassembly-rows").textContent();
                await workspace.locator("#tab-memory-view").click();
                await workspace.locator("#memory-size").selectOption("64");
                await workspace.locator("#btn-memory-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length === 4 &&
                    document.getElementById("btn-cancel").disabled);
                const memory = await workspace.locator("#memory-rows").textContent();
                await showProcesses(workspace);
                await workspace.waitForFunction(() => document.getElementById("process-summary").textContent.includes("257 collected") &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#process-grid").press("End");
                await workspace.locator("#process-filter").fill("process256");
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length);
                for (const tab of ["#tab-memory-view", "#tab-disassembly", "#tab-processes"])
                {
                    await workspace.locator(tab).click();
                }
                assert.equal(await workspace.locator("#memory-rows").textContent(), memory);
                assert.equal(await workspace.locator("#disassembly-rows").textContent(), code);
                assert.equal(await workspace.locator("#process-filter").inputValue(), "process256");
                assert.match(await workspace.locator("#process-name").textContent(), /process256/);
                assert.equal(await workspace.locator("#result-detail").textContent(), selected);
                assert.equal(await workspace.locator("#result-title").textContent(), "code-fixture");
                assert.equal(await workspace.evaluate(() => document.getElementById("memory").contains(document.getElementById("processes"))), true);
                assert.equal(await workspace.evaluate(() => document.getElementById("workspace-primary").contains(document.getElementById("processes"))), false);
                assert.equal(await workspace.locator("#inspection-tabs [aria-selected=true]").count(), 1);
                assert.equal(await workspace.locator("#inspection-tabs [role=tab]").count(), 4);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["execute", "memoryRead", "disassemblyRead"].includes(item.method)).length), reads);
                const main = await workspace.locator("#workspace-primary").boundingBox();
                const panel = await workspace.locator("#memory").boundingBox();
                assert.ok(main.x + main.width <= panel.x && panel.x + panel.width <= 1921);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "process-right-panel.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER process tabs, filter and actions fit narrow panels and restore the selected process tab", async () =>
        {
            const workspace = await inspectionWorkspace();
            try
            {
                await showProcesses(workspace);
                await workspace.waitForFunction(() => document.querySelectorAll(".process-row").length > 0 &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#process-grid").press("Home");
                for (const viewport of [{ width: 360, height: 480 }, { width: 600, height: 520 }, { width: 1920, height: 1050 }])
                {
                    await workspace.setViewportSize(viewport);
                    if (viewport.width === 1920)
                    {
                        await workspace.locator("#memory-splitter").press("Home");
                    }
                    for (const id of ["tab-processes", "tab-memory-view", "tab-disassembly", "btn-memory-close", "process-filter",
                        "btn-process-refresh", "btn-process-details", "btn-process-threads", "btn-process-vad", "btn-process-token", "btn-process-attach"])
                    {
                        const node = workspace.locator("#" + id);
                        await node.scrollIntoViewIfNeeded();
                        const box = await node.boundingBox();
                        assert.ok(box.x >= 0 && box.y >= 0 && box.x + box.width <= viewport.width + 1 &&
                            box.y + box.height <= viewport.height + 1, id + " left the viewport: " + JSON.stringify(box));
                    }
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "process-panel-" + viewport.width + ".png") });
                    }
                }
                await workspace.locator("#tab-processes").press("ArrowLeft");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "tab-registers");
                await workspace.locator("#tab-registers").press("ArrowRight");
                assert.equal(await workspace.locator("#tab-processes").getAttribute("aria-selected"), "true");
                await workspace.locator("#tab-processes").press("ArrowRight");
                assert.equal(await workspace.locator("#tab-memory-view").getAttribute("aria-selected"), "true");
                await workspace.locator("#tab-memory-view").press("End");
                await workspace.locator("#tab-registers").press("Home");
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await workspace.locator("#btn-memory-close").click();
                await workspace.locator("#btn-memory-panel").click();
                assert.equal(await workspace.locator("#tab-processes").getAttribute("aria-selected"), "true");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), reads);
                await workspace.reload();
                await workspace.waitForFunction(() => document.getElementById("process-summary").textContent.includes("257 collected") &&
                    document.getElementById("btn-cancel").disabled);
                assert.equal(await workspace.locator("#tab-processes").getAttribute("aria-selected"), "true");
                assert.equal(await workspace.locator("#memory").isVisible(), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute" &&
                    item.params.command === "!dml_proc").length), 1);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER process detail results reveal Results in a narrow drawer while retaining the selected process", async () =>
        {
            const workspace = await inspectionWorkspace();
            try
            {
                await workspace.setViewportSize({ width: 360, height: 640 });
                await showProcesses(workspace);
                await workspace.waitForFunction(() => document.querySelectorAll(".process-row").length > 0 &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#process-grid").press("Home");
                await workspace.locator("#process-grid").press("ArrowDown");
                await workspace.locator("#btn-process-threads").click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "!threads" &&
                    document.getElementById("btn-cancel").disabled);
                assert.equal(await workspace.locator("#memory").isVisible(), false);
                assert.equal(await workspace.locator("#evidence").isVisible(), true);
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "result-table");
                const request = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "processAction"));
                assert.equal(request.params.index, "1");
                assert.equal(request.params.action, "threads");
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                await showProcesses(workspace);
                assert.match(await workspace.locator("#process-name").textContent(), /process1.exe/);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), reads);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER Disassembly tabs retain independent views, copy exact values and follow decoded boundaries", async () =>
        {
            const workspace = await inspectionWorkspace();
            try
            {
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "disassemblyRead")), false);
                await workspace.locator("#disassembly-count").selectOption("16");
                await workspace.locator("#btn-disassembly-ip").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .disassembly-row").length === 16 &&
                    document.getElementById("btn-cancel").disabled);
                const decoded = await workspace.locator("#disassembly-rows").textContent();
                assert.equal(await workspace.locator("#disassembly-rows .current-ip").count(), 1);
                const first = workspace.locator("#disassembly-rows .disassembly-row").first();
                await first.locator("[role=gridcell]").nth(1).click();
                assert.equal(await workspace.evaluate(() => navigator.clipboard.readText()), "0xffff800000001000");
                await workspace.locator("#disassembly-grid").press("ArrowDown");
                assert.match(await workspace.locator("#disassembly-position").textContent(), /0xffff800000001004/);
                await workspace.locator("#disassembly-rows .selected [role=gridcell]").nth(2).press("Enter");
                assert.equal(await workspace.evaluate(() => navigator.clipboard.readText()), "call sample!Worker (ffff8000`00002000)");
                await workspace.locator("#tab-memory-view").click();
                await workspace.locator("#memory-size").selectOption("64");
                await workspace.locator("#btn-memory-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length === 4 &&
                    document.getElementById("btn-cancel").disabled);
                const memory = await workspace.locator("#memory-rows").textContent();
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => /^(memoryRead|disassemblyRead)$/.test(item.method)).length);
                await workspace.locator("#tab-memory-view").press("ArrowRight");
                assert.equal(await workspace.locator("#tab-disassembly").getAttribute("aria-selected"), "true");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "tab-disassembly");
                assert.equal(await workspace.locator("#disassembly-rows").textContent(), decoded);
                assert.match(await workspace.locator("#disassembly-position").textContent(), /0xffff800000001004/);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => /^(memoryRead|disassemblyRead)$/.test(item.method)).length), reads);
                await workspace.locator("#btn-disassembly-next").click();
                await workspace.waitForFunction(() => document.getElementById("disassembly-address").value === "0xffff800000001040" &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#btn-disassembly-back").click();
                assert.equal(await workspace.locator("#disassembly-address").inputValue(), "0xffff800000001000");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "disassemblyRead").length), 2);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "disassembly-right-panel.png") });
                }
                await workspace.locator("#tab-memory-view").click();
                assert.equal(await workspace.locator("#memory-rows").textContent(), memory);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER header Continue Break works outside Inspect with color focus and narrow layouts", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { followExecution: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                const toggle = workspace.locator("#btn-execution-toggle");
                await workspace.waitForFunction(() => !document.getElementById("btn-execution-toggle").disabled);
                await workspace.locator("#btn-disassembly-follow").evaluate(button => button.click());
                await workspace.locator("#btn-memory-close").click();
                await workspace.locator("#prompt").fill("unsent command");
                await workspace.setViewportSize({ width: 1280, height: 800 });
                await toggle.focus();
                const colors = [];
                for (const width of [1280, 700, 360])
                {
                    await workspace.setViewportSize({ width, height: 800 });
                    for (const id of ["btn-palette", "btn-execution-toggle"])
                    {
                        const box = await workspace.locator("#" + id).boundingBox();
                        assert.ok(box && box.width >= 30 && box.x >= 0 && box.x + box.width <= width, id + " overflows at " + width);
                    }
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "execution-header-stopped-" + width + ".png") });
                        if (width === 1280)
                        {
                            await workspace.locator("#app-header").screenshot({ path: path.join(evidence, "execution-toolbar-continue.png") });
                        }
                    }
                }
                colors.push(await toggle.evaluate(button => getComputedStyle(button).color));
                await workspace.locator("#prompt").focus();
                await workspace.keyboard.press("F5");
                await workspace.waitForFunction(() => !document.getElementById("btn-execution-toggle").disabled &&
                    document.getElementById("btn-execution-toggle").dataset.action === "break");
                colors.push(await toggle.evaluate(button => getComputedStyle(button).color));
                assert.notEqual(colors[0], colors[1], "Continue and Break must have distinct colors");
                assert.equal(await workspace.locator("#memory").isVisible(), false);
                assert.equal(await workspace.locator("#prompt").inputValue(), "unsent command");
                await workspace.setViewportSize({ width: 1280, height: 800 });
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "execution-header-running.png") });
                    await workspace.locator("#app-header").screenshot({ path: path.join(evidence, "execution-toolbar-break.png") });
                }
                await workspace.evaluate(() => window.knTestHoldBreak = true);
                await toggle.click();
                await workspace.waitForFunction(() => document.getElementById("execution-toggle-label").textContent === "Breaking...");
                assert.equal(await toggle.isDisabled(), true);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "execution-header-breaking.png") });
                }
                await workspace.evaluate(() =>
                {
                    window.knTestBreak("0xffff800000003000");
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => !document.getElementById("btn-execution-toggle").disabled &&
                    document.getElementById("btn-execution-toggle").dataset.action === "continue");
                assert.deepEqual(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["debuggerAction", "breakExecution"].includes(item.method)).map(item => item.method)), ["debuggerAction", "breakExecution"]);
                assert.equal(await workspace.locator("#memory").isVisible(), false);
                assert.equal(await workspace.locator("#prompt").inputValue(), "unsent command");
                await workspace.emulateMedia({ reducedMotion: "reduce", forcedColors: "active" });
                await workspace.locator("#btn-palette").focus();
                await workspace.keyboard.press("Tab");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-execution-toggle");
                assert.equal(await toggle.evaluate(button => getComputedStyle(button).outlineStyle), "solid");
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER header can Break while the Continue completion is delayed", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { followExecution: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                const toggle = workspace.locator("#btn-execution-toggle");
                await workspace.waitForFunction(() => !document.getElementById("btn-execution-toggle").disabled);
                await workspace.locator("#btn-disassembly-follow").evaluate(button => button.click());
                await workspace.locator("#btn-memory-close").click();
                await workspace.evaluate(() => window.knTestHoldExecution = true);
                await toggle.click();
                await workspace.waitForFunction(() => typeof window.knTestReleaseExecution === "function" &&
                    !document.getElementById("btn-execution-toggle").disabled &&
                    document.getElementById("btn-execution-toggle").dataset.action === "break");
                assert.equal(await workspace.locator("#btn-cancel").isDisabled(), false);
                await toggle.click();
                await workspace.waitForFunction(() => document.getElementById("status").textContent.includes("exec break"));
                assert.equal(await toggle.isDisabled(), true, "Continue still owns the pending worker receipt");
                await workspace.evaluate(() => window.knTestReleaseExecution());
                await workspace.waitForFunction(() => !document.getElementById("btn-execution-toggle").disabled &&
                    document.getElementById("btn-execution-toggle").dataset.action === "continue");
                assert.ok((await workspace.locator("#status").textContent()).includes("exec break"));
                assert.equal(await workspace.locator("#memory").isVisible(), false);
                assert.deepEqual(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["debuggerAction", "breakExecution", "interrupt"].includes(item.method)).map(item => item.method)),
                    ["debuggerAction", "breakExecution"]);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER breakpoint notification opens Event with addresses and conditions without stealing focus", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                const lastEvent = { kind: "LastEvent", type: "0x0000000000000001", id: "7", breakpointId: "7",
                    address: "0xffff800000004000", description: "Breakpoint 7 hit", processId: "0", threadId: "2" };
                await workspace.addInitScript(fixtureInit, { eventBreakpoints: true, lastEvent, breakpointSequence: "0", breakpoints: [
                    { kind: "Breakpoint", id: "7", enabled: true, address: "0xffff800000004000", expression: "driver!Callback",
                        trigger: "Execute", condition: "@rax == 0 && @rcx != 0", command: ".echo hit", passCount: "3", matchThreadId: "2" },
                    { kind: "Breakpoint", id: "9", enabled: false, address: "0xffff800000005000", expression: "",
                        trigger: "Read / Write (8 bytes)", condition: "", command: "", passCount: "1", matchThreadId: null },
                    { kind: "Breakpoint", id: "12", enabled: true, address: null, deferred: true, expression: "missing!Function",
                        trigger: "Execute", condition: null, conditionStatus: "Unavailable from debugger data model", command: "" }
                ] });
                await workspace.setViewportSize({ width: 1440, height: 900 });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                assert.equal(await workspace.locator("#breakpoint-toast").isVisible(), false, "Initial status is a baseline");
                await workspace.locator("#prompt").fill("db unfinished");
                await workspace.evaluate(() =>
                {
                    window.knTestBreak("0xffff800000004000");
                    window.knTestBreakpointSequence = "1";
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.locator("#breakpoint-toast").waitFor({ state: "visible" });
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "prompt");
                assert.equal(await workspace.locator("#prompt").inputValue(), "db unfinished");
                assert.equal(await workspace.locator("#breakpoint-toast-title").textContent(), "Breakpoint #7 hit");
                const box = await workspace.locator("#breakpoint-toast").boundingBox();
                assert.ok(box && box.x + box.width <= 1440 && box.x > 1000 && box.y > 600 && box.y + box.height <= 900);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "breakpoint-hit-toast.png") });
                }
                await workspace.locator("#btn-breakpoint-event").click();
                await workspace.waitForFunction(() => document.getElementById("result-title").textContent === "event" &&
                    document.querySelectorAll("#result-rows [role='row']").length === 3);
                assert.equal(await workspace.locator("#btn-event").getAttribute("aria-pressed"), "true");
                assert.equal(await workspace.locator("#breakpoint-toast").isVisible(), false);
                assert.equal(await workspace.locator("#prompt").inputValue(), "db unfinished");
                assert.match(await workspace.locator("#event-summary").textContent(), /Breakpoint 7 hit/);
                const rows = await workspace.locator("#result-rows").textContent();
                for (const value of ["0xffff800000004000", "@rax == 0 && @rcx != 0", "Read / Write (8 bytes)", "None",
                    "Deferred (see expression)", "missing!Function", "Unavailable (see Row details)"])
                {
                    assert.ok(rows.includes(value), "Missing breakpoint setting: " + value);
                }
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "event-breakpoint-settings.png") });
                }
                await workspace.evaluate(() => document.getElementById("btn-refresh-status").click());
                assert.equal(await workspace.locator("#breakpoint-toast").isVisible(), false);
                await workspace.setViewportSize({ width: 360, height: 640 });
                await workspace.evaluate(() =>
                {
                    window.knTestBreak("0xffff800000004000");
                    window.knTestBreakpointSequence = "2";
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.locator("#breakpoint-toast").waitFor({ state: "visible" });
                for (const id of ["breakpoint-toast", "btn-breakpoint-event", "btn-breakpoint-toast-dismiss"])
                {
                    const bounds = await workspace.locator("#" + id).boundingBox();
                    assert.ok(bounds && bounds.x >= 0 && bounds.y >= 0 && bounds.x + bounds.width <= 360 && bounds.y + bounds.height <= 640);
                }
                await workspace.locator("#btn-breakpoint-toast-dismiss").focus();
                await workspace.keyboard.press("Enter");
                assert.equal(await workspace.locator("#breakpoint-toast").isVisible(), false);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER breakpoint notifications require a live observer and recover without replay", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                const lastEvent = { kind: "LastEvent", type: "0x1", breakpointId: "7",
                    address: "0xffff800000004000", description: "Breakpoint 7 hit" };
                await workspace.addInitScript(fixtureInit, { lastEvent, breakpointSequence: "10" });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                const status = async (sequence, image) =>
                {
                    await workspace.evaluate(({ sequence, image }) =>
                    {
                        window.knTestBreakpointSequence = sequence;
                        window.knTestCurrentProcess.image = image;
                        window.knTestBreak("0xffff800000004000");
                        document.getElementById("btn-refresh-status").click();
                    }, { sequence, image });
                    await workspace.waitForFunction(expected => document.getElementById("current-process-image").textContent === expected, image);
                };
                await status(null, "ObserverUnavailable");
                assert.equal(await workspace.locator("#breakpoint-toast").isVisible(), false);
                await status(null, "CommandInvalidated");
                assert.equal(await workspace.locator("#breakpoint-toast").isVisible(), false);
                await status("11", "ObserverRecovered");
                assert.equal(await workspace.locator("#breakpoint-toast").isVisible(), false);
                await status("12", "NewObservedHit");
                assert.equal(await workspace.locator("#breakpoint-toast").isVisible(), true);
                assert.equal(await workspace.locator("#breakpoint-toast-title").textContent(), "Breakpoint #7 hit");
                await workspace.locator("#btn-breakpoint-toast-dismiss").focus();
                await status(undefined, "ObserverLostAgain");
                assert.equal(await workspace.locator("#breakpoint-toast").isVisible(), false);
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-refresh-status");
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER breakpoint stops reveal Disassembly and stepping follows IP without changing drafts or Results", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { followExecution: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#prompt").fill("unsent command");
                await workspace.locator("#btn-memory-close").click();
                await workspace.evaluate(() =>
                {
                    window.knTestStopped = false;
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => document.getElementById("prompt").disabled);
                await workspace.evaluate(() =>
                {
                    window.knTestBreak("0xffff800000002000");
                    document.getElementById("btn-refresh-status").click();
                });
                const currentIp = async address => workspace.waitForFunction(expected =>
                    document.querySelector("#disassembly-rows .current-ip")?.textContent.includes(expected) &&
                    !document.getElementById("btn-debug-over").disabled, address);
                await currentIp("0xffff800000002000");
                assert.equal(await workspace.locator("#disassembly-view").isVisible(), true);
                assert.equal(await workspace.locator("#prompt").inputValue(), "unsent command");
                assert.equal(await workspace.locator("#result-title").textContent(), "Debugger workspace");
                await workspace.locator("#disassembly-grid").focus();
                await workspace.keyboard.press("F10");
                await currentIp("0xffff800000002001");
                await workspace.keyboard.press("F11");
                await currentIp("0xffff800000002002");
                assert.deepEqual(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "debuggerAction")
                    .map(item => item.params.operation)), ["step-over", "step-into"]);
                await workspace.locator("#btn-debug-continue").click();
                await workspace.waitForFunction(() => document.getElementById("prompt").disabled && document.getElementById("btn-debug-over").disabled);
                await workspace.evaluate(() =>
                {
                    window.knTestBreak("0xffff800000003000");
                    document.getElementById("btn-refresh-status").click();
                });
                await currentIp("0xffff800000003000");
                assert.equal(await workspace.locator("#workspace-feedback").isHidden(), true);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "follow-ip-after-steps.png") });
                }
                await workspace.setViewportSize({ width: 360, height: 720 });
                await workspace.waitForFunction(() => document.getElementById("memory").getBoundingClientRect().width <= window.innerWidth);
                for (const id of ["btn-disassembly-follow", "btn-debug-continue", "btn-debug-over", "btn-debug-into"])
                {
                    const box = await workspace.locator("#" + id).boundingBox();
                    assert.ok(box && box.x >= 0 && box.x + box.width <= 360, id + " overflows the narrow drawer: " + JSON.stringify(box));
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER manual code browsing pauses Follow IP and the toggle resumes at the current stop", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { followExecution: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#tab-disassembly").click();
                await workspace.locator("#disassembly-address").fill("0xffff800000006000");
                await workspace.locator("#btn-disassembly-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .disassembly-row").length === 32 &&
                    document.getElementById("btn-cancel").disabled);
                assert.equal(await workspace.locator("#btn-disassembly-follow").getAttribute("aria-pressed"), "false");
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "disassemblyRead").length);
                await workspace.evaluate(() =>
                {
                    window.knTestBreak("0xffff800000007000");
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                assert.equal(await workspace.locator("#disassembly-address").inputValue(), "0xffff800000006000");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "disassemblyRead").length), reads);
                await workspace.locator("#btn-disassembly-follow").click();
                await workspace.waitForFunction(() => document.querySelector("#disassembly-rows .current-ip")?.textContent.includes("0xffff800000007000") &&
                    document.getElementById("btn-cancel").disabled);
                assert.equal(await workspace.locator("#btn-disassembly-follow").getAttribute("aria-pressed"), "true");
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER forwarded execution follows the stop across target generation invalidation", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.addInitScript(fixtureInit, { followExecution: true });
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#prompt").fill("g");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelector("#disassembly-rows .current-ip")?.textContent.includes("0xffff800000003000") &&
                    !document.getElementById("prompt").disabled);
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "disassemblyRead"));
                assert.equal(reads.length, 1);
                assert.equal(reads[0].params.expectedStamp.targetGeneration, "2");
                assert.equal(reads[0].params.expectedStamp.stopEpoch, "2");
                assert.equal(await workspace.locator("#tab-disassembly").getAttribute("aria-selected"), "true");
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER late execution receipts preserve newer stopped running and Busy status", async () =>
        {
            for (const mode of ["stopped", "running", "Busy"])
            {
                const workspace = await context.newPage();
                workspace.on("pageerror", error => errors.push(error.message));
                try
                {
                    await workspace.addInitScript(fixtureInit, { followExecution: true });
                    await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                    await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                    await workspace.locator("#tab-disassembly").click();
                    await workspace.locator("#btn-disassembly-ip").click();
                    await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .disassembly-row").length === 32 &&
                        !document.getElementById("prompt").disabled);
                    const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "disassemblyRead").length);
                    await workspace.evaluate(() =>
                    {
                        window.knTestHoldExecution = true;
                    });
                    await workspace.locator("#btn-debug-over").click();
                    await workspace.waitForFunction(() => typeof window.knTestReleaseExecution === "function");
                    const expected = await workspace.evaluate(mode =>
                    {
                        const target = window.knTestBreak("0xffff800000003000");
                        window.knTestStopped = mode !== "running";
                        window.knTestBusy = mode === "Busy";
                        document.getElementById("btn-refresh-status").click();
                        return target;
                    }, mode);
                    if (mode !== "stopped")
                    {
                        await workspace.waitForFunction(mode => document.getElementById("status").textContent.includes(
                            mode === "Busy" ? "debugger busy" : "exec go"), mode);
                    }
                    await workspace.evaluate(() => window.knTestReleaseExecution());
                    if (mode === "stopped")
                    {
                        await workspace.waitForFunction(() => document.querySelector("#disassembly-rows .current-ip")?.textContent.includes("0xffff800000003000") &&
                            !document.getElementById("prompt").disabled);
                    }
                    else
                    {
                        await workspace.waitForFunction(() => document.getElementById("btn-cancel").disabled &&
                            document.getElementById("prompt").disabled && document.getElementById("btn-debug-over").disabled);
                    }
                    const requests = await workspace.evaluate(() => window.knTestRequests);
                    const laterReads = requests.filter(item => item.method === "disassemblyRead").slice(reads);
                    assert.equal(laterReads.length, mode === "stopped" ? 1 : 0, mode);
                    for (const read of laterReads)
                    {
                        assert.deepEqual(read.params.expectedStamp, expected, mode);
                    }
                    assert.equal(requests.filter(item => item.method === "debuggerAction").length, 1, mode);
                }
                finally
                {
                    await workspace.close();
                }
            }
        });
        await check("T-UI-BROWSER inspection address menus cross-open retained rows in docked and floating panels", async () =>
        {
            for (const detached of [false, true])
            {
                const { local, workspace } = await floatingWorkspace();
                try
                {
                    await workspace.locator("#tab-memory-view").click();
                    await workspace.locator("#memory-size").selectOption("64");
                    await workspace.locator("#memory-address").fill("nt!Example");
                    await workspace.locator("#memory-address").press("Enter");
                    await workspace.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length === 4 &&
                        document.getElementById("btn-cancel").disabled);
                    const memory = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "memoryRead"));
                    await workspace.locator("#prompt").fill("code-fixture");
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 3 &&
                        document.getElementById("btn-cancel").disabled);
                    await workspace.locator(".result-row").nth(1).click();
                    const detail = await workspace.locator("#result-detail").textContent();
                    const panel = detached ? await detachInspection(workspace) : workspace;
                    const address = panel.locator("#memory-rows .memory-row").nth(1).getByRole("gridcell").first();
                    await address.focus();
                    await address.press("Shift+F10");
                    assert.equal(await panel.locator("#cell-open-memory").isVisible(), false);
                    await panel.locator("#cell-copy-menu").press("End");
                    await panel.locator("#cell-open-disassembly").press("Enter");
                    await panel.waitForFunction(() => document.getElementById("disassembly-address").value === "0xffff800000001010" &&
                        document.querySelectorAll("#disassembly-rows .disassembly-row").length === 32);
                    const decode = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "disassemblyRead"));
                    assert.equal(decode.params.source.resultId, "memory-" + memory.requestId);
                    assert.equal(decode.params.source.index, "1");
                    assert.deepEqual(decode.params.source.path, ["address"]);
                    assert.equal(await panel.locator("#btn-disassembly-follow").getAttribute("aria-pressed"), "false");
                    const instruction = panel.locator("#disassembly-rows .disassembly-row").nth(2).getByRole("gridcell").nth(1);
                    const selected = await instruction.textContent();
                    await instruction.click({ button: "right" });
                    assert.equal(await panel.locator("#cell-open-disassembly").isVisible(), false);
                    if (evidence)
                    {
                        await panel.screenshot({ path: path.join(evidence, "inspection-cross-menu-" + (detached ? "floating" : "docked") + ".png") });
                    }
                    await panel.locator("#cell-open-memory").click();
                    await panel.waitForFunction(selected => document.getElementById("memory-address").value === selected &&
                        document.querySelectorAll("#memory-rows .memory-row").length === 4, selected);
                    const read = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "memoryRead"));
                    assert.equal(read.params.source.resultId, "disassembly-" + decode.requestId);
                    assert.equal(read.params.source.index, "2");
                    assert.deepEqual(read.params.source.path, ["address"]);
                    assert.equal(read.params.space, "virtual");
                    assert.equal(await workspace.locator("#result-title").textContent(), "code-fixture");
                    assert.equal(await workspace.locator("#result-detail").textContent(), detail);
                    await panel.locator("#memory-rows .memory-row").first().getByRole("gridcell").nth(1).click({ button: "right" });
                    assert.equal(await panel.locator("#cell-open-memory").isVisible(), false);
                    assert.equal(await panel.locator("#cell-open-disassembly").isVisible(), false);
                }
                finally
                {
                    await local.close();
                }
            }
        });
        await check("T-UI-BROWSER inspection cross-navigation uses captured spaces and history despite edited address drafts", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.locator("#tab-memory-view").click();
                await workspace.locator("#memory-size").selectOption("64");
                await workspace.locator("#memory-space").selectOption("physical");
                await workspace.locator("#memory-address").fill("0");
                await workspace.locator("#memory-address").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length === 4 &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#memory-space").selectOption("virtual");
                await workspace.locator("#memory-address").fill("nt!Example");
                await workspace.locator("#memory-rows .memory-row").first().getByRole("gridcell").first().click({ button: "right" });
                assert.equal(await workspace.locator("#cell-open-disassembly").isDisabled(), true);
                await workspace.locator("#cell-copy-menu").press("Escape");
                await workspace.locator("#btn-memory-read").click();
                await workspace.waitForFunction(() => document.getElementById("memory-address").value === "0xffff800000001000" &&
                    document.getElementById("btn-cancel").disabled);
                const capture = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "memoryRead"));
                await workspace.locator("#memory-format").selectOption("8");
                await workspace.locator("#memory-space").selectOption("physical");
                await workspace.locator("#memory-address").fill("0xdeadbeef");
                await workspace.locator("#memory-rows .memory-row").nth(2).getByRole("gridcell").first().click({ button: "right" });
                await workspace.locator("#cell-open-disassembly").click();
                await workspace.waitForFunction(() => document.getElementById("disassembly-address").value === "0xffff800000001020" &&
                    document.getElementById("btn-cancel").disabled);
                const original = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "disassemblyRead"));
                assert.equal(original.params.source.resultId, "memory-" + capture.requestId);
                assert.equal(original.params.source.index, "2");
                await workspace.locator("#btn-disassembly-next").click();
                await workspace.waitForFunction(() => document.getElementById("disassembly-address").value !== "0xffff800000001020" &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#btn-disassembly-back").click();
                await workspace.locator("#disassembly-address").fill("nt!OtherDraft");
                const instruction = workspace.locator("#disassembly-rows .disassembly-row").nth(3).getByRole("gridcell").nth(1);
                const address = await instruction.textContent();
                await instruction.press("Shift+F10");
                await workspace.locator("#cell-open-memory").click();
                await workspace.waitForFunction(address => document.getElementById("memory-address").value === address &&
                    document.getElementById("btn-cancel").disabled, address);
                const read = await workspace.evaluate(() => window.knTestRequests.findLast(item => item.method === "memoryRead"));
                assert.equal(read.params.source.resultId, "disassembly-" + original.requestId);
                assert.equal(read.params.source.index, "3");
                assert.equal(read.params.expression, address);
                assert.equal(read.params.space, "virtual");
                assert.equal(await workspace.locator("#memory-space").inputValue(), "virtual");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "debuggerAction")), false);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER physical Memory addresses retain copy actions with Disassembly disabled", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.locator("#tab-memory-view").click();
                await workspace.locator("#memory-space").selectOption("physical");
                await workspace.locator("#memory-address").fill("0");
                await workspace.locator("#memory-address").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length > 0 &&
                    document.getElementById("btn-cancel").disabled);
                const address = workspace.locator("#memory-rows .memory-row").first().getByRole("gridcell").first();
                await address.click({ button: "right" });
                assert.equal(await workspace.locator("#cell-copy-value").isEnabled(), true);
                assert.equal(await workspace.locator("#cell-open-disassembly").isDisabled(), true);
                assert.match(await workspace.locator("#cell-open-disassembly").getAttribute("title"), /Physical addresses/);
                await workspace.locator("#cell-copy-menu").press("Escape");
                assert.equal(await address.evaluate(node => document.activeElement === node), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "disassemblyRead")), false);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER generic address menus bind sorted fields and keep physical zero out of Disassembly", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.setViewportSize({ width: 1920, height: 1050 });
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#prompt").fill("address-menus");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 2 && document.getElementById("btn-cancel").disabled);
                await workspace.locator('#table-head [data-sort-key=\'["base"]\']').click();
                const base = workspace.locator(".result-row").first().getByText("0xffff800000001000", { exact: true });
                await base.click({ button: "right" });
                await workspace.locator("#cell-copy-menu").press("End");
                await workspace.locator("#cell-open-disassembly").press("Enter");
                await workspace.waitForFunction(() => document.getElementById("disassembly-address").value === "0xffff800000001000" &&
                    document.getElementById("btn-cancel").disabled);
                const read = await workspace.evaluate(() => window.knTestRequests.find(item => item.method === "disassemblyRead"));
                assert.equal(read.params.source.index, "1");
                assert.deepEqual(read.params.source.path, ["base"]);
                assert.equal(await workspace.locator("#result-title").textContent(), "address-menus");
                await workspace.locator("#prompt").fill("mixed-address-menu");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 1 && document.getElementById("btn-cancel").disabled);
                await workspace.locator(".result-row").getByText("0x0000000000000000", { exact: true }).click({ button: "right" });
                assert.equal(await workspace.locator("#cell-open-disassembly").isDisabled(), true);
                assert.equal(await workspace.locator("#cell-open-memory").isEnabled(), true);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "physical-address-menu.png") });
                }
                await workspace.locator("#cell-open-memory").click();
                await workspace.waitForFunction(() => document.getElementById("memory-address").value === "0x0000000000000000" &&
                    document.getElementById("btn-cancel").disabled);
                assert.equal(await workspace.locator("#memory-space").inputValue(), "physical");
                const request = await workspace.evaluate(() => window.knTestRequests.find(item => item.method === "memoryRead"));
                assert.deepEqual(request.params.source.path, ["pa"]);
                assert.equal(request.params.space, "physical");
                await workspace.locator(".result-row").getByText("0xffff800000008000", { exact: true }).click({ button: "right" });
                assert.equal(await workspace.locator("#cell-open-memory").isVisible(), false);
                assert.equal(await workspace.locator("#cell-open-disassembly").isVisible(), false);
                assert.equal(JSON.parse(await workspace.locator("#result-detail").textContent()).pa, "0x0000000000000000");
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER Inspector and menus share process and copy-only address restrictions", async () =>
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            try
            {
                await workspace.setViewportSize({ width: 1920, height: 1050 });
                await workspace.addInitScript(fixtureInit);
                await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                for (const command of ["foreign-address-menu", "copy-only-address-menu"])
                {
                    await workspace.locator("#prompt").fill(command);
                    await workspace.locator("#prompt").press("Enter");
                    await workspace.waitForFunction(command => document.getElementById("result-title").textContent === command &&
                        document.querySelectorAll(".result-row").length === 1 && document.getElementById("btn-cancel").disabled, command);
                    const cell = workspace.getByRole("gridcell", { name: "Copy Address, row 1", exact: true });
                    await cell.click({ button: "right" });
                    assert.equal(await workspace.locator("#cell-open-disassembly").isVisible(), command === "foreign-address-menu");
                    if (command === "foreign-address-menu")
                    {
                        assert.equal(await workspace.locator("#cell-open-disassembly").isDisabled(), true);
                        assert.match(await workspace.locator("#cell-open-memory").getAttribute("title"), /owning process/);
                    }
                    await workspace.locator("#cell-copy-menu").press("Escape");
                    for (const id of ["btn-navigate", "btn-disassemble", "btn-source"])
                    {
                        assert.equal(await workspace.locator("#" + id).isDisabled(), true, command + " " + id);
                    }
                }
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    ["memoryRead", "disassemblyRead", "navigateResult"].includes(item.method))), false);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "restricted-address-inspector.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        async function callbackWorkspace()
        {
            const workspace = await context.newPage();
            workspace.on("pageerror", error => errors.push(error.message));
            await workspace.setViewportSize({ width: 1920, height: 1050 });
            await workspace.addInitScript(fixtureInit, { callbackNavigation: true });
            await workspace.goto(`http://127.0.0.1:${server.address().port}/`);
            await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
            await workspace.locator("#prompt").fill("!callbacks");
            await workspace.locator("#prompt").press("Enter");
            await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 4 &&
                document.getElementById("btn-cancel").disabled);
            return workspace;
        }
        await check("T-UI-BROWSER callback Pre Post selection opens distinct Memory and Disassembly ranges without replacing Results", async () =>
        {
            const workspace = await callbackWorkspace();
            try
            {
                await workspace.locator(".result-row").nth(1).click();
                await workspace.locator("#callback-address").selectOption("postRoutine");
                await workspace.locator("#btn-open-memory").click();
                await workspace.waitForFunction(() => document.getElementById("memory-address").value === "0xffff800000004000" &&
                    document.querySelectorAll("#memory-rows .memory-row").length === 16 && document.getElementById("btn-cancel").disabled);
                await workspace.locator("#callback-address").selectOption("preRoutine");
                await workspace.locator("#btn-disassemble").click();
                await workspace.waitForFunction(() => document.getElementById("disassembly-address").value === "0xffff800000003000" &&
                    document.querySelectorAll("#disassembly-rows .disassembly-row").length === 32 && document.getElementById("btn-cancel").disabled);
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => ["memoryRead", "disassemblyRead"].includes(item.method)));
                assert.deepEqual(reads.map(item => [item.method, item.params.source.index, item.params.source.field]),
                    [["memoryRead", "1", "postRoutine"], ["disassemblyRead", "1", "preRoutine"]]);
                assert.equal(await workspace.locator("#result-title").textContent(), "!callbacks");
                assert.match(await workspace.locator("#result-detail").textContent(), /Object.Process/);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "callback-address-inspector.png") });
                }
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER sorted callback address menus support keyboard opening and reject null or stale callbacks", async () =>
        {
            const workspace = await callbackWorkspace();
            try
            {
                await workspace.locator('#table-head [data-sort-key=\'["preRoutine"]\']').click();
                const post = workspace.locator(".result-row").first().locator('[aria-colindex="4"]');
                await post.click({ button: "right" });
                await workspace.locator("#cell-copy-menu").press("End");
                assert.equal(await workspace.locator("#cell-open-disassembly").evaluate(node => document.activeElement === node), true);
                await workspace.locator("#cell-open-disassembly").press("Enter");
                await workspace.waitForFunction(() => document.getElementById("disassembly-address").value === "0xffff800000002000" &&
                    document.getElementById("btn-cancel").disabled);
                const read = await workspace.evaluate(() => window.knTestRequests.find(item => item.method === "disassemblyRead"));
                assert.equal(read.params.source.index, "2");
                assert.equal(read.params.source.field, "postRoutine");
                await workspace.locator(".result-row").nth(2).locator('[aria-colindex="4"]').click({ button: "right" });
                assert.equal(await workspace.locator("#cell-open-memory").isDisabled(), true);
                assert.equal(await workspace.locator("#cell-open-disassembly").isDisabled(), true);
                await workspace.locator("#cell-copy-menu").press("Escape");
                await post.click({ button: "right" });
                await workspace.evaluate(() =>
                {
                    window.knTestChangeContext();
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => document.getElementById("cell-open-memory").disabled);
                assert.equal(await workspace.locator("#cell-open-disassembly").isDisabled(), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "disassemblyRead").length), 1);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER callback menu keeps keyboard focus when its current navigation action becomes unavailable", async () =>
        {
            for (const mode of ["context", "running", "busy"])
            {
                const workspace = await callbackWorkspace();
                try
                {
                    const post = workspace.locator(".result-row").nth(1).locator('[aria-colindex="4"]');
                    await post.click({ button: "right" });
                    await workspace.locator("#cell-copy-menu").press("End");
                    assert.equal(await workspace.locator("#cell-open-disassembly").evaluate(node => document.activeElement === node), true);
                    await workspace.evaluate(mode =>
                    {
                        if (mode === "context")
                        {
                            window.knTestChangeContext();
                        }
                        else if (mode === "running")
                        {
                            window.knTestStopped = false;
                        }
                        else
                        {
                            window.knTestBusy = true;
                        }
                        document.getElementById("btn-refresh-status").click();
                    }, mode);
                    await workspace.waitForFunction(() => document.getElementById("cell-open-disassembly").disabled);
                    const focus = await workspace.evaluate(() => ({ active: document.activeElement.id,
                        menuHidden: document.getElementById("cell-copy-menu").classList.contains("hidden"),
                        reads: window.knTestRequests.filter(item => /^(memoryRead|disassemblyRead)$/.test(item.method)).length }));
                    if (evidence)
                    {
                        fs.writeFileSync(path.join(evidence, "callback-menu-focus-" + mode + ".json"), JSON.stringify(focus, null, 2));
                        await workspace.screenshot({ path: path.join(evidence, "callback-menu-focus-" + mode + ".png") });
                    }
                    assert.equal(focus.reads, 0);
                    await workspace.keyboard.press("End");
                    assert.equal(await workspace.locator("#cell-copy-row").evaluate(node => document.activeElement === node), true,
                        mode + " prevented keyboard navigation to an enabled menu action");
                    await workspace.keyboard.press("Escape");
                    assert.equal(await workspace.locator("#cell-copy-menu").isVisible(), false);
                    assert.equal(await post.evaluate(node => document.activeElement === node), true);
                    assert.equal(focus.active, "cell-copy-value", mode + " retained focus on a disabled navigation action");
                }
                finally
                {
                    await workspace.close();
                }
            }
        });
        await check("T-UI-BROWSER callback menu opens the same detached Memory view with the selected source field", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ callbackNavigation: true });
            try
            {
                await workspace.locator("#prompt").fill("!callbacks");
                await workspace.locator("#prompt").press("Enter");
                await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 4 && document.getElementById("btn-cancel").disabled);
                const popup = await detachInspection(workspace);
                await workspace.locator(".result-row").nth(1).locator('[aria-colindex="4"]').click({ button: "right" });
                await workspace.locator("#cell-open-memory").click();
                await popup.waitForFunction(() => document.getElementById("memory-address").value === "0xffff800000004000" &&
                    document.querySelectorAll("#memory-rows .memory-row").length === 16);
                const source = await workspace.evaluate(() => window.knTestRequests.find(item => item.method === "memoryRead").params.source);
                assert.equal(source.field, "postRoutine");
                assert.equal(source.index, "1");
                assert.equal(await workspace.locator("#result-title").textContent(), "!callbacks");
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER Inspector opens code in the right tab using the sorted row's immutable source", async () =>
        {
            const workspace = await inspectionWorkspace();
            try
            {
                await workspace.locator("#btn-memory-close").click();
                await workspace.locator("#result-open-toggle").click();
                await workspace.locator("#result-id-input").fill("code-fixture");
                await workspace.locator("#btn-result-load").click();
                await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 3);
                const address = workspace.locator('#table-head [data-sort-key=\'["address"]\']');
                await address.click();
                await address.click();
                await workspace.locator(".result-row").first().click();
                const selected = await workspace.locator("#result-detail").textContent();
                await workspace.locator("#btn-disassemble").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .disassembly-row").length === 32 &&
                    document.getElementById("btn-cancel").disabled);
                const request = await workspace.evaluate(() => window.knTestRequests.find(item => item.method === "disassemblyRead"));
                assert.equal(request.params.source.resultId, "code-fixture");
                assert.equal(request.params.source.index, "2");
                assert.equal(request.params.source.action, "disassemble");
                assert.equal(await workspace.locator("#disassembly-address").inputValue(), "0xffff800000001008");
                assert.equal(await workspace.locator("#result-title").textContent(), "code-fixture");
                assert.equal(await workspace.locator("#result-detail").textContent(), selected);
                assert.equal(await workspace.locator("#tab-disassembly").getAttribute("aria-selected"), "true");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item =>
                    item.method === "navigateResult" || (item.method === "execute" && item.params.command !== "breakpoints"))), false);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    item.method === "execute" && item.params.command === "breakpoints").length), 1);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER Disassembly shares panel resizing, narrow layout and saved tab without automatic reads", async () =>
        {
            const workspace = await inspectionWorkspace();
            try
            {
                await workspace.locator("#btn-disassembly-read").click();
                await workspace.waitForFunction(() => document.querySelectorAll("#disassembly-rows .disassembly-row").length === 32 &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#memory-splitter").press("End");
                const width = await workspace.locator("#memory-splitter").getAttribute("aria-valuenow");
                for (const viewport of [{ width: 600, height: 520 }, { width: 360, height: 480 }])
                {
                    await workspace.setViewportSize(viewport);
                    for (const id of ["tab-memory-view", "tab-disassembly", "btn-memory-close", "disassembly-address",
                        "disassembly-count", "btn-disassembly-read", "btn-disassembly-next"])
                    {
                        const node = workspace.locator("#" + id);
                        await node.scrollIntoViewIfNeeded();
                        const box = await node.boundingBox();
                        assert.ok(box.x >= 0 && box.y >= 0 && box.x + box.width <= viewport.width + 1 &&
                            box.y + box.height <= viewport.height + 1, id + " left the viewport: " + JSON.stringify(box));
                    }
                    await workspace.locator("#disassembly-grid").focus();
                    await workspace.locator("#disassembly-grid").press("End");
                    assert.match(await workspace.locator("#disassembly-position").textContent(), /0xffff80000000107c/);
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "disassembly-panel-" + viewport.width + ".png") });
                    }
                }
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "disassemblyRead").length);
                await workspace.keyboard.press("Control+m");
                assert.equal(await workspace.locator("#memory").isVisible(), false);
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-memory-panel");
                await workspace.keyboard.press("Control+m");
                assert.equal(await workspace.locator("#tab-disassembly").getAttribute("aria-selected"), "true");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "disassemblyRead").length), reads);
                await workspace.setViewportSize({ width: 1920, height: 1050 });
                await workspace.waitForFunction(width => document.getElementById("memory-splitter").getAttribute("aria-valuenow") === width, width);
                await workspace.reload();
                await workspace.waitForFunction(() => !document.getElementById("btn-disassembly-read").disabled);
                assert.equal(await workspace.locator("#tab-disassembly").getAttribute("aria-selected"), "true");
                assert.equal(await workspace.locator("#memory").isVisible(), true);
                assert.equal(await workspace.locator("#disassembly-rows .disassembly-row").count(), 0);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "disassemblyRead" || item.method === "memoryRead")), false);
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER choosing shorter process details refills the expanded process viewport", async () =>
        {
            const workspace = await inspectionWorkspace();
            try
            {
                await workspace.setViewportSize({ width: 1920, height: 1800 });
                await workspace.evaluate(() =>
                {
                    window.knTestLargeProcessDetails = true;
                });
                await showProcesses(workspace);
                await workspace.waitForFunction(() => document.getElementById("btn-cancel").disabled);
                await workspace.locator("#btn-process-refresh").click();
                await workspace.waitForFunction(() => document.getElementById("process-summary").textContent.includes("257 collected") &&
                    document.getElementById("btn-cancel").disabled);
                await workspace.locator("#process-grid").press("Home");
                const before = await workspace.evaluate(() => ({ height: document.getElementById("process-view").clientHeight,
                    rows: document.querySelectorAll(".process-row").length }));
                await workspace.getByRole("gridcell", { name: "Copy PID for PID 4", exact: true }).click();
                const after = await workspace.evaluate(() => ({ height: document.getElementById("process-view").clientHeight,
                    rows: document.querySelectorAll(".process-row").length,
                    needed: Math.ceil(document.getElementById("process-view").clientHeight / 28) }));
                assert.ok(before.height >= 600 && after.height > before.height + 100, JSON.stringify({ before, after }));
                assert.ok(after.rows >= after.needed && after.rows <= 128, JSON.stringify({ before, after }));
                assert.equal(await workspace.evaluate(() => document.activeElement.getAttribute("aria-label")), "Copy PID for PID 4");
                await workspace.keyboard.press("Shift+F10");
                assert.equal(await workspace.locator("#cell-copy-menu").isVisible(), true);
                await workspace.keyboard.press("Escape");
                assert.equal(await workspace.evaluate(() => document.activeElement.getAttribute("aria-label")), "Copy PID for PID 4");
            }
            finally
            {
                await workspace.close();
            }
        });
        await check("T-UI-BROWSER visibility fixture locks every retained target action until fresh status", async () =>
        {
            const workspace = await inspectionWorkspace();
            try
            {
                await workspace.locator("#result-open-toggle").click();
                await workspace.locator("#result-id-input").fill("code-fixture");
                await workspace.locator("#btn-result-load").click();
                await workspace.waitForFunction(() => document.querySelectorAll(".result-row").length === 3);
                await workspace.locator(".result-row").first().click();
                await showProcesses(workspace);
                await workspace.waitForFunction(() => document.getElementById("process-summary").textContent.includes("257 collected") &&
                    document.getElementById("btn-cancel").disabled && !document.getElementById("prompt").disabled);
                await workspace.locator(".process-row").first().click();
                const actions = ["btn-memory-read", "btn-disassembly-read", "btn-disassembly-ip", "btn-navigate", "btn-disassemble",
                    "btn-process-refresh", "btn-process-details", "btn-process-threads", "btn-process-vad", "btn-process-token", "btn-process-attach"];
                for (const id of actions)
                {
                    assert.equal(await workspace.locator("#" + id).isEnabled(), true, id + " was not available before hiding");
                }
                const selected = await workspace.locator("#result-detail").textContent();
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["execute", "memoryRead", "disassemblyRead", "processAction", "navigateResult"].includes(item.method)).length);
                await workspace.evaluate(() =>
                {
                    let hidden = true;
                    Object.defineProperty(document, "hidden", { configurable: true, get: () => hidden });
                    window.knTestHoldStatus = true;
                    document.dispatchEvent(new Event("visibilitychange"));
                    hidden = false;
                    document.dispatchEvent(new Event("visibilitychange"));
                });
                await workspace.waitForFunction(() => typeof window.knTestReleaseStatus === "function" && document.getElementById("prompt").disabled);
                for (const id of actions)
                {
                    assert.equal(await workspace.locator("#" + id).isEnabled(), false, id + " bypassed the fresh-status wait");
                }
                await workspace.evaluate(ids => ids.forEach(id => document.getElementById(id).dispatchEvent(new MouseEvent("click"))), actions);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["execute", "memoryRead", "disassemblyRead", "processAction", "navigateResult"].includes(item.method)).length), reads);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "workspace-reopen-awaiting-status.png") });
                }
                await workspace.evaluate(() =>
                {
                    window.knTestHoldStatus = false;
                    window.knTestReleaseStatus();
                });
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                for (const id of actions)
                {
                    assert.equal(await workspace.locator("#" + id).isEnabled(), true, id + " did not recover after fresh status");
                }
                assert.equal(await workspace.locator("#result-detail").textContent(), selected);
            }
            finally
            {
                await workspace.close();
            }
        });
        async function detachInspectionView(workspace, view)
        {
            await workspace.locator(view === "memory" ? "#tab-memory-view" : "#tab-" + view).click();
            const opened = workspace.waitForEvent("popup");
            await workspace.locator("#btn-float-" + view).click();
            const popup = await opened;
            popup.setDefaultTimeout(8000);
            popup.on("pageerror", error => errors.push(error.message));
            await popup.locator("#btn-float-" + view).filter({ hasText: "Dock" }).waitFor();
            return popup;
        }
        await check("T-UI-BROWSER workspace outer spacing follows overlays and floating windows", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ adaptiveLayout: true });
            async function inset(view, selector)
            {
                const bounds = await view.locator(selector).evaluate(node =>
                {
                    const box = node.getBoundingClientRect();
                    return { left: box.left, right: box.right, width: document.documentElement.clientWidth };
                });
                assert.ok(Math.abs(bounds.left - 8) <= 1 && Math.abs(bounds.width - bounds.right - 8) <= 1,
                    selector + " must keep its outer inset");
            }
            try
            {
                for (const viewport of [{ width: 1600, height: 900 }, { width: 900, height: 640 }, { width: 360, height: 360 }])
                {
                    await workspace.setViewportSize(viewport);
                    await inset(workspace, "#root");
                    assert.equal(await workspace.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
                    if (viewport.width === 900)
                    {
                        if (!await workspace.locator("#memory").isVisible())
                        {
                            await workspace.locator("#btn-memory-panel").click();
                        }
                        const edges = await workspace.evaluate(() => ({
                            panel: document.getElementById("memory").getBoundingClientRect().toJSON(),
                            splitter: document.getElementById("memory-splitter").getBoundingClientRect().toJSON(), width: innerWidth
                        }));
                        assert.ok(Math.abs(edges.width - edges.panel.right - 8) <= 1, JSON.stringify(edges));
                        assert.ok(Math.abs(edges.splitter.right - edges.panel.left) <= 1, JSON.stringify(edges));
                        await workspace.locator("#btn-memory-close").click();
                        await workspace.locator("#btn-sidebar").click();
                        assert.equal(Math.round((await workspace.locator("#sidebar").boundingBox()).x), 8);
                        await workspace.locator("#btn-library-close").click();
                    }
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "workspace-inset-" + viewport.width + ".png") });
                    }
                }
                await workspace.setViewportSize({ width: 1600, height: 900 });
                await workspace.locator("#btn-memory-panel").click();
                const memory = await detachInspectionView(workspace, "memory");
                await memory.setViewportSize({ width: 360, height: 360 });
                await inset(memory, "#memory-view");
                assert.equal(await memory.getByRole("button", { name: "Read details", exact: true }).count(), 1);
                await memory.locator("#btn-float-memory").click();
                const group = await detachInspection(workspace);
                await group.setViewportSize({ width: 520, height: 480 });
                await inset(group, "#memory");
                if (evidence)
                {
                    await group.screenshot({ path: path.join(evidence, "inspect-group-inset.png") });
                }
                await group.locator("#btn-inspection-float").click();
                assert.equal(await workspace.locator("#memory").isVisible(), true);
                const labels = await workspace.evaluate(() => document.body.innerText + " " +
                    Array.from(document.querySelectorAll("[title], [aria-label]")).map(node =>
                        (node.getAttribute("title") || "") + " " + (node.getAttribute("aria-label") || "")).join(" "));
                assert.doesNotMatch(labels, /\b(evidence|contract)\b/i);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER P1 memory details stay local across narrow floating and docked views", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ memoryEvidence: true });
            try
            {
                await local.grantPermissions(["clipboard-read", "clipboard-write"]);
                await workspace.locator("#tab-memory-view").click();
                await workspace.locator("#memory-size").selectOption("64");
                await workspace.locator("#btn-memory-read").click();
                await workspace.locator(".memory-unreadable").first().waitFor();
                const copiedCell = workspace.locator("#memory-rows .copyable").first();
                await copiedCell.focus();
                await workspace.keyboard.down("Enter");
                await workspace.keyboard.down("Enter");
                await workspace.keyboard.up("Enter");
                assert.equal(await workspace.locator("#memory-evidence").isVisible(), false,
                    "Holding Enter to copy a cell must not open read details");
                assert.equal(await workspace.evaluate(() => navigator.clipboard.readText()), await copiedCell.textContent());
                const reads = await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["memoryRead", "execute", "processAction"].includes(item.method)).length);
                await workspace.locator(".memory-unreadable").first().click();
                assert.match(await workspace.locator("#memory-evidence-facts").textContent(), /7 read \/ 9 unavailable/);
                assert.match(await workspace.locator("#memory-evidence-ranges").textContent(), /HRESULT 0x0000000080004005/);
                assert.match(await workspace.locator("#memory-evidence-cause").textContent(), /Cause: Unknown/);
                await workspace.locator("#btn-memory-evidence-close").press("Escape");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-memory-evidence");
                await workspace.locator("#memory-grid").press("Enter");
                const captured = await workspace.locator("#memory-rows").textContent();
                const memory = await detachInspectionView(workspace, "memory");
                for (const viewport of [{ width: 360, height: 360 }, { width: 520, height: 480 }])
                {
                    await memory.setViewportSize(viewport);
                    await memory.locator("#btn-memory-evidence-close").scrollIntoViewIfNeeded();
                    assert.equal(await memory.locator("#memory-evidence").evaluate(node => node.scrollWidth <= node.clientWidth + 1), true);
                    await memory.locator("#btn-memory-evidence-close").click();
                    await memory.locator("#btn-memory-evidence").click();
                    await memory.locator("#memory-evidence-cause").scrollIntoViewIfNeeded();
                    assert.equal(await memory.locator("#btn-memory-evidence-close").evaluate(node =>
                    {
                        const box = node.getBoundingClientRect();
                        return document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2) === node;
                    }), true, "Close remains reachable while evidence scrolls");
                    const readingPosition = await memory.locator("#memory-evidence").evaluate(node =>
                    {
                        window.knTestEvidenceNode = document.getElementById("memory-evidence-facts").firstChild;
                        return node.scrollTop;
                    });
                    await workspace.locator("#btn-refresh-status").click();
                    assert.equal(await memory.evaluate(() => window.knTestEvidenceNode ===
                        document.getElementById("memory-evidence-facts").firstChild), true);
                    assert.equal(await memory.locator("#memory-evidence").evaluate(node => node.scrollTop), readingPosition);
                    assert.equal(await memory.locator("#memory-rows").textContent(), captured);
                    if (evidence)
                    {
                        await memory.screenshot({ path: path.join(evidence, "p1-memory-evidence-" + viewport.width + ".png") });
                    }
                }
                await memory.locator("#btn-float-memory").click();
                await workspace.locator("#memory-evidence").waitFor();
                assert.equal(await workspace.locator("#memory-rows").textContent(), captured);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    ["memoryRead", "execute", "processAction"].includes(item.method)).length), reads);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER independent inspection four windows preserve state and native close docks only its view", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.locator("#memory-address").fill("nt!KeBugCheckEx");
                await workspace.evaluate(() =>
                {
                    window.knSavedPanels = ["processes", "memory-view", "disassembly-view", "registers-view"].map(id => document.getElementById(id));
                });
                const panels = {};
                for (const view of ["processes", "memory", "disassembly", "registers"])
                {
                    panels[view] = await detachInspectionView(workspace, view);
                    assert.equal(await panels[view].title(), "KNDbgX - " + view[0].toUpperCase() + view.slice(1));
                }
                await panels.registers.locator("#registers-rows .register-row").waitFor();
                assert.equal(await panels.memory.locator("#memory-address").inputValue(), "nt!KeBugCheckEx");
                assert.equal(await workspace.locator("#btn-inspection-float").isEnabled(), true);
                await workspace.locator("#tab-memory-view").click();
                assert.equal(await panels.registers.locator("#registers-grid").isVisible(), true);
                assert.equal(await workspace.locator("#inspection-detached").isVisible(), true);
                await panels.memory.locator("#memory-address").fill("nt!NtCreateFile+10");
                await panels.processes.locator("#process-filter").fill("process12");
                await panels.registers.locator("#registers-filter").fill("rip");
                if (evidence)
                {
                    await panels.registers.screenshot({ path: path.join(evidence, "independent-registers.png") });
                    await panels.memory.screenshot({ path: path.join(evidence, "independent-memory.png") });
                }
                const token = await panels.memory.evaluate(() => location.hash.split("-").at(-1));
                await workspace.evaluate(token => window.knTestCloseInspectionFrame(token), token);
                await workspace.locator("#memory-address").waitFor();
                assert.equal(await workspace.locator("#memory-address").inputValue(), "nt!NtCreateFile+10");
                assert.equal(panels.registers.isClosed(), false);
                assert.equal(panels.processes.isClosed(), false);
                await workspace.locator("#btn-inspection-dock").click();
                await workspace.waitForFunction(() => window.knSavedPanels.every(node => node.ownerDocument === document));
                assert.equal(await workspace.locator("#process-filter").inputValue(), "process12");
                assert.equal(await workspace.locator("#registers-filter").inputValue(), "rip");
                assert.equal(await workspace.evaluate(() => new Set(window.knSavedPanels).size), 4);
                assert.equal(await workspace.locator("#btn-inspection-float").isEnabled(), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER independent inspection chrome keeps data and controls reachable in compact windows and reports target state", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ registers:
                ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]
                    .map((name, index) => ({ kind: "Register", name, value: "0x" + (0xffff800000001000n + BigInt(index * 16)).toString(16) })) });
            try
            {
                const panels = {};
                for (const view of ["memory", "disassembly", "registers"])
                {
                    const popup = panels[view] = await detachInspectionView(workspace, view);
                    if (view !== "registers")
                    {
                        await popup.locator("#" + view + "-address").fill("sample!Routine");
                        await popup.locator("#btn-" + view + "-read").click();
                    }
                    await popup.locator("#" + view + "-rows > div").first().waitFor();
                    await popup.waitForFunction(() => document.querySelector(".inspection-status-state").textContent === "Stopped");
                    for (const viewport of [{ width: 560, height: 740 }, { width: 1280, height: 900 }, { width: 320, height: 370 }])
                    {
                        await popup.setViewportSize(viewport);
                        const geometry = await popup.evaluate(() =>
                        {
                            const dock = document.querySelector(".inspection-view-tools > button").getBoundingClientRect();
                            const status = document.querySelector(".independent-inspection-status").getBoundingClientRect();
                            return { dockVisible: dock.x >= 0 && dock.right <= innerWidth && dock.y >= 0 && dock.bottom <= innerHeight,
                                statusVisible: status.y >= 0 && status.bottom <= innerHeight,
                                overflow: document.documentElement.scrollWidth > innerWidth };
                        });
                        assert.deepEqual(geometry, { dockVisible: true, statusVisible: true, overflow: false }, view + JSON.stringify(viewport));
                        await popup.locator("#" + view + "-rows > div").first().scrollIntoViewIfNeeded();
                        const cell = await popup.locator("#" + view + "-rows > div").first().boundingBox();
                        const heading = await popup.locator(".inspection-view-tools").boundingBox();
                        const statusTop = (await popup.locator(".independent-inspection-status").boundingBox()).y;
                        assert.ok(cell.y >= heading.y + heading.height && cell.y < statusTop, "The first " + view + " row must remain reachable");
                        if (evidence)
                        {
                            await popup.screenshot({ path: path.join(evidence, "floating-" + view + "-" + viewport.width + ".png") });
                        }
                    }
                    await popup.setViewportSize({ width: 560, height: 740 });
                    await popup.locator(".inspection-view").evaluate(node =>
                    {
                        node.scrollTop = 0;
                    });
                }
                const captured = await panels.memory.locator("#memory-rows").textContent();
                await workspace.evaluate(() =>
                {
                    window.knTestCurrentProcess.image = "VeryLongProcessName".repeat(8) + ".exe";
                    document.getElementById("btn-refresh-status").click();
                });
                await panels.memory.waitForFunction(() => document.querySelector(".inspection-status-process").title.endsWith(".exe"));
                for (const [change, label] of [[{ knTestStopped: false }, "Running"], [{ knTestBusy: true }, "Debugger busy"],
                    [{ knTestBusy: false, knTestStatusError: "ReadFailed" }, "Status unavailable"],
                    [{ knTestStatusError: "", knTestStopped: true }, "Stopped"]])
                {
                    await workspace.evaluate(change =>
                    {
                        Object.assign(window, change);
                        document.getElementById("btn-refresh-status").click();
                    }, change);
                    await panels.memory.waitForFunction(label => document.querySelector(".inspection-status-state").textContent === label, label);
                    assert.equal(await panels.memory.locator("#btn-memory-read").isEnabled(), label === "Stopped");
                    assert.equal(await panels.memory.locator("#memory-rows").textContent(), captured);
                }
                await panels.memory.emulateMedia({ forcedColors: "active", reducedMotion: "reduce" });
                await panels.memory.setViewportSize({ width: 320, height: 370 });
                const dock = panels.memory.locator("#btn-float-memory");
                await dock.focus();
                assert.equal(await dock.evaluate(node => node === document.activeElement), true);
                if (evidence)
                {
                    await panels.memory.screenshot({ path: path.join(evidence, "floating-memory-contrast.png") });
                }
                await panels.memory.keyboard.press("Space");
                await workspace.locator("#memory-grid").waitFor();
                assert.equal(await workspace.locator("#memory-rows").textContent(), captured);
                assert.equal(await workspace.locator(".inspection-view-kicker").first().isVisible(), false);
                assert.equal(panels.registers.isClosed(), false);
                assert.equal(panels.disassembly.isClosed(), false);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER inspection group can float its views and accept guarded drag docking without replacing data", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                const group = await detachInspection(workspace);
                await group.locator("#tab-memory-view").click();
                await group.locator("#memory-address").fill("sample!RetainedDraft");
                await group.locator("#btn-memory-read").click();
                await group.locator("#memory-rows > div").first().waitFor();
                const captured = await group.locator("#memory-rows").textContent();
                const opened = workspace.waitForEvent("popup");
                await group.locator("#btn-float-memory").click();
                const memory = await opened;
                await memory.locator("#btn-float-memory").filter({ hasText: "Dock" }).waitFor();
                const token = await memory.evaluate(() => location.hash.split("-").at(-1));
                const groupToken = await group.evaluate(() => location.hash.split("-").at(-1));
                assert.equal(await group.locator("#btn-inspection-float").isEnabled(), true);
                assert.equal(await memory.locator("#memory-rows").textContent(), captured);
                const message = { token, dragId: "1", phase: "preview", destination: "group", destinationToken: groupToken };
                await workspace.evaluate(message => window.knTestDockDrag(message), message);
                await group.locator(".inspection-dock-group.active").waitFor();
                assert.equal(await workspace.locator(".inspection-dock-main").isVisible(), true);
                if (evidence)
                {
                    await group.screenshot({ path: path.join(evidence, "group-dock-guide.png") });
                }
                await workspace.evaluate(message => window.knTestDockDrag({ ...message, phase: "cancel" }), message);
                assert.equal(await group.locator(".inspection-dock-guide").count(), 0);
                await workspace.evaluate(message => window.knTestDockDrag(message), message);
                await workspace.evaluate(message => window.knTestDockDrag({ ...message, phase: "drop" }), message);
                assert.equal(memory.isClosed(), false, "A cancelled drag cannot be committed by a delayed drop");
                await workspace.evaluate(message =>
                {
                    window.knTestDockDrag({ ...message, dragId: "2" });
                    window.knTestDockDrag({ ...message, dragId: "2", phase: "drop", destinationToken: "stale" });
                }, message);
                assert.equal(memory.isClosed(), false, "The group identity must still match at drop time");
                await workspace.evaluate(message => window.knTestDockDrag({ ...message, dragId: "3" }), message);
                await workspace.locator("#btn-palette").click();
                await workspace.locator("#palette-input").waitFor();
                await workspace.evaluate(message => window.knTestDockDrag({ ...message, dragId: "3", phase: "drop" }), message);
                assert.equal(memory.isClosed(), false, "A modal must invalidate a pending drag");
                await workspace.keyboard.press("Escape");
                await workspace.evaluate(message =>
                {
                    window.knTestDockDrag({ ...message, dragId: "4" });
                    window.knTestDockDrag({ ...message, dragId: "4", phase: "drop" });
                }, message);
                await group.locator("#memory-grid").waitFor();
                assert.equal(await group.locator("#memory-rows").textContent(), captured);
                assert.equal(await group.locator("#tab-memory-view").getAttribute("aria-selected"), "true");
                assert.equal(await group.locator("#btn-float-memory").isEnabled(), true);
                for (const viewport of [{ width: 560, height: 740 }, { width: 1280, height: 900 }, { width: 360, height: 420 }])
                {
                    await group.setViewportSize(viewport);
                    const bounds = await group.locator("#btn-inspection-float").boundingBox();
                    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= viewport.width);
                    const footer = await group.locator("#floating-inspection-status").boundingBox();
                    assert.ok(footer.y + footer.height <= viewport.height);
                    if (evidence)
                    {
                        await group.screenshot({ path: path.join(evidence, "inspection-group-" + viewport.width + ".png") });
                    }
                }
                await workspace.evaluate(token =>
                {
                    window.knTestDockDrag({ token, dragId: "5", phase: "preview", destination: "main" });
                    window.knTestDockDrag({ token, dragId: "5", phase: "drop", destination: "main" });
                }, groupToken);
                await workspace.locator("#memory-grid").waitFor();
                assert.equal(await workspace.locator("#memory-rows").textContent(), captured);
                assert.equal(await workspace.locator(".inspection-dock-guide").count(), 0);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER inspection review failed group reveal after docking retains the view in the workspace", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                const memory = await detachInspectionView(workspace, "memory");
                await memory.locator("#btn-memory-read").click();
                await memory.locator("#memory-rows > div").first().waitFor();
                const captured = await memory.locator("#memory-rows").textContent();
                await memory.locator("#memory-address").fill("sample!RetainedDockDraft");
                const registers = await detachInspectionView(workspace, "registers");
                await registers.locator("#registers-rows .register-row").waitFor();
                const group = await detachInspection(workspace);
                const token = await group.evaluate(() => location.hash.split("-").at(-1));
                await group.locator("#btn-memory-close").click();
                await workspace.waitForFunction(token => !window.knTestInspectionStates[token].visible, token);
                await workspace.evaluate(() =>
                {
                    window.knTestFailInspectionAction = "show";
                });
                await memory.locator("#btn-float-memory").click();
                await workspace.locator("#memory-address").waitFor({ timeout: 3000 });
                assert.equal(await workspace.locator("#memory-address").inputValue(), "sample!RetainedDockDraft");
                assert.equal(await workspace.locator("#memory-rows").textContent(), captured);
                assert.equal(group.isClosed(), true);
                assert.equal(registers.isClosed(), false);
                assert.equal(await registers.locator("#registers-filter").isVisible(), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER inspection review obsolete group reveal failure cannot undo a later show", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                const memory = await detachInspectionView(workspace, "memory");
                const group = await detachInspection(workspace);
                await group.locator("#btn-memory-close").click();
                await workspace.evaluate(() =>
                {
                    window.knTestFailInspectionAction = "show";
                    window.knTestHoldInspectionErrors = true;
                });
                await memory.locator("#btn-float-memory").click();
                await workspace.waitForFunction(() => window.knTestPendingInspection.length === 1);
                await workspace.evaluate(() =>
                {
                    window.knTestFailInspectionAction = "";
                });
                await workspace.locator("#btn-memory-panel").click();
                await workspace.locator("#btn-memory-panel").click();
                await workspace.evaluate(() => window.knTestReleaseInspection());
                assert.equal(group.isClosed(), false);
                assert.equal(await group.locator("#memory-grid").isVisible(), true);
                assert.equal(await workspace.locator("#memory-grid").count(), 0);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER inspection mixed windows preserve siblings when docking the group or dropping into the workspace", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                const memory = await detachInspectionView(workspace, "memory");
                await memory.locator("#memory-address").fill("sample!KeepThisDraft");
                const group = await detachInspection(workspace);
                await group.locator("#tab-disassembly").click();
                const opened = workspace.waitForEvent("popup");
                await group.locator("#btn-float-disassembly").click();
                const code = await opened;
                await code.locator("#btn-float-disassembly").filter({ hasText: "Dock" }).waitFor();
                const token = await code.evaluate(() => location.hash.split("-").at(-1));
                await workspace.evaluate(token =>
                {
                    window.knTestDockDrag({ token, dragId: "1", phase: "preview", destination: "main" });
                    window.knTestDockDrag({ token, dragId: "1", phase: "drop", destination: "main" });
                }, token);
                await workspace.locator("#disassembly-grid").waitFor();
                assert.equal(group.isClosed(), true);
                assert.equal(memory.isClosed(), false);
                assert.equal(await memory.locator("#memory-address").inputValue(), "sample!KeepThisDraft");
                await workspace.evaluate(token =>
                {
                    window.knTestDockDrag({ token, dragId: "2", phase: "preview", destination: "main" });
                    window.knTestDockDrag({ token, dragId: "2", phase: "drop", destination: "main" });
                }, token);
                assert.equal(memory.isClosed(), false, "A closed window's stale token must not dock a sibling");
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER independent inspection modal suspension and blocked popups preserve sibling windows", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                const memory = await detachInspectionView(workspace, "memory");
                const registers = await detachInspectionView(workspace, "registers");
                await registers.locator("#registers-rows .register-row").waitFor();
                await registers.locator("#registers-filter").focus();
                await registers.keyboard.press("Control+k");
                await workspace.locator("#palette-input").waitFor();
                assert.equal(await memory.locator("#memory-view").evaluate(node => node.inert), true);
                assert.equal(await registers.locator("#registers-view").evaluate(node => node.inert), true);
                await workspace.keyboard.press("Escape");
                await registers.waitForFunction(() => !document.getElementById("registers-view").inert);
                assert.equal(await memory.locator("#memory-view").evaluate(node => node.inert), false);
                await registers.locator("#btn-float-registers").click();
                await workspace.locator("#registers-grid").waitFor();
                assert.equal(memory.isClosed(), false);
                assert.equal(await memory.locator("#memory-address").isVisible(), true);
                await workspace.evaluate(() =>
                {
                    window.open = () => null;
                });
                await workspace.locator("#btn-float-registers").click();
                assert.equal(await workspace.locator("#registers-grid").isVisible(), true);
                assert.equal(memory.isClosed(), false);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER independent inspection Registers stays selected while Follow IP refreshes both stopped views", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ followExecution: true });
            try
            {
                await workspace.locator("#tab-registers").click();
                await workspace.locator("#registers-rows .register-row").waitFor();
                await workspace.evaluate(() => window.knTestBreak("0xffff800000004000"));
                await workspace.locator("#btn-refresh-status").click();
                await workspace.waitForFunction(() => document.getElementById("registers-rows").textContent.includes("0xffff800000004000"));
                assert.equal(await workspace.locator("#tab-registers").getAttribute("aria-selected"), "true");
                assert.equal(await workspace.locator("#registers-grid").isVisible(), true);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.some(item => item.method === "disassemblyRead")), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER inspection review native close invalidates an older independent focus acknowledgement", async () =>
        {
            for (const sibling of [false, true])
            {
                const { local, workspace } = await floatingWorkspace();
                try
                {
                    if (sibling)
                    {
                        await detachInspectionView(workspace, "processes");
                    }
                    const popup = await detachInspectionView(workspace, "memory");
                    const token = await popup.evaluate(() => location.hash.split("-").at(-1));
                    await workspace.evaluate(() =>
                    {
                        window.knTestHoldInspectionFocus = true;
                    });
                    await popup.locator("#memory-address").press("Control+l");
                    await workspace.waitForFunction(() => window.knTestPendingInspection.length === 1);
                    await workspace.evaluate(token => window.knTestCloseInspectionFrame(token), token);
                    await workspace.locator("#memory-address").waitFor();
                    assert.equal(await workspace.evaluate(() => document.activeElement.id), "tab-memory-view");
                    await workspace.evaluate(() => window.knTestReleaseInspection());
                    assert.equal(await workspace.evaluate(() => document.activeElement.id), "tab-memory-view",
                        "A delayed reply stole docking focus with sibling=" + sibling);
                }
                finally
                {
                    await local.close();
                }
            }
        });
        await check("T-UI-BROWSER inspection review register refresh dismisses copy actions from the replaced capture", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                await workspace.locator("#tab-registers").click();
                const value = workspace.locator("#registers-rows .register-row .copyable").nth(1);
                await value.click({ button: "right" });
                await workspace.locator("#cell-copy-menu").waitFor();
                await workspace.evaluate(() =>
                {
                    window.knTestBreak("0xffff800000005000");
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => document.getElementById("registers-rows").textContent.includes("0xffff800000005000"));
                assert.equal(await workspace.locator("#cell-copy-menu").isVisible(), false,
                    "The current register table retained a copy menu containing a value from the previous stop");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "registers-grid");
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER inspection review register refresh preserves a sibling memory copy menu", async () =>
        {
            const { local, workspace } = await floatingWorkspace();
            try
            {
                const memory = await detachInspectionView(workspace, "memory");
                await memory.locator("#memory-address").fill("nt!NtCreateFile");
                await memory.locator("#btn-memory-read").click();
                await memory.waitForFunction(() => document.querySelectorAll("#memory-rows .memory-row").length > 0);
                await workspace.locator("#tab-registers").click();
                await workspace.locator("#registers-rows .register-row").waitFor();
                await memory.locator("#memory-rows .copyable").first().click({ button: "right" });
                const menu = memory.locator("#cell-copy-menu");
                await menu.waitFor();
                await workspace.evaluate(() =>
                {
                    window.knTestBreak("0xffff800000006000");
                    document.getElementById("btn-refresh-status").click();
                });
                await workspace.waitForFunction(() => document.getElementById("registers-rows").textContent.includes("0xffff800000006000"));
                assert.equal(await menu.isVisible(), true, "A register refresh dismissed another view's captured memory copy menu");
                assert.equal(await menu.evaluate(node => node.contains(document.activeElement)), true);
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER P0 context and symbol health preserve cache and draft-only actions", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace({ diagnostics: true, adaptiveLayout: true });
            try
            {
                const before = await workspace.evaluate(() => window.knTestRequests.length);
                await workspace.locator("#btn-context").click();
                assert.match(await workspace.locator("#context-fields").textContent(), /Implicit EPROCESS.*0xffff800000001000/s);
                assert.match(await workspace.locator("#context-fields").textContent(), /Unknown.*\.trap\/\.cxr/s);
                await workspace.locator("#btn-context-symbols").click();
                assert.equal(await workspace.evaluate(index => window.knTestRequests.slice(index).filter(item =>
                    ["execute", "symbolModules", "symbolHealth"].includes(item.method)).length, before), 0);
                await workspace.locator("#btn-symbol-modules").click();
                await workspace.locator("#symbol-module option").filter({ hasText: "nt" }).waitFor({ state: "attached" });
                await workspace.locator("#symbol-type").fill("_EPROCESS");
                await workspace.locator("#symbol-field").fill("MissingField");
                await workspace.locator("#btn-symbol-inspect").click();
                await workspace.waitForFunction(() => document.getElementById("symbol-fields").textContent.includes("FieldUnavailable"));
                assert.match(await workspace.locator("#symbol-fields").textContent(), /Image \/ PDB matchMatched/);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "p0-symbol-health.png") });
                }
                await workspace.locator("#btn-symbol-reload-draft").click();
                assert.equal(await workspace.locator("#prompt").inputValue(), ".reload /f nt");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 0);
                assert.equal(await workspace.locator("#context-panel").isVisible(), false);
                await workspace.locator("#btn-context").click();
                await workspace.locator("#btn-context-close").focus();
                await workspace.keyboard.press("Escape");
                assert.equal(await workspace.locator("#context-panel").isVisible(), false);
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "btn-context");
                await workspace.locator("#btn-context").click();
                await workspace.locator("#btn-context-overview").click();
                await workspace.evaluate(() => window.knTestChangeContext());
                await workspace.locator("#btn-context-refresh").click();
                await workspace.waitForFunction(() => document.getElementById("context-fields").textContent.includes("changed.exe"));
                await workspace.locator("#btn-context-symbols").click();
                assert.equal(await workspace.locator("#btn-symbol-inspect").isDisabled(), true);
                assert.equal(await workspace.locator("#btn-symbol-reload-draft").isDisabled(), true);
                assert.match(await workspace.locator("#symbol-fields").textContent(), /Historical/);
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER P0 diagnostics remain reachable in short narrow windows at both densities", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace({ diagnostics: true, adaptiveLayout: true });
            try
            {
                for (const density of ["comfortable", "compact"])
                {
                    await workspace.setViewportSize({ width: 1200, height: 800 });
                    await workspace.locator("#workspace-layout-toggle").click();
                    await workspace.locator("#workspace-density").selectOption(density);
                    await workspace.locator("#workspace-layout-toggle").press("Escape");
                    await workspace.locator("#btn-context").click();
                    await workspace.locator("#btn-context-symbols").click();
                    for (const viewport of [{ width: 360, height: 280 }, { width: 520, height: 360 }, { width: 1200, height: 800 }])
                    {
                        await workspace.setViewportSize(viewport);
                        const panel = await workspace.locator("#context-panel").boundingBox();
                        assert.ok(panel.x >= 0 && panel.y >= 0 && panel.x + panel.width <= viewport.width + 1 &&
                            panel.y + panel.height <= viewport.height + 1, JSON.stringify({ viewport, panel, density }));
                        await workspace.locator("#symbol-field").fill("MissingField");
                        await workspace.locator("#btn-symbol-inspect").scrollIntoViewIfNeeded();
                        assert.equal(await workspace.locator("#btn-context-close").evaluate(node =>
                        {
                            const box = node.getBoundingClientRect();
                            return document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2) === node;
                        }), true, "Sticky close control must remain reachable");
                        assert.equal(await workspace.locator("#context-panel").evaluate(node => node.scrollWidth <= node.clientWidth + 1), true);
                        if (evidence && viewport.width === 360)
                        {
                            await workspace.screenshot({ path: path.join(evidence, "p0-symbols-small-" + density + ".png") });
                        }
                    }
                    await workspace.locator("#btn-context-close").click();
                }
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER P0 operation observation preserves focus and keeps cancellation unconfirmed", async () =>
        {
            const operations = [{ operationId: "p0-active", method: "symbolHealth", phase: "CancelRequested", delivery: "Pending",
                observation: { stage: "SymbolQuery", elapsedMs: "0", stageElapsedMs: "2000", sinceProgressMs: "2000", cancelElapsedMs: "1000" } }];
            const { workspace, inspectorContext } = await inspectorWorkspace({ diagnostics: true, adaptiveLayout: true, operations });
            try
            {
                await workspace.locator("#btn-operations").click();
                await workspace.locator(".operation-row").waitFor();
                await workspace.locator("#pause-inspection-reads").check();
                await workspace.locator("#pause-inspection-reads").focus();
                const polls = await workspace.evaluate(() => window.knTestOperationPolls);
                await workspace.waitForFunction(previous => window.knTestOperationPolls > previous, polls);
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "pause-inspection-reads");
                assert.match(await workspace.locator(".operation-observation").textContent(), /Symbol API call.*wait cause unconfirmed.*execution has not completed/s);
                assert.match(await workspace.locator("#btn-context").textContent(), /reads paused/);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 0);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "p0-operation-observation.png") });
                }
                await workspace.locator("#btn-operations-close").click();
                const closedPolls = await workspace.evaluate(() => window.knTestOperationPolls);
                await workspace.waitForTimeout(1700);
                assert.equal(await workspace.evaluate(() => window.knTestOperationPolls), closedPolls);
                await workspace.reload();
                await workspace.waitForFunction(() => !document.getElementById("prompt").disabled);
                await workspace.locator("#btn-operations").click();
                assert.equal(await workspace.locator("#pause-inspection-reads").isChecked(), true);
                await workspace.locator("#btn-operations-close").click();
                await showProcesses(workspace);
                assert.match(await workspace.locator("#process-summary").textContent(), /automatic reads paused/);
                const registers = await detachInspectionView(workspace, "registers");
                await registers.setViewportSize({ width: 520, height: 360 });
                assert.match(await registers.locator("#registers-summary").textContent(), /Automatic reads are paused.*Use Refresh/);
                assert.equal(await registers.locator("#registers-rows .register-row").count(), 0);
                await registers.locator("#btn-registers-refresh").click();
                await registers.locator("#registers-rows .register-row").waitFor();
                assert.match(await registers.locator("#registers-summary").textContent(), /automatic reads paused/);
                if (evidence)
                {
                    await registers.screenshot({ path: path.join(evidence, "p0-floating-registers-paused.png") });
                }
                await registers.locator("#btn-float-registers").click();
                await workspace.locator("#registers-rows .register-row").waitFor();
                assert.match(await workspace.locator("#registers-summary").textContent(), /automatic reads paused/);
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER P0 operation receipt recovery marks unknown and acknowledges completion", async () =>
        {
            const operations = ["p0-expiring", "p0-completing"].map(operationId => ({ operationId,
                method: "symbolHealth", phase: "Running", delivery: "Pending", observation: {
                    stage: "SymbolQuery", elapsedMs: "0", stageElapsedMs: "0", sinceProgressMs: "0" } }));
            const { workspace, inspectorContext } = await inspectorWorkspace({ diagnostics: true, adaptiveLayout: true, operations });
            try
            {
                await workspace.locator("#btn-operations").click();
                await workspace.waitForFunction(() => document.querySelectorAll(".operation-row").length === 2);
                await workspace.evaluate(records =>
                {
                    window.knTestOperationOverrides[records[0].operationId] = { ...records[0], unavailable: true };
                    window.knTestOperationOverrides[records[1].operationId] = { ...records[1], phase: "Completed",
                        ok: true, outcome: "Success", observation: { ...records[1].observation, stage: "ResultReady" } };
                }, operations);
                await workspace.waitForFunction(() => document.querySelector(".operation-row.unknown") &&
                    document.getElementById("operations-list").textContent.includes("Acknowledged"));
                assert.match(await workspace.locator(".operation-row.unknown").textContent(), /p0-expiring.*Unknown.*unconfirmed/s);
                assert.deepEqual(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    item.method === "operationAck").map(item => item.params.operationId)), ["p0-completing"]);
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item =>
                    item.method === "execute" || item.method === "symbolHealth").length), 0);
                if (evidence)
                {
                    await workspace.screenshot({ path: path.join(evidence, "p0-operation-receipt-recovery.png") });
                }
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER display audit result menus remain visible above Console and inspection at both densities", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace({ adaptiveLayout: true });
            try
            {
                await hideInspection(workspace);
                await workspace.locator("#btn-breakpoints").click();
                for (const density of ["compact", "comfortable"])
                {
                    await workspace.setViewportSize({ width: 1280, height: 800 });
                    await workspace.locator("#workspace-layout-toggle").click();
                    await workspace.locator("#workspace-density").selectOption(density);
                    await workspace.locator("#workspace-layout-toggle").press("Escape");
                    for (const viewport of [{ width: 900, height: 600 }, { width: 360, height: 480 }, { width: 360, height: 280 }])
                    {
                        await workspace.setViewportSize(viewport);
                        for (const id of ["result-open", "result-info", "result-columns", "address-navigation", "breakpoint-create", "workspace-layout"])
                        {
                            const menu = workspace.locator("#" + id);
                            await menu.locator(":scope > summary").click();
                            const popup = menu.locator(":scope > .tool-popover");
                            const bounds = await popup.boundingBox();
                            assert.ok(bounds.x >= 0 && bounds.y >= 0 && bounds.x + bounds.width <= viewport.width + 1 &&
                                bounds.y + bounds.height <= viewport.height + 1, id + " leaves the viewport: " + JSON.stringify(bounds));
                            const controls = popup.locator("button:visible,input:visible,select:visible,summary:visible");
                            for (const control of await controls.all())
                            {
                                await control.scrollIntoViewIfNeeded();
                                assert.equal(await control.evaluate(node =>
                                {
                                    const box = node.getBoundingClientRect();
                                    const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2);
                                    return node === hit || node.contains(hit);
                                }), true, id + " has an obstructed control: " + await control.getAttribute("id"));
                            }
                            if (evidence && id === "result-info")
                            {
                                await workspace.screenshot({ path: path.join(evidence, "display-menu-" + density + "-" + viewport.height + ".png") });
                            }
                            await controls.last().press("Escape");
                            assert.equal(await menu.evaluate(node => node.open), false);
                            assert.equal(await menu.locator(":scope > summary").evaluate(node => node === document.activeElement), true);
                        }
                    }
                }
                await workspace.setViewportSize({ width: 360, height: 280 });
                await workspace.locator("#result-info-toggle").click();
                const popup = workspace.locator("#result-info-popover");
                await popup.evaluate(node => node.scrollTop = node.scrollHeight);
                const previousScroll = await popup.evaluate(node => node.scrollTop);
                assert.ok(previousScroll > 0);
                await workspace.setViewportSize({ width: 360, height: 281 });
                await workspace.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
                assert.ok(Math.abs(await popup.evaluate(node => node.scrollTop) - previousScroll) <= 2,
                    "Repositioning jumps away from the capture details being read");
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER display audit menus and diagnostics dismiss each other and outside clicks preserve input", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace({ adaptiveLayout: true, diagnostics: true });
            try
            {
                await workspace.setViewportSize({ width: 1600, height: 800 });
                await hideInspection(workspace);
                await workspace.locator("#prompt").fill("draft kept");
                await workspace.locator("#workspace-layout-toggle").click();
                await workspace.locator("#btn-context").click();
                assert.equal(await workspace.locator("#workspace-layout").evaluate(node => node.open), false);
                await workspace.locator("#workspace-layout-toggle").click();
                assert.equal(await workspace.locator("#context-panel").isHidden(), true);
                await workspace.locator("#btn-operations").click();
                assert.equal(await workspace.locator("#workspace-layout").evaluate(node => node.open), false);
                await workspace.locator("#workspace-layout-toggle").click();
                assert.equal(await workspace.locator("#operations-panel").isHidden(), true);
                await workspace.locator("#prompt").click();
                assert.equal(await workspace.locator("#workspace-layout").evaluate(node => node.open), false);
                assert.equal(await workspace.locator("#prompt").inputValue(), "draft kept");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "prompt");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), 0);
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER display audit keyboard focus leaves menus without obscuring its destination", async () =>
        {
            const { workspace, inspectorContext } = await inspectorWorkspace({ adaptiveLayout: true });
            try
            {
                await workspace.setViewportSize({ width: 360, height: 280 });
                await workspace.locator("#btn-breakpoints").click();
                await workspace.locator("#prompt").fill("draft kept");
                const executions = await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length);
                for (const id of ["result-open", "result-info", "result-columns", "address-navigation", "breakpoint-create", "workspace-layout"])
                {
                    const menu = workspace.locator("#" + id);
                    const summary = menu.locator(":scope > summary");
                    await summary.focus();
                    await summary.press("Enter");
                    assert.equal(await menu.evaluate(node => node.open), true);
                    await workspace.keyboard.press("Control+l");
                    assert.equal(await workspace.evaluate(() => document.activeElement.id), "prompt");
                    assert.equal(await menu.evaluate(node => node.open), false, id + " obscures the command input after Ctrl+L");
                    const inputHit = await workspace.locator("#prompt").evaluate(node =>
                    {
                        const box = node.getBoundingClientRect();
                        const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2);
                        return { visible: hit === node, hit: hit && (hit.id || hit.tagName), x: box.x, y: box.y, width: box.width, height: box.height };
                    });
                    assert.equal(inputHit.visible, true, id + " leaves input obscured: " + JSON.stringify(inputHit));
                }
                await workspace.locator("#workspace-layout-toggle").focus();
                await workspace.keyboard.press("Enter");
                await workspace.keyboard.press("Control+b");
                assert.equal(await workspace.evaluate(() => document.activeElement.id), "filter");
                assert.equal(await workspace.locator("#workspace-layout").evaluate(node => node.open), false);
                await workspace.keyboard.press("Control+b");
                await workspace.locator("#result-open-toggle").focus();
                await workspace.keyboard.press("Enter");
                await workspace.keyboard.press("Tab");
                assert.equal(await workspace.locator("#result-open").evaluate(node => node.open), true,
                    "Tab between controls in the menu must keep it open");
                await workspace.keyboard.press("Control+l");
                await workspace.locator("#result-open-toggle").focus();
                await workspace.keyboard.press("Enter");
                await workspace.keyboard.press("Shift+Tab");
                assert.equal(await workspace.locator("#result-open").evaluate(node => node.open), false);
                assert.equal(await workspace.locator("#prompt").inputValue(), "draft kept");
                assert.equal(await workspace.evaluate(() => window.knTestRequests.filter(item => item.method === "execute").length), executions);
            }
            finally
            {
                await inspectorContext.close();
            }
        });
        await check("T-UI-BROWSER display audit inspection overlay follows context reflow and docking without covering input", async () =>
        {
            const { local, workspace } = await floatingWorkspace({ adaptiveLayout: true });
            try
            {
                for (const width of [610, 626, 720])
                {
                    await workspace.setViewportSize({ width, height: 823 });
                    if (await workspace.locator("#memory").isHidden())
                    {
                        await workspace.locator("#btn-memory-panel").click();
                    }
                    const popup = await detachInspectionView(workspace, "registers");
                    await popup.locator("#btn-float-registers").click();
                    await workspace.locator("#registers-grid").waitFor();
                    await workspace.evaluate(() =>
                    {
                        window.knTestCurrentProcess.image = "process-with-a-long-observed-image-name.exe";
                        window.knTestCurrentProcess.eprocess = "0xffff800000001000";
                    });
                    await workspace.locator("#btn-refresh-status").click();
                    await workspace.waitForFunction(() => document.getElementById("current-process-image").textContent.includes("long-observed"));
                    await workspace.waitForTimeout(60);
                    const geometry = await workspace.evaluate(() =>
                    {
                        const panel = document.getElementById("memory").getBoundingClientRect();
                        const workspace = document.getElementById("workspace-split").getBoundingClientRect();
                        const input = document.getElementById("command-area").getBoundingClientRect();
                        return { top: panel.top, bottom: panel.bottom, workspaceTop: workspace.top, inputTop: input.top };
                    });
                    assert.ok(geometry.top >= geometry.workspaceTop - 1 && geometry.bottom <= geometry.inputTop + 1,
                        "Inspection obscures reflowed context or input at " + width + ": " + JSON.stringify(geometry));
                    if (evidence)
                    {
                        await workspace.screenshot({ path: path.join(evidence, "display-inspection-reflow-" + width + ".png") });
                    }
                }
            }
            finally
            {
                await local.close();
            }
        });
        await check("T-UI-BROWSER no unhandled page errors", () => assert.deepEqual(errors, []));
        process.exitCode = failures ? 1 : 0;
    }
    finally
    {
        if (browser)
        {
            await browser.close();
        }
        await new Promise(resolve => server.close(resolve));
    }
}

main().catch(error =>
{
    console.error(error);
    process.exitCode = 1;
});
