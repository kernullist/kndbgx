// KNDbgX front-end logic: catalog rendering, command execution, history,
// completion and output console rendering. Talks to the host exclusively
// through WebView2 postMessage with JSON objects.

(function () {
  "use strict";

  var inspectionSerial = 0;
  var inspectionPanels = Object.create(null);
  var inspectionDockDrag = { id: "0", ended: false, token: "", guides: [] };
  var inspectionFloat = { window: null, opening: null, serial: 0, nodes: Object.create(null),
    documents: [], windows: [], visibilityToken: 0, visibilityEpoch: "0", interaction: 0,
    timeout: null, observer: null, suspended: false };

  function uiElement(id)
  {
    var node = document.getElementById(id);
    if (!node && inspectionFloat.window)
    {
      try
      {
        node = inspectionFloat.window.document.getElementById(id);
      }
      catch (error)
      {
        // Retained nodes can still be returned to the main document after close.
      }
    }
    Object.keys(inspectionPanels).some(function (view)
    {
      var item = inspectionPanels[view];
      if (!node && item.window)
      {
        try
        {
          node = item.window.document.getElementById(id);
        }
        catch (error)
        {
          // Retained nodes survive a closing child document.
        }
      }
      return !!node;
    });
    if (!node)
    {
      var retained = inspectionFloat.nodes[id];
      var containers = [inspectionFloat.nodes.memory, inspectionFloat.nodes["cell-copy-menu"], inspectionFloat.nodes["copy-fallback"]].concat(Object.keys(inspectionPanels).map(function (view)
      {
        return inspectionPanels[view].panel;
      }));
      if (retained && containers.some(function (container)
      {
        return container && (container === retained || container.contains(retained));
      }))
      {
        node = retained;
      }
    }
    return node;
  }

  function uiView(node)
  {
    return node && node.ownerDocument && node.ownerDocument.defaultView || window;
  }

  function uiActiveElement()
  {
    try
    {
      var child = Object.keys(inspectionPanels).map(function (view)
      {
        return inspectionPanels[view].window;
      }).find(function (popup)
      {
        return popup && !popup.closed && popup.document.hasFocus();
      });
      if (child)
      {
        return child.document.activeElement;
      }
      var popup = inspectionFloat.window;
      if (popup && !popup.closed && popup.document.hasFocus())
      {
        return popup.document.activeElement;
      }
    }
    catch (error)
    {
      // A closing secondary window must not interrupt the main document.
    }
    return document.activeElement;
  }

  function listenDocument(type, callback, options)
  {
    document.addEventListener(type, callback, options);
    if (["keydown", "pointerdown", "focusin"].indexOf(type) >= 0)
    {
      inspectionFloat.documents.push([type, callback, options]);
    }
  }

  function listenWindow(type, callback, options)
  {
    window.addEventListener(type, callback, options);
    if (["resize", "blur", "scroll"].indexOf(type) >= 0)
    {
      inspectionFloat.windows.push([type, callback, options]);
    }
  }

  if (window.knDbgXFrontendReady)
  {
    return;
  }

  ["pointerdown", "keydown"].forEach(function (type)
  {
    listenDocument(type, function ()
    {
      ++inspectionFloat.interaction;
    }, true);
  });

  var bridge = null;

  try {
    bridge = window.chrome.webview;
  } catch (err) {
    bridge = null;
  }

  var els = {
    catalog: uiElement("catalog"),
    filter: uiElement("filter"),
    output: uiElement("output"),
    prompt: uiElement("prompt"),
    promptGhost: uiElement("prompt-ghost"),
    promptGhostText: uiElement("prompt-ghost-text"),
    promptGhostPrefix: uiElement("prompt-ghost-prefix"),
    promptGhostSuffix: uiElement("prompt-ghost-suffix"),
    commandArea: uiElement("command-area"),
    commandProgress: uiElement("command-progress"),
    commandPhase: uiElement("command-phase"),
    commandElapsed: uiElement("command-elapsed"),
    suggest: uiElement("suggest"),
    status: uiElement("status"),
    btnClear: uiElement("btn-clear"),
    btnCancel: uiElement("btn-cancel"),
    btnSave: uiElement("btn-save"),
    modalBackdrop: uiElement("modal-backdrop"),
    modalPreview: uiElement("modal-preview"),
    modalConfirm: uiElement("modal-confirm"),
    modalCancel: uiElement("modal-cancel"),
    resultView: uiElement("result-view"),
    resultSpacer: uiElement("result-spacer"),
    resultRows: uiElement("result-rows"),
    resultSummary: uiElement("result-summary"),
    resultDetail: uiElement("result-detail"),
    selectionScope: uiElement("selection-scope"),
    root: uiElement("root"),
    paletteBackdrop: uiElement("palette-backdrop"),
    paletteInput: uiElement("palette-input"),
    paletteResults: uiElement("palette-results"),
    paletteClose: uiElement("palette-close"),
    resultHistory: uiElement("result-history"),
    detailFields: uiElement("detail-fields"),
    activity: uiElement("activity"),
    btnRun: uiElement("btn-run")
  };

  var state = {
    nextId: 1,
    pending: {},
    commandsByName: Object.create(null),
    groups: [],
    librarySort: "default",
    libraryCollapsed: Object.create(null),
    libraryFilter: "",
    libraryFilterCollapsed: Object.create(null),
    history: [],
    historyIndex: -1,
    historyDraft: null,
    historyRecalled: null,
    suggestItems: [],
    suggestActive: -1,
    suggestToken: 0,
    suggestInput: "",
    suggestTemplate: "",
    suggestContext: null,
    symbolCompletion: { timer: null, active: null, queued: null, accepted: null, expired: [] },
    addressCompletions: [],
    addressHistory: { memory: [], disassembly: [] },
    parameterDraft: null,
    busy: false,
    cancelRequested: false,
    busyStartedAt: null,
    activityTimer: null,
    phase: "Booting",
    uiGeneration: "",
    target: { sessionId: "", targetGeneration: "" },
    ready: false,
    connected: false,
    statusBusy: false,
    statusKnown: false,
    debuggerRevision: 0,
    preparedDebuggerRevision: 0,
    currentRequest: "",
    runToken: 0,
    composing: false,
    outputChunks: [],
    outputUnits: 0,
    resultId: "",
    resultTarget: null,
    selectedRow: null,
    selectedAddressField: "",
    rowCount: 0,
    rowBase: 0,
    rowOffset: -1,
    rowPending: false,
    stopStream: false,
    resultMeta: {},
    resultError: "",
    resultFailed: false,
    resultOutputLength: "",
    resultCommand: "",
    tableLayouts: [],
    tableLayout: null,
    columnDrag: null,
    recentResults: [],
    resultTabs: [],
    activeResultTab: "",
    resultTabSerial: 0,
    resultTabRetention: 0,
    resultTabMenu: null,
    resultTabDrag: null,
    resultTabRename: null,
    resultScreen: "results",
    returnResult: null,
    resultRestore: null,
    resultLoadToken: 0,
    resultLoadId: "",
    statusToken: 0,
    resultRevision: 0,
    detailsRevision: -1,
    rowCache: [],
    rowIndices: [],
    tableSort: { entries: null, order: null, applied: null, requested: null, loading: false, loaded: 0, error: "" },
    rowError: "",
    resultLoadError: "",
    resultNotice: { key: "", dismissed: false },
    selectedIndex: -1,
    selectedOriginalIndex: -1,
    pendingSelection: -1,
    paletteItems: [],
    paletteActive: 0,
    paletteComposing: false,
    libraryVisible: null,
    libraryPinned: false,
    libraryFavorites: [],
    selectedCommand: "",
    commandSelectionRevision: 0,
    consoleVisible: false,
    consoleEnabled: true,
    consoleEpoch: 0,
    clipboardPending: false,
    copyStatusTimer: null,
    feedbackTimer: null,
    inspectorVisible: false,
    workspaceDensity: "compact",
    windowRows: Object.create(null)
  };
  var inspectionViews = ["processes", "memory", "disassembly", "registers"];
  inspectionViews.forEach(function (view)
  {
    inspectionPanels[view] = { view: view, token: "", epoch: "0", window: null, opening: null,
      panel: null, timeout: null, suspended: false, visibility: 0 };
  });
  state.registers = { rows: [], changed: [], pins: [], stamp: null, lastAttempt: "", complete: false, loading: false, cancelled: false, error: "" };
  state.sessionStatus = {};
  state.executionControl = { starting: false, breaking: false, serial: 0, timer: null, target: null };
  state.currentProcessValues = {};
  state.processes = { rows: [], filtered: [], selected: -1, sort: null, resultId: "", stamp: null, meta: {},
    loading: false, cancelled: false, error: "", lastAttempt: "", timer: null };
  var processColumns = [
    { key: "pid", label: "PID" }, { key: "image", label: "Image" }, { key: "eprocess", label: "EPROCESS" },
    { key: "dtb", label: "DTB" }, { key: "createTime", label: "Created (FILETIME)" }
  ];
  state.memory = { snapshot: null, selected: -1, loading: false, cancelled: false, error: "", failedRead: null, evidenceOpen: false };
  state.memoryPanel = { visible: true, width: 520, effectiveWidth: 520, overlay: false, drag: null, tab: "memory" };
  state.inspectorPanel = { width: null, effectiveWidth: 296, resizable: false, drag: null };
  state.disassembly = { snapshot: null, selected: -1, loading: false, cancelled: false, error: "", history: [],
    followIP: true, stopTarget: null, sawRunning: false, pendingFollow: null, followSerial: 0, awaitingStop: false };
  state.breakpoints = { rows: [], resultId: "", stamp: null, complete: false, error: "", token: 0, loading: false, rowControls: [] };
  state.breakpointNotification = { scope: "", session: "", stop: "", running: false, sequence: null };
  state.operations = { serial: 0, open: false, loading: false, records: [], actions: [], error: "", checked: "" };
  state.capabilities = [];
  state.pauseInspectionReads = false;
  state.contextView = { open: false, tab: "context", observed: null, received: "", modules: [], moduleStamp: null,
    selected: "", nextCursor: "0", complete: true, total: "0", unknown: 0, health: null, loading: false, error: "" };
  state.operations.nodes = Object.create(null);
  state.operations.timer = null;
  state.savedExports = Object.create(null);

  var missingNodes = Object.keys(els).filter(function (key)
  {
    return !els[key];
  });
  if (missingNodes.length !== 0)
  {
    if (els.status)
    {
      els.status.textContent = "frontend failed: missing " + missingNodes.join(", ");
      els.status.className = "status bad";
    }
    return;
  }
  window.knDbgXFrontendReady = true;
  els.status.textContent = bridge ? "frontend ready; connecting bridge..." : "bridge unavailable";

  // ---------- messaging ----------

  function debuggerBusy()
  {
    return state.statusBusy || (state.ready && !state.statusKnown) || (state.connected && state.sessionStatus.stopped === false);
  }

  function preparedCommandCurrent()
  {
    return !debuggerBusy() && state.preparedDebuggerRevision === state.debuggerRevision;
  }

  function phase(value)
  {
    state.phase = value;
    updateCommandActivity();
  }

  function updateCommandElapsed()
  {
    state.activityTimer = null;
    if (!state.busy)
    {
      return;
    }
    var tenths = Math.max(0, Math.floor((performance.now() - state.busyStartedAt) / 100));
    els.commandElapsed.textContent = (tenths / 10).toFixed(1) + "s";
    state.activityTimer = setTimeout(updateCommandElapsed, 250);
  }

  function updateCommandActivity()
  {
    var waiting = debuggerBusy();
    var active = state.busy || waiting;
    els.activity.textContent = waiting ? "Busy" : state.phase;
    els.commandArea.classList[active ? "add" : "remove"]("is-busy");
    els.commandProgress.classList[active ? "remove" : "add"]("hidden");
    els.commandArea.classList[state.busy && state.phase === "AwaitingApproval" ? "add" : "remove"]("awaiting-approval");
    els.prompt.setAttribute("aria-describedby", active ? "command-progress" : "command-hint");
    if (waiting)
    {
      els.commandPhase.textContent = !state.statusKnown && !state.statusBusy ? "Waiting for target status" : "Busy";
    }
    if (!state.busy)
    {
      if (state.activityTimer !== null)
      {
        clearTimeout(state.activityTimer);
        state.activityTimer = null;
      }
      state.busyStartedAt = null;
      els.commandElapsed.textContent = "";
      return;
    }
    var labels = { Planning: "Preparing", Streaming: "Receiving output", AwaitingApproval: "Awaiting approval", Idle: "Working" };
    if (!waiting)
    {
      els.commandPhase.textContent = labels[state.phase] || state.phase;
    }
    if (state.busyStartedAt === null)
    {
      state.busyStartedAt = performance.now();
    }
    if (state.activityTimer === null)
    {
      updateCommandElapsed();
    }
  }

  function workerMethod(method)
  {
    return ["execute", "executePlan", "previewWrite", "navigateResult", "processAction", "memoryRead", "disassemblyRead", "breakpointPlan", "breakpointApply", "debuggerAction", "saveLog", "status", "symbolModules", "symbolHealth"].indexOf(method) >= 0;
  }

  function queryOperation(id)
  {
    var pending = state.pending[id];
    if (!pending || !pending.worker || pending.querying)
    {
      return;
    }
    pending.querying = true;
    send("operationStatus", { requestId: id, operationId: pending.operationId || "" }).then(function (reply)
    {
      pending.querying = false;
      if (state.pending[id] !== pending)
      {
        return;
      }
      var operation = reply && reply.ok && reply.result;
      if (operation && operation.terminal)
      {
        onMessage({ data: operation.terminal });
        return;
      }
      if (reply && reply.error === "OperationUnknownOrExpired")
      {
        delete state.pending[id];
        pending({ ok: false, outcomeUnknown: true,
          error: "Outcome unknown: the host no longer retains this operation. Check stored results and output files before running the command again." });
        return;
      }
      if (state.currentRequest === id && state.phase !== "Cancelling")
      {
        phase(operation ? operation.phase : "Outcome unknown; checking");
      }
      pending.watch();
    });
  }

  function send(method, params) {
    var request = {
      schema: "kndbgx.rpc.v3", requestId: String(state.nextId++),
      uiGeneration: state.uiGeneration,
      sessionId: state.target.sessionId || "",
      expectedTargetGeneration: state.target.targetGeneration || "",
      method: method, params: params || {}
    };
    if (!bridge || (!state.ready && method !== "hello") || Object.keys(state.pending).length >= 32) {
      return Promise.resolve({ ok: false, error: "Bridge unavailable, not ready, or request limit reached" });
    }
    if (workerMethod(method) && method !== "status") {
      state.currentRequest = request.requestId;
    }
    return new Promise(function (resolve) {
      var timer = null;
      if (!workerMethod(method)) {
        timer = setTimeout(function () {
          if (state.pending[request.requestId]) {
            delete state.pending[request.requestId];
            if (method === "completeSymbols")
            {
              // The host retains worker receipts until acknowledged, even after this optional read expires.
              state.symbolCompletion.expired.push(request.requestId);
              if (state.symbolCompletion.expired.length > 128)
              {
                state.symbolCompletion.expired.shift();
              }
            }
            resolve({ ok: false, error: "timeout: " + method + "; request was not retried" });
          }
        }, 8000);
      }
      state.pending[request.requestId] = function (message) {
        if (timer !== null) { clearTimeout(timer); }
        resolve(message);
      };
      var pending = state.pending[request.requestId];
      pending.worker = workerMethod(method);
      pending.watch = function ()
      {
        if (timer !== null) { clearTimeout(timer); }
        timer = setTimeout(function () { queryOperation(request.requestId); }, 4000);
      };
      if (pending.worker) { pending.watch(); }
      try
      {
        bridge.postMessage(request);
      }
      catch (error)
      {
        delete state.pending[request.requestId];
        if (timer !== null)
        {
          clearTimeout(timer);
        }
        resolve({ ok: false, error: "Bridge send failed: " + method + "; request was not retried" });
      }
    });
  }

  function onMessage(event) {
    var message = event.data;
    if (typeof message === "string") {
      try { message = JSON.parse(message); } catch (error) { return; }
    }
    if (!message || message.schema !== "kndbgx.rpc.v3" || typeof message.requestId !== "string") { return; }
    if (message.type === "inspectionDockDrag" && message.requestId === "" && state.ready && message.uiGeneration === state.uiGeneration)
    {
      receiveInspectionDrag(message);
      return;
    }
    if (message.type === "inspectionHidden" && message.requestId === "" && state.ready && message.uiGeneration === state.uiGeneration)
    {
      var independent = inspectionViews.find(function (view)
      {
        return inspectionPanels[view].token === message.token && !!message.token;
      });
      if (independent)
      {
        var item = inspectionPanels[independent];
        if (typeof message.visibilityEpoch === "string" && /^(0|[1-9][0-9]{0,19})$/.test(message.visibilityEpoch) &&
            BigInt(message.visibilityEpoch) > BigInt(item.epoch))
        {
          item.epoch = message.visibilityEpoch;
          dockInspectionView(independent, true);
        }
        return;
      }
    }
    if (message.type === "inspectionHidden" && message.requestId === "" && state.ready &&
        message.uiGeneration === state.uiGeneration && message.token === String(inspectionFloat.serial))
    {
      if (!acceptInspectionEpoch(message.visibilityEpoch))
      {
        return;
      }
      if (inspectionFloat.opening)
      {
        cancelInspectionFloat();
      }
      else if (inspectionFloat.window)
      {
        setMemoryPanel(false, true);
      }
      return;
    }
    var resolve = state.pending[message.requestId];
    if (!resolve)
    {
      var expired = state.symbolCompletion.expired.indexOf(message.requestId);
      if (expired >= 0 && message.uiGeneration === state.uiGeneration && message.type === "completed")
      {
        state.symbolCompletion.expired.splice(expired, 1);
        if (typeof message.operationId === "string" && message.operationId)
        {
          send("operationAck", { operationId: message.operationId });
        }
      }
      return;
    }
    if (!state.ready && message.requestId === "1" && message.ok && message.uiGeneration) {
      state.uiGeneration = message.uiGeneration;
    }
    if (message.uiGeneration !== state.uiGeneration) { return; }
    if (message.type === "accepted" || message.type === "progress") {
      resolve.operationId = message.operationId || resolve.operationId;
      if (state.currentRequest === message.requestId && state.phase !== "Cancelling")
      {
        phase(message.type === "accepted" ? "Queued" : "Running");
      }
      return;
    }
    if (message.type !== "completed" && message.type !== "resultChunk") { return; }
    delete state.pending[message.requestId];
    resolve(message);
    if (message.operationId)
    {
      send("operationAck", { operationId: message.operationId });
    }
  }

  if (bridge) { bridge.addEventListener("message", onMessage); }

  // ---------- output rendering ----------

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function renderLine(text) {
    var html = escapeHtml(text);

    // [tag] coloring for kn-live-dbg style section headers.
    html = html.replace(/\[([A-Za-z][\w.\-]{0,40})\]/g, function (match, tag) {
      var lowered = tag.toLowerCase();

      if (lowered.indexOf("warn") === 0 ||
          lowered.indexOf("suspicious") >= 0 ||
          lowered.indexOf("high") === 0) {
        return '<span class="t-warn">[' + tag + ']</span>';
      }

      if (lowered.indexOf("error") === 0 || lowered.indexOf("fail") === 0) {
        return '<span class="t-error">[' + tag + ']</span>';
      }

      return '<span class="t-tag">[' + tag + ']</span>';
    });

    return html;
  }

  function clearOutput() {
    els.output.textContent = "";
    state.outputChunks = [];
    state.outputUnits = 0;
    uiElement("console-size").textContent = "0 characters";
    uiElement("btn-copy-console").disabled = true;
  }

  function appendOutput(text, cssClass) {
    if (!state.consoleEnabled)
    {
      return;
    }
    text = String(text);
    var wrap = uiElement("console-wrap");
    var follow = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 48;
    var limit = 262144;
    if (text.length > limit) { text = "[display truncated; save result for full output]\n" + text.slice(-limit + 64); }
    var span = document.createElement("span");
    if (cssClass) { span.className = cssClass; }
    span.innerHTML = renderLine(text);
    els.output.appendChild(span);
    state.outputChunks.push({ node: span, size: text.length, text: text });
    state.outputUnits += text.length;
    while (state.outputUnits > limit || state.outputChunks.length > 256) {
      var old = state.outputChunks.shift();
      state.outputUnits -= old.size;
      els.output.removeChild(old.node);
    }
    uiElement("console-size").textContent = state.outputUnits.toLocaleString() + " characters";
    uiElement("btn-copy-console").disabled = state.outputUnits === 0;
    if (follow) { wrap.scrollTop = wrap.scrollHeight; }
  }

  function revealConsole()
  {
    if (state.consoleEnabled && !state.consoleVisible)
    {
      state.consoleVisible = true;
      updateLayout();
    }
  }

  function appendLine(text, cssClass)
  {
    if (!state.consoleEnabled)
    {
      workspaceFeedback(text, cssClass === "t-error" || cssClass === "t-warn");
    }
    if (state.consoleEnabled && (cssClass === "t-error" || cssClass === "t-warn"))
    {
      workspaceFeedback(text, true);
    }
    appendOutput(text + "\n", cssClass);
  }

  function pullOutput(id, cursor)
  {
    if (state.stopStream || !state.consoleEnabled)
    {
      return Promise.resolve();
    }
    return send("outputChunk", { resultId: id, cursor: String(cursor) }).then(function (reply)
    {
      if (state.stopStream || !state.consoleEnabled)
      {
        return;
      }
      if (!reply || !reply.ok)
      {
        appendLine("[output] " + ((reply && reply.error) || "unavailable"), "t-error");
        return;
      }
      var chunk = reply.result;
      if (!chunk || chunk.resultId !== id || chunk.offset !== String(cursor) || typeof chunk.text !== "string" ||
        (!chunk.complete && (!Number.isSafeInteger(Number(chunk.next)) || Number(chunk.next) <= Number(cursor))))
      {
        appendLine("[output] invalid chunk sequence; export the stored result for complete output", "t-error");
        return;
      }
      appendOutput(chunk.text);
      if (!chunk.complete)
      {
        return pullOutput(id, chunk.next);
      }
    });
  }

  var addressFieldsByRow = new WeakMap();

  function checkedResultPage(reply, id, collection, cursor, total)
  {
    if (!reply || !reply.ok || !reply.result || reply.result.resultId !== id || reply.result.offset !== String(cursor))
    {
      throw new Error("Rows unavailable. Reopen the stored result or run the command again.");
    }
    if (reply.result.collection && reply.result.collection !== collection)
    {
      throw new Error("The result type changed while loading rows.");
    }
    var page = reply.result[collection];
    if (!Array.isArray(page) || page.length > 128 ||
        (!page.length && cursor < total) || cursor + page.length > total ||
        (reply.result.next !== undefined && Number(reply.result.next) !== cursor + page.length) ||
        (reply.result.total !== undefined && Number(reply.result.total) !== total) ||
        (reply.result.complete !== undefined && reply.result.complete !== (cursor + page.length === total)))
    {
      throw new Error("Result page is invalid or did not advance. Export the stored result for all records.");
    }
    var addresses = reply.result.addressFields;
    if (addresses !== undefined)
    {
      if (!Array.isArray(addresses) || addresses.length !== page.length || addresses.some(function (fields)
      {
        return !Array.isArray(fields) || fields.length > 32 || fields.some(function (field)
        {
          return !field || !Array.isArray(field.path) || !field.path.length || field.path.length > 4 ||
            field.path.some(function (part) { return typeof part !== "string" || !/^[a-z0-9_]{1,64}$/i.test(part); }) ||
            ["virtual", "physical"].indexOf(field.space) < 0 || typeof field.allowZero !== "boolean" ||
            (field.process !== undefined && (typeof field.process !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(field.process)));
        });
      }))
      {
        throw new Error("Invalid result address metadata. Reopen the stored result.");
      }
      page.forEach(function (row, index)
      {
        if (row && typeof row === "object")
        {
          addressFieldsByRow.set(row, addresses[index]);
        }
      });
    }
    return page;
  }

  function updateTableBusy()
  {
    uiElement("result-table").setAttribute("aria-busy", String(state.tableSort.loading ||
      (state.rowPending && !state.tableSort.order)));
  }

  function displayRows(offset, rows, indices)
  {
    state.rowOffset = offset;
    state.rowCache = rows;
    state.rowIndices = indices;
    state.rowError = "";
    discoverColumns(rows);
    updateEvidenceSummary();
    renderRows();
    if (state.resultRestore)
    {
      els.resultView.scrollLeft = state.resultRestore.scrollLeft;
      state.resultRestore = null;
    }
    if (state.pendingSelection >= offset && state.pendingSelection < offset + rows.length)
    {
      var selected = state.pendingSelection;
      state.pendingSelection = -1;
      chooseRow(selected);
    }
  }

  // Keep row DOM bounded even when sorting the displayed collection's 100k rows.
  function showRows(force)
  {
    syncTableViewport();
    if (!state.resultId || !state.rowCount)
    {
      return;
    }
    if (state.resultRestore && state.tableSort.loading)
    {
      state.resultRestore.scrollTop = els.resultView.scrollTop;
      state.resultRestore.scrollLeft = els.resultView.scrollLeft;
      return;
    }
    var offset = Math.max(0, Math.floor(els.resultView.scrollTop / workspaceRowHeight()) - 8);
    if (state.pendingSelection >= 0 && (state.pendingSelection < offset || state.pendingSelection >= offset + 128))
    {
      offset = state.pendingSelection;
    }
    var wanted = Math.min(128, Math.max(24, Math.ceil(els.resultView.clientHeight / workspaceRowHeight()) + 16));
    if (force !== true && offset === state.rowOffset && (state.rowCache.length >= wanted || offset + state.rowCache.length >= state.rowCount))
    {
      return;
    }
    if (state.tableSort.order)
    {
      var entries = state.tableSort.order.slice(offset, offset + 128);
      displayRows(offset, entries.map(function (entry)
      {
        return entry.row;
      }), entries.map(function (entry)
      {
        return entry.index;
      }));
      return;
    }
    if (state.rowPending)
    {
      return;
    }
    state.rowPending = true;
    updateTableBusy();
    var id = state.resultId;
    var revision = state.resultRevision;
    var collection = state.resultCollection || "rows";
    var total = collection === "findings" ? state.findingCount : state.observationCount;
    var base = state.rowBase;
    var rows = [];
    function fetchPage(cursor)
    {
      return send("resultPage", { resultId: id, offset: String(cursor), collection: collection }).then(function (reply)
      {
        if (revision !== state.resultRevision)
        {
          return;
        }
        var page = checkedResultPage(reply, id, collection, cursor, total);
        if (base && cursor === 0 && (!page[0] || page[0].kind !== "LastEvent"))
        {
          throw new Error("The event record order could not be verified. Export the retained result for the complete capture.");
        }
        var skip = Math.max(0, base - cursor);
        var remaining = Math.max(0, Math.min(128 - rows.length, state.rowCount - offset - rows.length));
        rows = rows.concat(page.slice(skip, skip + remaining));
        var next = cursor + page.length;
        if (page.length && rows.length < wanted && next < state.rowCount + base && !reply.result.complete)
        {
          return fetchPage(next);
        }
      });
    }
    fetchPage(offset ? offset + base : 0).then(function ()
    {
      state.rowPending = false;
      updateTableBusy();
      if (revision !== state.resultRevision)
      {
        showRows();
        return;
      }
      displayRows(offset, rows, rows.map(function (_, index)
      {
        return offset + index + base;
      }));
      // A scroll can overtake the asynchronous response.
      if (Math.max(0, Math.floor(els.resultView.scrollTop / workspaceRowHeight()) - 8) !== offset)
      {
        showRows();
      }
    }).catch(function (error)
    {
      state.rowPending = false;
      updateTableBusy();
      if (revision === state.resultRevision)
      {
        state.pendingSelection = -1;
        state.rowError = error.message;
        updateEvidenceSummary();
      }
      else
      {
        showRows();
      }
    });
  }

  function scalar(value)
  {
    if (value === null || value === undefined)
    {
      return "Unavailable";
    }
    return typeof value === "object" ? JSON.stringify(value) : String(value);
  }

  // Field paths, not display labels, identify columns. Records remain unmodified.
  var tableProfiles = [
    { commands: "callbacks", kinds: "ObjectCallbackRegistration", fields: "callbackType preRoutine postRoutine flags preSymbol postSymbol routine symbol module family ownership slot objectType active reason scope" },
    { commands: "nmi gdt hal", kinds: "RoutineObservation CallbackTable", fields: "family routine symbol module ownership context slot cpu vector objectType operations handler address reason" },
    { commands: "hive", kinds: "RegistryHive", fields: "rootPath filePath fileUserName hive flags fileSize routine symbol ownership" },
    { commands: "timer", kinds: "KernelTimer", fields: "cpu dueTimeRaw periodMs signalState routine symbol dpc decode object queue" },
    { commands: "dpc", kinds: "QueuedDpc", fields: "cpu queue routine symbol module importance deferredContext object ownership" },
    { commands: "fwtable", kinds: "", fields: "provider routine symbol module ownership signature record" },
    { commands: "idt", kinds: "IdtGate", fields: "cpu vector routine symbol symbolSource module ownership type dpl present validGate slot" },
    { commands: "ssdt", kinds: "", fields: "pid image filterMode filterSet filterDecision session serviceId serviceName blockedServices allowedServices auditServices unknownServices win32kDisable family symbol routine dispatchState entryRoutine ownership index slot" },
    { commands: "process procscan dml_proc", kinds: "Process", fields: "eprocess pid image dtb createTime" },
    { commands: "threads thread", kinds: "Thread", fields: "tid ethread process.pid process.image start startSymbol win32Start win32StartSymbol startOwner win32StartOwner" },
    { commands: "lm modules", kinds: "Module", fields: "name base symbol size path moduleIdentity" },
    { commands: "stack k kb kp kv", kinds: "StackFrame", fields: "index address symbol module stack return sourceFile sourceLine" },
    { commands: "registers r", kinds: "Register", fields: "name value rawBytes type" },
    { commands: "cr", kinds: "", fields: "cpu register value writeProtect smep smap la57 unavailableReason registerSource" },
    { commands: "msrcheck", kinds: "ProcessorRegister", fields: "cpu register value unavailableReason registerSource" },
    { commands: "breakpoints bl", kinds: "Breakpoint", fields: "address symbol condition enabled id expression trigger command passCount currentPassCount matchThreadId oneShot goOnly" },
    { commands: "event", kinds: "LastEvent Breakpoint", fields: "address symbol condition enabled id expression trigger command passCount matchThreadId description" },
    { commands: "u ub uf", kinds: "HostFunctionDisassembly", fields: "address bytes instruction symbol" },
    { commands: "dt", kinds: "", fields: "field offset type pointer symbol size bitOffset bitWidth arrayCount bytes valueStatus" },
    { commands: "x ln", kinds: "", fields: "symbol address displacement type" },
    { commands: "vad", kinds: "Vad", fields: "start end pageProtection executableByVad object process.pid process.image protectionIndex" },
    { commands: "handles", kinds: "ProcessHandle", fields: "ownerPid targetPid handle object typeIndex grantedAccess crossProcess" },
    { commands: "hiddenproc", kinds: "ProcessCrossView", fields: "pid observation activeList.image cidTable.image activeList.eprocess cidTable.eprocess activeList.createTime cidTable.createTime kernel.image host.image kernel.eprocess kernel.createTime host.createTime" },
    { commands: "drvobj", kinds: "DriverDispatch Driver", fields: "name major handler symbol ownership driverName device driverObject object start size" },
    { commands: "devstack", kinds: "Device DeviceAttachment", fields: "driverName device type stackSize flags driverObject link attachedFrom attachedTo" },
    { commands: "etw", kinds: "EtwLoggerContext EtwSession", fields: "name loggerId loggerStatus loggerMode eventsLost logFile clockType rawClock object clockRepresentation" },
    { commands: "alpc", kinds: "AlpcPort", fields: "name portType owner.pid owner.image connectionName address peerPort connectionPort nameState ownerProcess" },
    { commands: "minifilter", kinds: "Minifilter", fields: "name altitude family major routine symbol module ownership filter object frame" },
    { commands: "dds dqs dps", kinds: "MemoryPointer", fields: "address pointer symbol symbolSource readable width" },
    { commands: "?", kinds: "ExpressionValue", fields: "expression value symbol symbolSource unsigned signed" },
    { commands: "vtop kpage", kinds: "PageTranslation", fields: "va symbol pa dtb pageSize writable executable error entries" },
    { commands: "module", kinds: "ModulePeObservation", fields: "module base symbol size timestamp sections" },
    { commands: "unloaded", kinds: "UnloadedDriver", fields: "name StartAddress EndAddress CurrentTime timeBasis index record ringNextIndex" },
    { commands: "piddb", kinds: "PiDDBEntry", fields: "name timeDateStamp loadStatus loadStatusClass entry reason" },
    { commands: "cihash", kinds: "CiHashEntry", fields: "name hash secondaryHash cacheStatusRaw entry reason" },
    { commands: "token", kinds: "ProcessToken", fields: "process.pid tokenTypeName mandatoryLabelRid privilegesPresent privilegesEnabled privilegesEnabledByDefault address AuthenticationId TokenId SessionId" },
    { commands: "mapper", kinds: "", fields: "sourceCommand name timeDateStamp loadStatus hash StartAddress EndAddress cacheStatusRaw entry" },
    { commands: "wnf", kinds: "WnfNameDecode", fields: "encoded lifetimeName scopeName permanentData ownerTagText sequence version" },
    { commands: "etl-import", kinds: "EtwEvent", fields: "providerName eventId taskName opcodeName pid tid timestampFileTime payloadBytes provider" },
    { commands: "pool bigpool", kinds: "BigPoolAllocation", fields: "address symbol tag size nonPaged" },
    { commands: "payload", kinds: "", fields: "address tag size wxObserved rangeClassified inspectedPages totalPages unavailablePages ownership mode" },
    { commands: "ioctl", kinds: "IoctlDecode", fields: "code deviceType function method access" },
    { commands: "ntstatus", kinds: "NtStatusDecode", fields: "value name severity facility code" },
    { commands: "diag-catalog diagnose triage", kinds: "DiagnosticRecipe DiagnosticStep HostDiagnostic", fields: "id name category recipe command status description reason" }
  ];

  function columnValue(row, path)
  {
    if (row && row.kind === "Breakpoint" && path.length === 1 && path[0] === "symbol" && !row.symbol &&
        row.deferred && typeof row.expression === "string" && row.expression)
    {
      return row.expression + " (deferred)";
    }
    if (row && path.length === 1 && path[0] === "major" &&
        (row.kind === "DriverDispatch" || row.family === "Minifilter.PreOperation" || row.family === "Minifilter.PostOperation") &&
        typeof row.majorName === "string" && row.majorName)
    {
      // The grid uses the name; the immutable record retains the numeric major.
      return row.majorName;
    }
    if (row && typeof row.callbackType === "string" && row.callbackType.indexOf("Object.") !== 0 && path.length === 1)
    {
      // A single-routine registration shares the primary routine/symbol columns.
      if (path[0] === "preRoutine")
      {
        return row.routine;
      }
      if (path[0] === "preSymbol")
      {
        return row.symbol;
      }
      if (path[0] === "preSymbolSource")
      {
        return row.symbolSource;
      }
    }
    var value = row;
    for (var i = 0; i < path.length; ++i)
    {
      if (value === null || typeof value !== "object" || !Object.prototype.hasOwnProperty.call(value, path[i]))
      {
        return undefined;
      }
      value = value[path[i]];
    }
    return value;
  }

  function columnLabel(path)
  {
    if (path.length === 1 && firstToken(state.resultMeta.commandId || state.resultCommand).replace(/^!/, "").toLowerCase() === "piddb")
    {
      var piddbLabels = { name: "Driver name", timeDateStamp: "PE timestamp (raw)", loadStatus: "Load status (NTSTATUS)",
        loadStatusClass: "Cached result", entry: "Cache entry" };
      if (Object.prototype.hasOwnProperty.call(piddbLabels, path[0]))
      {
        return piddbLabels[path[0]];
      }
    }
    if (path.length === 1 && ["breakpoints", "event"].indexOf(state.resultMeta.commandId) >= 0)
    {
      var breakpointLabels = { condition: "Condition (/w)", expression: "Address expression", matchThreadId: "Debugger thread" };
      if (Object.prototype.hasOwnProperty.call(breakpointLabels, path[0]))
      {
        return breakpointLabels[path[0]];
      }
    }
    var names = { pid: "PID", tid: "TID", eprocess: "EPROCESS", ethread: "ETHREAD", dtb: "DTB", rva: "RVA",
      id: "ID", cpu: "CPU", irql: "IRQL", rawBytes: "Raw bytes", ruleId: "Rule", addressSpace: "Address space",
      smep: "SMEP", smap: "SMAP", la57: "LA57", registerSource: "Read from", unavailableReason: "Why unavailable",
      callbackType: "Callback type", preRoutine: "Routine / Pre", postRoutine: "Post callback", preSymbol: "Symbol / Pre", postSymbol: "Post symbol" };
    names.dueTimeRaw = "Due time (raw 100 ns)";
    names.periodMs = "Period (ms)";
    names.wxObserved = "W+X observed";
    names.cacheStatusRaw = "Cache status (raw)";
    names.hash = "Hash (20 bytes)";
    names.secondaryHash = "Secondary hash (20 bytes)";
    return path.length ? path.map(function (key)
    {
      var label = Object.prototype.hasOwnProperty.call(names, key) ? names[key] :
        key.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_-]/g, " ");
      label = label.replace(/\b(pid|tid|id|cpu|rva|dtb|irp|ioctl|irql|etw|alpc|wnf|pdb|dpc|ssdt|pe)\b/gi, function (word)
      {
        return word.toUpperCase();
      });
      return label.charAt(0).toUpperCase() + label.slice(1);
    }).join(" / ") : "Value";
  }

  function activateTableLayout()
  {
    endColumnResize(false);
    var key = JSON.stringify([state.resultId, state.resultCollection]);
    var retained = state.resultRestore && state.resultRestore.layout;
    var layout = retained && retained.key === key ? retained : state.tableLayouts.find(function (item)
    {
      return item.key === key;
    });
    if (!layout)
    {
      layout = { key: key, columns: [], keys: Object.create(null), kinds: [], manual: false, limited: false,
        rowNumber: { key: "#", label: "#", path: [], width: 48, defaultWidth: 48 } };
    }
    state.tableLayouts = state.tableLayouts.filter(function (item)
    {
      return item.key !== key;
    });
    state.tableLayouts.unshift(layout);
    state.tableLayouts = state.tableLayouts.slice(0, 32);
    state.tableLayout = layout;
    if (state.resultRestore && Object.prototype.hasOwnProperty.call(state.resultRestore, "sort"))
    {
      layout.sort = state.resultRestore.sort;
    }
    var menu = uiElement("result-columns");
    if (menu.contains && menu.contains(uiActiveElement()))
    {
      uiElement("columns-toggle").focus();
    }
    menu.open = false;
    renderColumnChoices();
    renderTableHeader();
  }

  function discoverColumns(rows)
  {
    var layout = state.tableLayout;
    var changed = false;
    var wasLimited = layout.limited;
    var command = firstToken(state.resultMeta.commandId || state.resultCommand).replace(/^!/, "").toLowerCase();
    var recordWidths = {
      cihash: { name: 520, hash: 320, secondaryHash: 320 },
      mapper: { name: 480, hash: 320 },
      hive: { rootPath: 360, filePath: 400, fileUserName: 480 },
      alpc: { name: 360 },
      etw: { name: 360, logFile: 440 },
      drvobj: { major: 240, name: 320, driverName: 240 },
      devstack: { driverName: 240 }
    };
    function visit(value, path, descend)
    {
      var key = JSON.stringify(path);
      if (path.length || value === null || typeof value !== "object" || Array.isArray(value))
      {
        if (!layout.keys[key])
        {
          if (layout.columns.length >= 96)
          {
            layout.limited = true;
            return;
          }
          var field = path.join(".");
          var address = /(?:address|routine|slot|base|eprocess|ethread|dtb|stack|return|start|end|object|handler|pointer)$/i.test(field);
          var wide = /(?:message|reason|description|instruction|path|symbol|interpretation|text)$/i.test(field);
          var narrow = /(?:^|\.)(?:pid|tid|id|index|cpu|size|count|enabled|severity|type|register|writeProtect|smep|smap|la57)$/i.test(field);
          var column = { key: key, path: path, label: columnLabel(path), visible: false,
            width: field === "rawBytes" ? 300 : wide ? 280 : address ? 172 : narrow ? 96 : 160,
            css: address ? "row-address" : "row-value" };
          if (state.resultCollection === "rows" && Object.prototype.hasOwnProperty.call(recordWidths, command) &&
              Object.prototype.hasOwnProperty.call(recordWidths[command], field))
          {
            column.width = recordWidths[command][field];
          }
          if (state.resultMeta.commandId === "breakpoints" && state.resultCollection === "rows" && field === "enabled")
          {
            column.width = 176;
            column.minWidth = 160;
          }
          if (state.resultMeta.commandId === "event" && state.resultCollection === "rows")
          {
            column.width = field === "kind" ? 104 : field === "id" ? 64 : field === "condition" ? 240 : column.width;
          }
          column.defaultWidth = column.width;
          layout.keys[key] = column;
          layout.columns.push(column);
          changed = true;
        }
      }
      if (descend !== false && value && typeof value === "object" && !Array.isArray(value) && path.length < 2)
      {
        Object.keys(value).forEach(function (name)
        {
          if (name.length > 256)
          {
            layout.limited = true;
            return;
          }
          visit(value[name], path.concat(name));
        });
      }
    }
    rows.forEach(function (row)
    {
      if (row && typeof row.callbackType === "string" && !layout.callbackRegistrations)
      {
        layout.callbackRegistrations = true;
        changed = true;
      }
      if (row && typeof row.kind === "string" && row.kind.length <= 256 && layout.kinds.indexOf(row.kind) < 0 && layout.kinds.length < 96)
      {
        layout.kinds.push(row.kind);
        changed = true;
      }
    });
    // Add command fields before metadata uses up the column limit.
    var priority = columnPriority();
    rows.forEach(function (row)
    {
      priority.forEach(function (field)
      {
        var path = field.split(".");
        var value = columnValue(row, path);
        if (value !== undefined)
        {
          visit(value, path, false);
        }
      });
    });
    rows.forEach(function (row)
    {
      visit(row, []);
    });
    if (changed || wasLimited !== layout.limited)
    {
      updateColumnLabels();
      if (!layout.manual)
      {
        recommendColumns();
      }
      renderColumnChoices();
    }
  }

  function columnPriority()
  {
    var layout = state.tableLayout;
    var command = firstToken(state.resultMeta.commandId || state.resultCommand).replace(/^!/, "").toLowerCase();
    var profile = tableProfiles.find(function (item)
    {
      return item.commands.split(" ").indexOf(command) >= 0;
    }) || tableProfiles.find(function (item)
    {
      return layout.kinds.some(function (kind)
      {
        return item.kinds.split(" ").indexOf(kind) >= 0;
      });
    });
    var preferred = state.resultCollection === "findings" ? "severity ruleId message reason address module source file line" :
      command === "callbacks" && layout.callbackRegistrations ? "callbackType preRoutine postRoutine flags preSymbol postSymbol" :
      command === "ssdt" && layout.kinds.indexOf("Win32kServicePolicy") >= 0 ?
        "serviceName filterDecision serviceId pid session image filterMode filterSet filterBit entryRoutine policyReason" :
      (profile ? profile.fields : "name image pid tid address routine module symbol value status message reason");
    var priority = preferred.split(" ");
    if (layout.kinds.length > 1 && !(command === "callbacks" && layout.callbackRegistrations && state.resultCollection === "rows"))
    {
      priority.unshift("kind");
    }
    // Coverage gaps and export references must stay understandable in mixed tables.
    if (layout.kinds.indexOf("CoverageGap") >= 0 || layout.kinds.indexOf("RecordReference") >= 0)
    {
      if (command === "callbacks" && layout.kinds.indexOf("RecordReference") < 0)
      {
        priority.push("reason", "scope");
      }
      else
      {
        priority.unshift("reason", "scope");
      }
    }
    return priority;
  }

  function recommendColumns()
  {
    var layout = state.tableLayout;
    var priority = columnPriority();
    function rank(column)
    {
      var field = column.path.join(".");
      var index = priority.indexOf(field);
      if (index >= 0)
      {
        return index;
      }
      return /^(?:kind|context|target|addressSpace|interpretation|layoutSource|verification|moduleIdentity)(?:\.|$)/.test(field) ? 200 :
        column.path.length > 1 ? 150 : 100;
    }
    layout.columns.sort(function (left, right)
    {
      return rank(left) - rank(right);
    });
    layout.columns.forEach(function (column, index)
    {
      var callbackColumns = layout.callbackRegistrations && state.resultCollection === "rows" &&
        firstToken(state.resultMeta.commandId || state.resultCommand).replace(/^!/, "").toLowerCase() === "callbacks" &&
        layout.kinds.indexOf("RecordReference") < 0;
      column.visible = index < (callbackColumns ? 6 : 9) && (rank(column) < 200 || layout.columns.length <= 3) &&
        (!callbackColumns || priority.indexOf(column.path.join(".")) >= 0);
      var command = firstToken(state.resultMeta.commandId || state.resultCommand).replace(/^!/, "").toLowerCase();
      if (state.resultCollection === "rows" &&
          ((layout.kinds.indexOf("PiDDBEntry") >= 0 && command === "piddb") ||
           (layout.kinds.indexOf("CiHashEntry") >= 0 && command === "cihash")))
      {
        column.visible = priority.indexOf(column.path.join(".")) >= 0;
      }
    });
    if (!visibleColumns().length && layout.columns.length)
    {
      layout.columns[0].visible = true;
    }
  }

  function updateColumnLabels()
  {
    var counts = Object.create(null);
    var used = Object.create(null);
    used["#"] = true;
    function normalized(label)
    {
      return label.replace(/\s+/g, " ").trim();
    }
    state.tableLayout.columns.forEach(function (column)
    {
      var base = normalized(column.summary ? "Observation" : columnLabel(column.path));
      counts[base] = (counts[base] || 0) + 1;
    });
    state.tableLayout.columns.forEach(function (column)
    {
      var base = normalized(column.summary ? "Observation" : columnLabel(column.path));
      var exact = (base || "Field") + " " + column.key;
      var label = !base || counts[base] > 1 || base === "#" ? exact : base;
      var suffix = 1;
      while (used[normalized(label)])
      {
        label = exact + " [" + suffix++ + "]";
      }
      used[normalized(label)] = true;
      column.label = label;
    });
  }

  function visibleColumns()
  {
    return state.tableLayout ? state.tableLayout.columns.filter(function (column)
    {
      return column.visible;
    }) : [];
  }

  var tableCollator = new Intl.Collator("en", { numeric: true, sensitivity: "base" });

  function tableSortValue(value)
  {
    if (value === null || value === undefined || value === "")
    {
      return { rank: 2 };
    }
    if (typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value)))
    {
      return { rank: 0, value: Number(value) };
    }
    if (typeof value === "string" && value.length <= 128)
    {
      var text = value.trim();
      if (/^[+-]?\d+$/.test(text))
      {
        return { rank: 0, value: BigInt(text) };
      }
      if (/^0x[0-9a-f]+$/i.test(text) || /^(?:0x)?[0-9a-f]{1,8}`[0-9a-f]{8}$/i.test(text))
      {
        return { rank: 0, value: BigInt("0x" + text.replace(/^0x/i, "").replace("`", "")) };
      }
      if (/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(text) && Number.isFinite(Number(text)))
      {
        return { rank: 0, value: Number(text) };
      }
    }
    return { rank: 1, value: scalar(value) };
  }

  function compareTableSortKeys(left, right, direction)
  {
    // Missing values stay last in either direction.
    if (left.rank === 2 || right.rank === 2)
    {
      return left.rank === right.rank ? 0 : left.rank === 2 ? 1 : -1;
    }
    var comparison = left.rank - right.rank;
    if (!comparison)
    {
      comparison = left.rank === 0 ? (left.value < right.value ? -1 : left.value > right.value ? 1 : 0) :
        tableCollator.compare(left.value, right.value);
    }
    return comparison * direction;
  }

  function applyTableSort(sorting)
  {
    if (sorting !== state.tableSort || !sorting.requested)
    {
      return;
    }
    var choice = sorting.requested;
    var direction = choice.direction === "ascending" ? 1 : -1;
    var keyed = sorting.entries.map(function (entry)
    {
      var value = choice.index ? entry.index : choice.path.length ? columnValue(entry.row, choice.path) :
        entry.row && typeof entry.row === "object" ? observationSummary(entry.row) : entry.row;
      if (!choice.index && typeof value === "string" && value !== "")
      {
        value = displayField(value, choice.path, entry.row);
      }
      return { entry: entry, key: tableSortValue(value) };
    });
    keyed.sort(function (left, right)
    {
      return compareTableSortKeys(left.key, right.key, direction) || left.entry.index - right.entry.index;
    });
    sorting.order = keyed.map(function (item)
    {
      return item.entry;
    });
    sorting.applied = choice;
    sorting.requested = null;
    sorting.error = "";
    state.tableLayout.sort = choice;
    ++state.resultRevision;
    state.selectedIndex = sorting.order.findIndex(function (entry)
    {
      return entry.index === state.selectedOriginalIndex;
    });
    selectObservation(state.selectedIndex >= 0 ? sorting.order[state.selectedIndex].row : null);
    state.pendingSelection = -1;
    state.rowOffset = -1;
    state.rowCache = [];
    state.rowIndices = [];
    els.resultView.scrollTop = state.resultRestore ? state.resultRestore.scrollTop : 0;
    updateTableBusy();
    showRows(true);
  }

  function loadTableSort(sorting)
  {
    if (sorting.entries)
    {
      applyTableSort(sorting);
      return;
    }
    if (sorting.loading)
    {
      updateRowSelection();
      return;
    }
    if (state.rowOffset === 0 && state.rowCache.length === state.rowCount)
    {
      sorting.entries = state.rowCache.map(function (row, index)
      {
        return { row: row, index: state.rowIndices[index] };
      });
      applyTableSort(sorting);
      return;
    }
    sorting.loading = true;
    sorting.loaded = 0;
    updateTableBusy();
    updateRowSelection();
    var id = state.resultId;
    var collection = state.resultCollection;
    var total = collection === "findings" ? state.findingCount : state.observationCount;
    var limit = state.rowCount;
    var base = state.rowBase;
    var entries = state.rowOffset === 0 ? state.rowCache.map(function (row, index)
    {
      return { row: row, index: state.rowIndices[index] };
    }) : [];
    sorting.loaded = entries.length;
    updateRowSelection();
    function fetchPage(cursor)
    {
      return send("resultPage", { resultId: id, offset: String(cursor), collection: collection }).then(function (reply)
      {
        if (sorting !== state.tableSort)
        {
          return;
        }
        var page = checkedResultPage(reply, id, collection, cursor, total);
        if (base && cursor === 0 && (!page[0] || page[0].kind !== "LastEvent"))
        {
          throw new Error("The event record order could not be verified.");
        }
        var skip = Math.max(0, base - cursor);
        page.slice(skip, skip + limit - entries.length).forEach(function (row, index)
        {
          entries.push({ row: row, index: cursor + skip + index });
        });
        sorting.loaded = entries.length;
        updateRowSelection();
        if (entries.length < limit)
        {
          return fetchPage(cursor + page.length);
        }
      });
    }
    fetchPage(entries.length ? entries.length + base : 0).then(function ()
    {
      if (sorting !== state.tableSort)
      {
        return;
      }
      sorting.entries = entries;
      sorting.loading = false;
      applyTableSort(sorting);
    }).catch(function (error)
    {
      if (sorting !== state.tableSort)
      {
        return;
      }
      sorting.loading = false;
      sorting.requested = null;
      sorting.error = "Sort could not be applied. " + error.message;
      updateTableBusy();
      renderTableHeader();
      updateEvidenceSummary();
      updateRowSelection();
      showRows();
    });
  }

  function sortTableColumn(column, index)
  {
    if (!state.resultId || !state.rowCount)
    {
      return;
    }
    var sorting = state.tableSort;
    var current = sorting.requested || sorting.applied;
    var key = index === 0 ? "#" : column.key;
    sorting.requested = { key: key, path: column.path, index: index === 0, label: column.label,
      direction: current && current.key === key && current.direction === "ascending" ? "descending" : "ascending" };
    sorting.error = "";
    renderTableHeader();
    updateEvidenceSummary();
    loadTableSort(sorting);
  }

  function renderTableHeader()
  {
    endColumnResize(false);
    var head = uiElement("table-head");
    var columns = visibleColumns();
    var focusedKey = uiActiveElement() && uiActiveElement().dataset && uiActiveElement().dataset.sortKey;
    var resizeKey = uiActiveElement() && uiActiveElement().dataset && uiActiveElement().dataset.resizeKey;
    var focusedButton = null;
    head.textContent = "";
    var template = applyTableWidths();
    tableColumns().forEach(function (column, index)
    {
      var cell = document.createElement("span");
      cell.setAttribute("role", "columnheader");
      cell.setAttribute("aria-colindex", String(index + 1));
      cell.title = index ? column.key : "Original row number";
      var key = index ? column.key : "#";
      var sort = state.tableSort.applied;
      var sorted = sort && sort.key === key;
      cell.setAttribute("aria-sort", sorted ? sort.direction : "none");
      var button = document.createElement("button");
      button.type = "button";
      button.className = "table-sort";
      button.dataset.sortKey = key;
      button.dataset.sortDirection = sorted ? sort.direction : "none";
      button.textContent = column.label;
      var pending = state.tableSort.requested || sort;
      button.title = "Sort " + (pending && pending.key === key && pending.direction === "ascending" ? "descending" : "ascending") +
        " by " + column.label;
      button.setAttribute("aria-label", column.label + ": " + button.title);
      button.disabled = !state.rowCount;
      button.addEventListener("click", function ()
      {
        sortTableColumn(column, index);
      });
      button.addEventListener("focus", function ()
      {
        revealTableColumn(column, index, cell, false);
      });
      cell.appendChild(button);
      var handle = columnResizeHandle(column, index, cell);
      cell.appendChild(handle);
      head.appendChild(cell);
      if (key === focusedKey)
      {
        focusedButton = button;
      }
      if (key === resizeKey)
      {
        focusedButton = handle;
      }
    });
    uiElement("result-table").setAttribute("aria-colcount", String(columns.length + 1));
    syncTableViewport();
    if (focusedButton)
    {
      focusedButton.focus({ preventScroll: true });
    }
    return template;
  }

  function syncTableViewport()
  {
    var head = uiElement("table-head");
    head.style.width = Math.max(parseInt(head.style.minWidth, 10) || 0, els.resultView.clientWidth || 0) + "px";
    head.style.transform = "translateX(" + -els.resultView.scrollLeft + "px)";
    tableColumns().forEach(function (column, index)
    {
      var cell = head.children[index];
      if (cell && cell.children[1])
      {
        cell.children[1].setAttribute("aria-valuenow", String(Math.round(measuredColumnWidth(column, cell))));
      }
    });
  }

  function tableColumns()
  {
    return state.tableLayout ? [state.tableLayout.rowNumber].concat(visibleColumns()) : [];
  }

  function measuredColumnWidth(column, cell)
  {
    var width = cell.getBoundingClientRect().width;
    return Number.isFinite(width) && width > 0 ? width : column.width;
  }

  function applyTableWidths()
  {
    var columns = tableColumns();
    var template = columns.map(function (column, index)
    {
      return index === columns.length - 1 && !column.fixedWidth ? "minmax(" + column.width + "px, 1fr)" : column.width + "px";
    }).join(" ");
    var minimum = columns.reduce(function (total, column)
    {
      return total + column.width;
    }, 0) + "px";
    var head = uiElement("table-head");
    head.style.gridTemplateColumns = template;
    head.style.minWidth = minimum;
    els.resultRows.style.minWidth = minimum;
    els.resultSpacer.style.minWidth = minimum;
    Array.prototype.forEach.call(els.resultRows.children, function (row)
    {
      row.style.gridTemplateColumns = template;
    });
    syncTableViewport();
    return template;
  }

  function revealTableColumn(column, index, cell, trailing)
  {
    var left = tableColumns().slice(0, index).reduce(function (total, item)
    {
      return total + item.width;
    }, 0);
    var width = measuredColumnWidth(column, cell);
    var viewport = els.resultView.clientWidth || 0;
    if (viewport)
    {
      if (width > viewport)
      {
        els.resultView.scrollLeft = trailing ? left + width - viewport : left;
      }
      else if (left < els.resultView.scrollLeft)
      {
        els.resultView.scrollLeft = left;
      }
      else if (left + width > els.resultView.scrollLeft + viewport)
      {
        els.resultView.scrollLeft = left + width - viewport;
      }
      uiElement("result-table").scrollLeft = 0;
      syncTableViewport();
    }
  }

  function setColumnWidth(column, width)
  {
    column.width = Math.round(Math.max(column.minWidth || (column.key === "#" ? 48 : 64), Math.min(4096, width)));
    column.fixedWidth = true;
    applyTableWidths();
  }

  function endColumnResize(cancelled)
  {
    var drag = state.columnDrag;
    if (!drag)
    {
      return;
    }
    state.columnDrag = null;
    els.root.classList.remove("column-resizing");
    if (cancelled)
    {
      drag.column.width = drag.previousWidth;
      drag.column.fixedWidth = drag.previousFixed;
      applyTableWidths();
      els.resultView.scrollLeft = drag.startScroll;
      syncTableViewport();
    }
    if (typeof drag.handle.hasPointerCapture === "function" && drag.handle.hasPointerCapture(drag.pointerId))
    {
      drag.handle.releasePointerCapture(drag.pointerId);
    }
  }

  function moveColumnResize(event)
  {
    var drag = state.columnDrag;
    if (drag && event.pointerId === drag.pointerId && Number.isFinite(event.clientX))
    {
      event.preventDefault();
      // Width-driven scroll clamping is not pointer movement.
      var delta = event.clientX - drag.startX;
      if (delta !== 0 || drag.moved)
      {
        drag.moved = true;
        setColumnWidth(drag.column, drag.startWidth + delta);
      }
    }
  }

  function columnResizeHandle(column, index, cell)
  {
    var handle = document.createElement("span");
    handle.className = "table-resize";
    handle.tabIndex = 0;
    handle.dataset.resizeKey = column.key;
    handle.setAttribute("role", "separator");
    handle.setAttribute("aria-label", "Resize " + column.label + " column");
    handle.setAttribute("aria-controls", "result-table");
    handle.setAttribute("aria-orientation", "vertical");
    handle.setAttribute("aria-valuemin", String(column.minWidth || (column.key === "#" ? 48 : 64)));
    handle.setAttribute("aria-valuemax", "4096");
    handle.title = "Drag to resize. Left/Right adjust width; Shift uses larger steps; Home/End choose limits. Double-click restores default.";
    handle.addEventListener("focus", function ()
    {
      revealTableColumn(column, index, cell, true);
    });
    handle.addEventListener("click", function (event)
    {
      event.preventDefault();
      event.stopPropagation();
    });
    handle.addEventListener("dblclick", function (event)
    {
      event.preventDefault();
      endColumnResize(false);
      column.width = column.defaultWidth;
      column.fixedWidth = false;
      applyTableWidths();
      revealTableColumn(column, index, cell, true);
    });
    handle.addEventListener("pointerdown", function (event)
    {
      if (state.columnDrag || state.memoryPanel.drag || state.inspectorPanel.drag || event.button !== 0 || event.isPrimary === false || !Number.isFinite(event.clientX))
      {
        return;
      }
      event.preventDefault();
      handle.focus({ preventScroll: true });
      if (typeof handle.setPointerCapture === "function")
      {
        try
        {
          handle.setPointerCapture(event.pointerId);
        }
        catch (error)
        {
          workspaceFeedback("Drag unavailable. Focus the column divider and use Left/Right to resize.");
          return;
        }
      }
      state.columnDrag = { handle: handle, column: column, pointerId: event.pointerId, startX: event.clientX,
        startScroll: els.resultView.scrollLeft, startWidth: measuredColumnWidth(column, cell),
        previousWidth: column.width, previousFixed: column.fixedWidth };
      els.root.classList.add("column-resizing");
    });
    handle.addEventListener("lostpointercapture", function ()
    {
      if (state.columnDrag && state.columnDrag.handle === handle)
      {
        endColumnResize(false);
      }
    });
    handle.addEventListener("keydown", function (event)
    {
      if (event.ctrlKey || event.altKey || event.metaKey || event.isComposing ||
          ["ArrowLeft", "ArrowRight", "Home", "End"].indexOf(event.key) < 0)
      {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      endColumnResize(false);
      var step = event.shiftKey ? 64 : 16;
      var width = event.key === "Home" ? Number(handle.getAttribute("aria-valuemin")) : event.key === "End" ? 4096 :
        measuredColumnWidth(column, cell) + (event.key === "ArrowLeft" ? -step : step);
      setColumnWidth(column, width);
      revealTableColumn(column, index, cell, true);
    });
    return handle;
  }

  function renderColumnChoices()
  {
    var layout = state.tableLayout;
    var list = uiElement("column-list");
    var focusedKey = uiActiveElement() && uiActiveElement().dataset && uiActiveElement().dataset.columnKey;
    var scrollTop = list.scrollTop;
    var focusedInput = null;
    list.textContent = "";
    layout.columns.forEach(function (column)
    {
      var label = document.createElement("label");
      var input = document.createElement("input");
      var text = document.createElement("span");
      input.type = "checkbox";
      input.checked = column.visible;
      input.dataset.columnKey = column.key;
      input.setAttribute("aria-label", column.label);
      input.addEventListener("change", function ()
      {
        column.visible = input.checked;
        layout.manual = true;
        renderRows();
        updateColumnCount();
      });
      text.textContent = column.label;
      label.title = column.key;
      label.appendChild(input);
      label.appendChild(text);
      list.appendChild(label);
      if (column.key === focusedKey)
      {
        focusedInput = input;
      }
    });
    updateColumnCount();
    list.scrollTop = scrollTop;
    if (focusedInput)
    {
      focusedInput.focus({ preventScroll: true });
    }
  }

  function updateColumnCount()
  {
    var layout = state.tableLayout;
    uiElement("columns-toggle").textContent = "Columns " + visibleColumns().length + "/" + layout.columns.length;
    uiElement("column-status").textContent = layout.limited ?
      "Field limit reached. Inspect a row or export for all fields." :
      "Fields from loaded pages. Select a row for its complete record.";
    positionToolMenus();
  }

  function positionToolMenus(event)
  {
    (resultMenus || []).forEach(function (ids)
    {
      var menu = uiElement(ids[0]);
      var popup = uiElement(ids[2]);
      var toggle = uiElement(ids[1]);
      if (!menu.open || (event && popup.contains(event.target)))
      {
        return;
      }
      var anchor = toggle.getBoundingClientRect();
      var margin = 8;
      var viewportWidth = window.innerWidth;
      var viewportHeight = window.innerHeight;
      if (anchor.bottom < 0 || anchor.top > viewportHeight || anchor.right < 0 || anchor.left > viewportWidth)
      {
        menu.open = false;
        if (menu.contains(uiActiveElement()))
        {
          toggle.focus({ preventScroll: true });
        }
        return;
      }
      var width = Math.min(ids[0] === "result-info" ? 460 : 320, Math.max(0, viewportWidth - 2 * margin));
      var maximumHeight = Math.max(0, viewportHeight - 2 * margin);
      popup.style.width = width + "px";
      var contentHeight = popup.scrollHeight + popup.offsetHeight - popup.clientHeight;
      var desiredHeight = Math.min(contentHeight || 400, maximumHeight);
      var below = viewportHeight - margin - anchor.bottom - 6;
      var above = anchor.top - 6 - margin;
      var down = below >= desiredHeight || below >= above;
      var available = Math.max(0, down ? below : above);
      var floating = available < Math.min(200, desiredHeight);
      popup.style.maxHeight = (floating ? maximumHeight : available) + "px";
      var left = ids[0] === "breakpoint-create" ? anchor.left : anchor.right - width;
      popup.style.left = Math.max(margin, Math.min(left, viewportWidth - width - margin)) + "px";
      popup.style.top = (floating ? margin : down ? anchor.bottom + 6 : anchor.top - 6 - popup.offsetHeight) + "px";
    });
  }

  listenWindow("scroll", positionToolMenus, true);

  uiElement("btn-columns-reset").addEventListener("click", function ()
  {
    if (state.tableLayout)
    {
      state.tableLayout.manual = false;
      recommendColumns();
      renderColumnChoices();
      renderRows();
    }
  });
  uiElement("btn-columns-all").addEventListener("click", function ()
  {
    if (state.tableLayout)
    {
      state.tableLayout.manual = true;
      state.tableLayout.columns.forEach(function (column)
      {
        column.visible = true;
      });
      renderColumnChoices();
      renderRows();
    }
  });
  uiElement("btn-columns-widths").addEventListener("click", function ()
  {
    if (state.tableLayout)
    {
      endColumnResize(false);
      [state.tableLayout.rowNumber].concat(state.tableLayout.columns).forEach(function (column)
      {
        column.width = column.defaultWidth;
        column.fixedWidth = false;
      });
      applyTableWidths();
    }
  });
  uiElement("result-columns").addEventListener("keydown", function (event)
  {
    if (event.key === "Escape")
    {
      event.preventDefault();
      uiElement("result-columns").open = false;
      uiElement("columns-toggle").focus();
    }
  });

  function tableCellText(value)
  {
    return value === undefined ? "\u2014" : value === null ? "Unknown" : value === "" ? "(empty)" :
      value === true ? "Yes" : value === false ? "No" : scalar(value);
  }

  function displayField(value, path, row)
  {
    if (row && row.kind === "Breakpoint" && path.length === 1)
    {
      if (path[0] === "condition")
      {
        return value === "" ? "None" : value === null || value === undefined ? "Unavailable (see Row details)" : tableCellText(value);
      }
      if (path[0] === "command" && value === "")
      {
        return "None";
      }
      if (path[0] === "matchThreadId" && value === null)
      {
        return "Any debugger thread";
      }
      if (path[0] === "address" && row.deferred && value === null)
      {
        return "Deferred (see expression)";
      }
    }
    var field = path.join(".");
    if (row && row.kind === "AlpcPort" && field === "name" && value == null)
    {
      return row.nameState === "Unnamed" ? "Unnamed" : "Name unavailable";
    }
    if (!path.length)
    {
      return observationSummary(row);
    }
    if (row && typeof row.callbackType === "string")
    {
      var paired = row.callbackType.indexOf("Object.") === 0;
      if (value === undefined && ((!paired && ["preRoutine", "postRoutine", "preSymbol", "postSymbol"].indexOf(field) >= 0) ||
          (paired && ["routine", "symbol"].indexOf(field) >= 0)))
      {
        return "N/A";
      }
      if (value === null && (field === "preSymbol" || field === "postSymbol") &&
          row[field + "Source"] === "NotRegistered")
      {
        return "Not registered";
      }
    }
    if (value === null && row && /(?:^symbol|Symbol)$/.test(field))
    {
      var source = columnValue(row, path.slice(0, -1).concat(path[path.length - 1] + "Source"));
      return source === "NotRegistered" ? "Not registered" : source === "NullAddress" ? "Null address" : "Unresolved";
    }
    var labels = {
      SavedProcessorState: "Saved CPU state", CurrentProcessorMsr: "Event CPU (MSR)",
      ProcessorSwitchRequired: "Not read on this CPU", CurrentEventProcessorUnverified: "Event CPU could not be verified",
      CurrentProcessorMsrUnreadable: "MSR read failed", ProcessorBlockUnavailable: "CPU state unavailable",
      SavedRegisterLayoutUnavailable: "Saved register layout unavailable", SavedRegisterUnreadable: "Saved register unreadable"
    };
    if ((field === "registerSource" || field === "unavailableReason") && typeof value === "string" &&
      Object.prototype.hasOwnProperty.call(labels, value))
    {
      return labels[value];
    }
    return tableCellText(value);
  }

  function renderRows()
  {
    closeCopyMenu();
    ensureObservationColumn();
    var template = renderTableHeader();
    var columns = visibleColumns();
    if (els.resultRows.contains && els.resultRows.contains(uiActiveElement()))
    {
      uiElement("result-table").focus();
    }
    els.resultRows.textContent = "";
    state.breakpoints.rowControls = [];
    els.resultRows.style.transform = "translateY(" + state.rowOffset * workspaceRowHeight() + "px)";
    state.rowCache.forEach(function (row, local)
    {
      var index = state.rowOffset + local;
      var original = state.rowIndices[local];
      var entry = document.createElement("div");
      entry.className = "result-row" + (index === state.selectedIndex ? " selected" : "");
      var event = state.resultMeta.commandId === "event" && state.resultMeta.analysis && state.resultMeta.analysis.lastEvent;
      if (event && row && row.kind === "Breakpoint" && row.id === event.breakpointId)
      {
        entry.classList.add("event-matched-breakpoint");
        entry.setAttribute("aria-description", "Matches the last event breakpoint ID; these are settings at capture time");
      }
      entry.id = "observation-" + index;
      entry.setAttribute("role", "row");
      entry.setAttribute("aria-rowindex", String(index + 2));
      entry.setAttribute("aria-selected", String(index === state.selectedIndex));
      entry.style.gridTemplateColumns = template;
      [null].concat(columns).forEach(function (column, columnIndex)
      {
        var value = column ? displayField(columnValue(row, column.path), column.path, row) : String(original + 1 - state.rowBase);
        var cell = document.createElement("span");
        cell.className = column ? column.css : "row-index";
        cell.setAttribute("role", "gridcell");
        cell.setAttribute("aria-colindex", String(columnIndex + 1));
        cell.textContent = value.length > 512 ? value.slice(0, 512) + "..." : value;
        cell.title = value.length > 4096 ? value.slice(0, 4096) + "... (see Row details)" : value;
        if (column && column.path.length === 1 && column.path[0] === "enabled" &&
          state.resultMeta.commandId === "breakpoints" && state.resultCollection === "rows" && row && row.kind === "Breakpoint")
        {
          renderBreakpointState(cell, row, index);
        }
        else if (column && columnValue(row, column.path) !== undefined)
        {
          var callbackField = callbackColumnField(row, column.path);
          var navigation = resultAddressNavigation(row, column.path, original);
          bindCopyValue(cell, function ()
          {
            return clipboardValue(columnValue(row, column.path));
          }, "value from row " + (original + 1), "Copy " + column.label + ", row " + (original + 1), function ()
          {
            chooseRow(index);
            if (callbackField)
            {
              selectCallbackAddress(callbackField);
            }
          }, function ()
          {
            return JSON.stringify(row, null, 2);
          }, navigation);
        }
        entry.appendChild(cell);
      });
      entry.addEventListener("click", function ()
      {
        chooseRow(index);
        uiElement("result-table").focus();
      });
      els.resultRows.appendChild(entry);
    });
    updateRowSelection();
  }

  function observationSummary(row)
  {
    if (row !== null && typeof row !== "object")
    {
      return tableCellText(row);
    }
    if (!row || typeof row !== "object")
    {
      return "Record has no observation fields; see Row details.";
    }
    var keys = Object.keys(row).filter(function (key)
    {
      return !/^(?:kind|context|target|interpretation|layoutSource|moduleIdentity|symbolSource|symbolField)$/.test(key);
    });
    var known = keys.filter(function (key)
    {
      return row[key] !== null && row[key] !== "";
    });
    return (known.length ? known : keys).slice(0, 3).map(function (key)
    {
      return columnLabel([key]) + ": " + tableCellText(row[key]);
    }).join("; ") || "Record has no observation fields; see Row details.";
  }

  function ensureObservationColumn()
  {
    var layout = state.tableLayout;
    var columns = visibleColumns().filter(function (column)
    {
      return column.path.length && column.path[0] !== "kind";
    });
    var sparse = state.rowCache.some(function (row)
    {
      return !columns.some(function (column)
      {
        var value = columnValue(row, column.path);
        return value !== undefined && value !== null && value !== "";
      });
    });
    if (sparse)
    {
      var key = "[]";
      var summary = layout.keys[key];
      if (!summary)
      {
        summary = { key: key, path: [], label: "Observation", width: 360, defaultWidth: 360, css: "row-value", visible: false, summary: true };
        layout.keys[key] = summary;
        layout.columns.push(summary);
      }
      if (!summary.visible)
      {
        summary.visible = true;
        updateColumnLabels();
        renderColumnChoices();
      }
    }
  }

  function updateRowSelection()
  {
    Array.prototype.forEach.call(els.resultRows.children, function (entry, index)
    {
      var selected = state.rowOffset + index === state.selectedIndex;
      entry.classList[selected ? "add" : "remove"]("selected");
      entry.setAttribute("aria-selected", String(selected));
      Array.prototype.forEach.call(entry.querySelectorAll(".copyable"), function (button)
      {
        button.tabIndex = selected ? 0 : -1;
      });
      Array.prototype.forEach.call(entry.querySelectorAll(".breakpoint-row-toggle"), function (button)
      {
        button.tabIndex = selected ? 0 : -1;
      });
    });
    var visible = state.selectedIndex >= state.rowOffset && state.selectedIndex < state.rowOffset + state.rowCache.length;
    uiElement("result-table").setAttribute("aria-activedescendant", visible ? "observation-" + state.selectedIndex : "");
    var sorting = state.tableSort;
    var position = state.selectedIndex < 0 ? "No row selected" :
      "Row " + (state.selectedIndex + 1).toLocaleString() + " of " + state.rowCount.toLocaleString();
    uiElement("row-position").textContent = sorting.loading ?
      "Loading rows for sorting: " + sorting.loaded.toLocaleString() + " / " + state.rowCount.toLocaleString() :
      (sorting.applied ? "Sorted by " + sorting.applied.label + " (" + sorting.applied.direction + ") / " : "") + position;
  }

  function chooseRow(index)
  {
    var row = state.rowCache[index - state.rowOffset];
    if (index < state.rowOffset || index >= state.rowOffset + state.rowCache.length)
    {
      state.pendingSelection = index;
      showRows(true);
      return;
    }
    if (state.selectedOriginalIndex !== state.rowIndices[index - state.rowOffset])
    {
      state.selectedAddressField = "";
    }
    state.selectedIndex = index;
    state.selectedOriginalIndex = state.rowIndices[index - state.rowOffset];
    state.pendingSelection = -1;
    selectObservation(row);
    updateRowSelection();
  }

  function resultViewState()
  {
    return { id: state.resultId, command: state.resultCommand, collection: state.resultCollection,
      originalIndex: state.selectedOriginalIndex, addressField: state.selectedAddressField, layout: state.tableLayout,
      sort: state.tableSort.requested || state.tableSort.applied || (state.tableLayout && state.tableLayout.sort) || null,
      scrollTop: state.resultRestore ? state.resultRestore.scrollTop : els.resultView.scrollTop,
      scrollLeft: state.resultRestore ? state.resultRestore.scrollLeft : els.resultView.scrollLeft };
  }

  function resultTabRoom(id)
  {
    if (state.resultTabs.length < 128 || state.resultTabs.some(function (tab)
    {
      return tab.id === id;
    }))
    {
      return true;
    }
    workspaceFeedback("Up to 128 result tabs can stay open. Close a tab before opening another result.", true);
    return false;
  }

  function syncResultTabs()
  {
    var token = ++state.resultTabRetention;
    send("resultTabs", { resultIds: state.resultTabs.map(function (tab)
    {
      return tab.id;
    }) }).then(function (reply)
    {
      if (token !== state.resultTabRetention)
      {
        return;
      }
      if (!reply || !reply.ok || !reply.result || !Array.isArray(reply.result.missing) || reply.result.missing.length)
      {
        workspaceFeedback("Some result tabs could not be retained. Their stored data may be unavailable; close and reopen affected tabs.", true);
      }
    });
  }

  function saveResultTab()
  {
    var tab = state.resultTabs.find(function (item)
    {
      return item.id === state.resultId;
    });
    if (tab && state.resultScreen === "results")
    {
      tab.collection = state.resultCollection;
      tab.views[state.resultCollection] = resultViewState();
    }
  }

  function openResultTab(tab)
  {
    if (state.resultTabs.indexOf(tab) >= 0 && !state.busy && state.ready)
    {
      loadResult(tab.id);
    }
  }

  function updateResultTabName(tab)
  {
    var name = tab.name || tab.command;
    tab.label.textContent = name;
    tab.button.title = (tab.name ? tab.name + "\n" : "") + tab.command + " / " + tab.id;
    tab.button.setAttribute("aria-label", name + " / " + tab.id.slice(0, 8));
    tab.close.setAttribute("aria-label", "Close result: " + name + " / " + tab.id.slice(0, 8));
  }

  function finishResultTabRename(cancel, restoreFocus)
  {
    var edit = state.resultTabRename;
    if (!edit)
    {
      return;
    }
    state.resultTabRename = null;
    if (!cancel && state.resultTabs.indexOf(edit.tab) >= 0)
    {
      edit.tab.name = edit.input.value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 128)
        .replace(/[\ud800-\udbff]$/, "");
      updateResultTabName(edit.tab);
    }
    edit.tab.element.removeChild(edit.input);
    setHidden(edit.tab.button, false);
    if (restoreFocus && state.resultTabs.indexOf(edit.tab) >= 0 && !edit.tab.button.disabled)
    {
      edit.tab.button.focus({ preventScroll: true });
    }
  }

  function renameResultTab(tab)
  {
    if (state.busy || !state.ready || state.resultTabs.indexOf(tab) < 0)
    {
      return;
    }
    finishResultTabRename(false, false);
    endResultTabDrag(true);
    closeResultTabMenu(false);
    closeCopyMenu(false);
    var input = document.createElement("input");
    input.type = "text";
    input.className = "result-tab-name";
    input.maxLength = 128;
    input.value = tab.name || tab.command;
    input.setAttribute("aria-label", "Result tab name");
    input.setAttribute("aria-description", "Enter to save, Escape to cancel. Leave empty to restore the command name.");
    var edit = { tab: tab, input: input, composing: false };
    state.resultTabRename = edit;
    input.addEventListener("compositionstart", function ()
    {
      edit.composing = true;
    });
    input.addEventListener("compositionend", function ()
    {
      edit.composing = false;
    });
    input.addEventListener("keydown", function (event)
    {
      event.stopPropagation();
      if (state.resultTabRename !== edit || event.isComposing || event.keyCode === 229 || edit.composing ||
          event.ctrlKey || event.altKey || event.metaKey || event.shiftKey)
      {
        return;
      }
      if (event.key === "Enter" || event.key === "Escape")
      {
        event.preventDefault();
        finishResultTabRename(event.key === "Escape", true);
      }
    });
    input.addEventListener("blur", function ()
    {
      if (state.resultTabRename === edit)
      {
        finishResultTabRename(false, false);
      }
    });
    input.addEventListener("contextmenu", function (event)
    {
      event.stopPropagation();
    });
    tab.element.insertBefore(input, tab.close);
    setHidden(tab.button, true);
    input.focus({ preventScroll: true });
    input.select();
    input.scrollIntoView({ block: "nearest", inline: "nearest" });
  }

  function moveResultTab(tab, before)
  {
    if (state.busy || !state.ready || state.resultTabs.indexOf(tab) < 0 || before === tab ||
        (before && state.resultTabs.indexOf(before) < 0))
    {
      return;
    }
    var tabs = state.resultTabs.filter(function (item)
    {
      return item !== tab;
    });
    var index = before ? tabs.indexOf(before) : tabs.length;
    if (state.resultTabs.indexOf(tab) === index)
    {
      return;
    }
    tabs.splice(index, 0, tab);
    var focused = uiActiveElement();
    state.resultTabs = tabs;
    uiElement("result-tabs").insertBefore(tab.element, before ? before.element : null);
    if (tab.element.contains(focused))
    {
      focused.focus({ preventScroll: true });
    }
    updateResultScreens();
  }

  function clearResultTabDrop()
  {
    state.resultTabs.forEach(function (tab)
    {
      tab.element.classList.remove("drop-before");
      tab.element.classList.remove("drop-after");
    });
  }

  function updateResultTabDrop(drag)
  {
    clearResultTabDrop();
    var strip = uiElement("result-tabs");
    var bounds = strip.getBoundingClientRect();
    drag.inside = drag.x >= bounds.left && drag.x <= bounds.right && drag.y >= bounds.top && drag.y <= bounds.bottom;
    if (!drag.inside)
    {
      clearTimeout(drag.timer);
      drag.timer = null;
      return;
    }
    var tabs = state.resultTabs.filter(function (tab)
    {
      return tab !== drag.tab;
    });
    drag.before = tabs.find(function (tab)
    {
      var box = tab.element.getBoundingClientRect();
      return drag.x < (box.left + box.right) / 2;
    }) || null;
    var marker = drag.before || tabs[tabs.length - 1];
    if (marker)
    {
      marker.element.classList.add(drag.before ? "drop-before" : "drop-after");
    }
    var edge = Math.min(32, (bounds.right - bounds.left) / 4);
    var direction = drag.x < bounds.left + edge ? -1 : drag.x > bounds.right - edge ? 1 : 0;
    drag.scrollDirection = direction;
    var next = Math.max(0, Math.min(Math.max(0, strip.scrollWidth - strip.clientWidth), strip.scrollLeft + direction * 16));
    if (direction && Number.isFinite(next) && next !== strip.scrollLeft)
    {
      if (!drag.timer)
      {
        drag.timer = setTimeout(function ()
        {
          drag.timer = null;
          if (state.resultTabDrag === drag)
          {
            strip.scrollLeft = Math.max(0, Math.min(Math.max(0, strip.scrollWidth - strip.clientWidth),
              strip.scrollLeft + drag.scrollDirection * 16));
            updateResultTabDrop(drag);
          }
        }, 32);
      }
    }
    else
    {
      clearTimeout(drag.timer);
      drag.timer = null;
    }
  }

  function endResultTabDrag(cancel)
  {
    var drag = state.resultTabDrag;
    if (!drag)
    {
      return;
    }
    state.resultTabDrag = null;
    clearTimeout(drag.timer);
    clearResultTabDrop();
    drag.tab.element.classList.remove("drag-source");
    uiElement("result-tabs").classList.remove("reordering");
    if (drag.started)
    {
      drag.tab.button.title = drag.title;
    }
    var buttonBounds = drag.tab.button.getBoundingClientRect();
    var clickInside = Number.isFinite(drag.x) && Number.isFinite(drag.y) &&
      drag.x >= buttonBounds.left && drag.x < buttonBounds.right && drag.y >= buttonBounds.top && drag.y < buttonBounds.bottom;
    if (drag.started || cancel || !clickInside)
    {
      drag.tab.suppressClick = true;
      drag.tab.suppressRename = true;
    }
    if (typeof drag.tab.button.releasePointerCapture === "function")
    {
      try
      {
        drag.tab.button.releasePointerCapture(drag.pointerId);
      }
      catch (error)
      {
      }
    }
    if (!cancel && drag.started && drag.inside)
    {
      moveResultTab(drag.tab, drag.before);
    }
  }

  function moveResultTabDrag(event)
  {
    var drag = state.resultTabDrag;
    if (!drag || event.pointerId !== drag.pointerId || !Number.isFinite(event.clientX) || !Number.isFinite(event.clientY))
    {
      return;
    }
    drag.x = event.clientX;
    drag.y = event.clientY;
    if (!drag.started && Math.hypot(drag.x - drag.startX, drag.y - drag.startY) < 6)
    {
      return;
    }
    event.preventDefault();
    if (!drag.started)
    {
      var editing = state.resultTabRename;
      finishResultTabRename(false, false);
      if (editing)
      {
        drag.tab.button.focus({ preventScroll: true });
      }
      closeResultTabMenu(false);
      closeCopyMenu(false);
      drag.started = true;
      drag.title = drag.tab.button.title;
      drag.tab.button.title = "";
      drag.tab.element.classList.add("drag-source");
      uiElement("result-tabs").classList.add("reordering");
    }
    updateResultTabDrop(drag);
  }

  function invalidateResultLoad()
  {
    state.resultLoadId = "";
    uiElement("result-load-status").textContent = "";
    return ++state.resultLoadToken;
  }

  function closeResultTab(tab)
  {
    closeResultTabs([tab]);
  }

  function closeResultTabs(tabs, cancelPending, keptTab)
  {
    var closing = state.resultTabs.filter(function (tab)
    {
      return tabs.indexOf(tab) >= 0;
    });
    if (!closing.length || state.busy || !state.ready)
    {
      return;
    }
    endResultTabDrag(true);
    if (state.resultTabRename && closing.indexOf(state.resultTabRename.tab) >= 0)
    {
      finishResultTabRename(true, false);
    }
    var index = state.resultTabs.findIndex(function (tab)
    {
      return tab.id === state.activeResultTab;
    });
    var closesActive = closing.some(function (tab)
    {
      return tab.id === state.activeResultTab;
    });
    if (cancelPending || closesActive || closing.length === state.resultTabs.length || closing.some(function (tab)
    {
      return tab.id === state.resultLoadId;
    }))
    {
      invalidateResultLoad();
    }
    closeResultTabMenu(false);
    state.resultTabs = state.resultTabs.filter(function (tab)
    {
      return closing.indexOf(tab) < 0;
    });
    closing.forEach(function (tab)
    {
      uiElement("result-tabs").removeChild(tab.element);
    });
    syncResultTabs();
    if (closesActive || !state.resultTabs.length || (keptTab && state.activeResultTab !== keptTab.id))
    {
      var next = keptTab || state.resultTabs[Math.min(index, state.resultTabs.length - 1)];
      selectResult({ command: "Debugger workspace", rowCount: "0", findingCount: "0", emptyWorkspace: true });
      if (next)
      {
        next.button.focus();
        openResultTab(next);
      }
      else
      {
        uiElement("result-table").focus();
      }
    }
    else
    {
      updateResultScreens();
      var active = state.resultTabs.find(function (item)
      {
        return item.id === state.activeResultTab;
      });
      if (active)
      {
        active.button.focus();
      }
    }
  }

  function closeResultTabMenu(restoreFocus)
  {
    var opened = state.resultTabMenu;
    if (!opened)
    {
      return;
    }
    state.resultTabMenu = null;
    var menu = uiElement("result-tab-menu");
    var focused = menu.contains(uiActiveElement());
    opened.tab.button.title = opened.title;
    opened.tab.close.title = opened.closeTitle;
    opened.tab.button.setAttribute("aria-expanded", "false");
    setHidden(menu, true);
    if (restoreFocus !== false && focused)
    {
      if (state.resultTabs.indexOf(opened.tab) >= 0 && !opened.tab.button.disabled)
      {
        opened.tab.button.focus({ preventScroll: true });
      }
      else
      {
        uiElement("result-table").focus();
      }
    }
  }

  function openResultTabMenu(tab, event)
  {
    event.preventDefault();
    event.stopPropagation();
    if (state.resultTabs.indexOf(tab) < 0 || state.busy || !state.ready)
    {
      return;
    }
    endResultTabDrag(true);
    finishResultTabRename(false, false);
    closeCopyMenu(false);
    closeResultTabMenu(false);
    var menu = uiElement("result-tab-menu");
    var anchor = tab.element.getBoundingClientRect();
    state.resultTabMenu = { tab: tab, title: tab.button.title, closeTitle: tab.close.title,
      bounds: [anchor.left, anchor.top, anchor.right, anchor.bottom] };
    tab.button.title = "";
    tab.close.title = "";
    tab.button.setAttribute("aria-expanded", "true");
    uiElement("result-tab-close-others").disabled = state.resultTabs.length < 2;
    setHidden(menu, false);
    var x = event.clientX || anchor.left;
    var y = event.clientY || anchor.bottom;
    menu.style.left = Math.max(8, Math.min(x, window.innerWidth - menu.offsetWidth - 8)) + "px";
    menu.style.top = Math.max(8, Math.min(y, window.innerHeight - menu.offsetHeight - 8)) + "px";
    uiElement("result-tab-close-current").focus({ preventScroll: true });
  }

  ["current", "others", "all"].forEach(function (action)
  {
    var button = uiElement("result-tab-close-" + action);
    button.addEventListener("click", function ()
    {
      var opened = state.resultTabMenu;
      if (!opened || button.disabled)
      {
        return;
      }
      closeResultTabMenu();
      closeResultTabs(state.resultTabs.filter(function (tab)
      {
        return action === "all" || (action === "current" ? tab === opened.tab : tab !== opened.tab);
      }), action !== "current", action === "others" ? opened.tab : null);
    });
  });
  uiElement("result-tab-menu").addEventListener("keydown", function (event)
  {
    if (event.key === "Escape" || event.key === "Tab")
    {
      if (event.key === "Escape")
      {
        event.preventDefault();
      }
      event.stopPropagation();
      closeResultTabMenu();
    }
    else if (["ArrowDown", "ArrowUp", "Home", "End"].indexOf(event.key) >= 0)
    {
      event.preventDefault();
      event.stopPropagation();
      var buttons = ["current", "others", "all"].map(function (action)
      {
        return uiElement("result-tab-close-" + action);
      }).filter(function (button)
      {
        return !button.disabled;
      });
      var index = buttons.indexOf(uiActiveElement());
      var next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 :
        (index + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length;
      buttons[next].focus({ preventScroll: true });
    }
  });

  function addResultTab(id, command)
  {
    var tab = { id: id, command: command, collection: "rows", views: Object.create(null) };
    tab.element = document.createElement("div");
    tab.element.className = "result-tab";
    tab.element.setAttribute("role", "presentation");
    tab.button = document.createElement("button");
    tab.button.type = "button";
    tab.button.id = "result-tab-" + (++state.resultTabSerial);
    tab.button.setAttribute("role", "tab");
    tab.button.setAttribute("aria-controls", "evidence");
    tab.button.setAttribute("aria-haspopup", "menu");
    tab.button.setAttribute("aria-expanded", "false");
    tab.button.setAttribute("aria-description", "Double-click or press F2 to rename this result tab.");
    tab.button.draggable = false;
    var label = document.createElement("span");
    label.className = "result-tab-label";
    label.textContent = command;
    tab.label = label;
    tab.button.appendChild(label);
    var suffix = document.createElement("span");
    suffix.className = "result-tab-id";
    suffix.setAttribute("aria-hidden", "true");
    suffix.textContent = id.slice(0, 8);
    tab.button.appendChild(suffix);
    tab.close = document.createElement("button");
    tab.close.type = "button";
    tab.close.className = "result-tab-close";
    tab.close.textContent = "\u00d7";
    tab.close.title = "Close result tab";
    updateResultTabName(tab);
    tab.button.addEventListener("click", function (event)
    {
      if (tab.suppressClick && event.detail !== 0)
      {
        tab.suppressClick = false;
        event.preventDefault();
        return;
      }
      if (state.resultTabRename)
      {
        finishResultTabRename(false, false);
        tab.button.focus({ preventScroll: true });
      }
      if (event.detail > 1 || (state.resultScreen === "results" && state.resultId === tab.id && !state.resultLoadId &&
          !state.resultLoadError && !state.rowError && !state.tableSort.error))
      {
        return;
      }
      openResultTab(tab);
    });
    tab.button.addEventListener("dblclick", function (event)
    {
      if (event.button === 0 && !tab.suppressRename)
      {
        event.preventDefault();
        renameResultTab(tab);
      }
    });
    tab.button.addEventListener("pointerdown", function (event)
    {
      tab.suppressClick = false;
      tab.suppressRename = false;
      if (state.resultTabDrag || state.columnDrag || state.memoryPanel.drag || state.inspectorPanel.drag || state.busy || !state.ready ||
          state.resultTabs.length < 2 || event.button !== 0 || event.isPrimary === false ||
          !Number.isFinite(event.clientX) || !Number.isFinite(event.clientY))
      {
        return;
      }
      if (typeof tab.button.setPointerCapture === "function")
      {
        try
        {
          tab.button.setPointerCapture(event.pointerId);
        }
        catch (error)
        {
          return;
        }
      }
      state.resultTabDrag = { tab: tab, pointerId: event.pointerId, startX: event.clientX, startY: event.clientY };
    });
    tab.button.addEventListener("lostpointercapture", function ()
    {
      if (state.resultTabDrag && state.resultTabDrag.tab === tab)
      {
        endResultTabDrag(true);
      }
    });
    tab.close.addEventListener("click", function ()
    {
      closeResultTab(tab);
    });
    tab.element.addEventListener("pointerdown", function (event)
    {
      if (state.resultTabRename && event.target !== state.resultTabRename.input)
      {
        event.preventDefault();
      }
    });
    tab.element.addEventListener("contextmenu", function (event)
    {
      openResultTabMenu(tab, event);
    });
    tab.element.addEventListener("keydown", function (event)
    {
      if (!event.isComposing && !event.repeat && !event.ctrlKey && !event.altKey && !event.metaKey &&
          (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")))
      {
        openResultTabMenu(tab, event);
      }
    });
    tab.button.addEventListener("keydown", function (event)
    {
      if (event.ctrlKey && event.shiftKey && !event.altKey && !event.metaKey && !event.isComposing &&
          ["ArrowLeft", "ArrowRight"].indexOf(event.key) >= 0 && !state.busy && state.ready)
      {
        event.preventDefault();
        event.stopPropagation();
        endResultTabDrag(true);
        var position = state.resultTabs.indexOf(tab);
        if (position >= 0 && (event.key === "ArrowLeft" ? position > 0 : position < state.resultTabs.length - 1))
        {
          closeResultTabMenu(false);
          moveResultTab(tab, state.resultTabs[position + (event.key === "ArrowLeft" ? -1 : 2)] || null);
          tab.button.scrollIntoView({ block: "nearest", inline: "nearest" });
        }
        return;
      }
      if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || event.isComposing || state.busy || !state.ready)
      {
        return;
      }
      var index = state.resultTabs.indexOf(tab);
      if (index < 0)
      {
        return;
      }
      if (event.key === "Delete")
      {
        event.preventDefault();
        closeResultTab(tab);
      }
      else if (event.key === "F2" && !event.repeat)
      {
        event.preventDefault();
        event.stopPropagation();
        renameResultTab(tab);
      }
      else if (["ArrowLeft", "ArrowRight", "Home", "End"].indexOf(event.key) >= 0)
      {
        event.preventDefault();
        var target = event.key === "Home" ? 0 : event.key === "End" ? state.resultTabs.length - 1 :
          (index + (event.key === "ArrowRight" ? 1 : -1) + state.resultTabs.length) % state.resultTabs.length;
        state.resultTabs[target].button.focus();
        state.resultTabs[target].button.scrollIntoView({ block: "nearest", inline: "nearest" });
        openResultTab(state.resultTabs[target]);
      }
    });
    tab.element.appendChild(tab.button);
    tab.element.appendChild(tab.close);
    state.resultTabs.push(tab);
    uiElement("result-tabs").appendChild(tab.element);
    syncResultTabs();
    return tab;
  }

  function updateResultScreens()
  {
    if (!state.ready || state.busy)
    {
      endResultTabDrag(true);
      closeResultTabMenu();
      finishResultTabRename(false, false);
    }
    ["results", "stack", "breakpoints", "event"].forEach(function (screen)
    {
      var button = uiElement("btn-" + screen);
      button.className = state.resultScreen === screen ? "active" : "";
      button.setAttribute("aria-pressed", String(state.resultScreen === screen));
    });
    var back = uiElement("btn-results");
    back.disabled = !state.ready || state.busy || !state.returnResult;
    back.title = state.returnResult ? "Return to " + state.returnResult.command + " without running it again" :
      "Return to the last command result without running it again";
    setHidden(uiElement("result-tabs"), !state.resultTabs.length);
    state.resultTabs.forEach(function (tab)
    {
      var active = tab.id === state.activeResultTab;
      tab.element.classList[active ? "add" : "remove"]("active");
      tab.button.setAttribute("aria-selected", String(active && state.resultScreen === "results"));
      tab.button.tabIndex = active || !state.activeResultTab && tab === state.resultTabs[0] ? 0 : -1;
      tab.button.disabled = !state.ready || state.busy;
      tab.close.disabled = !state.ready || state.busy;
      tab.close.tabIndex = active ? 0 : -1;
    });
    var activeTab = state.resultTabs.find(function (item)
    {
      return item.id === state.activeResultTab;
    });
    var panel = uiElement("evidence");
    panel.setAttribute("role", activeTab && state.resultScreen === "results" ? "tabpanel" : "region");
    panel.setAttribute("aria-labelledby", activeTab && state.resultScreen === "results" ? activeTab.button.id : "result-title");
  }

  function selectResult(result, collection, selectionRevision, screen, restore)
  {
    endResultTabDrag(true);
    closeResultTabMenu();
    saveResultTab();
    screen = ["stack", "breakpoints", "event"].indexOf(screen) >= 0 ? screen : "results";
    if (screen !== "results" && state.resultScreen === "results" && state.resultId)
    {
      state.returnResult = resultViewState();
    }
    else if (screen === "results")
    {
      state.returnResult = null;
    }
    var tab = screen === "results" && state.resultTabs.find(function (item)
    {
      return item.id === result.resultId;
    });
    if (screen === "results")
    {
      state.activeResultTab = result.resultId || "";
      if (!restore && tab)
      {
        restore = tab.views[collection || tab.collection];
      }
      collection = collection || (restore && restore.collection);
    }
    state.resultScreen = screen;
    state.resultRestore = restore || null;
    invalidateResultLoad();
    var info = uiElement("result-info");
    if (info.open && state.resultId !== result.resultId)
    {
      if (info.contains && info.contains(uiActiveElement()))
      {
        uiElement("result-info-toggle").focus();
      }
      info.open = false;
    }
    ++state.resultRevision;
    state.resultId = result.resultId || "";
    state.resultMeta = result.data || {};
    var isStack = state.resultMeta.commandId === "stack";
    var stackContext = isStack && state.resultMeta.analysis && state.resultMeta.analysis.stackContext || {};
    setHidden(uiElement("stack-summary"), !isStack);
    uiElement("stack-context").textContent = isStack ? targetContextLabel(stackContext) : "";
    uiElement("stack-context").title = isStack ? targetContextDetails(stackContext, "stack") : "";
    var lastEvent = state.resultMeta.commandId === "event" && state.resultMeta.analysis && state.resultMeta.analysis.lastEvent;
    setHidden(uiElement("event-summary"), !lastEvent);
    uiElement("event-description").textContent = lastEvent ? lastEvent.description || lastEvent.eventName || "Last debugger event" : "";
    var eventAddress = eventLocation(lastEvent);
    uiElement("event-context").textContent = lastEvent ?
      (lastEvent.breakpointId !== undefined && lastEvent.breakpointId !== null ? "Breakpoint #" + lastEvent.breakpointId + " / " : "") +
      targetContextLabel(lastEvent) +
      " / " + eventAddress.label : "";
    uiElement("event-context").title = targetContextDetails(lastEvent);
    uiElement("event-symbol").textContent = lastEvent && typeof lastEvent.configuredSymbol === "string" ? lastEvent.configuredSymbol : "";
    setHidden(uiElement("event-symbol"), !uiElement("event-symbol").textContent);
    uiElement("event-address").textContent = eventAddress.value || "Address unavailable";
    uiElement("event-address").disabled = !eventAddress.value;
    uiElement("event-address").title = eventAddress.label + (lastEvent && lastEvent.addressStatus ? ". " + lastEvent.addressStatus : "");
    uiElement("event-address").setAttribute("aria-label", "Copy " + eventAddress.label);
    if (lastEvent && state.connected && processStampKey(state.resultMeta.target) === processStampKey(state.target))
    {
      setHidden(uiElement("event-unread"), true);
    }
    state.resultError = result.error || result.retentionError || "";
    if (state.resultError === state.resultMeta.status)
    {
      state.resultError = "";
    }
    state.resultFailed = result.ok === false && state.resultMeta.status !== "Partial";
    state.resultOutputLength = result.outputLength === undefined ? "" : String(result.outputLength);
    state.resultLoadError = "";
    state.resultTarget = state.resultMeta.target;
    state.selectedRow = null;
    state.selectedAddressField = restore && restore.addressField || "";
    state.selectedIndex = -1;
    state.selectedOriginalIndex = -1;
    state.pendingSelection = -1;
    state.rowCache = [];
    state.rowIndices = [];
    state.tableSort = { entries: null, order: null, applied: null, requested: null, loading: false, loaded: 0, error: "" };
    state.rowError = "";
    state.observationCount = Math.max(0, Number(result.rowCount) || 0);
    state.findingCount = Math.max(0, Number(result.findingCount) || 0);
    state.resultCollection = collection || (state.observationCount === 0 && state.findingCount > 0 ? "findings" : "rows");
    state.rowBase = lastEvent && lastEvent.kind === "LastEvent" && state.resultCollection === "rows" && state.observationCount > 0 ? 1 : 0;
    setHidden(uiElement("event-settings-heading"), !state.rowBase);
    uiElement("event-match-hint").textContent = state.rowBase && typeof lastEvent.breakpointId === "string" ?
      " / Last stop BP #" + lastEvent.breakpointId + "; matching rows are marked" : "";
    uiElement("result-collection").value = state.resultCollection;
    state.rowCount = Math.min(100000, state.resultCollection === "findings" ? state.findingCount : state.observationCount - state.rowBase);
    uiElement("result-table").setAttribute("aria-label", state.resultCollection === "findings" ? "Findings" : "Rows");
    state.rowOffset = -1;
    els.resultView.scrollTop = 0;
    els.resultView.scrollLeft = 0;
    els.resultSpacer.style.height = state.rowCount * workspaceRowHeight() + "px";
    if (restore)
    {
      state.pendingSelection = restore.originalIndex >= state.rowBase && restore.originalIndex < state.rowCount + state.rowBase ?
        restore.originalIndex - state.rowBase : -1;
      state.selectedOriginalIndex = state.pendingSelection >= 0 ? restore.originalIndex : -1;
      els.resultView.scrollTop = restore.scrollTop;
    }
    els.resultRows.setAttribute("aria-rowcount", String(state.rowCount));
    uiElement("result-table").setAttribute("aria-rowcount", String(state.rowCount + 1));
    var known = state.recentResults.find(function (item) { return item.id === state.resultId; });
    var command = result.command || (known && known.command) || state.resultMeta.commandId || "Stored result";
    if (typeof command !== "string")
    {
      command = "Stored result";
    }
    uiElement("result-title").textContent = command;
    uiElement("result-title").title = command;
    state.resultCommand = result.emptyWorkspace === true ? "" : command;
    if (screen === "results" && state.resultId && !tab)
    {
      tab = addResultTab(state.resultId, command);
    }
    if (selectionRevision === state.commandSelectionRevision && !els.prompt.value.trim())
    {
      selectCommand(command);
    }
    activateTableLayout();
    if (state.resultRestore)
    {
      els.resultView.scrollLeft = state.resultRestore.scrollLeft;
      syncTableViewport();
    }
    if (state.resultId)
    {
      state.recentResults = state.recentResults.filter(function (item) { return item.id !== state.resultId; });
      state.recentResults.unshift({ id: state.resultId, command: command });
      state.recentResults = state.recentResults.slice(0, 16);
    }
    renderResultHistory();
    els.btnSave.disabled = state.busy || !state.resultId;
    setHidden(uiElement("result-empty"), state.rowCount > 0);
    updateEvidenceSummary();
    selectObservation(null);
    els.resultRows.textContent = "";
    updateRowSelection();
    updateResultScreens();
    if (tab && tab.button.scrollIntoView)
    {
      tab.button.scrollIntoView({ block: "nearest", inline: "nearest" });
    }
    updateTableBusy();
    if (state.rowCount && state.tableLayout.sort)
    {
      state.tableSort.requested = state.tableLayout.sort;
      loadTableSort(state.tableSort);
    }
    else
    {
      showRows();
    }
  }

  function renderResultHistory()
  {
    els.resultHistory.textContent = "";
    var placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Recent results";
    els.resultHistory.appendChild(placeholder);
    state.recentResults.forEach(function (item)
    {
      var option = document.createElement("option");
      option.value = item.id;
      option.textContent = item.command + " / " + item.id;
      els.resultHistory.appendChild(option);
    });
    els.resultHistory.value = state.resultId;
    els.resultHistory.disabled = state.busy || !state.recentResults.length;
  }

  function historicalResult()
  {
    var a = state.resultTarget;
    var b = state.target;
    return !state.connected || !a || JSON.stringify(a.contextIdentity) !== JSON.stringify(b.contextIdentity) ||
      ["sessionId", "targetGeneration", "stopEpoch", "contextGeneration", "symbolGeneration"].some(function (key)
    {
      return a[key] !== b[key];
    });
  }

  function showNotice(text)
  {
    var notice = uiElement("result-notice");
    var key = JSON.stringify([state.resultId, state.resultTarget, state.target, state.connected, text]);
    if (state.resultNotice.key !== key)
    {
      state.resultNotice.key = key;
      state.resultNotice.dismissed = false;
    }
    uiElement("result-notice-text").textContent = text;
    var summary = String(text || "").split(/\r?\n/)[0];
    uiElement("result-notice-summary").textContent = summary.length > 180 ? summary.slice(0, 177) + "..." : summary;
    uiElement("result-notice-summary").title = "Expand for the complete collection notice";
    setHidden(notice, !text || state.resultNotice.dismissed);
  }

  uiElement("btn-result-notice-dismiss").addEventListener("click", function ()
  {
    if (!uiElement("result-notice").classList.contains("hidden"))
    {
      state.resultNotice.dismissed = true;
      dismissNotice("result-notice", "btn-result-notice-dismiss", "result-table");
    }
  });

  function dismissNotice(id, buttonId, focusId)
  {
    var focused = uiActiveElement() === uiElement(buttonId);
    setHidden(uiElement(id), true);
    updateLayout();
    if (focused)
    {
      var target = uiElement(focusId);
      if (target.disabled)
      {
        target = uiElement("result-table");
      }
      target.focus({ preventScroll: true });
    }
  }

  function resultText(value)
  {
    if (typeof value !== "string")
    {
      return "";
    }
    return value.length > 2000 ? value.slice(0, 2000) + "... (Export has the complete details)" : value;
  }

  function countText(value)
  {
    var text = String(value === undefined ? "" : value);
    return /^(0|[1-9][0-9]{0,19})$/.test(text) ? text.replace(/\B(?=(\d{3})+(?!\d))/g, ",") : "";
  }

  function collectionReason(coverage, source)
  {
    var reasons = {
      GlobalWalkBudget: "The walk reached its time or entry limit. The list is incomplete; narrow the command's scope when supported.",
      CollectionBudget: "Collection reached its time or entry limit. The list is incomplete; narrow the command's scope when supported.",
      FieldsOrOwnershipUnavailable: "Some fields or owning modules could not be resolved. Check rows with unknown values and Details.",
      FrameBudget: "The requested frame limit was reached. Increase the frame count to inspect more of the stack.",
      RegisterUnavailable: "Some registers are unavailable in this debugger context. Unknown values were not read as zero.",
      MemoryReadIncomplete: "Part of the requested memory could not be read.",
      InstructionBytesUnavailable: "Instruction bytes or the decoder were unavailable. No unknown instruction is reported as decoded.",
      OutputBudgetExceeded: "Collection stopped at the output limit. Narrow the command's scope; Export contains only the retained result.",
      ResultRetentionBudget: "The result exceeded the storage limit. Run a smaller query.",
      ContextChangedDuringCollection: "The debugger context changed during collection. Run the command again after the target stops.",
      Cancelled: "Collection was cancelled. Any retained rows are incomplete.",
      HostDiagnosticUnparsed: "WinDbg returned text output. It has not been interpreted as structured diagnostic findings.",
      HostFunctionDisassemblyUnparsed: "WinDbg returned function text. Inspect View output; complete function coverage has not been verified.",
      InputCoverageIncomplete: "At least one input is incomplete. An absent item does not establish that it was removed.",
      PeHeadersUnavailable: "The PE headers could not be read completely. No complete image was exported."
    };
    var reason = resultText(coverage.stopReason);
    if (!reason || reason === "NotCollected")
    {
      return "";
    }
    if (reason === "FieldsOrOwnershipUnavailable")
    {
      if (source === "TargetRegisters:CurrentProcessorMsr")
      {
        return "Some MSRs were not read in this debugger context.";
      }
      if (source === "TargetMemory:SavedProcessorControl")
      {
        return "Some saved register values or their layouts could not be read.";
      }
    }
    return Object.prototype.hasOwnProperty.call(reasons, reason) ? reasons[reason] :
      "Collection stopped: " + reason.replace(/([a-z0-9])([A-Z])/g, "$1 $2") + ".";
  }

  function updateResultDetails(coverage, error)
  {
    if (state.detailsRevision === state.resultRevision)
    {
      return;
    }
    state.detailsRevision = state.resultRevision;
    var details = uiElement("result-facts");
    details.textContent = "";
    function field(name, value)
    {
      if (!value)
      {
        return;
      }
      var term = document.createElement("dt");
      var text = document.createElement("dd");
      term.textContent = name;
      text.textContent = value;
      details.appendChild(term);
      details.appendChild(text);
    }
    field("Status", resultText(state.resultMeta.status) || "Not available");
    field("Error", error);
    var counts = [];
    [["visitedEntries", "visited"], ["readEntries", "read"], ["decodedEntries", "decoded"],
      ["unknownEntries", "unknown"], ["unreadableEntries", "unreadable"]].forEach(function (item)
    {
      var count = countText(coverage[item[0]]);
      if (count)
      {
        counts.push(count + " " + item[1]);
      }
    });
    field("Collection", counts.join(" / "));
    field("Stop reason", resultText(coverage.stopReason));
    var provenance = state.resultMeta.provenance || {};
    field("Source", resultText(provenance.source));
    field("Consistency", resultText(provenance.consistency));
    var analysis = state.resultMeta.analysis;
    if (analysis && typeof analysis === "object" && !Array.isArray(analysis))
    {
      Object.keys(analysis).slice(0, 12).forEach(function (key)
      {
        var value = analysis[key];
        var summary = Array.isArray(value) ? value.length + " items (see Export for full details)" :
          value && typeof value === "object" ? Object.keys(value).length + " fields (see Export for full details)" : tableCellText(value);
        field(columnLabel([key]), resultText(summary));
        if (key === "diagnostics" && Array.isArray(value))
        {
          value.filter(function (item)
          {
            return item && (item.kind === "CoverageGap" || item.kind === "EmptyObservation");
          }).slice(0, 8).forEach(function (item)
          {
            field("Gap / " + resultText(item.scope), resultText(item.reason));
          });
        }
      });
    }
    var limits = state.resultMeta.limitations;
    if (Array.isArray(limits))
    {
      limits.slice(0, 8).forEach(function (limit)
      {
        field("Limit", resultText(limit));
      });
      if (limits.length > 8)
      {
        field("More", "Export includes all limitations.");
      }
    }
    if (state.resultMeta.metadataOmitted)
    {
      field("Details", "Metadata was too large to display. Export includes the stored metadata.");
    }
    var stamp = state.resultTarget || {};
    field("Context", "Stop " + (stamp.stopEpoch || "?") + " / context " + (stamp.contextGeneration || "?") +
      " / symbols " + (stamp.symbolGeneration || "?"));
    field("Result ID", state.resultId);
    field("Storage", "Retained in memory. Pins do not save a capture to disk.");
    field("Last export", state.savedExports[state.resultId] || "No successful export recorded in this document");
  }

  function resultOrigin()
  {
    var source = resultText((state.resultMeta.provenance || {}).source);
    if (source === "HostCpuid+TargetRegisters")
    {
      return "Host + target";
    }
    if (/^(host-file:|HostFiles:|HostDumpMetadata|LegacyTextImport)/.test(source))
    {
      return "Imported file";
    }
    if (/^(TargetMemory:|TargetRegisters:|target$|target-host-extension$)/.test(source))
    {
      return "Debug target";
    }
    if (/^(host$|host-local$|host-wfp$|host-firmware$|HostCodeIntegrity|HostToolhelp)/.test(source))
    {
      return "Debugger host";
    }
    if (source === "windbg" || source === "opaque-engine")
    {
      return "Debugger engine";
    }
    if (source === "provided-values" || source === "InputDecoder")
    {
      return "Provided input";
    }
    return source || "Source unspecified";
  }

  function updateProcessComparisonSummary(incomplete)
  {
    var isComparison = state.resultMeta.commandId === "!hiddenproc";
    var note = uiElement("process-comparison-note");
    uiElement("result-count").classList[isComparison ? "add" : "remove"]("process-comparison-count");
    setHidden(note, !isComparison);
    note.textContent = "";
    if (!isComparison)
    {
      return;
    }
    var summary = state.resultMeta.analysis && state.resultMeta.analysis.processComparison;
    var keys = ["total", "matched", "mismatchCandidates", "indeterminate"];
    var valid = summary && keys.every(function (key)
    {
      var value = summary[key];
      return (typeof value === "string" && /^\d+$/.test(value) || typeof value === "number") &&
        Number.isSafeInteger(Number(value)) && Number(value) >= 0;
    });
    valid = valid && Number(summary.total) === state.observationCount &&
      Number(summary.matched) + Number(summary.mismatchCandidates) + Number(summary.indeterminate) === Number(summary.total);
    var labels = ["Total", "Matched", "Mismatch candidates", "Indeterminate"];
    uiElement("result-count").textContent = labels.map(function (label, index)
    {
      var count = index === 0 ? state.observationCount.toLocaleString() :
        valid ? Number(summary[keys[index]]).toLocaleString() : "Unavailable";
      return label + " " + count;
    }).join(" / ");
    note.textContent = "All compared processes, including matches. Mismatch candidates need re-observation; they are not confirmed hidden processes.";
    if (!valid)
    {
      note.textContent += " This capture has no valid count breakdown; run !hiddenproc again to collect one.";
    }
    if (incomplete || state.resultMeta.status !== "Success")
    {
      note.textContent += " Collection is incomplete or unavailable; counts cover collected rows only and cannot establish absence.";
    }
  }

  function updateEvidenceSummary()
  {
    var stamp = state.resultTarget || {};
    var historical = !!state.resultId && historicalResult();
    var coverage = state.resultMeta.coverage || {};
    var status = state.resultMeta.status;
    var incomplete = status === "Partial" || (coverage.complete === false && coverage.stopReason !== "NotCollected");
    var label = status === "Partial" || (status === "Success" && incomplete) ? "Partial result" : status === "Success" ? "Completed" :
      resultText(status).replace(/([a-z0-9])([A-Z])/g, "$1 $2") || (state.resultFailed ? "Command failed" : "Status unavailable");
    var origin = resultOrigin();
    els.resultSummary.textContent = state.resultId ? origin + " / " + label + " / " + (historical ? "Historical" : "Current context") : "No result selected";
    els.resultSummary.title = state.resultId + " | target " + (stamp.sessionId || "unknown") + ":" +
      (stamp.targetGeneration || "?") + " | symbols " + (stamp.symbolGeneration || "?") +
      " | Source: " + resultText((state.resultMeta.provenance || {}).source) +
      " | Current refers to the debugger context. This is a retained snapshot, not a live value.";
    els.resultSummary.className = historical ? "historical" : incomplete || (status && status !== "Success") ? "partial" : "";
    uiElement("result-count").textContent = state.rowBase ? (state.observationCount - state.rowBase).toLocaleString() + " breakpoint settings / 1 last stop" :
      (state.observationCount || 0).toLocaleString() + " rows / " + (state.findingCount || 0).toLocaleString() + " findings";
    updateProcessComparisonSummary(incomplete);
    uiElement("result-rows-option").textContent = (state.rowBase ? "Breakpoints" : "Rows") + " (" +
      Math.max(0, (state.observationCount || 0) - state.rowBase).toLocaleString() + ")";
    uiElement("result-findings-option").textContent = "Findings (" + (state.findingCount || 0).toLocaleString() + ")";
    setHidden(uiElement("btn-result-export-path"), !state.savedExports[state.resultId]);
    var error = resultText((state.resultMeta.error || {}).message) || resultText(state.resultError);
    var source = (state.resultMeta.provenance || {}).source;
    var reason = incomplete || (status && status !== "Success") ? collectionReason(coverage, source) : "";
    var warning = [];
    if (state.resultLoadError)
    {
      warning.push(state.resultLoadError);
    }
    if (state.rowError)
    {
      warning.push(state.rowError);
    }
    if (state.tableSort.error)
    {
      warning.push(state.tableSort.error);
    }
    if (historical)
    {
      warning.push("This result is from an earlier debugger context. Select a current result to navigate addresses.");
    }
    if ((state.resultCollection === "findings" ? state.findingCount : state.observationCount) > 100000)
    {
      warning.push("The table displays the first 100,000 records. Export includes every record.");
    }
    if (error)
    {
      warning.push(error);
    }
    if (reason)
    {
      warning.push(reason);
    }
    if (incomplete || (status && status !== "Success"))
    {
      var gaps = [];
      [["unknownEntries", "unknown"], ["unreadableEntries", "unreadable"]].forEach(function (item)
      {
        var count = countText(coverage[item[0]]);
        if (count && count !== "0")
        {
          gaps.push(count + " " + item[1]);
        }
      });
      if (gaps.length)
      {
        warning.push(gaps.join(" / ") + ".");
      }
      if (!error && !reason && !gaps.length)
      {
        warning.push(label + ". Open Capture info for the collection limits and source.");
      }
    }
    if (source === "TargetRegisters:CurrentProcessorMsr")
    {
      warning.push("Only the selected event CPU can be read. Other CPUs remain unknown; this is not a comparison across CPUs.");
    }
    else if (source === "TargetMemory:SavedProcessorControl")
    {
      warning.push("Values come from saved CPU state and may lag a running target. Differences alone do not indicate hooks.");
    }
    var analysis = state.resultMeta.analysis || {};
    if (incomplete && countText(analysis.completedQueues) && countText(analysis.expectedQueues))
    {
      warning.push("Queues fully read: " + countText(analysis.completedQueues) + " of " + countText(analysis.expectedQueues) + ".");
    }
    showNotice(warning.join(" "));
    updateResultDetails(coverage, error);
    setHidden(uiElement("empty-starts"), !!state.resultId || !!state.resultCommand || !state.connected || !state.sessionStatus.stopped);
    setHidden(uiElement("btn-empty-processes"), !state.sessionStatus.kernelMode);
    if (!state.resultId && !state.resultCommand)
    {
      uiElement("empty-title").textContent = "Ready to inspect";
      uiElement("empty-message").textContent = state.connected && state.sessionStatus.stopped ?
        "Read the stopped target with Inspect or Capture stack. Find a command inserts a draft for you to run." :
        state.connected ? "Target is running. Break the target to inspect its current context, or browse commands below." :
        "Connect a target in WinDbg. You can browse commands and open retained results while disconnected.";
      setHidden(uiElement("btn-empty-output"), true);
      return;
    }
    var failed = state.resultFailed || (status && status !== "Success" && status !== "Partial");
    uiElement("empty-title").textContent = failed ? label : incomplete ? "No rows collected" : state.rowBase ? "No breakpoint settings captured" :
      state.resultCollection === "findings" ? "No findings reported" : state.resultOutputLength !== "0" ? "Text output" : "No rows returned";
    uiElement("empty-message").textContent = error || reason || (failed ? "Open Capture info or View output for the failure reason." :
      incomplete ? "Collection is incomplete. An empty table does not mean there is nothing to find." :
      state.rowBase ? "The last stop is shown above. One-shot or removed breakpoints may no longer appear in the settings list." :
      state.resultCollection === "findings" ? "This command reported no findings. Check Capture info for its scope and limitations." :
      state.resultOutputLength === "0" ? "The command completed without table rows or saved text." :
      "This result has no table rows. View output to read the saved text, or Export to save the complete result.");
    setHidden(uiElement("btn-empty-output"), !state.resultId || state.resultOutputLength === "0");
    ["btn-empty-output", "btn-result-output"].forEach(function (id)
    {
      uiElement(id).disabled = state.busy || !state.resultId || state.resultOutputLength === "0";
    });
  }

  function callbackAddressFields(row)
  {
    return row && row.kind === "ObjectCallbackRegistration" ? ["preRoutine", "postRoutine"] :
      row && ["RoutineObservation", "RegistryHive", "KernelTimer", "QueuedDpc"].indexOf(row.kind) >= 0 ? ["routine"] : [];
  }

  function callbackColumnField(row, path)
  {
    if (path.length !== 1)
    {
      return "";
    }
    var field = row && row.kind === "RoutineObservation" && path[0] === "preRoutine" ? "routine" : path[0];
    return callbackAddressFields(row).indexOf(field) >= 0 ? field : "";
  }

  function callbackNavigation(row, field, original)
  {
    var address = row && row[field];
    var valid = typeof address === "string" && /^0x[0-9a-f]{1,16}$/i.test(address) && BigInt(address) !== 0n &&
      (!row.addressSpace || row.addressSpace === "virtual");
    return { address: valid ? address : "", space: "virtual", field: field, row: row,
      reason: address === null || address === undefined ? "Callback address is unavailable." :
        typeof address === "string" && /^0x0+$/i.test(address) ? "Callback is not registered." :
        valid ? "" : "Callback address is invalid.",
      source: { resultId: state.resultId, collection: state.resultCollection || "rows",
        index: String(original), field: field, expectedStamp: state.resultTarget } };
  }

  function selectedCallbackNavigation()
  {
    return callbackAddressFields(state.selectedRow).indexOf(state.selectedAddressField) >= 0 ?
      callbackNavigation(state.selectedRow, state.selectedAddressField, state.selectedOriginalIndex) : null;
  }

  function resultAddressNavigation(row, path, original)
  {
    var callback = callbackColumnField(row, path);
    if (callback)
    {
      return callbackNavigation(row, callback, original);
    }
    var descriptors = addressFieldsByRow.get(row);
    var descriptor = descriptors && descriptors.find(function (field)
    {
      return JSON.stringify(field.path) === JSON.stringify(path);
    });
    if (!descriptors && path.length === 1 && path[0] === "address" && row &&
        ["virtual", "physical"].indexOf(row.addressSpace) >= 0)
    {
      descriptor = { path: path, space: row.addressSpace, allowZero: true };
    }
    if (!descriptor)
    {
      return null;
    }
    var address = columnValue(row, path);
    var valid = typeof address === "string" && /^0x[0-9a-f]{1,16}$/i.test(address) &&
      (descriptor.allowZero || BigInt(address) !== 0n);
    return { address: valid ? address : "", space: descriptor.space, process: descriptor.process, row: row,
      reason: address === null || address === undefined ? "Address is unavailable." :
        valid ? "" : "Address is null or invalid.",
      source: { resultId: state.resultId, collection: state.resultCollection || "rows", index: String(original),
        path: descriptor.path.slice(), expectedStamp: state.resultTarget } };
  }

  function navigationProcessCurrent(navigation)
  {
    var context = state.target && state.target.contextIdentity;
    var userLimit = context && context.effectiveArchitecture === "0x000000000000014c" ? 0x100000000n : 0x8000000000000000n;
    return !navigation.process || navigation.space !== "virtual" || BigInt(navigation.address) >= userLimit ||
      !!context && typeof context.implicitProcess === "string" && /^0x[0-9a-f]{1,16}$/i.test(context.implicitProcess) &&
      BigInt(navigation.process) !== 0n && BigInt(navigation.process) === BigInt(context.implicitProcess);
  }

  function addressNavigationAvailable(navigation, view)
  {
    if (!navigation || !navigation.address || !state.ready || state.busy || debuggerBusy() || !state.connected ||
        !state.sessionStatus.stopped || navigation.row.historical || (view === "disassembly" && navigation.space !== "virtual") ||
        !navigationProcessCurrent(navigation) ||
        (navigation.row.target && processStampKey(navigation.row.target) !== processStampKey(navigation.source.expectedStamp)) ||
        processStampKey(navigation.source.expectedStamp) !== processStampKey(state.target))
    {
      return false;
    }
    if (navigation.origin)
    {
      return view !== navigation.origin.view && inspectionVisible(navigation.origin.view) &&
        state[navigation.origin.view].snapshot === navigation.origin.snapshot;
    }
    return navigation.source.resultId === state.resultId && navigation.source.collection === state.resultCollection;
  }

  function inspectionAddressNavigation(view, snapshot, row, index)
  {
    var byteOffset = view === "memory" ? index * memoryRowBytes() : 0;
    var sourceIndex = view === "memory" ? Math.floor(byteOffset / 16) : index;
    return { address: row.address, space: view === "memory" ? snapshot.space : "virtual", row: row,
      origin: { view: view, snapshot: snapshot },
      source: Object.assign({ resultId: snapshot.resultId, collection: "rows", index: String(sourceIndex), path: ["address"], expectedStamp: snapshot.stamp },
        view === "memory" ? { byteOffset: String(byteOffset % 16) } : {}) };
  }

  function selectCallbackAddress(field)
  {
    if (callbackAddressFields(state.selectedRow).indexOf(field) >= 0)
    {
      state.selectedAddressField = field;
      selectObservation(state.selectedRow);
    }
  }

  function openAddressNavigation(navigation, view)
  {
    if (!addressNavigationAvailable(navigation, view))
    {
      return;
    }
    var source = Object.assign({}, navigation.source, { action: view === "memory" ? "memory" : "disassemble" });
    setInspectionTab(view);
    setMemoryPanel(true);
    uiElement(view + "-address").value = navigation.address;
    if (view === "memory")
    {
      uiElement("memory-space").value = navigation.space;
      updateMemoryActions();
      readMemory(source);
    }
    else
    {
      updateDisassemblyActions();
      readDisassembly(source);
    }
  }

  function selectObservation(row)
  {
    var changed = state.selectedRow !== row || state.renderedIndex !== state.selectedIndex || state.renderedRevision !== state.resultRevision;
    state.selectedRow = row;
    var selected = state.selectedIndex >= 0;
    if (changed)
    {
      state.renderedIndex = state.selectedIndex;
      state.renderedRevision = state.resultRevision;
      els.resultDetail.textContent = selected ? JSON.stringify(row, null, 2) : "";
      uiElement("detail-kind").textContent = selected ? (row && row.kind) || "Row" : "No selection";
      if (state.copyMenu && els.detailFields.contains(state.copyMenu.anchor))
      {
        closeCopyMenu();
      }
      if (els.detailFields.contains(uiActiveElement()))
      {
        uiElement("result-table").focus();
      }
      els.detailFields.textContent = "";
      if (row)
      {
        Object.keys(row).slice(0, 48).forEach(function (key)
        {
          var term = document.createElement("dt");
          var value = document.createElement("dd");
          term.textContent = key;
          var full = row.kind === "AlpcPort" && key === "name" ? displayField(row[key], [key], row) : scalar(row[key]);
          value.textContent = full.length > 512 ? full.slice(0, 512) + "... (see raw record)" : full;
          bindCopyValue(value, function ()
          {
            return clipboardValue(row[key]);
          }, "field " + key, "Copy field " + key, callbackAddressFields(row).indexOf(key) >= 0 ? function ()
          {
            selectCallbackAddress(key);
          } : null, null, resultAddressNavigation(row, [key], state.selectedOriginalIndex));
          value.tabIndex = 0;
          els.detailFields.appendChild(term);
          els.detailFields.appendChild(value);
        });
      }
    }
    var fields = callbackAddressFields(row);
    var selector = uiElement("callback-address");
    if (row && fields.indexOf(state.selectedAddressField) < 0)
    {
      state.selectedAddressField = fields.find(function (field)
      {
        return callbackNavigation(row, field, state.selectedOriginalIndex).address;
      }) || fields[0] || "";
    }
    setHidden(uiElement("callback-address-choice"), !fields.length);
    setHidden(uiElement("btn-open-memory"), !fields.length);
    if (changed)
    {
      selector.textContent = "";
      fields.forEach(function (field)
      {
        var option = document.createElement("option");
        var navigation = callbackNavigation(row, field, state.selectedOriginalIndex);
        option.value = field;
        option.textContent = (field === "preRoutine" ? "Pre" : field === "postRoutine" ? "Post" : "Routine") + ": " +
          (navigation.address || navigation.reason);
        selector.appendChild(option);
      });
    }
    selector.value = state.selectedAddressField;
    var callback = selectedCallbackNavigation();
    var navigation = callback || row && resultAddressNavigation(row, ["address"], state.selectedOriginalIndex);
    uiElement("btn-open-memory").disabled = !addressNavigationAvailable(callback);
    var address = callback ? callback.address : row && row.address;
    var space = row && row.addressSpace;
    var valid = typeof address === "string" && /^0x[0-9a-f]{1,16}$/i.test(address) &&
      (space === "virtual" || space === "physical");
    var historical = historicalResult() || !!(row && row.historical);
    els.selectionScope.textContent = callback ?
      (callback.address ? (callback.field === "preRoutine" ? "Pre" : callback.field === "postRoutine" ? "Post" : "Routine") +
        " / virtual " + callback.address + (historical ? " / historical" : "") : callback.reason) :
      valid ? space + " " + address + (historical ? " / historical" : "") :
      (row ? (addressFieldsByRow.get(row) || []).length ? "Right-click an address field to open Memory or Disassembly." :
        "No address available for navigation" : "Select a row to inspect its fields.");
    uiElement("btn-navigate").disabled = !!callback || !addressNavigationAvailable(navigation);
    uiElement("btn-disassemble").disabled = !addressNavigationAvailable(navigation, "disassembly");
    uiElement("btn-source").disabled = !addressNavigationAvailable(navigation, "disassembly") || typeof row.sourceFile !== "string";
    uiElement("btn-copy-bytes").disabled = !row || typeof row.rawBytes !== "string";
    uiElement("btn-copy-symbol").disabled = !row || typeof row.symbolRva !== "string";
    uiElement("btn-copy-row").disabled = !selected;
    updateCopyNavigation();
    updateBreakpointControls();
  }

  uiElement("callback-address").addEventListener("change", function ()
  {
    selectCallbackAddress(uiElement("callback-address").value);
  });
  uiElement("btn-open-memory").addEventListener("click", function ()
  {
    openAddressNavigation(selectedCallbackNavigation(), "memory");
  });

  function runView(command, action, screen)
  {
    if (state.busy || debuggerBusy() || !state.ready)
    {
      return;
    }
    executeCurrentInput(action ? {
      resultId: state.resultId, collection: state.resultCollection || "rows", index: String(state.selectedOriginalIndex),
      action: action, expectedStamp: state.resultTarget
    } : null, screen, command);
  }

  ["stack", "breakpoints", "event", "back", "forward", "bookmark", "bookmarks"].forEach(function (command)
  {
    uiElement("btn-" + command).addEventListener("click", function ()
    {
      if (command === "breakpoints")
      {
        refreshBreakpoints(true, "breakpoints");
      }
      else
      {
        runView(command, null, ["stack", "event"].indexOf(command) >= 0 ? command : undefined);
      }
    });
  });
  uiElement("btn-results").addEventListener("click", function ()
  {
    if (!uiElement("btn-results").disabled && state.returnResult)
    {
      loadResult(state.returnResult.id, state.returnResult);
    }
  });
  uiElement("btn-navigate").addEventListener("click", function ()
  {
    var row = state.selectedRow;
    if (row && !uiElement("btn-navigate").disabled)
    {
      runView("navigate " + (row.addressSpace === "physical" ? "pa " : "va ") + row.address, "navigate");
    }
  });
  uiElement("btn-disassemble").addEventListener("click", function ()
  {
    if (!uiElement("btn-disassemble").disabled)
    {
      openAddressNavigation(selectedCallbackNavigation() ||
        resultAddressNavigation(state.selectedRow, ["address"], state.selectedOriginalIndex), "disassembly");
    }
  });
  uiElement("btn-source").addEventListener("click", function ()
  {
    if (state.selectedRow && !uiElement("btn-source").disabled)
    {
      runView("source " + state.selectedRow.address, "source");
    }
  });
  uiElement("btn-refresh-status").addEventListener("click", refreshStatus);
  function clearFeedbackTimer()
  {
    if (state.feedbackTimer !== null)
    {
      clearTimeout(state.feedbackTimer);
      state.feedbackTimer = null;
    }
  }

  function workspaceFeedback(text, persistent)
  {
    clearFeedbackTimer();
    var node = uiElement("workspace-feedback");
    uiElement("workspace-feedback-text").textContent = text;
    setHidden(node, !text);
    updateMemoryPanelLayout();
    if (text && !persistent)
    {
      var timer = setTimeout(function ()
      {
        if (state.feedbackTimer === timer)
        {
          state.feedbackTimer = null;
          dismissNotice("workspace-feedback", "btn-workspace-dismiss", "prompt");
        }
      }, 5000);
      state.feedbackTimer = timer;
    }
  }

  uiElement("btn-workspace-dismiss").addEventListener("click", function ()
  {
    clearFeedbackTimer();
    dismissNotice("workspace-feedback", "btn-workspace-dismiss", "prompt");
  });

  function copyFocusGrid(node)
  {
    for (var index = 0; index < inspectionViews.length; ++index)
    {
      var view = inspectionViews[index];
      if (inspectionPanel(view).contains(node))
      {
        return inspectionGrid(view);
      }
    }
    return "result-table";
  }

  function restoreCopyFocus(grid)
  {
    if (["process-grid", "memory-grid", "disassembly-grid", "registers-grid"].indexOf(grid) >= 0)
    {
      var view = inspectionViews.find(function (name)
      {
        return inspectionGrid(name) === grid;
      });
      grid = inspectionVisible(view) ? grid : state.memoryPanel.visible ? inspectionGrid(state.memoryPanel.tab) : "btn-memory-panel";
    }
    uiElement(grid || "result-table").focus();
  }

  function clipboardValue(value)
  {
    return typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }

  function hasSelectedText(node)
  {
    var view = uiView(node || uiActiveElement());
    var selection = view.getSelection && view.getSelection();
    return !!(selection && String(selection) && (!node || !selection.anchorNode ||
      node.contains(selection.anchorNode) || node.contains(selection.focusNode)));
  }

  function closeCopyMenu(restoreFocus)
  {
    var opened = state.copyMenu;
    if (!opened)
    {
      return;
    }
    state.copyMenu = null;
    var menu = uiElement("cell-copy-menu");
    var focused = menu.contains(uiActiveElement());
    setHidden(menu, true);
    if (restoreFocus !== false && focused)
    {
      if (opened.anchor.isConnected !== false && !opened.anchor.disabled)
      {
        opened.anchor.focus({ preventScroll: true });
      }
      else
      {
        restoreCopyFocus(opened.grid);
      }
    }
  }

  function updateCopyNavigation()
  {
    var navigation = state.copyMenu && state.copyMenu.navigation;
    var focused = uiActiveElement();
    ["memory", "disassembly"].forEach(function (view)
    {
      var button = uiElement("cell-open-" + view);
      setHidden(button, !navigation || !!navigation.origin && navigation.origin.view === view);
      button.disabled = !addressNavigationAvailable(navigation, view);
      button.title = navigation && (navigation.reason || (view === "disassembly" && navigation.space === "physical" ?
        "Physical addresses can only be opened in Memory." : navigation.address && !navigationProcessCurrent(navigation) ?
        "Attach the owning process before reading its virtual addresses." :
        button.disabled ? "A current result and stopped target are required." : "")) || "";
    });
    if (state.copyMenu && [uiElement("cell-open-memory"), uiElement("cell-open-disassembly")].indexOf(focused) >= 0 &&
        (focused.disabled || focused.classList.contains("hidden")))
    {
      uiElement("cell-copy-value").focus({ preventScroll: true });
    }
  }

  function openCopyMenu(node, value, label, rowText, event, navigation)
  {
    closeResultTabMenu(false);
    closeCopyMenu(false);
    var menu = uiElement("cell-copy-menu");
    var view = uiView(node);
    if (node.ownerDocument && menu.ownerDocument !== node.ownerDocument)
    {
      rememberInspectionNodes(menu);
      node.ownerDocument.body.appendChild(menu);
    }
    state.copyMenu = { anchor: node, value: value, label: label, rowText: rowText, grid: copyFocusGrid(node), navigation: navigation };
    setHidden(uiElement("cell-copy-row"), typeof rowText !== "string");
    updateCopyNavigation();
    setHidden(menu, false);
    var anchor = node.getBoundingClientRect();
    state.copyMenu.bounds = [anchor.left, anchor.top, anchor.right, anchor.bottom];
    var x = event.clientX || anchor.left;
    var y = event.clientY || anchor.bottom;
    menu.style.left = Math.max(8, Math.min(x, view.innerWidth - menu.offsetWidth - 8)) + "px";
    menu.style.top = Math.max(8, Math.min(y, view.innerHeight - menu.offsetHeight - 8)) + "px";
    uiElement("cell-copy-value").focus({ preventScroll: true });
  }

  function bindCopyValue(node, readValue, label, accessibleLabel, select, readRow, navigation)
  {
    node.classList.add("copyable");
    node.tabIndex = -1;
    node.setAttribute("aria-label", accessibleLabel || "Copy " + label);
    node.setAttribute("aria-description", node.textContent);
    node.setAttribute("aria-keyshortcuts", "Enter Space Control+C Shift+F10");
    node.title = (node.title || "") + (node.title ? "\n" : "") +
      (navigation ? "Click to select and copy; right-click to open Memory or Disassembly" :
        "Click to copy the full value; right-click for copy options");
    function selectCell()
    {
      if (select)
      {
        var replacement = select();
        if (replacement && typeof replacement.focus === "function")
        {
          // Selection can replace a virtualized row while its details resize.
          node = replacement;
        }
      }
      node.focus({ preventScroll: true });
    }
    function copyValue(event)
    {
      if (node.disabled || (event.detail && event.detail > 1) || hasSelectedText(node))
      {
        return;
      }
      event.stopPropagation();
      selectCell();
      copyText(readValue(), label);
    }
    function showMenu(event)
    {
      if (node.disabled || typeof readValue() !== "string")
      {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      selectCell();
      openCopyMenu(node, readValue(), label, readRow ? readRow() : null, event, navigation);
    }
    node.addEventListener("click", copyValue);
    node.addEventListener("contextmenu", showMenu);
    node.addEventListener("keydown", function (event)
    {
      if (event.isComposing || event.repeat)
      {
        return;
      }
      if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10"))
      {
        showMenu(event);
      }
      else if (event.key === "Enter" || event.key === " " ||
        ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "c" && !hasSelectedText()))
      {
        event.preventDefault();
        copyValue(event);
      }
    });
  }

  ["value", "row"].forEach(function (kind)
  {
    uiElement("cell-copy-" + kind).addEventListener("click", function ()
    {
      var opened = state.copyMenu;
      if (opened)
      {
        closeCopyMenu();
        copyText(kind === "value" ? opened.value : opened.rowText,
          kind === "value" ? opened.label : "row as JSON");
      }
    });
  });
  ["memory", "disassembly"].forEach(function (view)
  {
    uiElement("cell-open-" + view).addEventListener("click", function ()
    {
      var navigation = state.copyMenu && state.copyMenu.navigation;
      closeCopyMenu();
      openAddressNavigation(navigation, view);
    });
  });
  uiElement("cell-copy-menu").addEventListener("keydown", function (event)
  {
    if (event.key === "Escape" || event.key === "Tab")
    {
      if (event.key === "Escape")
      {
        event.preventDefault();
      }
      event.stopPropagation();
      closeCopyMenu();
    }
    else if (["ArrowDown", "ArrowUp", "Home", "End"].indexOf(event.key) >= 0)
    {
      event.preventDefault();
      var choices = ["cell-copy-value", "cell-copy-row", "cell-open-memory", "cell-open-disassembly"].map(uiElement).filter(function (node)
      {
        return !node.classList.contains("hidden") && !node.disabled;
      });
      var index = choices.indexOf(uiActiveElement());
      var next = event.key === "Home" ? 0 : event.key === "End" ? choices.length - 1 :
        (index + (event.key === "ArrowUp" ? -1 : 1) + choices.length) % choices.length;
      if (choices[next])
      {
        choices[next].focus();
      }
    }
  });
  listenDocument("pointerdown", function (event)
  {
    if (!els.root.inert)
    {
      closeToolMenus(event.target);
    }
    if (state.resultTabMenu && !uiElement("result-tab-menu").contains(event.target))
    {
      closeResultTabMenu(false);
    }
    if (state.copyMenu && !uiElement("cell-copy-menu").contains(event.target))
    {
      closeCopyMenu(false);
    }
  });
  listenDocument("focusin", function (event)
  {
    if (!els.root.inert)
    {
      closeToolMenus(event.target);
    }
    if (state.resultTabDrag && !state.resultTabDrag.tab.button.contains(event.target))
    {
      endResultTabDrag(true);
    }
    if (state.resultTabMenu && !uiElement("result-tab-menu").contains(event.target))
    {
      closeResultTabMenu(false);
    }
  });
  listenWindow("blur", function ()
  {
    hideSuggest();
    endResultTabDrag(true);
    closeResultTabMenu(false);
    closeCopyMenu(false);
  });
  listenDocument("visibilitychange", function ()
  {
    if (document.hidden)
    {
      hideSuggest();
      endResultTabDrag(true);
      closeResultTabMenu(false);
      closeCopyMenu(false);
    }
    else if (state.ready)
    {
      state.statusKnown = false;
      ++state.debuggerRevision;
      updateCurrentProcess();
      updateProcessActions();
      updateMemoryActions();
      updateDisassemblyActions();
      updateInputUI();
      selectObservation(state.selectedRow);
      if (!state.busy)
      {
        refreshStatus();
      }
    }
    scheduleWorkspaceStatus();
  });
  ["resize", "scroll"].forEach(function (name)
  {
    listenWindow(name, function (event)
    {
      if (name === "resize")
      {
        endResultTabDrag(true);
      }
      else if (state.resultTabDrag && state.resultTabDrag.started && event.target === uiElement("result-tabs"))
      {
        updateResultTabDrop(state.resultTabDrag);
      }
      if (state.resultTabMenu)
      {
        var tabAnchor = state.resultTabMenu.tab.element.getBoundingClientRect();
        var tabBounds = [tabAnchor.left, tabAnchor.top, tabAnchor.right, tabAnchor.bottom];
        if (name === "resize" || tabBounds.some(function (value, index)
        {
          return value !== state.resultTabMenu.bounds[index];
        }))
        {
          closeResultTabMenu();
        }
      }
      if (state.copyMenu)
      {
        var anchor = state.copyMenu.anchor.getBoundingClientRect();
        var bounds = [anchor.left, anchor.top, anchor.right, anchor.bottom];
        if (name === "resize" || bounds.some(function (value, index)
        {
          return value !== state.copyMenu.bounds[index];
        }))
        {
          closeCopyMenu();
        }
      }
    }, true);
  });

  function clipboardFeedback(text)
  {
    var node = uiElement("copy-status");
    clearTimeout(state.copyStatusTimer);
    node.textContent = text;
    setHidden(node, false);
    updateMemoryPanelLayout();
    state.copyStatusTimer = setTimeout(function ()
    {
      setHidden(node, true);
      updateMemoryPanelLayout();
    }, 5000);
  }

  function closeCopyFallback()
  {
    var panel = uiElement("copy-fallback");
    if (panel.contains && panel.contains(uiActiveElement()))
    {
      restoreCopyFocus(state.copyFallbackGrid);
    }
    setHidden(panel, true);
    uiElement("copy-text").value = "";
    updateMemoryPanelLayout();
  }

  function copyText(text, label)
  {
    if (typeof text !== "string")
    {
      return;
    }
    if (state.clipboardPending)
    {
      clipboardFeedback("A clipboard write is still pending. Try again when it completes.");
      return;
    }
    if (text.indexOf("\u0000") >= 0)
    {
      // CF_UNICODETEXT ends at NUL. JSON escaping preserves the remainder.
      text = JSON.stringify(text);
      label += " as a JSON string (embedded NUL)";
    }
    var source = uiActiveElement();
    var origin = copyFocusGrid(source);
    var owner = uiView(source);
    closeCopyFallback();
    function fallback()
    {
      clipboardFeedback("Clipboard unavailable for " + label + ". The complete value is ready for manual copy.");
      var fallbackPanel = uiElement("copy-fallback");
      var destination = uiView(uiElement(origin) || source);
      if (destination !== window && (inspectionFloat.window === destination && state.memoryPanel.visible && !inspectionFloat.suspended ||
          inspectionViews.some(function (view)
          {
            return inspectionPanels[view].window === destination && independentInspectionVisible(view);
          })))
      {
        rememberInspectionNodes(fallbackPanel);
        destination.document.body.insertBefore(fallbackPanel, destination.document.body.firstChild);
      }
      else if (fallbackPanel.ownerDocument && fallbackPanel.ownerDocument !== document)
      {
        uiElement("main").insertBefore(fallbackPanel, uiElement("workspace-split"));
      }
      var field = uiElement("copy-text");
      field.value = text;
      state.copyFallbackGrid = origin;
      setHidden(uiElement("copy-fallback"), false);
      updateMemoryPanelLayout();
      if (!els.root.inert)
      {
        field.focus();
        field.select();
      }
    }
    state.clipboardPending = true;
    clipboardFeedback("Copying " + label + "...");
    try
    {
      var ownerNavigator = owner === window ? (typeof navigator === "undefined" ? null : navigator) : owner.navigator;
      var clipboard = ownerNavigator && ownerNavigator.clipboard;
      if (!clipboard || typeof clipboard.writeText !== "function")
      {
        throw new Error("Clipboard unavailable");
      }
      Promise.resolve(clipboard.writeText(text)).then(function ()
      {
        state.clipboardPending = false;
        clipboardFeedback("Copied " + label + ".");
      }, function ()
      {
        state.clipboardPending = false;
        fallback();
      });
    }
    catch (error)
    {
      state.clipboardPending = false;
      fallback();
    }
  }

  function copySelected(field)
  {
    var row = state.selectedRow;
    if (!row || typeof row[field] !== "string")
    {
      return;
    }
    copyText(row[field], "field " + field);
  }
  uiElement("btn-copy-close").addEventListener("click", closeCopyFallback);
  uiElement("btn-copy-row").addEventListener("click", function ()
  {
    if (state.selectedIndex >= 0)
    {
      copyText(JSON.stringify(state.selectedRow, null, 2), "row " + (state.selectedOriginalIndex + 1) + " as JSON");
    }
  });
  uiElement("result-table").addEventListener("copy", function (event)
  {
    // Preserve ordinary text selection; a grid selection copies the complete record.
    if (state.selectedIndex >= 0 && event.clipboardData && !hasSelectedText())
    {
      if (state.clipboardPending)
      {
        event.preventDefault();
        clipboardFeedback("A clipboard write is still pending. Try again when it completes.");
        return;
      }
      event.clipboardData.setData("text/plain", JSON.stringify(state.selectedRow, null, 2));
      event.preventDefault();
      clipboardFeedback("Copied row " + (state.selectedOriginalIndex + 1) + " as JSON.");
    }
  });
  uiElement("btn-copy-console").addEventListener("click", function ()
  {
    if (state.outputUnits)
    {
      copyText(state.outputChunks.map(function (chunk)
      {
        return chunk.text;
      }).join(""), "displayed console text");
    }
  });
  uiElement("btn-copy-bytes").addEventListener("click", function () { copySelected("rawBytes"); });
  uiElement("btn-copy-symbol").addEventListener("click", function () { copySelected("symbolRva"); });
  uiElement("btn-result-load").addEventListener("click", function ()
  {
    loadResult(uiElement("result-id-input").value.trim());
  });

  els.resultView.addEventListener("scroll", showRows);
  uiElement("result-collection").addEventListener("change", function (event)
  {
    var collection = event.target.value;
    if (collection !== "rows" && collection !== "findings")
    {
      return;
    }
    selectResult({ resultId: state.resultId, data: state.resultMeta, rowCount: state.observationCount,
      findingCount: state.findingCount, outputLength: state.resultOutputLength,
      ok: !state.resultFailed, error: state.resultError }, collection, undefined, state.resultScreen);
  });

  function appendCommandEcho(commandText) {
    var time = new Date().toTimeString().slice(0, 8);
    appendOutput("[" + time + "] ", "t-dim");
    appendOutput(commandText + "\n", "t-cmd");
  }

  // ---------- status ----------

  // Process inventory is independent of the active command result.
  function processStampKey(stamp)
  {
    return JSON.stringify(stamp || null);
  }

  function processListCurrent()
  {
    return state.connected && state.sessionStatus.stopped && !state.processes.error && state.processes.resultId &&
      processStampKey(state.processes.stamp) === processStampKey(state.target);
  }

  function processIdentity(row)
  {
    return row ? JSON.stringify([row.eprocess, row.pid, row.createTime]) : "";
  }

  function scheduleWorkspaceStatus()
  {
    clearTimeout(state.processes.timer);
    if (state.ready && !document.hidden)
    {
      state.processes.timer = setTimeout(function ()
      {
        if (!document.hidden && (!state.busy || state.executionControl.starting || state.executionControl.breaking) && !state.statusPending)
        {
          refreshStatus();
        }
        scheduleWorkspaceStatus();
      }, state.disassembly.awaitingStop || (state.connected && !state.sessionStatus.stopped) || state.statusBusy ? 500 : 3000);
    }
  }

  function updateProcessActions()
  {
    var inventory = state.processes;
    var row = inventory.rows[inventory.selected];
    var valid = !state.busy && !debuggerBusy() && row && processListCurrent();
    ["details", "threads", "vad", "token"].forEach(function (action)
    {
      uiElement("btn-process-" + action).disabled = !valid;
    });
    var identityKnown = row && typeof row.pid === "string" && typeof row.createTime === "string" &&
      typeof row.dtb === "string" && !/^0x0+$/i.test(row.dtb);
    uiElement("btn-process-attach").disabled = !valid || !identityKnown || !state.sessionStatus.canAttachProcess;
    uiElement("btn-process-refresh").disabled = state.busy || debuggerBusy() || !state.ready || !state.connected ||
      !state.sessionStatus.kernelMode || !state.sessionStatus.stopped;
    var hint = !row ? "Select a process to inspect its address space." : !processListCurrent() ?
      "Refresh the process list at the current debugger stop before using an action." : !identityKnown ?
      "Attach needs a readable PID, creation time and DTB." : !state.sessionStatus.canAttachProcess ?
      state.sessionStatus.processAttachReason || "Address-space switching is unavailable on this target." :
      "Attach uses the selected process for debugger virtual-memory reads and address translation.";
    var active = (state.target.contextIdentity || {}).implicitProcess;
    if (row && typeof active === "string" && active.toLowerCase() === String(row.eprocess).toLowerCase())
    {
      hint = "This is the debugger's current process address space. " + hint;
    }
    uiElement("process-attach-hint").textContent = hint;
  }

  function updateProcessSummary()
  {
    var inventory = state.processes;
    var coverage = inventory.meta.coverage || {};
    var text = !inventory.resultId ? "No process list collected." : inventory.filtered.length + " shown / " +
      inventory.rows.length + " collected" + (coverage.complete ? " / complete" : " / partial coverage");
    if (inventory.resultId && !processListCurrent())
    {
      text += " / previous snapshot";
    }
    if (inventory.loading)
    {
      text += " / refreshing...";
    }
    if (state.pauseInspectionReads)
    {
      text += " / automatic reads paused";
    }
    uiElement("process-summary").textContent = text;
    var notice = inventory.error || (state.statusBusy ? "Debugger busy. Showing the last checked process list." :
      !state.connected ? "Debugger disconnected. The previous list is retained." :
      !state.sessionStatus.kernelMode ? "Process inventory requires a kernel debugging session." :
      !state.sessionStatus.stopped ? "Waiting for the target to stop. The previous list is retained." :
      inventory.resultId && !coverage.complete ? "Process collection is incomplete: " +
        (coverage.stopReason || inventory.meta.status || "see result coverage") + ". Refresh to collect again." : "");
    uiElement("process-notice").textContent = notice;
    setHidden(uiElement("process-notice"), !notice);
    updateProcessSortHeaders();
    updateProcessActions();
  }

  function updateProcessSortHeaders()
  {
    var inventory = state.processes;
    processColumns.forEach(function (column)
    {
      var sorted = inventory.sort && inventory.sort.key === column.key;
      var direction = sorted ? inventory.sort.direction : "none";
      var button = uiElement("process-sort-" + column.key);
      uiElement("process-column-" + column.key).setAttribute("aria-sort", direction);
      button.dataset.sortDirection = direction;
      button.title = "Sort " + (direction === "ascending" ? "descending" : "ascending") + " by " + column.label;
      button.setAttribute("aria-label", column.label + ": " + button.title);
      button.disabled = !inventory.rows.length;
    });
  }

  function chooseProcess(index)
  {
    var inventory = state.processes;
    inventory.selected = index;
    renderContextDetails();
    var row = inventory.rows[index];
    setHidden(uiElement("process-inspector"), !row);
    uiElement("process-name").textContent = row ? (row.image || "Unknown image") + " / PID " +
      (row.pid === null ? "Unknown" : row.pid) : "Select a process";
    var fields = uiElement("process-fields");
    fields.textContent = "";
    if (row)
    {
      Object.keys(row).filter(function (key)
      {
        return key !== "kind";
      }).forEach(function (key)
      {
        var term = document.createElement("dt");
        term.textContent = columnLabel([key]);
        var value = document.createElement("dd");
        value.textContent = tableCellText(row[key]);
        fields.appendChild(term);
        fields.appendChild(value);
      });
    }
    updateProcessSelection();
    updateProcessActions();
    syncProcessViewport();
  }

  function updateProcessSelection()
  {
    var inventory = state.processes;
    Array.prototype.forEach.call(uiElement("process-rows").children, function (entry)
    {
      var selected = Number(entry.dataset.processIndex) === inventory.selected;
      entry.className = "process-row" + (selected ? " selected" : "");
      entry.setAttribute("aria-selected", String(selected));
      Array.prototype.forEach.call(entry.querySelectorAll(".copyable"), function (button)
      {
        button.tabIndex = selected ? 0 : -1;
      });
    });
    var position = inventory.filtered.indexOf(inventory.selected);
    var row = inventory.rows[inventory.selected];
    uiElement("process-position").textContent = row ? "PID " + row.pid +
      (position < 0 ? " / filtered out" : " / row " + (position + 1)) : "No process selected";
    var grid = uiElement("process-grid");
    grid.setAttribute("aria-activedescendant", uiElement("process-row-" + inventory.selected) ?
      "process-row-" + inventory.selected : "");
  }

  function renderProcessRows()
  {
    closeCopyMenu();
    var inventory = state.processes;
    var view = uiElement("process-view");
    var container = uiElement("process-rows");
    var focused = uiActiveElement();
    var focusedEntry = focused && focused.parentElement;
    var focusedRecord = focusedEntry && focusedEntry.processRecord;
    var focusedIndex = focusedEntry && focusedEntry.dataset ? Number(focusedEntry.dataset.processIndex) : -1;
    var focusedColumn = focused && focused.getAttribute ? Number(focused.getAttribute("aria-colindex")) - 1 : -1;
    uiElement("process-head").style.transform = "translateX(" + (-view.scrollLeft) + "px)";
    if (container.contains && container.contains(uiActiveElement()))
    {
      uiElement("process-grid").focus();
    }
    container.textContent = "";
    var start = Math.max(0, Math.floor(view.scrollTop / workspaceRowHeight()) - 8);
    inventory.renderStart = start;
    var count = Math.min(128, Math.max(24, Math.ceil(view.clientHeight / workspaceRowHeight()) + 16));
    inventory.renderCount = count;
    uiElement("process-spacer").style.height = inventory.filtered.length * workspaceRowHeight() + "px";
    container.style.transform = "translateY(" + start * workspaceRowHeight() + "px)";
    uiElement("process-grid").setAttribute("aria-rowcount", String(inventory.filtered.length + 1));
    inventory.filtered.slice(start, start + count).forEach(function (index, local)
    {
      var row = inventory.rows[index];
      var entry = document.createElement("div");
      entry.id = "process-row-" + index;
      entry.dataset.processIndex = String(index);
      entry.processRecord = row;
      entry.setAttribute("role", "row");
      entry.setAttribute("aria-rowindex", String(start + local + 2));
      processColumns.forEach(function (definition, column)
      {
        var key = definition.key;
        var cell = document.createElement("span");
        cell.setAttribute("role", "gridcell");
        cell.setAttribute("aria-colindex", String(column + 1));
        cell.textContent = tableCellText(row[key]);
        cell.title = cell.textContent;
        if (row[key] !== undefined)
        {
          bindCopyValue(cell, function ()
          {
            return clipboardValue(row[key]);
          }, columnLabel([key]) + " from process " + row.pid, "Copy " + columnLabel([key]) + " for PID " + row.pid, function ()
          {
            chooseProcess(index);
            var current = uiElement("process-row-" + index);
            return current ? current.children[column] : cell;
          }, function ()
          {
            return JSON.stringify(row, null, 2);
          });
        }
        entry.appendChild(cell);
      });
      entry.addEventListener("click", function ()
      {
        chooseProcess(index);
        uiElement("process-grid").focus();
      });
      container.appendChild(entry);
    });
    updateProcessSelection();
    var replacement = focusedRecord && uiElement("process-row-" + focusedIndex);
    if (replacement && replacement.processRecord === focusedRecord && replacement.children[focusedColumn] &&
        replacement.children[focusedColumn].classList.contains("copyable"))
    {
      replacement.children[focusedColumn].focus({ preventScroll: true });
    }
  }

  function filterProcesses()
  {
    var inventory = state.processes;
    var query = uiElement("process-filter").value.trim().toLowerCase();
    inventory.filtered = [];
    inventory.rows.forEach(function (row, index)
    {
      if (!query || [row.pid, row.image, row.eprocess].some(function (value)
      {
        return typeof value === "string" && value.toLowerCase().indexOf(query) >= 0;
      }))
      {
        inventory.filtered.push(index);
      }
    });
    if (inventory.sort)
    {
      var direction = inventory.sort.direction === "ascending" ? 1 : -1;
      inventory.filtered = inventory.filtered.map(function (index)
      {
        return { index: index, key: tableSortValue(inventory.rows[index][inventory.sort.key]) };
      }).sort(function (left, right)
      {
        // Actions stay bound to source indices; equal values retain capture order.
        return compareTableSortKeys(left.key, right.key, direction) || left.index - right.index;
      }).map(function (entry)
      {
        return entry.index;
      });
    }
    uiElement("process-view").scrollTop = 0;
    if (inventory.selected >= 0 && inventory.filtered.indexOf(inventory.selected) < 0)
    {
      chooseProcess(-1);
    }
    renderProcessRows();
    updateProcessSummary();
  }

  function registersCurrent()
  {
    return state.connected && !debuggerBusy() && state.sessionStatus.stopped && state.registers.stamp &&
      processStampKey(state.registers.stamp) === processStampKey(state.target);
  }

  function updateRegistersSummary()
  {
    var viewer = state.registers;
    var current = registersCurrent();
    uiElement("btn-registers-refresh").disabled = !state.ready || state.busy || debuggerBusy() || !state.connected || !state.sessionStatus.stopped;
    uiElement("registers-summary").textContent = viewer.loading ? "Reading registers..." : viewer.stamp ?
      viewer.rows.length + " registers / " + (current ? "current stopped context" : "previous context") +
      (viewer.complete ? " / complete" : " / partial") : "Open this view on a stopped target to read registers.";
    if (state.pauseInspectionReads && !viewer.loading)
    {
      uiElement("registers-summary").textContent = viewer.stamp ? uiElement("registers-summary").textContent +
        " / automatic reads paused" : "Automatic reads are paused. Use Refresh to read registers.";
    }
    var context = viewer.rows.length && viewer.rows[0].context || {};
    uiElement("registers-context").textContent = viewer.stamp ? targetContextLabel(context) : "";
    uiElement("registers-context").title = viewer.stamp ? targetContextDetails(context) : "";
    var message = viewer.error || (viewer.stamp && !current ? "Target context changed or is running. Displayed values are from the previous capture." :
      viewer.stamp && !viewer.complete ? "Some registers are unavailable in this context. Unknown values are not zero." : "");
    uiElement("registers-notice").textContent = message;
    setHidden(uiElement("registers-notice"), !message);
  }

  function renderRegisters()
  {
    if (state.copyMenu && state.copyMenu.grid === "registers-grid")
    {
      closeCopyMenu();
    }
    var viewer = state.registers;
    var query = uiElement("registers-filter").value.trim().toLowerCase();
    var scope = uiElement("registers-scope").value;
    var container = uiElement("registers-rows");
    var focused = container.contains(uiActiveElement());
    if (focused)
    {
      uiElement("registers-grid").focus();
    }
    container.textContent = "";
    var count = 0;
    var rows = viewer.rows.map(function (row, index)
    {
      return { row: row, index: index, pinned: viewer.pins.indexOf(row.name) >= 0 };
    });
    if (scope === "all")
    {
      rows.sort(function (left, right)
      {
        return Number(right.pinned) - Number(left.pinned) || left.index - right.index;
      });
    }
    rows.forEach(function (item)
    {
      var row = item.row;
      var index = item.index;
      var pinned = item.pinned;
      if (query && (row.name || "").toLowerCase().indexOf(query) < 0 ||
          scope === "pinned" && !pinned || scope === "changed" && !viewer.changed[index])
      {
        return;
      }
      var entry = document.createElement("div");
      entry.className = "register-row" + (viewer.changed[index] ? " register-changed" : "");
      entry.setAttribute("role", "row");
      entry.setAttribute("aria-rowindex", String(++count + 1));
      var available = typeof row.value === "string" || typeof row.rawBytes === "string";
      [row.name || "Unknown", typeof row.value === "string" ? row.value : row.rawBytes || "Unavailable",
        !available ? "Unavailable" : viewer.changed[index] ? "Changed" : ""].forEach(function (value, column)
      {
        var cell = document.createElement("span");
        cell.setAttribute("role", "gridcell");
        cell.textContent = value;
        cell.title = value;
        if (column === 2 && typeof row.name === "string" && row.name.length <= 64)
        {
          var pin = document.createElement("button");
          pin.className = "quiet register-pin";
          pin.textContent = pinned ? "Unpin" : "Pin";
          pin.setAttribute("aria-label", (pinned ? "Unpin " : "Pin ") + row.name);
          pin.setAttribute("aria-pressed", String(pinned));
          pin.addEventListener("click", function ()
          {
            if (pinned)
            {
              viewer.pins = viewer.pins.filter(function (name)
              {
                return name !== row.name;
              });
            }
            else if (viewer.pins.length < 256)
            {
              viewer.pins.push(row.name);
            }
            try
            {
              window.localStorage.setItem("kndbgx.register-pins", JSON.stringify(viewer.pins));
            }
            catch (error)
            {
              // Pins remain available for this document if storage is unavailable.
            }
            renderRegisters();
          });
          cell.appendChild(pin);
        }
        if (column < 2 && available)
        {
          bindCopyValue(cell, function ()
          {
            return value;
          }, "register " + row.name, "Copy " + row.name + (column ? " value" : " name"), null, function ()
          {
            return JSON.stringify(row, null, 2);
          });
          cell.tabIndex = 0;
        }
        entry.appendChild(cell);
      });
      container.appendChild(entry);
    });
    uiElement("registers-grid").setAttribute("aria-rowcount", String(count + 1));
    uiElement("registers-count").textContent = count + " shown / " + viewer.rows.length + " collected" +
      (scope === "changed" ? " / Compared with the previous capture in this CPU/thread context" :
        scope === "pinned" && !count ? " / Pin names in All to keep them here" : "");
    updateRegistersSummary();
  }

  function registerContextKey(context)
  {
    context = context || {};
    var identity = context.targetContext || {};
    var captured = context.target && context.target.contextIdentity || {};
    return JSON.stringify([context.engineProcessId !== undefined ? context.engineProcessId : context.processId,
      context.engineThreadId !== undefined ? context.engineThreadId : context.threadId, context.processor,
      identity.pid, identity.tid, identity.eprocess, identity.ethread, captured.system,
      captured.implicitProcess, captured.implicitThread, captured.effectiveArchitecture]);
  }

  function refreshRegisters()
  {
    var viewer = state.registers;
    if (!state.ready || state.busy || debuggerBusy() || !state.connected || !state.sessionStatus.stopped)
    {
      updateRegistersSummary();
      return;
    }
    var expected = state.target;
    var revision = state.debuggerRevision;
    viewer.lastAttempt = processStampKey(expected);
    viewer.loading = true;
    viewer.cancelled = false;
    viewer.error = "";
    state.busy = true;
    setStatusBusy(true);
    phase("Reading registers");
    send("execute", { command: "registers" }).then(function (reply)
    {
      state.currentRequest = "";
      var result = reply && reply.ok && reply.result;
      if (!result || !result.resultId || !result.data || result.data.commandId !== "registers" ||
          ["Success", "Partial"].indexOf(result.data.status) < 0 || processStampKey(result.data.target) !== processStampKey(expected))
      {
        throw new Error(reply && reply.error || "Register read failed or the target context changed. Previous values are retained.");
      }
      var total = Number(result.rowCount);
      if (!Number.isSafeInteger(total) || total < 1 || total > 4096)
      {
        throw new Error("Register count is invalid or no register values are available.");
      }
      var rows = [];
      function readPage()
      {
        if (viewer.cancelled || revision !== state.debuggerRevision || processStampKey(expected) !== processStampKey(state.target))
        {
          throw new Error("Register refresh cancelled or context changed. Previous values are retained.");
        }
        var offset = rows.length;
        if (offset === total)
        {
          return Promise.resolve();
        }
        return send("resultPage", { resultId: result.resultId, collection: "rows", offset: String(offset) }).then(function (pageReply)
        {
          var page = pageReply && pageReply.ok && pageReply.result;
          if (!page || page.resultId !== result.resultId || page.collection !== "rows" || page.offset !== String(offset) ||
              !Array.isArray(page.rows) || !page.rows.length || page.rows.length > 128 || offset + page.rows.length > total ||
              Number(page.total) !== total || Number(page.next) !== offset + page.rows.length ||
              page.complete !== (offset + page.rows.length === total) || page.rows.some(function (row)
              {
                return !row || row.kind !== "Register" || row.name !== null && typeof row.name !== "string" ||
                  row.value !== null && row.value !== undefined && typeof row.value !== "string" ||
                  row.rawBytes !== null && row.rawBytes !== undefined && typeof row.rawBytes !== "string";
              }))
          {
            throw new Error(pageReply && pageReply.error || "Invalid register page. Previous values are retained.");
          }
          rows = rows.concat(page.rows);
          return readPage();
        });
      }
      return readPage().then(function ()
      {
        var sameContext = viewer.stamp && viewer.stamp.sessionId === expected.sessionId &&
          viewer.stamp.targetGeneration === expected.targetGeneration &&
          registerContextKey(viewer.rows[0] && viewer.rows[0].context) === registerContextKey(rows[0].context);
        var previous = Object.create(null);
        if (sameContext)
        {
          viewer.rows.forEach(function (row)
          {
            if (row.name)
            {
              previous[row.name] = row.value || row.rawBytes;
            }
          });
        }
        viewer.changed = rows.map(function (row)
        {
          var value = row.value || row.rawBytes;
          return typeof value === "string" && typeof previous[row.name] === "string" && previous[row.name] !== value;
        });
        viewer.rows = rows;
        viewer.stamp = result.data.target;
        viewer.complete = result.data.status === "Success" && rows.every(function (row)
        {
          return typeof row.value === "string" || typeof row.rawBytes === "string";
        });
        renderRegisters();
      });
    }).catch(function (error)
    {
      viewer.error = error.message;
    }).then(function ()
    {
      viewer.loading = false;
      finishRequest();
      updateRegistersSummary();
    });
  }

  function maybeRefreshRegisters()
  {
    if (!state.pauseInspectionReads && !document.hidden && inspectionVisible("registers") && !els.root.inert && !state.busy && !debuggerBusy() &&
        state.connected && state.sessionStatus.stopped && state.registers.lastAttempt !== processStampKey(state.target))
    {
      refreshRegisters();
    }
  }

  uiElement("registers-filter").addEventListener("input", renderRegisters);
  uiElement("registers-scope").addEventListener("change", renderRegisters);
  try
  {
    var registerPins = JSON.parse(window.localStorage.getItem("kndbgx.register-pins") || "[]");
    if (Array.isArray(registerPins) && registerPins.length <= 256 && registerPins.every(function (name)
    {
      return typeof name === "string" && name.length > 0 && name.length <= 64;
    }))
    {
      state.registers.pins = registerPins;
    }
  }
  catch (error)
  {
    // Malformed preferences do not affect the captured register values.
  }
  uiElement("btn-registers-refresh").addEventListener("click", refreshRegisters);


  function refreshProcesses()
  {
    var inventory = state.processes;
    if (state.busy || debuggerBusy() || !state.ready || !state.connected || !state.sessionStatus.kernelMode || !state.sessionStatus.stopped)
    {
      updateProcessSummary();
      return;
    }
    inventory.loading = true;
    inventory.cancelled = false;
    inventory.lastAttempt = processStampKey(state.target);
    inventory.error = "";
    state.busy = true;
    setStatusBusy(true);
    updateProcessSummary();
    phase("Loading processes");
    var selected = processIdentity(inventory.rows[inventory.selected]);
    send("execute", { command: "!dml_proc" }).then(function (reply)
    {
      state.currentRequest = "";
      var result = reply && reply.ok && reply.result;
      if (!result || !result.resultId || !result.data || result.data.commandId !== "!dml_proc" ||
        ["Success", "Partial"].indexOf(result.data.status) < 0)
      {
        throw new Error((reply && reply.error) || (result && result.error) || "Process collection failed.");
      }
      var total = Number(result.rowCount);
      if (!Number.isSafeInteger(total) || total < 0 || total > 100000)
      {
        throw new Error("Process count is invalid or exceeds the 100,000-row display limit.");
      }
      var rows = [];
      function readPage()
      {
        if (inventory.cancelled)
        {
          throw new Error("Process refresh cancelled. The previous list is retained.");
        }
        var offset = rows.length;
        if (offset === total)
        {
          return Promise.resolve();
        }
        return send("resultPage", { resultId: result.resultId, collection: "rows", offset: String(offset) }).then(function (pageReply)
        {
          var page = pageReply && pageReply.ok && pageReply.result;
          if (!page || page.resultId !== result.resultId || page.collection !== "rows" || page.offset !== String(offset) ||
            !Array.isArray(page.rows) || !page.rows.length || page.rows.length > 128 || offset + page.rows.length > total ||
            Number(page.total) !== total || Number(page.next) !== offset + page.rows.length ||
            page.complete !== (offset + page.rows.length === total) || page.rows.some(function (row)
            {
              return !row || row.kind !== "Process" || typeof row.eprocess !== "string";
            }))
          {
            throw new Error((pageReply && pageReply.error) || "Invalid process page. The previous list is retained.");
          }
          rows = rows.concat(page.rows);
          return readPage();
        });
      }
      return readPage().then(function ()
      {
        inventory.rows = rows;
        inventory.resultId = result.resultId;
        inventory.stamp = result.data.target;
        inventory.meta = result.data;
        inventory.selected = rows.findIndex(function (row)
        {
          return processIdentity(row) === selected;
        });
        filterProcesses();
        chooseProcess(inventory.selected);
      });
    }).catch(function (error)
    {
      inventory.error = error.message;
    }).then(function ()
    {
      inventory.loading = false;
      finishRequest();
      updateProcessSummary();
    });
  }

  function runProcessAction(action)
  {
    var inventory = state.processes;
    if (uiElement("btn-process-" + action).disabled)
    {
      return;
    }
    var binding = { resultId: inventory.resultId, index: String(inventory.selected), action: action, expectedStamp: inventory.stamp };
    if (action !== "attach")
    {
      if (!resultTabRoom())
      {
        return;
      }
      invalidateResultLoad();
      uiElement("result-load-status").textContent = "";
    }
    state.stopStream = !state.consoleEnabled;
    state.busy = true;
    setStatusBusy(true);
    phase("Queued");
    send("processAction", binding).then(function (reply)
    {
      state.currentRequest = "";
      if (!reply || !reply.ok)
      {
        inventory.error = (reply && reply.error) || "Process action failed. Refresh the list before trying again.";
        workspaceFeedback(inventory.error, true);
        updateProcessSummary();
        return;
      }
      if (action === "attach")
      {
        applyStatus(reply.result);
        var row = reply.result.process || {};
        workspaceFeedback("Address space attached: " + (row.image || "Unknown") + " / PID " + row.pid + " / " + row.eprocess + ".");
      }
      else
      {
        selectResult(reply.result);
        if (inspectionVisible("processes"))
        {
          if (state.memoryPanel.overlay)
          {
            setMemoryPanel(false);
          }
          focusMainWorkspace(uiElement("result-table"));
        }
        if (reply.result.resultId)
        {
          phase("Streaming");
          return pullOutput(reply.result.resultId, "0");
        }
      }
    }).catch(function (error)
    {
      workspaceFeedback(error.message, true);
    }).then(finishRequest);
  }

  ["details", "threads", "vad", "token", "attach"].forEach(function (action)
  {
    uiElement("btn-process-" + action).addEventListener("click", function ()
    {
      runProcessAction(action);
    });
  });
  uiElement("process-filter").addEventListener("input", filterProcesses);
  processColumns.forEach(function (column)
  {
    var button = uiElement("process-sort-" + column.key);
    button.addEventListener("click", function ()
    {
      var inventory = state.processes;
      if (!inventory.rows.length)
      {
        return;
      }
      inventory.sort = { key: column.key, direction: inventory.sort && inventory.sort.key === column.key &&
        inventory.sort.direction === "ascending" ? "descending" : "ascending" };
      filterProcesses();
    });
    button.addEventListener("focus", function ()
    {
      var view = uiElement("process-view");
      var head = uiElement("process-head");
      var bounds = uiElement("process-column-" + column.key).getBoundingClientRect();
      var left = bounds.left - head.getBoundingClientRect().left;
      var width = bounds.right - bounds.left;
      if (view.clientWidth)
      {
        if (left < view.scrollLeft || width > view.clientWidth)
        {
          view.scrollLeft = left;
        }
        else if (left + width > view.scrollLeft + view.clientWidth)
        {
          view.scrollLeft = left + width - view.clientWidth;
        }
        uiElement("process-grid").scrollLeft = 0;
        head.style.transform = "translateX(" + (-view.scrollLeft) + "px)";
      }
    });
  });
  uiElement("btn-process-refresh").addEventListener("click", refreshProcesses);
  uiElement("process-view").addEventListener("scroll", function ()
  {
    var view = uiElement("process-view");
    uiElement("process-head").style.transform = "translateX(" + (-view.scrollLeft) + "px)";
    if (Math.max(0, Math.floor(view.scrollTop / workspaceRowHeight()) - 8) !== state.processes.renderStart)
    {
      renderProcessRows();
    }
  });
  function syncProcessViewport()
  {
    if (!inspectionVisible("processes"))
    {
      return;
    }
    var needed = Math.min(128, Math.max(24, Math.ceil(uiElement("process-view").clientHeight / workspaceRowHeight()) + 16));
    if (needed > state.processes.renderCount)
    {
      renderProcessRows();
    }
  }
  uiElement("process-grid").addEventListener("keydown", function (event)
  {
    if (event.key === "Escape")
    {
      uiElement("process-grid").focus();
      return;
    }
    if (event.altKey || event.ctrlKey || event.metaKey || event.isComposing || !state.processes.filtered.length)
    {
      return;
    }
    var view = uiElement("process-view");
    var index = state.processes.filtered.indexOf(state.processes.selected);
    var page = Math.max(1, Math.floor(view.clientHeight / workspaceRowHeight()));
    switch (event.key)
    {
      case "ArrowDown": index = index < 0 ? 0 : index + 1; break;
      case "ArrowUp": index = index < 0 ? 0 : index - 1; break;
      case "Home": index = 0; break;
      case "End": index = state.processes.filtered.length - 1; break;
      case "PageDown": index = Math.max(0, index) + page; break;
      case "PageUp": index = Math.max(0, index) - page; break;
      default: return;
    }
    event.preventDefault();
    uiElement("process-grid").focus();
    index = Math.max(0, Math.min(state.processes.filtered.length - 1, index));
    if (index * workspaceRowHeight() < view.scrollTop)
    {
      view.scrollTop = index * workspaceRowHeight();
    }
    else if ((index + 1) * workspaceRowHeight() > view.scrollTop + view.clientHeight)
    {
      view.scrollTop = (index + 1) * workspaceRowHeight() - view.clientHeight;
    }
    chooseProcess(state.processes.filtered[index]);
    renderProcessRows();
  });

  function checkedAddressHistoryEntry(entry, view)
  {
    if (!entry || typeof entry.expression !== "string" || !entry.expression.trim() || entry.expression.length > 1024 ||
      /[;"\\{}\u0000-\u001f]/.test(entry.expression) ||
      (view === "memory" ? ["virtual", "physical"].indexOf(entry.space) < 0 : entry.space !== "virtual"))
    {
      return null;
    }
    return { expression: entry.expression.trim(), space: entry.space };
  }

  function loadAddressHistory()
  {
    try
    {
      var saved = window.localStorage.getItem("kndbgx.address-history");
      if (typeof saved !== "string" || saved.length > 65536)
      {
        return;
      }
      var settings = JSON.parse(saved);
      if (!settings || settings.version !== 1)
      {
        return;
      }
      ["memory", "disassembly"].forEach(function (view)
      {
        if (!Array.isArray(settings[view]))
        {
          return;
        }
        settings[view].forEach(function (value)
        {
          var entry = checkedAddressHistoryEntry(value, view);
          var history = state.addressHistory[view];
          if (entry && history.length < 20 && !history.some(function (item)
          {
            return item.expression === entry.expression && item.space === entry.space;
          }))
          {
            history.push(entry);
          }
        });
      });
    }
    catch (error)
    {
      // Keep in-document history usable when storage is unavailable or malformed.
    }
  }

  function renderAddressHistory(view)
  {
    var select = uiElement(view + "-address-history");
    var history = state.addressHistory[view];
    select.textContent = "";
    var placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = history.length ? "Select a recent address..." : "No recent addresses";
    select.appendChild(placeholder);
    history.forEach(function (entry, index)
    {
      var option = document.createElement("option");
      option.value = String(index);
      option.textContent = (view === "memory" ? "[" + (entry.space === "physical" ? "Physical" : "Virtual") + "] " : "") + entry.expression;
      option.title = option.textContent;
      select.appendChild(option);
    });
    select.value = "";
    select.disabled = !history.length || uiElement("btn-" + view + "-read").disabled;
  }

  function rememberAddress(view, expression, space)
  {
    var entry = checkedAddressHistoryEntry({ expression: expression, space: space }, view);
    if (!entry)
    {
      return;
    }
    state.addressHistory[view] = [entry].concat(state.addressHistory[view].filter(function (item)
    {
      return item.expression !== entry.expression || item.space !== entry.space;
    })).slice(0, 20);
    try
    {
      window.localStorage.setItem("kndbgx.address-history", JSON.stringify({ version: 1,
        memory: state.addressHistory.memory, disassembly: state.addressHistory.disassembly }));
    }
    catch (error)
    {
      // Retain the current document's history if saving fails.
    }
    renderAddressHistory(view);
  }

  ["memory", "disassembly"].forEach(function (view)
  {
    uiElement(view + "-address-history").addEventListener("change", function ()
    {
      var select = uiElement(view + "-address-history");
      var index = /^(0|[1-9][0-9]*)$/.test(select.value) ? Number(select.value) : -1;
      var entry = state.addressHistory[view][index];
      select.value = "";
      if (select.disabled || !entry || uiElement("btn-" + view + "-read").disabled ||
        !inspectionVisible(view))
      {
        return;
      }
      hideSuggest();
      uiElement(view + "-address").value = entry.expression;
      if (view === "memory")
      {
        uiElement("memory-space").value = entry.space;
        updateMemoryActions();
        readMemory();
      }
      else
      {
        setDisassemblyFollow(false);
        updateDisassemblyActions();
        readDisassembly();
      }
    });
  });

  function memoryHex(address)
  {
    return "0x" + address.toString(16).padStart(16, "0");
  }

  function memoryCurrent()
  {
    var snapshot = state.memory.snapshot;
    return snapshot && state.connected && state.sessionStatus.stopped &&
      processStampKey(snapshot.stamp) === processStampKey(state.target);
  }

  var memoryCaptureLabels = { Unknown: "Unknown", KernelRemote: "Live remote kernel", KernelLocal: "Live local kernel",
    KernelExdi: "Live kernel (eXDI)", KernelSmallDump: "Kernel small dump", KernelDump: "Kernel dump",
    KernelCompleteDump: "Kernel complete dump", KernelActiveDump: "Kernel active dump",
    UserLive: "Live user process", UserRemote: "Remote user process", UserMinidump: "User minidump", UserDump: "User dump" };

  function checkedMemoryEvidence(value, address, space, bytes)
  {
    if (!value || value.schema !== "kndbgx.memory-read.v1" || value.address !== memoryHex(address) ||
      value.addressSpace !== space || value.length !== String(bytes.length) || value.mapping !== "Unobserved" ||
      value.unreadableCause !== "Unknown" || !Array.isArray(value.attempts) || !value.attempts.length || value.attempts.length > 17 ||
      !value.capture || !Object.prototype.hasOwnProperty.call(memoryCaptureLabels, value.capture.kind))
    {
      return null;
    }
    var offset = 0;
    var read = 0;
    var valid = value.attempts.every(function (attempt)
    {
      if (!attempt || typeof attempt.requested !== "string" || typeof attempt.read !== "string" ||
        !/^[1-9][0-9]{0,4}$/.test(attempt.requested) || !/^(0|[1-9][0-9]{0,4})$/.test(attempt.read) ||
        attempt.address !== memoryHex(address + BigInt(offset)) || ["Success", "Partial", "Unavailable"].indexOf(attempt.status) < 0)
      {
        return false;
      }
      var size = Number(attempt.requested);
      var count = Number(attempt.read);
      if (size > 4096 || count > size || offset + size > bytes.length ||
        (attempt.status === "Success" && count !== size) ||
        bytes.slice(offset, offset + size).some(function (byte, index)
        {
          return (byte !== null) !== (index < count);
        }))
      {
        return false;
      }
      var error = attempt.nativeError;
      if (error !== null && (!error || error.domain !== "HRESULT" || typeof error.code !== "string" ||
        !/^0x[0-9a-f]{16}$/i.test(error.code)))
      {
        return false;
      }
      offset += size;
      read += count;
      return true;
    });
    var capture = value.capture;
    ["class", "qualifier"].forEach(function (key)
    {
      if (capture[key] !== null && (typeof capture[key] !== "string" || !/^[0-9]{1,10}$/.test(capture[key])))
      {
        valid = false;
      }
    });
    ["dumpFlags", "typeQueryHresult", "dumpFlagsHresult"].forEach(function (key)
    {
      if (capture[key] != null && (typeof capture[key] !== "string" || !/^0x[0-9a-f]{16}$/i.test(capture[key])))
      {
        valid = false;
      }
    });
    return valid && offset === bytes.length && value.read === String(read) ? value : null;
  }

  function renderMemoryEvidence()
  {
    var memory = state.memory;
    if (!memory.evidenceOpen)
    {
      return;
    }
    var snapshot = memory.snapshot;
    var failure = memory.failedRead;
    var key = JSON.stringify([snapshot && snapshot.resultId, memory.selected, memoryRowBytes(), !!memoryCurrent(), failure]);
    if (memory.evidenceKey === key && memory.evidenceSnapshot === snapshot)
    {
      return;
    }
    memory.evidenceKey = key;
    memory.evidenceSnapshot = snapshot;
    var facts = uiElement("memory-evidence-facts");
    var ranges = uiElement("memory-evidence-ranges");
    facts.textContent = "";
    ranges.textContent = "";
    uiElement("memory-evidence-attempt").textContent = failure ? "Latest read did not replace the capture: " +
      failure.expression + " / " + failure.space + " / " + failure.size + " bytes. " + failure.error : "";
    setHidden(uiElement("memory-evidence-attempt"), !failure);
    uiElement("memory-evidence-summary").textContent = snapshot ? "Saved capture" + (memoryCurrent() ? " in the last checked context." :
      "; previous or unconfirmed context. These bytes do not describe the current target.") : "No memory capture is available.";
    var cause = "Cause: Unknown. A failed or short read does not prove an invalid pointer, paged-out memory or a missing dump page. " +
      "Page-table and VAD mappings were not checked. Opening this panel does not read the target or change its state.";
    if (snapshot)
    {
      var evidence = snapshot.evidence;
      var start = memory.selected >= 0 ? memory.selected * memoryRowBytes() : 0;
      var end = memory.selected >= 0 ? Math.min(start + memoryRowBytes(), snapshot.bytes.length) : snapshot.bytes.length;
      var selected = snapshot.bytes.slice(start, end);
      var readable = selected.filter(function (byte)
      {
        return byte !== null;
      }).length;
      function fact(label, value)
      {
        var term = document.createElement("dt");
        var detail = document.createElement("dd");
        term.textContent = label;
        detail.textContent = value;
        facts.appendChild(term);
        facts.appendChild(detail);
      }
      fact("Result capture", snapshot.resultId);
      fact(memory.selected >= 0 ? "Selected row" : "Requested range", memoryHex(snapshot.address + BigInt(start)) + " - " +
        memoryHex(snapshot.address + BigInt(end - 1)));
      fact("Bytes", readable + " read / " + (selected.length - readable) + " unavailable / " + selected.length + " requested");
      fact("Address space", snapshot.space === "physical" ? "Physical; independent of the selected process" : "Virtual / captured implicit process " +
        ((snapshot.stamp.contextIdentity || {}).implicitProcess || "Unknown"));
      fact("Capture generations", "target " + snapshot.stamp.targetGeneration + " / stop " + snapshot.stamp.stopEpoch +
        " / context " + snapshot.stamp.contextGeneration);
      fact("Read input", snapshot.expression || memoryHex(snapshot.address));
      fact("Capture kind", evidence ? memoryCaptureLabels[evidence.capture.kind] : "Unknown; saved diagnostics unavailable or inconsistent");
      if (evidence)
      {
        var capture = evidence.capture;
        if (capture.kind.indexOf("Dump") >= 0 || capture.kind === "UserMinidump")
        {
          fact("Dump format flags", capture.dumpFlags || "Unknown");
          cause += " Dump origin (crash or live capture) and inclusion of this page are unconfirmed. Dump types can contain different user-page coverage.";
        }
        var offset = 0;
        evidence.attempts.forEach(function (attempt)
        {
          var size = Number(attempt.requested);
          var count = Number(attempt.read);
          if (offset < end && offset + size > start)
          {
            var item = document.createElement("li");
            var text = attempt.address + " - " + memoryHex(snapshot.address + BigInt(offset + size - 1)) +
              ": " + count + "/" + size + " bytes, " + attempt.status + ". ";
            if (count < size)
            {
              text += "Unavailable: " + memoryHex(snapshot.address + BigInt(offset + count)) + " - " +
                memoryHex(snapshot.address + BigInt(offset + size - 1)) + ". ";
            }
            text += attempt.nativeError ? "HRESULT " + attempt.nativeError.code + "." : "Native error unavailable.";
            item.textContent = text;
            ranges.appendChild(item);
          }
          offset += size;
        });
      }
      if (selected.length === readable)
      {
        cause = "All bytes in this range were read. This does not establish pointer validity, allocation lifetime or ownership. " +
          "Opening this panel uses the saved capture only.";
      }
    }
    uiElement("memory-evidence-cause").textContent = cause;
  }

  function setMemoryEvidence(open)
  {
    state.memory.evidenceOpen = open;
    setHidden(uiElement("memory-evidence"), !open);
    uiElement("btn-memory-evidence").setAttribute("aria-expanded", String(open));
    uiElement("btn-memory-evidence").textContent = open ? "Hide details" : "Read details";
    renderMemoryEvidence();
    uiElement(open ? "btn-memory-evidence-close" : "btn-memory-evidence").focus();
  }

  uiElement("btn-memory-evidence").addEventListener("click", function ()
  {
    setMemoryEvidence(!state.memory.evidenceOpen);
  });
  uiElement("btn-memory-evidence-close").addEventListener("click", function ()
  {
    setMemoryEvidence(false);
  });
  uiElement("memory-evidence").addEventListener("keydown", function (event)
  {
    if (event.key === "Escape")
    {
      event.preventDefault();
      event.stopPropagation();
      setMemoryEvidence(false);
    }
  });
  uiElement("memory-grid").addEventListener("keydown", function (event)
  {
    if (event.key === "Enter" && event.target === uiElement("memory-grid") && state.memory.snapshot &&
      !event.ctrlKey && !event.altKey && !event.metaKey && !event.isComposing && !event.repeat)
    {
      event.preventDefault();
      setMemoryEvidence(true);
    }
  });

  function updateMemoryActions()
  {
    var available = state.ready && state.connected && state.sessionStatus.stopped && !state.busy && !debuggerBusy();
    var snapshot = state.memory.snapshot;
    var unchanged = snapshot && uiElement("memory-address").value.trim() === memoryHex(snapshot.address) &&
      uiElement("memory-space").value === snapshot.space &&
      uiElement("memory-size").value === String(snapshot.bytes.length);
    var navigate = available && memoryCurrent() && unchanged && !state.memory.error;
    uiElement("btn-memory-read").disabled = !available;
    uiElement("btn-memory-evidence").disabled = !snapshot && !state.memory.failedRead;
    uiElement("memory-address-history").disabled = !available || !state.addressHistory.memory.length;
    uiElement("btn-memory-prev").disabled = !navigate || snapshot.address < BigInt(snapshot.bytes.length);
    uiElement("btn-memory-next").disabled = !navigate ||
      snapshot.address + BigInt(snapshot.bytes.length * 2 - 1) > BigInt("0xffffffffffffffff");
    ["memory-address", "memory-space", "memory-size"].forEach(function (id)
    {
      uiElement(id).disabled = state.busy;
    });
  }

  function updateMemorySummary()
  {
    var memory = state.memory;
    var snapshot = memory.snapshot;
    var readable = snapshot ? snapshot.bytes.filter(function (value)
    {
      return value !== null;
    }).length : 0;
    uiElement("memory-summary").textContent = snapshot ?
      memoryHex(snapshot.address) + " - " + memoryHex(snapshot.address + BigInt(snapshot.bytes.length - 1)) +
        " / " + readable + " of " + snapshot.bytes.length + " bytes readable" +
        (memoryCurrent() ? "" : " / previous snapshot") + (memory.loading ? " / reading..." : "") :
      memory.loading ? "Reading memory..." : "Enter an address and choose Read.";
    var context = snapshot && snapshot.stamp && snapshot.stamp.contextIdentity;
    uiElement("memory-context").textContent = snapshot ?
      (snapshot.space === "physical" ? "Physical memory" : "Virtual memory / debugger process " +
        ((context || {}).implicitProcess || "unavailable")) +
        (snapshot.expression && snapshot.expression !== memoryHex(snapshot.address) ? " / Input: " + resultText(snapshot.expression).slice(0, 96) : "") :
      "Virtual reads use the debugger's selected process address space.";
    uiElement("memory-context").title = snapshot ? "Read input: " + (snapshot.expression || memoryHex(snapshot.address)) : "";
    var notice = memory.error || (state.statusBusy ? "Debugger busy. Showing the last checked memory view." :
      !state.connected ? "Debugger disconnected. The previous view is retained." :
      !state.sessionStatus.stopped ? "Stop the target before reading memory. The previous view is retained." :
      snapshot && !memoryCurrent() ? "Debugger context changed. Read again to inspect this address in the current context." :
      snapshot && readable !== snapshot.bytes.length ? "Unreadable bytes are shown as ??. Missing memory is not treated as zero." : "");
    uiElement("memory-notice").textContent = notice;
    setHidden(uiElement("memory-notice"), !notice);
    updateMemoryActions();
    renderMemoryEvidence();
  }

  function memoryRowBytes()
  {
    return uiElement("memory-row-width").value === "8" ? 8 : 16;
  }

  function chooseMemoryRow(index)
  {
    state.memory.selected = index;
    Array.prototype.forEach.call(uiElement("memory-rows").children, function (row, position)
    {
      var selected = index === position;
      row.className = "memory-row" + (selected ? " selected" : "");
      row.setAttribute("aria-selected", String(selected));
      Array.prototype.forEach.call(row.querySelectorAll(".copyable"), function (button)
      {
        button.tabIndex = selected ? 0 : -1;
      });
    });
    var snapshot = state.memory.snapshot;
    uiElement("memory-position").textContent = snapshot && index >= 0 ?
      "Selected " + memoryHex(snapshot.address + BigInt(index * memoryRowBytes())) : "No memory selected";
    uiElement("memory-grid").setAttribute("aria-activedescendant", index >= 0 ? "memory-row-" + index : "");
    renderMemoryEvidence();
  }

  function renderMemoryRows()
  {
    closeCopyMenu();
    var container = uiElement("memory-rows");
    var grid = uiElement("memory-grid");
    if (container.contains && container.contains(uiActiveElement()))
    {
      grid.focus();
    }
    var width = Number(uiElement("memory-format").value);
    if ([1, 2, 4, 8].indexOf(width) < 0)
    {
      width = 1;
    }
    var rowBytes = memoryRowBytes();
    var asciiVisible = uiElement("memory-ascii").checked;
    var count = rowBytes / width;
    var template = "170px repeat(" + count + ", calc(" + (width * 2) + "ch + 12px))" +
      (asciiVisible ? " calc(" + rowBytes + "ch + 16px)" : "");
    var head = uiElement("memory-head");
    head.textContent = "";
    head.style.gridTemplateColumns = template;
    var labels = ["Address"];
    for (var column = 0; column < count; column++)
    {
      labels.push("+" + (column * width).toString(16).padStart(2, "0"));
    }
    if (asciiVisible)
    {
      labels.push("ASCII");
    }
    labels.forEach(function (text)
    {
      var cell = document.createElement("span");
      cell.setAttribute("role", "columnheader");
      cell.textContent = text;
      head.appendChild(cell);
    });
    container.textContent = "";
    var snapshot = state.memory.snapshot;
    var rowCount = snapshot ? Math.ceil(snapshot.bytes.length / rowBytes) : 0;
    grid.setAttribute("aria-colcount", String(count + 1 + (asciiVisible ? 1 : 0)));
    grid.setAttribute("aria-rowcount", String(rowCount + 1));
    for (var index = 0; index < rowCount; index++)
    {
      (function (rowIndex)
      {
        var bytes = snapshot.bytes.slice(rowIndex * rowBytes, rowIndex * rowBytes + rowBytes);
        var address = snapshot.address + BigInt(rowIndex * rowBytes);
        var row = document.createElement("div");
        row.id = "memory-row-" + rowIndex;
        row.setAttribute("role", "row");
        row.setAttribute("aria-rowindex", String(rowIndex + 2));
        row.style.gridTemplateColumns = template;
        function addCell(text, copied, label, navigation)
        {
          var cell = document.createElement("span");
          cell.setAttribute("role", "gridcell");
          cell.textContent = text;
          cell.title = label;
          if (copied !== null)
          {
            bindCopyValue(cell, function ()
            {
              return copied;
            }, label, "Copy " + label, function ()
            {
              chooseMemoryRow(rowIndex);
            }, function ()
            {
              return JSON.stringify({ address: memoryHex(address), addressSpace: snapshot.space, bytes: bytes }, null, 2);
            }, navigation);
          }
          else
          {
            cell.className = "memory-unreadable";
            cell.title = label + " / Click for read details";
            cell.addEventListener("click", function (event)
            {
              event.stopPropagation();
              chooseMemoryRow(rowIndex);
              setMemoryEvidence(true);
            });
          }
          row.appendChild(cell);
        }
        addCell(memoryHex(address), memoryHex(address), "address " + memoryHex(address),
          inspectionAddressNavigation("memory", snapshot, { address: memoryHex(address), addressSpace: snapshot.space }, rowIndex));
        for (var offset = 0; offset < rowBytes; offset += width)
        {
          var unit = bytes.slice(offset, offset + width);
          var known = unit.length === width && unit.every(function (value)
          {
            return value !== null;
          });
          var hex = known ? unit.reverse().map(function (value)
          {
            return value.toString(16).padStart(2, "0");
          }).join("") : "??".repeat(width);
          addCell(hex, known ? "0x" + hex : null, (width * 8) + "-bit value at " + memoryHex(address + BigInt(offset)));
        }
        var ascii = bytes.map(function (value)
        {
          return value === null ? "?" : value >= 32 && value < 127 ? String.fromCharCode(value) : ".";
        }).join("");
        if (asciiVisible)
        {
          addCell(ascii, ascii, "ASCII display at " + memoryHex(address));
        }
        row.addEventListener("click", function ()
        {
          chooseMemoryRow(rowIndex);
          grid.focus();
        });
        container.appendChild(row);
      })(index);
    }
    chooseMemoryRow(state.memory.selected < rowCount ? state.memory.selected : -1);
  }

  function readMemory(source)
  {
    if (uiElement("btn-memory-read").disabled)
    {
      return;
    }
    var memory = state.memory;
    var expression = uiElement("memory-address").value.trim();
    var space = uiElement("memory-space").value;
    var size = Number(uiElement("memory-size").value);
    if (!expression || expression.length > 1024 || /[;"\\{}\u0000-\u001f]/.test(expression) ||
      [64, 256, 1024].indexOf(size) < 0 || ["virtual", "physical"].indexOf(space) < 0)
    {
      memory.error = "Enter one address or expression without quotes, control characters or command separators.";
      memory.failedRead = { expression: expression, space: space, size: size, error: memory.error };
      updateMemorySummary();
      updateRegistersSummary();
      return;
    }
    memory.error = "";
    memory.loading = true;
    memory.cancelled = false;
    state.busy = true;
    setStatusBusy(true);
    updateMemorySummary();
    updateRegistersSummary();
    phase("Reading memory");
    var command = space === "physical" ? "!db" : "db";
    var expected = source ? source.expectedStamp : state.target;
    send("memoryRead", { expression: expression, space: space, length: String(size), source: source || {}, expectedStamp: expected }).then(function (reply)
    {
      state.currentRequest = "";
      var result = reply && reply.ok && reply.result;
      if (!result || !result.resultId || !result.data || result.data.commandId !== command ||
        ["Success", "Partial", "Unavailable"].indexOf(result.data.status) < 0 || Number(result.rowCount) !== size / 16 ||
        processStampKey(result.data.target) !== processStampKey(expected))
      {
        throw new Error((reply && reply.error) || (result && result.error) || "Memory read failed. The previous view is retained.");
      }
      var bytes = [];
      var address = null;
      var rows = 0;
      function readPage()
      {
        if (memory.cancelled)
        {
          throw new Error("Memory read cancelled. The previous view is retained.");
        }
        if (rows === size / 16)
        {
          return Promise.resolve();
        }
        return send("resultPage", { resultId: result.resultId, collection: "rows", offset: String(rows) }).then(function (pageReply)
        {
          var page = pageReply && pageReply.ok && pageReply.result;
          if (!page || page.resultId !== result.resultId || page.collection !== "rows" || page.offset !== String(rows) ||
            !Array.isArray(page.rows) || !page.rows.length || page.rows.length > size / 16 - rows ||
            Number(page.total) !== size / 16 || Number(page.next) !== rows + page.rows.length ||
            page.complete !== (rows + page.rows.length === size / 16))
          {
            throw new Error((pageReply && pageReply.error) || "Invalid memory page. The previous view is retained.");
          }
          page.rows.forEach(function (row)
          {
            if (!row || row.kind !== "MemoryBytes" || row.addressSpace !== space ||
              typeof row.address !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(row.address) ||
              !Array.isArray(row.bytes) || row.bytes.length !== 16 || row.bytes.some(function (value)
              {
                return value !== null && (!Number.isInteger(value) || value < 0 || value > 255);
              }))
            {
              throw new Error("Invalid memory bytes. The previous view is retained.");
            }
            var start = BigInt(row.address);
            if (address === null)
            {
              address = start;
            }
            if (start !== address + BigInt(bytes.length) || address + BigInt(size - 1) > BigInt("0xffffffffffffffff"))
            {
              throw new Error("Invalid memory address sequence. The previous view is retained.");
            }
            bytes = bytes.concat(row.bytes);
          });
          rows += page.rows.length;
          return readPage();
        });
      }
      return readPage().then(function ()
      {
        memory.snapshot = { address: address, space: space, bytes: bytes, stamp: result.data.target, resultId: result.resultId,
          expression: expression, evidence: checkedMemoryEvidence((result.data.analysis || {}).memoryRead, address, space, bytes) };
        memory.failedRead = null;
        memory.selected = -1;
        uiElement("memory-address").value = memoryHex(address);
        uiElement("memory-grid").scrollTop = 0;
        renderMemoryRows();
        rememberAddress("memory", expression, space);
      });
    }).catch(function (error)
    {
      memory.error = error.message;
      memory.failedRead = { expression: expression, space: space, size: size, error: error.message };
    }).then(function ()
    {
      memory.loading = false;
      finishRequest();
      updateMemorySummary();
      updateRegistersSummary();
    });
  }

  uiElement("memory-address").value = "@rip";
  uiElement("memory-size").value = "256";
  uiElement("memory-space").value = "virtual";
  uiElement("memory-format").value = "1";
  uiElement("memory-row-width").value = "16";
  uiElement("memory-ascii").checked = true;
  uiElement("btn-memory-read").addEventListener("click", function ()
  {
    readMemory();
  });
  ["memory-address", "memory-space", "memory-size"].forEach(function (id)
  {
    uiElement(id).addEventListener("input", updateMemoryActions);
    uiElement(id).addEventListener("change", updateMemoryActions);
  });
  uiElement("memory-format").addEventListener("change", renderMemoryRows);
  var previousMemoryRowBytes = memoryRowBytes();
  uiElement("memory-row-width").addEventListener("change", function ()
  {
    if (state.memory.selected >= 0)
    {
      state.memory.selected = Math.floor(state.memory.selected * previousMemoryRowBytes / memoryRowBytes());
    }
    previousMemoryRowBytes = memoryRowBytes();
    renderMemoryRows();
  });
  uiElement("memory-ascii").addEventListener("change", renderMemoryRows);
  ["prev", "next"].forEach(function (direction)
  {
    uiElement("btn-memory-" + direction).addEventListener("click", function ()
    {
      if (!uiElement("btn-memory-" + direction).disabled)
      {
        var snapshot = state.memory.snapshot;
        uiElement("memory-address").value = memoryHex(snapshot.address +
          BigInt(snapshot.bytes.length) * BigInt(direction === "prev" ? -1 : 1));
        readMemory();
      }
    });
  });
  uiElement("memory-grid").addEventListener("keydown", function (event)
  {
    var snapshot = state.memory.snapshot;
    if (!snapshot || event.ctrlKey || event.metaKey || event.altKey || event.isComposing)
    {
      return;
    }
    var index = state.memory.selected;
    switch (event.key)
    {
      case "ArrowDown": index++; break;
      case "ArrowUp": index--; break;
      case "Home": index = 0; break;
      case "End": index = Math.ceil(snapshot.bytes.length / memoryRowBytes()) - 1; break;
      case "Escape": uiElement("memory-grid").focus(); return;
      default: return;
    }
    event.preventDefault();
    uiElement("memory-grid").focus();
    chooseMemoryRow(Math.max(0, Math.min(Math.ceil(snapshot.bytes.length / memoryRowBytes()) - 1, index)));
    var selected = uiElement("memory-rows").children[state.memory.selected];
    if (selected)
    {
      selected.scrollIntoView({ block: "nearest", inline: "nearest" });
    }
  });
  renderMemoryRows();

  function breakpointListCurrent()
  {
    return state.statusKnown && state.connected && state.sessionStatus.stopped && !state.breakpoints.error &&
      state.breakpoints.resultId && processStampKey(state.breakpoints.stamp) === processStampKey(state.target);
  }

  function breakpointEditable()
  {
    return state.ready && !state.busy && !debuggerBusy() && state.sessionStatus.canEditBreakpoints === true;
  }

  function selectedBreakpointIndex()
  {
    return breakpointRowIndex(state.selectedRow);
  }

  function breakpointRowIndex(selected)
  {
    if (state.resultMeta.commandId !== "breakpoints" || state.resultCollection !== "rows" || !breakpointListCurrent() ||
      historicalResult() || !selected || selected.historical || !selected.identity || typeof selected.enabled !== "boolean")
    {
      return -1;
    }
    return state.breakpoints.rows.findIndex(function (row)
    {
      return row.id === selected.id && row.identity === selected.identity && row.enabled === selected.enabled;
    });
  }

  function breakpointRowSource(control)
  {
    var index = breakpointRowIndex(control.row);
    return state.breakpoints.rowControls.indexOf(control) >= 0 && control.resultId === state.resultId &&
      control.revision === state.resultRevision && index >= 0 ?
      { resultId: state.breakpoints.resultId, index: String(index) } : null;
  }

  function renderBreakpointState(cell, row, index)
  {
    cell.classList.add("breakpoint-state-cell");
    cell.textContent = "";
    var label = document.createElement("span");
    label.className = "breakpoint-state-label" + (row.enabled === true ? " enabled" : "");
    label.textContent = row.enabled === true ? "Enabled" : row.enabled === false ? "Disabled" : "Unavailable";
    bindCopyValue(label, function ()
    {
      return clipboardValue(row.enabled);
    }, "breakpoint state", "Copy enabled state for breakpoint " + row.id, function ()
    {
      chooseRow(index);
    }, function ()
    {
      return JSON.stringify(row, null, 2);
    });
    cell.appendChild(label);
    if (typeof row.enabled !== "boolean")
    {
      return;
    }
    var button = document.createElement("button");
    button.type = "button";
    button.className = "breakpoint-row-toggle";
    button.textContent = row.enabled ? "Disable" : "Enable";
    button.setAttribute("aria-label", button.textContent + " breakpoint " + row.id);
    button.title = button.textContent + " breakpoint " + row.id;
    var control = { button: button, row: row, resultId: state.resultId, revision: state.resultRevision };
    state.breakpoints.rowControls.push(control);
    button.disabled = !breakpointEditable() || !breakpointRowSource(control);
    button.addEventListener("click", function (event)
    {
      event.stopPropagation();
      var source = breakpointRowSource(control);
      if (!breakpointEditable() || !source)
      {
        return;
      }
      chooseRow(index);
      uiElement("result-table").focus({ preventScroll: true });
      prepareBreakpoint(row.enabled ? "breakpoint-disable" : "breakpoint-enable", source);
    });
    cell.appendChild(button);
  }

  function updateBreakpointControls()
  {
    var available = breakpointEditable();
    state.breakpoints.rowControls.forEach(function (control)
    {
      control.button.disabled = !available || !breakpointRowSource(control);
    });
    var index = selectedBreakpointIndex();
    var row = state.breakpoints.rows[index];
    setHidden(uiElement("breakpoint-tools"), state.resultMeta.commandId !== "breakpoints");
    uiElement("breakpoint-address").disabled = state.busy || debuggerBusy();
    uiElement("btn-breakpoint-add").disabled = !available || !uiElement("breakpoint-address").value.trim();
    ["enable", "disable", "remove"].forEach(function (action)
    {
      uiElement("btn-breakpoint-" + action).disabled = !available || !row || !row.identity ||
        (action === "enable" && row.enabled) || (action === "disable" && !row.enabled);
    });
    var canRead = state.ready && state.connected && state.sessionStatus.stopped && !state.busy && !debuggerBusy();
    uiElement("btn-breakpoint-refresh").disabled = !canRead;
    uiElement("btn-disassembly-breakpoints").disabled = !canRead;
    var notice = state.breakpoints.error || (!state.statusKnown ? "Waiting for target status." :
      !state.connected || !state.sessionStatus.stopped ? "Stop the target to manage breakpoints." :
      state.sessionStatus.canEditBreakpoints !== true ? "Breakpoint changes require a stopped live target; dumps and local kernel sessions are read only." :
      !breakpointListCurrent() ? "Refresh breakpoints to obtain their current state." :
      !state.breakpoints.complete ? "Breakpoint list is incomplete. Refresh before adding from disassembly." :
      row ? "Selected breakpoint " + row.id + " / " + (row.enabled ? "enabled" : "disabled") : "Select a breakpoint to edit it.");
    uiElement("breakpoint-notice").textContent = notice;
    uiElement("disassembly-breakpoint-notice").textContent = breakpointListCurrent() && state.breakpoints.complete ?
      "BP: filled = enabled / hollow = disabled / + = add / F9 toggles the selected instruction" : notice;
    updateBreakpointMarkers();
  }

  function captureBreakpoints(result)
  {
    var token = ++state.breakpoints.token;
    var total = Number(result && result.rowCount);
    if (!result || !result.resultId || !result.data || result.data.commandId !== "breakpoints" ||
      ["Success", "Partial"].indexOf(result.data.status) < 0 || !Number.isSafeInteger(total) || total < 0 || total > 4096)
    {
      return Promise.reject(new Error((result && result.error) || "Breakpoint list unavailable. The previous list is retained."));
    }
    var rows = [];
    var ids = Object.create(null);
    state.breakpoints.loading = true;
    function page()
    {
      if (token !== state.breakpoints.token || state.cancelRequested)
      {
        throw new Error("Breakpoint refresh cancelled. Refresh again to check current state.");
      }
      if (rows.length === total)
      {
        state.breakpoints.rows = rows;
        state.breakpoints.resultId = result.resultId;
        state.breakpoints.stamp = result.data.target;
        state.breakpoints.complete = result.data.status === "Success";
        state.breakpoints.error = "";
        updateBreakpointControls();
        return Promise.resolve(result);
      }
      var offset = rows.length;
      return send("resultPage", { resultId: result.resultId, collection: "rows", offset: String(offset) }).then(function (reply)
      {
        checkedResultPage(reply, result.resultId, "rows", offset, total).forEach(function (row)
        {
          if (!row || row.kind !== "Breakpoint" || typeof row.id !== "string" || !/^\d{1,10}$/.test(row.id) ||
            Number(row.id) > 4294967295 || ids[row.id] || typeof row.enabled !== "boolean" ||
            (row.address !== null && (typeof row.address !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(row.address))))
          {
            throw new Error("Invalid breakpoint list. Refresh before editing.");
          }
          ids[row.id] = true;
          rows.push(row);
        });
        return page();
      });
    }
    return Promise.resolve().then(page).then(function (captured)
    {
      state.breakpoints.loading = false;
      return captured;
    }, function (error)
    {
      state.breakpoints.loading = false;
      throw error;
    });
  }

  function fetchBreakpoints(show, screen)
  {
    screen = screen || state.resultScreen;
    phase("Reading breakpoints");
    return send("execute", { command: "breakpoints" }).then(function (reply)
    {
      state.currentRequest = "";
      if (!reply || !reply.ok)
      {
        throw new Error((reply && reply.error) || "Breakpoint refresh failed.");
      }
      return captureBreakpoints(reply.result);
    }).then(function (result)
    {
      if (show)
      {
        selectResult(result, undefined, undefined, screen);
      }
      return result;
    }).catch(function (error)
    {
      state.breakpoints.error = error.message;
      updateBreakpointControls();
    });
  }

  function refreshBreakpoints(show, screen)
  {
    if (!state.ready || state.busy || debuggerBusy() || !state.connected || !state.sessionStatus.stopped)
    {
      return;
    }
    state.busy = true;
    state.cancelRequested = false;
    if (show)
    {
      invalidateResultLoad();
    }
    setStatusBusy(true);
    fetchBreakpoints(show, screen).then(finishRequest);
  }

  function prepareBreakpoint(operation, source, expression, instruction)
  {
    if (!breakpointEditable())
    {
      return;
    }
    invalidateResultLoad();
    workspaceFeedback("");
    state.busy = true;
    state.cancelRequested = false;
    state.preparedDebuggerRevision = state.debuggerRevision;
    var run = ++state.runToken;
    var expected = state.target;
    state.restoreFocus = uiActiveElement() || els.prompt;
    setStatusBusy(true);
    phase("Planning");
    send("breakpointPlan", { operation: operation, source: source || {}, expression: expression || "", expectedStamp: expected }).then(function (reply)
    {
      state.currentRequest = "";
      var result = reply && reply.ok && reply.result;
      var plan = result && result.ok && result.plan;
      if (run !== state.runToken || state.cancelRequested || !preparedCommandCurrent() || state.sessionStatus.canEditBreakpoints !== true ||
        processStampKey(expected) !== processStampKey(state.target))
      {
        if (plan)
        {
          send("discardPlan", { planId: plan.planId, approvalToken: plan.approvalToken });
        }
        if (run === state.runToken)
        {
          workspaceFeedback(state.cancelRequested ? "Breakpoint preview cancelled." :
            "Breakpoint preview discarded: target status or context changed. Refresh before trying again.", !state.cancelRequested);
          finishRequest();
        }
        return;
      }
      if (!plan || typeof plan.planId !== "string" || !/^[a-f0-9]{64}$/i.test(plan.planId) ||
        typeof plan.approvalToken !== "string" || !/^[a-f0-9]{64}$/i.test(plan.approvalToken) || plan.operation !== operation ||
        processStampKey(plan.target) !== processStampKey(expected))
      {
        if (plan && typeof plan.planId === "string" && typeof plan.approvalToken === "string")
        {
          send("discardPlan", { planId: plan.planId, approvalToken: plan.approvalToken });
        }
        throw new Error((reply && reply.error) || (result && result.error) || "Breakpoint preview unavailable.");
      }
      var prepared = { breakpoint: true, operation: operation, planId: plan.planId, approvalToken: plan.approvalToken, expectedStamp: expected,
        instructionSnapshot: instruction ? state.disassembly.snapshot : null };
      if (operation === "breakpoint-enable" || operation === "breakpoint-disable")
      {
        applyBreakpoint(prepared);
        return;
      }
      pendingCommand = prepared;
      phase("AwaitingApproval");
      suspendFloatingInspection();
      uiElement("root").inert = true;
      els.modalBackdrop.setAttribute("aria-hidden", "false");
      els.modalPreview.textContent = operation + "\nTarget: " + expected.sessionId + "\nOperand: " + plan.operand +
        "\nOriginal: " + plan.original + "\nThis approval expires after 60 seconds and can be used once.";
      uiElement("modal-title").textContent = operation === "breakpoint-add" ? "Add breakpoint" : "Delete breakpoint";
      els.modalConfirm.textContent = operation === "breakpoint-add" ? "Add this breakpoint" : "Delete this breakpoint";
      els.modalBackdrop.classList.remove("hidden");
      els.modalCancel.focus();
    }).catch(function (error)
    {
      workspaceFeedback(error.message, true);
      finishRequest();
    });
  }

  function applyBreakpoint(plan)
  {
    if (!preparedCommandCurrent() || state.sessionStatus.canEditBreakpoints !== true || processStampKey(plan.expectedStamp) !== processStampKey(state.target))
    {
      rejectPreparedCommand(plan);
      return;
    }
    phase("Applying breakpoint");
    setStatusBusy(true);
    state.breakpoints.stamp = null;
    var applied = false;
    var refreshTarget = null;
    var refreshRevision = 0;
    send("breakpointApply", { planId: plan.planId, approvalToken: plan.approvalToken, expectedStamp: plan.expectedStamp }).then(function (reply)
    {
      state.currentRequest = "";
      var result = reply && reply.ok && reply.result;
      if (result && result.status)
      {
        ++state.statusToken;
        state.statusPending = false;
        applyStatus(result.status, true);
      }
      if (!result || !result.ok)
      {
        throw new Error((reply && reply.error) || (result && result.error) || "Breakpoint outcome unknown. Refresh; do not retry automatically.");
      }
      if (plan.operation !== "breakpoint-enable" && plan.operation !== "breakpoint-disable")
      {
        workspaceFeedback("Breakpoint change applied.");
      }
      applied = true;
      refreshTarget = result.status && result.status.target;
      refreshRevision = state.debuggerRevision;
      if (state.cancelRequested)
      {
        return null;
      }
      return fetchBreakpoints(state.resultMeta.commandId === "breakpoints");
    }).catch(function (error)
    {
      state.breakpoints.error = error.message;
      workspaceFeedback(error.message, true);
    }).then(function (refreshed)
    {
      var canRefresh = applied && refreshed && refreshTarget && !state.cancelRequested &&
        refreshRevision === state.debuggerRevision && processStampKey(refreshTarget) === processStampKey(state.target) &&
        processStampKey(refreshed.data.target) === processStampKey(refreshTarget);
      finishRequest();
      if (canRefresh && plan.instructionSnapshot && plan.instructionSnapshot === state.disassembly.snapshot &&
        inspectionVisible("disassembly") && !debuggerBusy())
      {
        uiElement("disassembly-address").value = memoryHex(plan.instructionSnapshot.address);
        uiElement("disassembly-count").value = String(plan.instructionSnapshot.count);
        readDisassembly(null, null, { rememberAddress: false });
      }
    });
  }

  function instructionBreakpoints(row)
  {
    return breakpointListCurrent() && disassemblyCurrent() ? state.breakpoints.rows.map(function (item, index)
    {
      return { row: item, index: index };
    }).filter(function (item)
    {
      return item.row.type === "0" && typeof item.row.address === "string" && BigInt(item.row.address) === BigInt(row.address);
    }) : [];
  }

  function updateBreakpointMarkers()
  {
    var snapshot = state.disassembly.snapshot;
    Array.prototype.forEach.call(uiElement("disassembly-rows").children, function (node, index)
    {
      var button = node.children[0] && node.children[0].children[0];
      if (!button || !snapshot)
      {
        return;
      }
      var matches = instructionBreakpoints(snapshot.rows[index]);
      var known = breakpointListCurrent() && state.breakpoints.complete && disassemblyCurrent();
      button.textContent = matches.length > 1 ? String(matches.length) : matches.length ? (matches[0].row.enabled ? "●" : "○") : known ? "+" : "?";
      button.className = "breakpoint-toggle" + (matches.length === 1 ? matches[0].row.enabled ? " enabled" : " disabled" : "");
      button.title = matches.length > 1 ? "Multiple breakpoints. Manage them in the list." :
        matches.length ? (matches[0].row.enabled ? "Disable" : "Enable") + " breakpoint " + matches[0].row.id : "Add breakpoint";
      button.setAttribute("aria-label", button.title + " at " + snapshot.rows[index].address + " (F9)");
      button.disabled = !breakpointEditable() || (!matches.length && !known);
    });
  }

  function toggleInstructionBreakpoint(index)
  {
    var snapshot = state.disassembly.snapshot;
    var row = snapshot && snapshot.rows[index];
    if (!row || !breakpointEditable())
    {
      return;
    }
    var matches = instructionBreakpoints(row);
    if (matches.length > 1)
    {
      refreshBreakpoints(true, "breakpoints");
    }
    else if (matches.length === 1)
    {
      prepareBreakpoint(matches[0].row.enabled ? "breakpoint-disable" : "breakpoint-enable",
        { resultId: state.breakpoints.resultId, index: String(matches[0].index) }, "", true);
    }
    else if (breakpointListCurrent() && state.breakpoints.complete && disassemblyCurrent())
    {
      prepareBreakpoint("breakpoint-add", { resultId: snapshot.resultId, index: String(index) }, "", true);
    }
  }

  uiElement("btn-breakpoint-add").addEventListener("click", function ()
  {
    if (!uiElement("btn-breakpoint-add").disabled)
    {
      prepareBreakpoint("breakpoint-add", null, uiElement("breakpoint-address").value.trim());
    }
  });
  uiElement("breakpoint-address").addEventListener("input", updateBreakpointControls);
  uiElement("breakpoint-address").addEventListener("keydown", function (event)
  {
    if (event.key === "Enter" && !event.isComposing && event.keyCode !== 229 && !uiElement("btn-breakpoint-add").disabled)
    {
      event.preventDefault();
      prepareBreakpoint("breakpoint-add", null, uiElement("breakpoint-address").value.trim());
    }
  });
  ["enable", "disable", "remove"].forEach(function (action)
  {
    uiElement("btn-breakpoint-" + action).addEventListener("click", function ()
    {
      if (!uiElement("btn-breakpoint-" + action).disabled)
      {
        prepareBreakpoint("breakpoint-" + action, { resultId: state.breakpoints.resultId, index: String(selectedBreakpointIndex()) });
      }
    });
  });
  uiElement("btn-breakpoint-refresh").addEventListener("click", function () { refreshBreakpoints(true); });
  uiElement("btn-disassembly-breakpoints").addEventListener("click", function () { refreshBreakpoints(false); });

  function disassemblyCurrent()
  {
    var snapshot = state.disassembly.snapshot;
    return snapshot && state.connected && state.sessionStatus.stopped &&
      processStampKey(snapshot.stamp) === processStampKey(state.target);
  }

  function setDisassemblyFollow(enabled)
  {
    var viewer = state.disassembly;
    viewer.followIP = enabled;
    viewer.pendingFollow = null;
    ++viewer.followSerial;
    try
    {
      window.localStorage.setItem("kndbgx.disassembly-follow", enabled ? "on" : "off");
    }
    catch (error)
    {
      // Following remains available without saved preferences.
    }
    updateDisassemblyActions();
  }

  function observeDisassemblyStop(result, suppressFollow)
  {
    var viewer = state.disassembly;
    if (!state.connected)
    {
      viewer.stopTarget = null;
      viewer.pendingFollow = null;
      viewer.sawRunning = false;
      viewer.awaitingStop = false;
      return;
    }
    if (!result.stopped)
    {
      viewer.sawRunning = true;
      viewer.pendingFollow = null;
      return;
    }
    var previous = viewer.stopTarget;
    var sameSession = previous && previous.sessionId === state.target.sessionId;
    var newStop = viewer.sawRunning || viewer.awaitingStop ||
      (sameSession && previous.stopEpoch !== state.target.stopEpoch);
    viewer.stopTarget = state.target;
    viewer.sawRunning = false;
    viewer.awaitingStop = false;
    if (suppressFollow || state.cancelRequested)
    {
      viewer.pendingFollow = null;
    }
    else if (newStop && viewer.followIP && !result.dumpFile && !result.localKernel)
    {
      viewer.pendingFollow = state.target;
    }
    else if (viewer.pendingFollow && sameSession && viewer.pendingFollow.stopEpoch === state.target.stopEpoch)
    {
      viewer.pendingFollow = state.target;
    }
  }

  function followDisassemblyStop()
  {
    var viewer = state.disassembly;
    if (state.pauseInspectionReads || document.hidden || !viewer.followIP || !viewer.pendingFollow || state.busy || debuggerBusy() || !state.connected ||
        !state.sessionStatus.stopped || !els.modalBackdrop.classList.contains("hidden") ||
        !els.paletteBackdrop.classList.contains("hidden") || state.columnDrag || state.memoryPanel.drag || state.inspectorPanel.drag ||
        typeof state.sessionStatus.instructionPointer !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(state.sessionStatus.instructionPointer))
    {
      return;
    }
    var expected = viewer.pendingFollow;
    viewer.pendingFollow = null;
    if (processStampKey(expected) !== processStampKey(state.target))
    {
      return;
    }
    if (!independentInspectionVisible("disassembly") && !(state.memoryPanel.visible && state.memoryPanel.tab === "registers"))
    {
      setInspectionTab("disassembly");
      if (!state.memoryPanel.visible)
      {
        setMemoryPanel(true);
      }
    }
    uiElement("disassembly-address").value = "@$ip";
    readDisassembly(null, { serial: viewer.followSerial, revision: state.debuggerRevision });
  }

  function controlExecution(operation)
  {
    if (["go", "step-into", "step-over"].indexOf(operation) < 0 || state.busy || debuggerBusy() ||
        !state.ready || !state.connected || !state.sessionStatus.stopped || state.sessionStatus.dumpFile ||
        state.sessionStatus.localKernel || state.sessionStatus.canControlExecution !== true)
    {
      return;
    }
    workspaceFeedback("");
    state.disassembly.error = "";
    state.disassembly.pendingFollow = null;
    state.disassembly.awaitingStop = true;
    state.executionControl.starting = true;
    state.busy = true;
    state.cancelRequested = false;
    state.statusKnown = false;
    state.statusBusy = true;
    ++state.debuggerRevision;
    var statusToken = ++state.statusToken;
    state.statusPending = false;
    setStatusBusy(true);
    phase(operation === "go" ? "Continuing" : "Stepping");
    send("debuggerAction", { operation: operation, expectedStamp: state.target }).then(function (reply)
    {
      state.currentRequest = "";
      var result = reply && reply.ok && reply.result;
      if (!result || result.ok !== true || result.operation !== operation)
      {
        state.disassembly.awaitingStop = false;
      }
      if (result && result.status && statusToken === state.statusToken)
      {
        state.statusPending = false;
        applyStatus(result.status);
      }
      if (!result || result.ok !== true || result.operation !== operation)
      {
        throw new Error((reply && reply.error) || (result && result.error) ||
          "Execution outcome unknown. Refresh context; do not retry automatically.");
      }
    }).catch(function (error)
    {
      state.disassembly.awaitingStop = false;
      workspaceFeedback(error.message, true);
    }).then(function ()
    {
      state.executionControl.starting = false;
      finishRequest();
      refreshStatus();
      scheduleWorkspaceStatus();
    });
  }

  function canBreakExecution()
  {
    return state.ready && state.statusKnown && state.connected && state.sessionStatus.stopped === false &&
      !state.sessionStatus.dumpFile && !state.sessionStatus.localKernel &&
      state.sessionStatus.canBreakExecution === true && !state.executionControl.breaking;
  }

  function clearPendingBreak()
  {
    var control = state.executionControl;
    clearTimeout(control.timer);
    control.timer = null;
    control.breaking = false;
    control.target = null;
    ++control.serial;
  }

  function updateExecutionToggle()
  {
    var control = state.executionControl;
    var button = uiElement("btn-execution-toggle");
    var running = state.connected && state.sessionStatus.stopped === false;
    var starting = control.starting && !(state.statusKnown && running);
    var pending = control.breaking || starting;
    var available = running ? canBreakExecution() : state.ready && state.statusKnown && state.connected &&
      !state.busy && !debuggerBusy() && state.sessionStatus.stopped === true &&
      !state.sessionStatus.dumpFile && !state.sessionStatus.localKernel && state.sessionStatus.canControlExecution === true;
    var label = control.breaking ? "Breaking..." : starting ? "Continuing..." : running ? "Break" : "Continue";
    button.disabled = pending || !available;
    button.dataset.action = running || control.breaking ? "break" : "continue";
    button.classList[pending ? "add" : "remove"]("is-pending");
    button.setAttribute("aria-busy", String(pending));
    button.setAttribute("aria-label", label);
    button.setAttribute("aria-keyshortcuts", running || pending ? "" : "F5");
    uiElement("execution-toggle-label").textContent = label;
    setHidden(uiElement("execution-toggle-key"), running || pending);
    button.title = control.breaking ? "Break requested; waiting for the target to stop" :
      starting ? "Applying execution control; waiting for target status" :
      !state.ready || !state.statusKnown ? "Waiting for target status. Use Refresh context to check again." :
      !state.connected ? "Connect a live target to control execution" :
      state.sessionStatus.dumpFile || state.sessionStatus.localKernel ? "Execution control is unavailable for dumps and local kernel debugging" :
      available ? running ? "Break into the running target" : "Continue execution (F5)" :
      state.busy || state.statusBusy ? "Wait for the current debugger operation to finish" : "Execution control is unavailable for this session";
  }

  function breakExecution()
  {
    if (!canBreakExecution())
    {
      return;
    }
    var control = state.executionControl;
    var serial = ++control.serial;
    control.breaking = true;
    control.target = state.target;
    state.disassembly.awaitingStop = true;
    ++state.statusToken;
    state.statusPending = false;
    workspaceFeedback("");
    updateExecutionToggle();
    send("breakExecution", { expectedStamp: state.target }).then(function (reply)
    {
      if (serial !== control.serial)
      {
        return;
      }
      if (!reply || !reply.ok || !reply.result || reply.result.requested !== true)
      {
        clearPendingBreak();
        workspaceFeedback((reply && reply.error) || "Break was not confirmed. Refresh context before trying again.", true);
      }
      else
      {
        control.timer = setTimeout(function ()
        {
          if (serial === control.serial)
          {
            clearPendingBreak();
            workspaceFeedback("Break is still unconfirmed. Check WinDbg or Refresh context before trying again.", true);
            updateExecutionToggle();
          }
        }, 10000);
      }
      updateExecutionToggle();
      refreshStatus();
      scheduleWorkspaceStatus();
    });
  }

  function updateDisassemblyActions()
  {
    updateExecutionToggle();
    var viewer = state.disassembly;
    var snapshot = viewer.snapshot;
    var available = state.ready && state.connected && state.sessionStatus.stopped && !state.busy && !debuggerBusy();
    var unchanged = snapshot && uiElement("disassembly-address").value.trim() === memoryHex(snapshot.address) &&
      uiElement("disassembly-count").value === String(snapshot.count);
    uiElement("btn-disassembly-read").disabled = !available;
    uiElement("disassembly-address-history").disabled = !available || !state.addressHistory.disassembly.length;
    uiElement("btn-disassembly-ip").disabled = !available;
    uiElement("btn-disassembly-back").disabled = state.busy || !viewer.history.length;
    uiElement("btn-disassembly-next").disabled = !available || !disassemblyCurrent() || !unchanged ||
      !snapshot.complete || !!viewer.error;
    uiElement("disassembly-address").disabled = state.busy;
    uiElement("disassembly-count").disabled = state.busy;
    var follow = uiElement("btn-disassembly-follow");
    follow.textContent = viewer.followIP ? state.pauseInspectionReads ? "IP follow suspended" : "Following IP" : "IP follow paused";
    follow.title = viewer.followIP && state.pauseInspectionReads ?
      "Automatic inspection reads are paused in Operations. Click to turn off Follow IP." : viewer.followIP ?
      "Pause automatic reads at each stop. Manual navigation pauses following too." : "Resume following the current instruction at each stop";
    follow.setAttribute("aria-pressed", String(viewer.followIP));
    ["continue", "over", "into"].forEach(function (action)
    {
      uiElement("btn-debug-" + action).disabled = !available || debuggerBusy() || state.sessionStatus.canControlExecution !== true;
    });
  }

  function updateDisassemblySummary()
  {
    var viewer = state.disassembly;
    var snapshot = viewer.snapshot;
    uiElement("disassembly-summary").textContent = snapshot ? memoryHex(snapshot.address) + " - " +
      memoryHex(snapshot.next - BigInt(1)) + " / " + snapshot.rows.length + " instructions" +
      (snapshot.complete ? "" : " / partial") + (disassemblyCurrent() ? "" : " / previous snapshot") +
      (viewer.loading ? " / reading..." : "") : viewer.loading ? "Reading instructions..." :
      "Enter an address and choose Read.";
    if (state.pauseInspectionReads && viewer.followIP)
    {
      uiElement("disassembly-summary").textContent += " / automatic reads paused";
    }
    var identity = snapshot && snapshot.stamp && snapshot.stamp.contextIdentity;
    uiElement("disassembly-context").textContent = snapshot ? "Virtual memory / debugger process " +
      ((identity || {}).implicitProcess || "unavailable") +
      (snapshot.expression && snapshot.expression !== memoryHex(snapshot.address) ? " / Input: " + resultText(snapshot.expression).slice(0, 96) : "") :
      "Decode instructions in the debugger's selected address space.";
    uiElement("disassembly-context").title = snapshot ? "Read input: " + (snapshot.expression || memoryHex(snapshot.address)) : "";
    var notice = viewer.error || (state.statusBusy ? "Debugger busy. Showing the last checked disassembly." :
      !state.connected ? "Debugger disconnected. The previous view is retained." :
      !state.sessionStatus.stopped ? "Stop the target before reading instructions. The previous view is retained." :
      snapshot && !disassemblyCurrent() ? "Debugger context changed. Read again to decode in the current context." :
      snapshot && !snapshot.complete ? snapshot.reason || "Only a readable instruction prefix was decoded." : "");
    uiElement("disassembly-notice").textContent = notice;
    setHidden(uiElement("disassembly-notice"), !notice);
    updateDisassemblyActions();
  }

  function chooseDisassemblyRow(index)
  {
    var viewer = state.disassembly;
    viewer.selected = index;
    Array.prototype.forEach.call(uiElement("disassembly-rows").children, function (node, position)
    {
      node.classList[position === index ? "add" : "remove"]("selected");
      node.setAttribute("aria-selected", String(position === index));
      Array.prototype.forEach.call(node.querySelectorAll(".copyable"), function (cell)
      {
        cell.tabIndex = position === index ? 0 : -1;
      });
      var breakpoint = node.children[0] && node.children[0].children[0];
      if (breakpoint)
      {
        breakpoint.tabIndex = position === index ? 0 : -1;
      }
    });
    var row = viewer.snapshot && viewer.snapshot.rows[index];
    uiElement("disassembly-position").textContent = row ? "Selected " + row.address : "No instruction selected";
    uiElement("disassembly-grid").setAttribute("aria-activedescendant", row ? "instruction-row-" + index : "");
  }

  function renderDisassemblyRows()
  {
    closeCopyMenu();
    var container = uiElement("disassembly-rows");
    var grid = uiElement("disassembly-grid");
    if (container.contains(uiActiveElement()))
    {
      grid.focus();
    }
    container.textContent = "";
    var snapshot = state.disassembly.snapshot;
    var ip = snapshot && (snapshot.instructionPointer !== undefined ? snapshot.instructionPointer :
      snapshot.stamp.contextIdentity && snapshot.stamp.contextIdentity.scopeInstruction);
    (snapshot ? snapshot.rows : []).forEach(function (row, index)
    {
      var current = typeof ip === "string" && /^0x[0-9a-f]{1,16}$/i.test(ip) && BigInt(row.address) === BigInt(ip);
      var node = document.createElement("div");
      node.className = "disassembly-row" + (current ? " current-ip" : "");
      node.id = "instruction-row-" + index;
      node.setAttribute("role", "row");
      node.setAttribute("aria-rowindex", String(index + 2));
      var gutter = document.createElement("span");
      gutter.className = "breakpoint-gutter";
      gutter.setAttribute("role", "gridcell");
      gutter.setAttribute("aria-colindex", "1");
      var toggle = document.createElement("button");
      toggle.className = "breakpoint-toggle";
      toggle.addEventListener("click", function (event)
      {
        event.stopPropagation();
        if (!toggle.disabled)
        {
          chooseDisassemblyRow(index);
          toggleInstructionBreakpoint(index);
        }
      });
      gutter.appendChild(toggle);
      node.appendChild(gutter);
      var fields = [["address", "address"], ["instructionText", "instruction"], ["bytes", "bytes"], ["symbol", "symbol"]];
      fields.forEach(function (field, column)
      {
        var value = row[field[0]];
        var text = typeof value === "string" ? value : displayField(value, [field[0]], row);
        var cell = document.createElement("span");
        cell.setAttribute("role", "gridcell");
        cell.setAttribute("aria-colindex", String(column + 2));
        cell.textContent = (current && column === 0 ? "IP " : "") + (text.length > 512 ? text.slice(0, 512) + "..." : text);
        cell.title = text;
        if (column === 1 && /^(?:j\w*|call|ret\w*|syscall|sysret|int3)\b/i.test(text))
        {
          cell.className = "disassembly-branch";
        }
        if (typeof value === "string")
        {
          bindCopyValue(cell, function ()
          {
            return value;
          }, field[1] + " at " + row.address, "Copy instruction " + field[1] + " at " + row.address, function ()
          {
            chooseDisassemblyRow(index);
          }, function ()
          {
            return JSON.stringify(row, null, 2);
          }, field[0] === "address" ? inspectionAddressNavigation("disassembly", snapshot, row, index) : null);
        }
        node.appendChild(cell);
      });
      node.addEventListener("click", function ()
      {
        chooseDisassemblyRow(index);
        grid.focus();
      });
      container.appendChild(node);
    });
    grid.setAttribute("aria-rowcount", String((snapshot ? snapshot.rows.length : 0) + 1));
    chooseDisassemblyRow(state.disassembly.selected);
    updateBreakpointMarkers();
  }

  function displayDisassembly(snapshot)
  {
    state.disassembly.snapshot = snapshot;
    state.disassembly.selected = -1;
    uiElement("disassembly-address").value = memoryHex(snapshot.address);
    uiElement("disassembly-count").value = String(snapshot.count);
    uiElement("disassembly-grid").scrollTop = 0;
    renderDisassemblyRows();
    updateDisassemblySummary();
  }

  function readDisassembly(source, automatic, options)
  {
    if (uiElement("btn-disassembly-read").disabled)
    {
      return;
    }
    var viewer = state.disassembly;
    var expression = uiElement("disassembly-address").value.trim();
    var count = Number(uiElement("disassembly-count").value);
    if (!expression || expression.length > 1024 || /[;"\\{}\u0000-\u001f]/.test(expression) || [16, 32, 64].indexOf(count) < 0)
    {
      viewer.error = "Enter one address or expression without quotes, control characters or command separators.";
      updateDisassemblySummary();
      return;
    }
    if (!automatic && (source || expression !== "@$ip"))
    {
      setDisassemblyFollow(false);
    }
    viewer.error = "";
    viewer.loading = true;
    viewer.cancelled = false;
    state.busy = true;
    setStatusBusy(true);
    updateDisassemblySummary();
    phase("Reading instructions");
    var expected = source ? source.expectedStamp : state.target;
    send("disassemblyRead", { expression: expression, count: String(count), source: source || {}, expectedStamp: expected }).then(function (reply)
    {
      state.currentRequest = "";
      var result = reply && reply.ok && reply.result;
      var total = result && Number(result.rowCount);
      if (!result || !result.resultId || !result.data || result.data.commandId !== "u" ||
          ["Success", "Partial"].indexOf(result.data.status) < 0 || !Number.isSafeInteger(total) || total < 1 || total > count ||
          (result.data.status === "Success" && total !== count) ||
          processStampKey(result.data.target) !== processStampKey(expected))
      {
        throw new Error((reply && reply.error) || (result && result.error) || "Disassembly failed. The previous view is retained.");
      }
      var rows = [];
      var address = null;
      var next = null;
      function readPage()
      {
        if (viewer.cancelled)
        {
          throw new Error("Disassembly cancelled. The previous view is retained.");
        }
        if (rows.length === total)
        {
          return Promise.resolve();
        }
        var offset = rows.length;
        return send("resultPage", { resultId: result.resultId, collection: "rows", offset: String(offset) }).then(function (pageReply)
        {
          var page = checkedResultPage(pageReply, result.resultId, "rows", offset, total);
          page.forEach(function (row)
          {
            if (!row || row.addressSpace !== "virtual" || typeof row.address !== "string" ||
                !/^0x[0-9a-f]{1,16}$/i.test(row.address) || typeof row.nextAddress !== "string" ||
                !/^0x[0-9a-f]{1,16}$/i.test(row.nextAddress) || typeof row.bytes !== "string" ||
                !/^(?:[0-9a-f]{2}){1,16}$/i.test(row.bytes) || typeof row.instructionText !== "string" ||
                !row.instructionText.trim() || row.instructionText.length > 4096)
            {
              throw new Error("Invalid instruction record. The previous view is retained.");
            }
            var start = BigInt(row.address);
            var end = BigInt(row.nextAddress);
            if (end <= start || end - start !== BigInt(row.bytes.length / 2) || (next !== null && start !== next))
            {
              throw new Error("Invalid instruction address sequence. The previous view is retained.");
            }
            if (address === null)
            {
              address = start;
            }
            next = end;
            rows.push(row);
          });
          return readPage();
        });
      }
      return readPage().then(function ()
      {
        if (automatic && (!viewer.followIP || automatic.serial !== viewer.followSerial ||
            automatic.revision !== state.debuggerRevision || debuggerBusy() ||
            processStampKey(expected) !== processStampKey(state.target)))
        {
          if (viewer.followIP && automatic.serial === viewer.followSerial && !viewer.cancelled && state.connected &&
              state.sessionStatus.stopped && viewer.stopTarget &&
              viewer.stopTarget.sessionId === state.target.sessionId && viewer.stopTarget.targetGeneration === state.target.targetGeneration)
          {
            viewer.pendingFollow = state.target;
          }
          return;
        }
        if (viewer.snapshot)
        {
          viewer.history.push(viewer.snapshot);
          viewer.history = viewer.history.slice(-16);
        }
        displayDisassembly({ rows: rows, address: address, next: next, count: count, stamp: result.data.target, expression: expression,
          resultId: result.resultId, instructionPointer: result.instructionPointer, complete: result.data.status === "Success",
          reason: resultText((result.data.error || {}).message) || resultText(result.error) });
        if (!automatic && (!options || options.rememberAddress !== false))
        {
          rememberAddress("disassembly", expression, "virtual");
        }
        if (automatic)
        {
          chooseDisassemblyRow(0);
        }
        return fetchBreakpoints(false);
      });
    }).catch(function (error)
    {
      viewer.error = error.message;
    }).then(function ()
    {
      viewer.loading = false;
      finishRequest();
      updateDisassemblySummary();
    });
  }

  uiElement("disassembly-address").value = "@$ip";
  uiElement("disassembly-count").value = "32";
  uiElement("btn-disassembly-follow").addEventListener("click", function ()
  {
    setDisassemblyFollow(!state.disassembly.followIP);
    if (state.disassembly.followIP && state.connected && state.sessionStatus.stopped)
    {
      state.disassembly.pendingFollow = state.target;
      followDisassemblyStop();
      maybeRefreshRegisters();
    }
  });
  [["continue", "go"], ["over", "step-over"], ["into", "step-into"]].forEach(function (action)
  {
    uiElement("btn-debug-" + action[0]).addEventListener("click", function ()
    {
      controlExecution(action[1]);
    });
  });
  uiElement("btn-disassembly-read").addEventListener("click", function ()
  {
    readDisassembly();
  });
  ["disassembly-address", "disassembly-count"].forEach(function (id)
  {
    uiElement(id).addEventListener("input", function ()
    {
      if (id === "disassembly-address")
      {
        setDisassemblyFollow(false);
      }
      updateDisassemblyActions();
    });
    uiElement(id).addEventListener("change", updateDisassemblyActions);
  });
  uiElement("btn-disassembly-ip").addEventListener("click", function ()
  {
    if (!uiElement("btn-disassembly-ip").disabled)
    {
      setDisassemblyFollow(true);
      uiElement("disassembly-address").value = "@$ip";
      readDisassembly();
    }
  });
  uiElement("btn-disassembly-next").addEventListener("click", function ()
  {
    if (!uiElement("btn-disassembly-next").disabled)
    {
      setDisassemblyFollow(false);
      uiElement("disassembly-address").value = memoryHex(state.disassembly.snapshot.next);
      readDisassembly();
    }
  });
  uiElement("btn-disassembly-back").addEventListener("click", function ()
  {
    if (!uiElement("btn-disassembly-back").disabled)
    {
      setDisassemblyFollow(false);
      state.disassembly.error = "";
      displayDisassembly(state.disassembly.history.pop());
    }
  });
  uiElement("disassembly-grid").addEventListener("keydown", function (event)
  {
    var viewer = state.disassembly;
    if (!viewer.snapshot || event.ctrlKey || event.metaKey || event.altKey || event.isComposing)
    {
      return;
    }
    var index = viewer.selected;
    var page = Math.max(1, Math.floor(uiElement("disassembly-grid").clientHeight / workspaceRowHeight()));
    switch (event.key)
    {
      case "F9": event.preventDefault(); toggleInstructionBreakpoint(index); return;
      case "ArrowDown": index++; break;
      case "ArrowUp": index--; break;
      case "Home": index = 0; break;
      case "End": index = viewer.snapshot.rows.length - 1; break;
      case "PageUp": index = Math.max(0, index) - page; break;
      case "PageDown": index = Math.max(0, index) + page; break;
      case "Escape": uiElement("disassembly-grid").focus(); return;
      default: return;
    }
    event.preventDefault();
    uiElement("disassembly-grid").focus();
    chooseDisassemblyRow(Math.max(0, Math.min(viewer.snapshot.rows.length - 1, index)));
    uiElement("disassembly-rows").children[state.disassembly.selected].scrollIntoView({ block: "nearest", inline: "nearest" });
  });
  renderDisassemblyRows();

  function diagnosticValue(value, fallback)
  {
    return typeof value === "string" && value ? value : fallback || "Unknown";
  }

  function diagnosticStamp(stamp)
  {
    return stamp ? "Session " + diagnosticValue(stamp.sessionId) + " / target " + diagnosticValue(stamp.targetGeneration) +
      " / stop " + diagnosticValue(stamp.stopEpoch) + " / context " + diagnosticValue(stamp.contextGeneration) +
      " / symbols " + diagnosticValue(stamp.symbolGeneration) : "No capture";
  }

  function diagnosticFields(id, rows)
  {
    var element = uiElement(id);
    var key = JSON.stringify(rows);
    if (element.knDiagnosticKey === key)
    {
      return;
    }
    element.knDiagnosticKey = key;
    element.textContent = "";
    rows.forEach(function (row)
    {
      var term = document.createElement("dt");
      term.textContent = row[0];
      var value = document.createElement("dd");
      value.textContent = row[1];
      element.appendChild(term);
      element.appendChild(value);
    });
  }

  function symbolModuleCurrent()
  {
    return state.statusKnown && state.connected && state.sessionStatus.stopped && state.contextView.moduleStamp &&
      processStampKey(state.contextView.moduleStamp) === processStampKey(state.target);
  }

  function selectedSymbolModule()
  {
    return state.contextView.modules.find(function (module)
    {
      return module.key.base === state.contextView.selected;
    });
  }

  function renderContextDetails()
  {
    var view = state.contextView;
    if (!view || !view.open)
    {
      return;
    }
    uiElement("btn-context-refresh").disabled = !state.ready || state.busy || state.statusPending === true;
    var observed = view.observed || {};
    var stamp = observed.target || {};
    var context = stamp.contextIdentity || {};
    var process = observed.currentProcess || {};
    var row = state.processes.rows[state.processes.selected];
    var current = state.statusKnown && processStampKey(stamp) === processStampKey(state.target);
    uiElement("context-observation").textContent = !view.observed ? "No context observed. Refresh context to check." :
      (!current || state.statusBusy ? "Current context unconfirmed; showing the last observation. " :
        observed.connected ? observed.stopped ? "Last observed stopped context. " : "Target running; captured values are historical. " : "No target. ") +
      "Received " + view.received + (state.pauseInspectionReads ? " / Automatic inspection reads paused." : "");
    var event = observed.lastEvent;
    var lastStop = event ? diagnosticValue(event.description, "Description unavailable") +
      " / type " + diagnosticValue(event.type) + " / " + eventLocation(event).label +
      (eventLocation(event).value ? " " + eventLocation(event).value : "") : "No verified event observation";
    diagnosticFields("context-fields", [
      ["Selected Processes row", row ? diagnosticValue(row.image) + " / PID " + diagnosticValue(row.pid) +
        " / EPROCESS " + diagnosticValue(row.eprocess) + (processListCurrent() ? " / UI selection only" : " / previous capture; UI selection only") : "No row selected"],
      ["Virtual address space", "Implicit EPROCESS " + diagnosticValue(context.implicitProcess) +
        "\nLast observed name/PID: " + diagnosticValue(process.image) + " / " + diagnosticValue(process.pid)],
      ["Translation DTB override", diagnosticValue(observed.contextDtbOverride, "None observed; not a process selection")],
      ["Registers / debugger thread", diagnosticValue(context.thread) + " (debugger ID, not OS TID) / CPU " + diagnosticValue(observed.currentProcessor)],
      ["Implicit ETHREAD", diagnosticValue(context.implicitThread)],
      ["Register context origin", "Unknown. A scope or instruction pointer does not identify an external .trap/.cxr source."],
      ["Current scope", "IP " + diagnosticValue(context.scopeInstruction) + " / frame " + diagnosticValue(context.scopeIndex) +
        "\nStack " + diagnosticValue(context.scopeStack) + " / frame address " + diagnosticValue(context.scopeFrame)],
      ["Last event observation", lastStop],
      ["Observed generations", diagnosticStamp(observed.target)],
      ["Selected result capture", diagnosticStamp(state.resultTarget)],
      ["Inspect Registers capture", diagnosticStamp(state.registers.stamp)],
      ["Next reads", "Manual expressions use the checked debugger context. Source-bound reads also verify the capture and owning process; physical reads use physical addresses."]
    ]);
    renderSymbolHealth();
  }

  function renderSymbolHealth()
  {
    var view = state.contextView;
    var supported = state.capabilities.indexOf("symbolHealth.v1") >= 0;
    var available = supported && state.ready && state.statusKnown && state.connected && state.sessionStatus.stopped &&
      !state.busy && !debuggerBusy() && !view.loading;
    var module = selectedSymbolModule();
    var health = view.health;
    var matching = health && module && health.module && processStampKey(health.module.key) === processStampKey(module.key);
    var live = matching && symbolModuleCurrent() && processStampKey(health.target) === processStampKey(state.target);
    var draft = live && typeof health.reloadDraft === "string" && typeof module.name === "string" &&
      /^[A-Za-z_][A-Za-z0-9_.-]{0,126}$/.test(module.name) && health.reloadDraft === ".reload /f " + module.name;
    uiElement("btn-symbol-modules").disabled = !available;
    uiElement("btn-symbol-more").disabled = !available || !symbolModuleCurrent() || view.modules.length >= 4096;
    setHidden(uiElement("btn-symbol-more"), view.complete);
    uiElement("symbol-module").disabled = view.loading || !view.modules.length;
    uiElement("btn-symbol-inspect").disabled = !available || !module || !symbolModuleCurrent();
    uiElement("btn-symbol-reload-draft").disabled = !available || !draft;
    uiElement("symbol-status").textContent = !supported ? "This host does not advertise symbol health support." :
      view.loading ? "Inspecting symbols... Operations shows the last observed stage; cancellation may wait for the engine." :
      (view.error ? view.error + " " : "") + (view.modules.length ? view.modules.length + " modules observed / " + view.total +
        (view.complete ? ". " : " / more pages available. ") + (view.unknown ? view.unknown + " entries unavailable. " : "") +
        (view.modules.length >= 4096 ? "4096-module display limit reached. " : "") +
        (!symbolModuleCurrent() ? "Previous module inventory; Read modules before inspecting. " : "") : "No module inventory collected. ");
    var fields = [["Module", module ? diagnosticValue(module.name) + " / " + module.key.base : "Select a loaded module"],
      ["Load state", matching ? diagnosticValue(health.module.loadState) : module ? diagnosticValue(module.loadState) + " / inventory observation" : "Unknown"],
      ["Image / PDB match", matching ? diagnosticValue(health.imageMatch) : "Unknown; inspect selected module"],
      ["PDB identity", matching && health.pdbIdentity ? diagnosticValue(health.pdbIdentity.guid) + " / age " + diagnosticValue(health.pdbIdentity.age) : "Unknown"],
      ["Type metadata", matching && typeof health.typeInformation === "boolean" ? health.typeInformation ? "Reported available" : "Not present in observed PDB" : "Unknown"],
      ["Capture state", matching ? live ? "Current checked context" : "Historical / context unconfirmed" : "Inventory only; no inspection captured"]];
    if (matching)
    {
      var query = health.requestedType || {};
      fields.push(["Requested type / field", query.name ? query.name + (query.field ? "." + query.field : "") : "Not requested"]);
      fields.push(["Query result", diagnosticValue(query.state) + (query.nativeError ? " / HRESULT " + query.nativeError : "")]);
      if (query.size !== null && query.size !== undefined)
      {
        fields.push(["Type size / field offset", diagnosticValue(query.size) + " bytes / " + diagnosticValue(query.fieldOffset, "Not requested or unavailable")]);
      }
      fields.push(["Metadata observation", health.nativeError ? "HRESULT " + health.nativeError : diagnosticValue(health.metadataReason, "Module metadata returned")]);
      fields.push(["Inspection generations", diagnosticStamp(health.target)]);
    }
    diagnosticFields("symbol-fields", fields);
  }

  function setContextOpen(open)
  {
    var panel = uiElement("context-panel");
    var focused = panel.contains && panel.contains(uiActiveElement());
    state.contextView.open = open;
    setHidden(panel, !open);
    uiElement("btn-context").setAttribute("aria-expanded", String(open));
    if (open)
    {
      closeToolMenus();
      setOperationsOpen(false);
      renderContextDetails();
      uiElement("btn-context-close").focus();
    }
    else if (focused)
    {
      uiElement("btn-context").focus();
    }
  }

  function setContextSection(section)
  {
    state.contextView.tab = section;
    var symbols = section === "symbols";
    uiElement("btn-context-overview").setAttribute("aria-pressed", String(!symbols));
    uiElement("btn-context-symbols").setAttribute("aria-pressed", String(symbols));
    setHidden(uiElement("context-overview"), symbols);
    setHidden(uiElement("context-symbols"), !symbols);
    renderContextDetails();
  }

  function validSymbolModule(module)
  {
    var key = module && module.key;
    if (!key || typeof key.base !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(key.base) || BigInt(key.base) === BigInt(0) ||
      !["size", "timestamp", "checksum"].every(function (name)
      {
        return typeof key[name] === "string" && /^(0|[1-9][0-9]{0,9})$/.test(key[name]) && BigInt(key[name]) <= BigInt("4294967295");
      }) || key.size === "0" || BigInt(key.base) + BigInt(key.size) > BigInt("18446744073709551616"))
    {
      return false;
    }
    return (module.name === null || typeof module.name === "string" && module.name.length <= 127) &&
      ["None", "Deferred", "ExportOnly", "PDB", "COFF", "CodeView", "SYM", "DIA", "Unknown"].indexOf(module.loadState) >= 0;
  }

  function populateSymbolModules()
  {
    var view = state.contextView;
    var select = uiElement("symbol-module");
    select.textContent = "";
    view.modules.forEach(function (module)
    {
      var option = document.createElement("option");
      option.value = module.key.base;
      option.textContent = diagnosticValue(module.name) + " / " + module.loadState + " / " + module.key.base;
      select.appendChild(option);
    });
    if (!selectedSymbolModule())
    {
      view.selected = view.modules.length ? view.modules[0].key.base : "";
    }
    select.value = view.selected;
  }

  function readSymbolModules(more)
  {
    var view = state.contextView;
    if (state.capabilities.indexOf("symbolHealth.v1") < 0 || state.busy || debuggerBusy() || !state.connected ||
      !state.sessionStatus.stopped || more && (!symbolModuleCurrent() || view.modules.length >= 4096))
    {
      return;
    }
    var expected = state.target;
    var modules = more ? view.modules.slice() : [];
    var unknown = more ? view.unknown : 0;
    view.loading = true;
    view.error = "";
    state.busy = true;
    setStatusBusy(true);
    phase("Reading module inventory");
    function page(cursor, remaining)
    {
      return send("symbolModules", { cursor: cursor, expectedStamp: expected }).then(function (reply)
      {
        var result = reply && reply.ok && reply.result;
        if (!result || !result.ok || processStampKey(result.target) !== processStampKey(expected) ||
          processStampKey(state.target) !== processStampKey(expected) || !state.statusKnown || !state.sessionStatus.stopped ||
          !Array.isArray(result.modules) || result.modules.length > 64 || !result.modules.every(validSymbolModule) ||
          typeof result.complete !== "boolean" || typeof result.nextCursor !== "string" || !/^\d{1,5}$/.test(result.nextCursor) ||
          typeof result.total !== "string" || !/^\d{1,5}$/.test(result.total) ||
          typeof result.unknown !== "string" || !/^\d{1,2}$/.test(result.unknown) || BigInt(result.total) > BigInt(65536) ||
          BigInt(result.nextCursor) < BigInt(cursor) || BigInt(result.nextCursor) > BigInt(result.total) ||
          BigInt(result.nextCursor) - BigInt(cursor) !== BigInt(result.modules.length + Number(result.unknown)) ||
          BigInt(result.nextCursor) - BigInt(cursor) > BigInt(64) ||
          result.complete !== (result.nextCursor === result.total) ||
          !result.complete && BigInt(result.nextCursor) === BigInt(cursor))
        {
          throw new Error(reply && reply.error || "Module inventory unavailable, malformed or from a previous context.");
        }
        result.modules.forEach(function (module)
        {
          if (modules.some(function (item)
          {
            return item.key.base === module.key.base;
          }))
          {
            throw new Error("Module inventory changed while paging. Read modules again.");
          }
          modules.push(module);
        });
        unknown += Number(result.unknown);
        if (!result.complete && remaining > 1 && modules.length < 4096 && !state.cancelRequested)
        {
          return page(result.nextCursor, remaining - 1);
        }
        view.modules = modules.slice(0, 4096);
        view.unknown = unknown;
        view.moduleStamp = expected;
        view.nextCursor = result.nextCursor;
        view.total = result.total;
        view.complete = result.complete;
        if (state.cancelRequested)
        {
          view.error = "Module paging stopped after cancellation. Only the completed pages are shown.";
        }
        populateSymbolModules();
      });
    }
    page(more ? view.nextCursor : "0", 8).catch(function (error)
    {
      view.error = error.message;
    }).then(function ()
    {
      view.loading = false;
      finishRequest();
      renderContextDetails();
    });
  }

  function inspectSymbolHealth()
  {
    var view = state.contextView;
    var module = selectedSymbolModule();
    if (state.capabilities.indexOf("symbolHealth.v1") < 0 || !module || !symbolModuleCurrent() || state.busy || debuggerBusy())
    {
      return;
    }
    var type = uiElement("symbol-type").value.trim();
    var field = uiElement("symbol-field").value.trim();
    if (type && !/^[A-Za-z0-9_]{1,128}$/.test(type) || field && (!type || !/^[A-Za-z0-9_]{1,128}$/.test(field)))
    {
      view.error = "Use a simple type and optional field name (letters, digits and underscores). A field requires a type.";
      renderContextDetails();
      return;
    }
    var expected = state.target;
    view.loading = true;
    view.error = "";
    state.busy = true;
    setStatusBusy(true);
    phase("Inspecting symbol health");
    send("symbolHealth", { moduleKey: module.key, typeName: type, fieldName: field, expectedStamp: expected }).then(function (reply)
    {
      var result = reply && reply.ok && reply.result;
      if (!result || !result.ok || !validSymbolModule(result.module) ||
        processStampKey(result.module.key) !== processStampKey(module.key) || processStampKey(result.target) !== processStampKey(expected) ||
        processStampKey(state.target) !== processStampKey(expected) || !state.statusKnown || !state.sessionStatus.stopped)
      {
        view.error = reply && reply.error || "Symbol inspection unavailable or from a previous context. The previous observation is retained.";
        return;
      }
      view.health = result;
    }).catch(function (error)
    {
      view.error = error.message;
    }).then(function ()
    {
      view.loading = false;
      finishRequest();
      renderContextDetails();
    });
  }

  uiElement("btn-context").addEventListener("click", function ()
  {
    setContextOpen(!state.contextView.open);
  });
  uiElement("btn-context-close").addEventListener("click", function ()
  {
    setContextOpen(false);
  });
  uiElement("context-panel").addEventListener("keydown", function (event)
  {
    if (event.key === "Escape")
    {
      event.stopPropagation();
      setContextOpen(false);
    }
  });
  uiElement("btn-context-refresh").addEventListener("click", function ()
  {
    if (state.ready && !state.busy && !state.statusPending)
    {
      refreshStatus();
    }
  });
  uiElement("btn-context-overview").addEventListener("click", function ()
  {
    setContextSection("context");
  });
  uiElement("btn-context-symbols").addEventListener("click", function ()
  {
    setContextSection("symbols");
  });
  uiElement("btn-context-processes").addEventListener("click", function ()
  {
    setContextOpen(false);
    setInspectionTab("processes");
    setMemoryPanel(true);
  });
  uiElement("symbol-module").addEventListener("change", function ()
  {
    state.contextView.selected = uiElement("symbol-module").value;
    renderContextDetails();
  });
  uiElement("btn-symbol-modules").addEventListener("click", function ()
  {
    readSymbolModules(false);
  });
  uiElement("btn-symbol-more").addEventListener("click", function ()
  {
    readSymbolModules(true);
  });
  uiElement("btn-symbol-inspect").addEventListener("click", inspectSymbolHealth);
  uiElement("btn-symbol-reload-draft").addEventListener("click", function ()
  {
    renderSymbolHealth();
    if (!uiElement("btn-symbol-reload-draft").disabled)
    {
      var draft = state.contextView.health.reloadDraft;
      setContextOpen(false);
      draftCommand(draft);
      workspaceFeedback("Reload draft inserted. Review it and press Enter to run it in WinDbg.", false);
    }
  });

  function updateCurrentProcess()
  {
    var status = state.sessionStatus;
    uiElement("context-state").textContent = !state.statusKnown ? "Context unconfirmed" : !state.connected ? "Disconnected" :
      (status.sessionKind || (status.kernelMode ? "Kernel" : "User") + (status.dumpFile ? " dump" : " live")) +
      " / " + (status.stopped ? "Stopped" : "Running");
    var process = status.currentProcess || {};
    var expected = (state.target.contextIdentity || {}).implicitProcess;
    var valid = state.connected && status.stopped && status.kernelMode &&
      typeof process.eprocess === "string" && /^0x[0-9a-f]{1,16}$/i.test(process.eprocess) &&
      typeof expected === "string" && /^0x[0-9a-f]{1,16}$/i.test(expected) &&
      BigInt(process.eprocess) !== BigInt(0) && BigInt(process.eprocess) === BigInt(expected);
    var values = {
      image: valid && typeof process.image === "string" && process.image.length ? process.image : null,
      pid: valid && typeof process.pid === "string" && /^(0|[1-9][0-9]{0,9})$/.test(process.pid) &&
        BigInt(process.pid) <= BigInt("4294967295") ? process.pid : null,
      eprocess: valid ? process.eprocess : null
    };
    state.currentProcessValues = values;
    Object.keys(values).forEach(function (field)
    {
      var value = values[field];
      var node = uiElement("current-process-" + field);
      var text = value === null ? "Unavailable" : value;
      if (node.textContent !== text)
      {
        node.textContent = text;
      }
      node.title = text;
      var copy = uiElement("copy-current-" + field);
      copy.disabled = value === null;
      copy.setAttribute("aria-description", text);
      if (state.copyMenu && state.copyMenu.anchor === copy && state.copyMenu.value !== value)
      {
        closeCopyMenu();
      }
    });
    uiElement("current-process-notice").textContent = !state.ready ? "Connecting..." :
      state.statusBusy ? (state.connected ? "Debugger busy; showing last checked process" : "Debugger busy; waiting for target status") :
      !state.statusKnown ? "Waiting for target status" :
      !state.connected ? "No target" : !status.stopped ? "Target running" :
      !status.kernelMode ? "Requires an x64 kernel target" :
      process.reason || (!valid ? "Current process unavailable" :
        state.busy || state.statusPending ? "Last checked; refreshing when idle" : "");
  }

  ["image", "pid", "eprocess"].forEach(function (field)
  {
    var node = uiElement("copy-current-" + field);
    bindCopyValue(node, function ()
    {
      return state.currentProcessValues[field];
    }, "current process " + field, node.getAttribute("aria-label"));
    node.tabIndex = 0;
  });

  function dismissBreakpointNotification()
  {
    var toast = uiElement("breakpoint-toast");
    if (toast.contains && toast.contains(uiActiveElement()))
    {
      uiElement("btn-refresh-status").focus({ preventScroll: true });
    }
    setHidden(toast, true);
  }

  function eventLocation(event)
  {
    if (event && typeof event.address === "string" && /^0x[0-9a-f]{1,16}$/i.test(event.address))
    {
      return { value: event.address, label: "Event IP" };
    }
    if (event && typeof event.configuredAddress === "string" && /^0x[0-9a-f]{1,16}$/i.test(event.configuredAddress))
    {
      return { value: event.configuredAddress, label: "Current BP setting address" };
    }
    return { value: null, label: "Event IP unavailable" };
  }

  function targetContextLabel(record)
  {
    var context = record && record.targetContext || {};
    var identity = [];
    if (typeof context.image === "string" && context.image)
    {
      identity.push(context.image);
    }
    ["pid", "tid"].forEach(function (key)
    {
      var value = context[key];
      identity.push(key.toUpperCase() + " " + (typeof value === "string" && /^\d+$/.test(value) ? value : "Unavailable"));
    });
    var processor = context.processor !== undefined ? context.processor : record && record.processor;
    if (typeof processor === "string" && /^\d+$/.test(processor))
    {
      identity.push("CPU " + processor);
    }
    return identity.join(" / ");
  }

  function targetContextDetails(record, captureKind)
  {
    if (!record)
    {
      return "";
    }
    var context = record.targetContext || {};
    var process = record.engineProcessId !== undefined ? record.engineProcessId : record.processId;
    var thread = record.engineThreadId !== undefined ? record.engineThreadId : record.threadId;
    return (context.source === "StoppedEventProcessor" ? "Thread and owning process on the event CPU at capture. " :
      context.source === "SelectedImplicitThread" ? "Selected implicit thread and its owning process at capture. CPU is the selected processor. " +
        (captureKind === "stack" ? "Explicit .cxr/.trap contexts can override the stack's register context. " : "Some registers remain processor-specific. ") :
      context.source === "CurrentSystemIds" ? "Selected process and thread at capture. " : "") +
      "Engine process ID: " + (process === null || process === undefined ? "Unavailable" : process) +
      "; engine thread ID: " + (thread === null || thread === undefined ? "Unavailable" : thread) +
      (context.eprocess ? "; EPROCESS: " + context.eprocess : "") + (context.ethread ? "; ETHREAD: " + context.ethread : "") +
      (context.reason ? ". " + context.reason : "");
  }

  function observeBreakpointHit(result)
  {
    if (!state.statusKnown)
    {
      return;
    }
    var notice = state.breakpointNotification;
    if (!state.connected || result.dumpFile || result.localKernel)
    {
      notice.scope = "";
      notice.session = "";
      notice.stop = "";
      notice.running = false;
      notice.sequence = null;
      setHidden(uiElement("event-unread"), true);
      dismissBreakpointNotification();
      return;
    }
    var target = result.target;
    if (!target || typeof target.sessionId !== "string" || typeof target.stopEpoch !== "string" ||
        typeof target.targetGeneration !== "string")
    {
      return;
    }
    var scope = target.sessionId + "/" + target.targetGeneration;
    var sequence = typeof result.breakpointSequence === "string" && /^\d{1,20}$/.test(result.breakpointSequence) ?
      result.breakpointSequence : null;
    var newHit = sequence !== null && notice.sequence !== null && sequence !== notice.sequence;
    // A stop generation can change for commands without any breakpoint hit.
    // Missing observer data and observer recovery both establish a new baseline.
    if (sequence === null || notice.sequence === null ||
        (scope !== notice.scope && !(notice.session === target.sessionId && newHit)))
    {
      if (notice.session !== target.sessionId)
      {
        setHidden(uiElement("event-unread"), true);
      }
      notice.scope = scope;
      notice.session = target.sessionId;
      notice.stop = target.stopEpoch;
      notice.running = !result.stopped;
      notice.sequence = sequence;
      dismissBreakpointNotification();
      return;
    }
    notice.scope = scope;
    if (!result.stopped)
    {
      notice.running = true;
      dismissBreakpointNotification();
      return;
    }
    if (!newHit)
    {
      if (notice.stop !== target.stopEpoch || notice.running)
      {
        dismissBreakpointNotification();
      }
      notice.stop = target.stopEpoch;
      notice.running = false;
      if (sequence !== null)
      {
        notice.sequence = sequence;
      }
      return;
    }
    dismissBreakpointNotification();
    var event = result.lastEvent;
    if (!event || typeof event.type !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(event.type))
    {
      // A failed event read must remain retryable on the next status poll.
      return;
    }
    notice.stop = target.stopEpoch;
    notice.running = false;
    notice.sequence = sequence;
    // An interrupt or initial INT3 exception is not a configured breakpoint hit.
    if (!/^0x0*1$/i.test(event.type))
    {
      return;
    }
    var id = typeof event.breakpointId === "string" && /^\d{1,10}$/.test(event.breakpointId) &&
      Number(event.breakpointId) < 4294967295 ? " #" + event.breakpointId : "";
    var location = eventLocation(event);
    var address = location.label + (location.value ? ": " + location.value : "");
    uiElement("breakpoint-toast-title").textContent = "Breakpoint" + id + " hit";
    uiElement("breakpoint-toast-detail").textContent = address +
      (typeof event.description === "string" && event.description ? "\n" + event.description.slice(0, 512) : "");
    setHidden(uiElement("event-unread"), false);
    setHidden(uiElement("breakpoint-toast"), false);
  }

  uiElement("btn-breakpoint-toast-dismiss").addEventListener("click", dismissBreakpointNotification);
  uiElement("btn-breakpoint-event").addEventListener("click", function ()
  {
    if (!state.ready || state.busy || debuggerBusy() || !state.connected || !state.sessionStatus.stopped)
    {
      return;
    }
    dismissBreakpointNotification();
    runView("event", null, "event");
  });

  function applyStatus(result, suppressFollow)
  {
    state.statusBusy = false;
    state.statusKnown = !!(result && typeof result.connected === "boolean" &&
      (!result.connected || typeof result.stopped === "boolean"));
    state.sessionStatus = state.statusKnown ? result : {};
    if (state.statusKnown)
    {
      state.contextView.observed = result;
      state.contextView.received = new Date().toLocaleTimeString();
    }
    state.connected = state.statusKnown && result.connected;
    if (debuggerBusy())
    {
      ++state.debuggerRevision;
    }
    if (state.statusKnown && result.target)
    {
      state.target = result.target;
    }
    var breaking = state.executionControl.target;
    if (state.executionControl.breaking && state.statusKnown && (!state.connected || result.stopped === true ||
      !result.target || !breaking || result.target.sessionId !== breaking.sessionId ||
      result.target.targetGeneration !== breaking.targetGeneration))
    {
      clearPendingBreak();
    }
    observeBreakpointHit(result);
    observeDisassemblyStop(result, suppressFollow);
    updateCurrentProcess();
    updateEvidenceSummary();
    selectObservation(state.selectedRow);
    updateProcessSummary();
    updateMemorySummary();
    updateRegistersSummary();
    updateDisassemblySummary();
    updateInputUI();
    followDisassemblyStop();
    maybeRefreshRegisters();
    if (!state.pauseInspectionReads && !document.hidden && inspectionVisible("processes") && !state.busy && state.connected && result.kernelMode && result.stopped &&
      !processListCurrent() && state.processes.lastAttempt !== processStampKey(state.target))
    {
      refreshProcesses();
    }
    if (!state.connected)
    {
      els.status.textContent = state.statusKnown ? "no session" : "status failed: invalid target status";
      els.status.className = "status bad";
      return;
    }

    var kind = result.sessionKind ||
      ((result.kernelMode ? "kernel" : "user") +
        (result.dumpFile ? " dump" : " live"));

    els.status.textContent =
      kind + " | exec " + result.execStatus +
      " | modules " + result.modulesLoaded +
      (result.ntResolved ? " | nt ok" : " | nt missing");

    els.status.className = result.stopped === false ? "status warn" : "status ok";
  }

  function refreshStatus()
  {
    state.statusPending = true;
    updateCurrentProcess();
    var token = ++state.statusToken;
    send("status", {}).then(function (reply)
    {
      if (token !== state.statusToken)
      {
        return;
      }
      state.statusPending = false;
      if (reply && reply.ok)
      {
        applyStatus(reply.result);
      }
      else
      {
        if (!reply || reply.error !== "EngineBusy")
        {
          state.disassembly.pendingFollow = null;
        }
        state.statusKnown = false;
        ++state.debuggerRevision;
        state.statusBusy = !!(reply && reply.error === "EngineBusy");
        if (!state.statusBusy)
        {
          state.connected = false;
        }
        updateCurrentProcess();
        updateProcessSummary();
        updateMemorySummary();
        updateRegistersSummary();
        updateDisassemblySummary();
        updateEvidenceSummary();
        selectObservation(state.selectedRow);
        updateInputUI();
        els.status.textContent = state.statusBusy ? "debugger busy | target status pending" : "status failed";
        els.status.className = state.statusBusy ? "status warn" : "status bad";
      }
    });
  }

  // ---------- catalog ----------

  function firstToken(text)
  {
    return String(text).trim().split(/\s+/)[0] || "";
  }

  function commandKey(text)
  {
    return firstToken(text).toLowerCase().replace(/^!/, "");
  }

  function selectCommand(command)
  {
    var token = commandKey(command);
    if (token && token[0] !== ":" && token !== state.selectedCommand)
    {
      state.selectedCommand = token;
      ++state.commandSelectionRevision;
    }
    updateCatalogSelection();
  }

  function updateCatalogSelection()
  {
    var selectedName = "";
    Object.keys(state.commandsByName).forEach(function (name)
    {
      if (commandKey(name) === state.selectedCommand)
      {
        selectedName = name;
      }
    });
    Array.prototype.forEach.call(els.catalog.querySelectorAll(".cmd-item"), function (item)
    {
      if (item.dataset.command)
      {
        var selectedSpec = state.commandsByName[selectedName];
        var selected = item.dataset.command === state.selectedCommand ||
          selectedSpec && selectedSpec.canonical && item.dataset.command === commandKey(selectedSpec.canonical);
        item.classList[selected ? "add" : "remove"]("active");
        item.setAttribute("aria-current", selected ? "true" : "false");
      }
    });
    var selected = uiElement("selected-command");
    selected.textContent = selectedName ? "Selected: " + selectedName : "No library command selected";
    selected.title = selectedName ? "Show " + selectedName + " in the library" : "Choose a command to edit";
    selected.disabled = !selectedName;
  }

  uiElement("selected-command").addEventListener("click", function ()
  {
    els.filter.value = "";
    uiElement("library-favorites").checked = false;
    state.groups.forEach(function (group)
    {
      if (group.commands.some(function (cmd)
      {
        return commandKey(cmd.name) === state.selectedCommand;
      }))
      {
        delete state.libraryCollapsed[group.name];
      }
    });
    saveLibraryPreferences();
    renderCatalog();
    Array.prototype.forEach.call(els.catalog.querySelectorAll(".cmd-item"), function (item)
    {
      if (item.dataset.command === state.selectedCommand)
      {
        item.focus();
        item.scrollIntoView({ block: "nearest" });
      }
    });
  });

  function fuzzyMatch(needle, haystack)
  {
    var cursor = 0;
    for (var i = 0; i < needle.length; ++i)
    {
      cursor = haystack.indexOf(needle[i], cursor);
      if (cursor < 0)
      {
        return false;
      }
      ++cursor;
    }
    return true;
  }

  function commandMatches(query, name, synopsis)
  {
    return query.toLowerCase().split(/\s+/).filter(Boolean).every(function (term)
    {
      return name.toLowerCase().indexOf(term) >= 0 || synopsis.toLowerCase().indexOf(term) >= 0 ||
        fuzzyMatch(term, name.toLowerCase());
    });
  }

  function draftCommand(command)
  {
    if (debuggerBusy())
    {
      return;
    }
    els.prompt.value = command;
    state.parameterDraft = null;
    hideSuggest();
    updateInputUI();
    if (els.root.classList.contains("library-overlay"))
    {
      state.libraryVisible = false;
      updateLayout();
      saveWorkspacePreferences();
    }
    els.prompt.focus();
    updateSuggest();
  }

  uiElement("kernel-workflow").addEventListener("change", function (event)
  {
    var command = event.target.value;
    if (command && !state.busy && !debuggerBusy() && state.ready)
    {
      draftCommand(command);
    }
    event.target.value = "";
  });

  function saveLibraryPreferences()
  {
    try
    {
      var settings = { version: 1, sort: state.librarySort, collapsed: [] };
      var length = JSON.stringify(settings).length;
      state.groups.forEach(function (group)
      {
        var name = group.name;
        var extra = JSON.stringify(name).length + (settings.collapsed.length ? 1 : 0);
        if (state.libraryCollapsed[name] === true && name.length <= 128 && settings.collapsed.length < 128 && length + extra <= 16384)
        {
          settings.collapsed.push(name);
          length += extra;
        }
      });
      window.localStorage.setItem("kndbgx.command-library", JSON.stringify(settings));
    }
    catch (error)
    {
      // Library controls remain available when preferences cannot be saved.
    }
  }

  function loadLibraryPreferences()
  {
    try
    {
      var saved = window.localStorage.getItem("kndbgx.command-library");
      if (typeof saved !== "string" || saved.length > 16384)
      {
        return;
      }
      var settings = JSON.parse(saved);
      if (!settings || settings.version !== 1)
      {
        return;
      }
      if (settings.sort === "alphabetical")
      {
        state.librarySort = "alphabetical";
      }
      if (Array.isArray(settings.collapsed) && settings.collapsed.length <= 128)
      {
        settings.collapsed.forEach(function (name)
        {
          if (typeof name === "string" && name.length > 0 && name.length <= 128)
          {
            state.libraryCollapsed[name] = true;
          }
        });
      }
    }
    catch (error)
    {
      // Keep the default library layout when preferences are unavailable or invalid.
    }
  }

  function compareLibraryNames(left, right)
  {
    var a = left.toLowerCase().replace(/^[!.]+/, "");
    var b = right.toLowerCase().replace(/^[!.]+/, "");
    if (a === b)
    {
      a = left.toLowerCase();
      b = right.toLowerCase();
    }
    return a < b ? -1 : a > b ? 1 : 0;
  }

  uiElement("library-sort").addEventListener("change", function (event)
  {
    if (!state.groups.length || ["default", "alphabetical"].indexOf(event.target.value) < 0)
    {
      return;
    }
    state.librarySort = event.target.value;
    saveLibraryPreferences();
    renderCatalog();
  });

  function renderCatalog()
  {
    els.catalog.textContent = "";
    var visibleCount = 0;
    var total = 0;
    var query = els.filter.value.trim();
    if (state.libraryFilter !== query)
    {
      state.libraryFilter = query;
      state.libraryFilterCollapsed = Object.create(null);
    }
    var groups = state.groups.slice();
    if (state.librarySort === "alphabetical")
    {
      groups.sort(function (a, b)
      {
        return compareLibraryNames(a.name, b.name);
      });
    }
    state.commandsByName = Object.create(null);
    groups.forEach(function (group, groupIndex)
    {
      group.commands.forEach(function (cmd)
      {
        state.commandsByName[firstToken(cmd.name).toLowerCase()] = cmd;
        ++total;
      });
      var visible = group.commands.filter(function (cmd)
      {
        return (!uiElement("library-favorites").checked || state.libraryFavorites.indexOf(cmd.canonical || cmd.name) >= 0) &&
          (query || !cmd.canonical || cmd.canonical === cmd.name) && commandMatches(query, cmd.name,
          (cmd.grammar || "") + " " + cmd.synopsis + " " + group.name + " " + cmd.support + " " +
          (Array.isArray(cmd.aliases) ? cmd.aliases.join(" ") : ""));
      });
      if (!visible.length)
      {
        return;
      }
      if (state.librarySort === "alphabetical")
      {
        visible.sort(function (a, b)
        {
          return compareLibraryNames(a.name, b.name);
        });
      }
      if (query)
      {
        visible.sort(function (left, right)
        {
          return Number(right.name.toLowerCase() === query.toLowerCase()) - Number(left.name.toLowerCase() === query.toLowerCase());
        });
      }
      visibleCount += visible.length;
      var collapsed = query ? state.libraryFilterCollapsed : state.libraryCollapsed;
      var title = document.createElement("button");
      title.type = "button";
      title.className = "group-title catalog-group-toggle";
      title.dataset.group = group.name;
      title.textContent = group.name + " / " + visible.length;
      title.setAttribute("aria-expanded", collapsed[group.name] === true ? "false" : "true");
      var list = document.createElement("div");
      list.id = "catalog-group-" + groupIndex;
      list.className = "catalog-group-items" + (collapsed[group.name] === true ? " hidden" : "");
      list.setAttribute("role", "group");
      list.setAttribute("aria-label", group.name);
      title.setAttribute("aria-controls", list.id);
      title.addEventListener("click", function ()
      {
        var closing = title.getAttribute("aria-expanded") === "true";
        if (closing)
        {
          collapsed[group.name] = true;
        }
        else
        {
          delete collapsed[group.name];
        }
        title.setAttribute("aria-expanded", closing ? "false" : "true");
        list.classList[closing ? "add" : "remove"]("hidden");
        if (!query)
        {
          saveLibraryPreferences();
        }
      });
      els.catalog.appendChild(title);
      els.catalog.appendChild(list);
      visible.forEach(function (cmd)
      {
        var item = document.createElement("button");
        item.className = "cmd-item";
        item.dataset.command = commandKey(cmd.name);
        var modeLabel = cmd.modes === "LiveKernel" ? "live kernel only" :
          cmd.modes === "LiveKernelLocal" ? "live local kernel only (host data; refuses remote targets)" :
          cmd.modes === "KernelDump" ? "kernel dump only" :
          cmd.modes === "DumpAndLive" ? "kernel dump + live" : null;
        item.title = (cmd.grammar ? cmd.grammar + " | " : "") + cmd.synopsis + " | " + cmd.support + (modeLabel ? " | " + modeLabel : "");
        var name = document.createElement("span");
        name.className = "name";
        name.textContent = cmd.name;
        var support = document.createElement("span");
        support.className = "support tag-" + cmd.support;
        support.textContent = cmd.support;
        var hint = document.createElement("span");
        hint.className = "hint";
        hint.textContent = cmd.synopsis;
        if (cmd.canonical && cmd.canonical !== cmd.name)
        {
          hint.textContent += " / Alias of " + cmd.canonical;
        }
        else if (Array.isArray(cmd.aliases) && cmd.aliases.length)
        {
          hint.textContent += " / Aliases: " + cmd.aliases.join(", ");
        }
        item.appendChild(support);
        if (cmd.modes === "LiveKernel" || cmd.modes === "KernelDump" || cmd.modes === "LiveKernelLocal")
        {
          var modeTag = document.createElement("span");
          modeTag.className = "support tag-modes";
          modeTag.textContent = cmd.modes === "LiveKernel" ? "live" : cmd.modes === "LiveKernelLocal" ? "live*" : "dump";
          modeTag.title = modeLabel;
          item.appendChild(modeTag);
        }
        item.appendChild(name);
        item.appendChild(hint);
        item.addEventListener("click", function ()
        {
          draftCommand(firstToken(cmd.name));
        });
        var entry = document.createElement("div");
        entry.className = "catalog-entry";
        entry.appendChild(item);
        var favorite = document.createElement("button");
        favorite.className = "command-favorite quiet";
        var favoriteName = cmd.canonical || cmd.name;
        function updateFavorite()
        {
          var active = state.libraryFavorites.indexOf(favoriteName) >= 0;
          favorite.textContent = active ? "★" : "☆";
          favorite.setAttribute("aria-pressed", String(active));
          favorite.setAttribute("aria-label", (active ? "Remove favorite " : "Favorite ") + favoriteName);
          favorite.title = (active ? "Remove from favorites" : "Add to favorites") + " / " + favoriteName;
        }
        favorite.addEventListener("click", function ()
        {
          if (state.libraryFavorites.indexOf(favoriteName) >= 0)
          {
            state.libraryFavorites = state.libraryFavorites.filter(function (name)
            {
              return name !== favoriteName;
            });
          }
          else if (state.libraryFavorites.length < 128)
          {
            state.libraryFavorites.push(favoriteName);
          }
          try
          {
            window.localStorage.setItem("kndbgx.command-favorites", JSON.stringify(state.libraryFavorites));
          }
          catch (error)
          {
            // Favorites remain usable when persistent storage is unavailable.
          }
          updateFavorite();
          if (uiElement("library-favorites").checked)
          {
            els.filter.focus();
            renderCatalog();
          }
        });
        updateFavorite();
        entry.appendChild(favorite);
        list.appendChild(entry);
      });
    });
    uiElement("catalog-count").textContent = visibleCount + " / " + total;
    uiElement("catalog-count").title = "Visible entries / searchable names including aliases. Aliases are grouped under their command by default.";
    updateCatalogSelection();
    if (!visibleCount)
    {
      var empty = document.createElement("div");
      empty.className = "group-title";
      empty.textContent = uiElement("library-favorites").checked ? "No matching favorites. Clear Favorites only, then star a command." :
        total ? "No matching commands" : "No commands available";
      els.catalog.appendChild(empty);
    }
    if (!els.paletteBackdrop.classList.contains("hidden"))
    {
      renderPalette();
    }
  }

  function applyFilter()
  {
    renderCatalog();
  }

  function setHidden(node, hidden)
  {
    node.classList[hidden ? "add" : "remove"]("hidden");
  }

  function isNarrow()
  {
    return typeof window.matchMedia === "function" && window.matchMedia("(max-width: 900px)").matches;
  }

  function memoryPanelBounds()
  {
    var available = uiElement("workspace-split").clientWidth || window.innerWidth || 900;
    var overlay = available < 992;
    var maximum = Math.max(1, Math.min(1000, available - (overlay ? 24 : 566)));
    return { minimum: Math.min(280, maximum), maximum: maximum, overlay: overlay, available: available };
  }

  function inspectorPanelBounds()
  {
    var content = uiElement("result-content");
    var available = content.clientWidth || window.innerWidth || 900;
    var stacked = els.root.classList.contains("memory-compact") || window.innerWidth <= 700 || window.innerHeight <= 540 ||
      typeof window.getComputedStyle === "function" && window.getComputedStyle(content).flexDirection === "column";
    var maximum = Math.max(1, Math.min(800, available - 326));
    var minimum = Math.min(240, maximum);
    return { minimum: minimum, maximum: maximum, resizable: state.inspectorVisible && !stacked && maximum > minimum };
  }

  function updateInspectorLayout()
  {
    var panel = state.inspectorPanel;
    var bounds = inspectorPanelBounds();
    var inspector = uiElement("inspector");
    var splitter = uiElement("inspector-splitter");
    panel.resizable = bounds.resizable;
    if (!bounds.resizable && panel.drag)
    {
      endInspectorResize(true);
      return;
    }
    if (!bounds.resizable && uiActiveElement() === splitter)
    {
      uiElement("btn-inspector").focus();
    }
    setHidden(splitter, !bounds.resizable);
    if (!bounds.resizable)
    {
      inspector.style.flexBasis = "";
      return;
    }
    var preferred = panel.width;
    if (preferred === null)
    {
      inspector.style.flexBasis = "";
      preferred = typeof window.getComputedStyle === "function" ? parseFloat(window.getComputedStyle(inspector).flexBasis) : 296;
    }
    if (!Number.isFinite(preferred))
    {
      preferred = 296;
    }
    panel.effectiveWidth = Math.round(Math.max(bounds.minimum, Math.min(bounds.maximum, preferred)));
    inspector.style.flexBasis = panel.effectiveWidth + "px";
    splitter.setAttribute("aria-valuemin", String(bounds.minimum));
    splitter.setAttribute("aria-valuemax", String(bounds.maximum));
    splitter.setAttribute("aria-valuenow", String(panel.effectiveWidth));
    splitter.setAttribute("aria-valuetext", panel.effectiveWidth + " pixels");
  }

  function saveInspectorWidth()
  {
    try
    {
      window.localStorage.setItem("kndbgx.inspector-width", JSON.stringify(state.inspectorPanel.width));
    }
    catch (error)
    {
      // Resizing remains available when preferences cannot be saved.
    }
  }

  function setInspectorWidth(width, remember)
  {
    var bounds = inspectorPanelBounds();
    state.inspectorPanel.width = width === null ? null : Math.round(Math.max(bounds.minimum, Math.min(bounds.maximum, width)));
    updateInspectorLayout();
    syncTableViewport();
    positionToolMenus();
    if (remember)
    {
      saveInspectorWidth();
    }
  }

  function endInspectorResize(cancelled)
  {
    var drag = state.inspectorPanel.drag;
    if (!drag)
    {
      return;
    }
    state.inspectorPanel.drag = null;
    els.root.classList.remove("inspector-resizing");
    var splitter = uiElement("inspector-splitter");
    if (typeof splitter.hasPointerCapture === "function" && splitter.hasPointerCapture(drag.pointerId))
    {
      splitter.releasePointerCapture(drag.pointerId);
    }
    if (cancelled)
    {
      state.inspectorPanel.width = drag.previousWidth;
      updateInspectorLayout();
      syncTableViewport();
      positionToolMenus();
    }
    saveInspectorWidth();
  }

  function moveInspectorResize(event)
  {
    var drag = state.inspectorPanel.drag;
    if (drag && event.pointerId === drag.pointerId && Number.isFinite(event.clientX))
    {
      event.preventDefault();
      var bounds = inspectorPanelBounds();
      var width = Math.round(Math.max(bounds.minimum, Math.min(bounds.maximum, drag.startWidth + drag.startX - event.clientX)));
      if (width !== state.inspectorPanel.effectiveWidth)
      {
        setInspectorWidth(width, false);
      }
    }
  }

  function independentInspectionVisible(view)
  {
    var item = inspectionPanels[view];
    return !!(item && item.window && !item.suspended && !item.window.closed);
  }

  function clearInspectionDockGuides(retire)
  {
    inspectionDockDrag.guides.forEach(function (node)
    {
      node.remove();
    });
    inspectionDockDrag.guides = [];
    inspectionDockDrag.token = "";
    if (retire !== false)
    {
      inspectionDockDrag.ended = true;
    }
  }

  function receiveInspectionDrag(message)
  {
    if (typeof message.dragId !== "string" || !/^[1-9][0-9]{0,19}$/.test(message.dragId) ||
        BigInt(message.dragId) < BigInt(inspectionDockDrag.id) ||
        message.dragId === inspectionDockDrag.id && inspectionDockDrag.ended)
    {
      return;
    }
    var view = inspectionViews.find(function (name)
    {
      return inspectionPanels[name].window && inspectionPanels[name].token === message.token;
    });
    var source = view ? inspectionPanels[view] : inspectionFloat;
    var valid = source.window && !source.window.closed && !source.suspended && !els.root.inert &&
      message.token === (view ? source.token : String(source.serial)) &&
      message.visibilityEpoch === (view ? source.epoch : source.visibilityEpoch);
    if (message.phase === "cancel" || !valid)
    {
      clearInspectionDockGuides();
      inspectionDockDrag.id = message.dragId;
      return;
    }
    var group = inspectionFloat.window && !inspectionFloat.window.closed && !inspectionFloat.suspended && state.memoryPanel.visible;
    var destinationValid = message.destination === "main" || message.destination === "group" && view && group &&
      message.destinationToken === String(inspectionFloat.serial) && message.destinationEpoch === inspectionFloat.visibilityEpoch;
    if (message.phase === "drop")
    {
      var active = inspectionDockDrag.id === message.dragId && inspectionDockDrag.token === message.token;
      clearInspectionDockGuides();
      inspectionDockDrag.id = message.dragId;
      if (!active || !destinationValid)
      {
        return;
      }
      if (message.destination === "main")
      {
        dockInspection(!view);
      }
      if (view)
      {
        dockInspectionView(view, true);
      }
      return;
    }
    if (message.phase !== "preview")
    {
      return;
    }
    clearInspectionDockGuides(false);
    inspectionDockDrag.id = message.dragId;
    inspectionDockDrag.ended = false;
    inspectionDockDrag.token = message.token;
    function guide(doc, destination, title, detail)
    {
      var node = doc.createElement("aside");
      node.className = "inspection-dock-guide inspection-dock-" + destination +
        (destinationValid && message.destination === destination ? " active" : "");
      node.setAttribute("role", "status");
      var heading = doc.createElement("strong");
      heading.textContent = title;
      var hint = doc.createElement("span");
      hint.textContent = detail;
      node.appendChild(heading);
      node.appendChild(hint);
      doc.body.appendChild(node);
      inspectionDockDrag.guides.push(node);
    }
    guide(document, "main", "Dock to workspace", group && view ? "Returns the Inspect group here / Release to dock / Esc to cancel" :
      "Release here to dock / Esc to cancel");
    if (group && view)
    {
      guide(inspectionFloat.window.document, "group", "Dock " + inspectionLabel(view) + " in Inspect", "Release here to join these tabs / Esc to cancel");
    }
  }

  function inspectionVisible(view)
  {
    return independentInspectionVisible(view) || state.memoryPanel.visible && state.memoryPanel.tab === view &&
      !(inspectionPanels[view] && inspectionPanels[view].window);
  }

  function independentInspectionControl(item, action)
  {
    var token = item.token;
    return send("inspectionWindow", { action: action, token: token, visibilityEpoch: item.epoch }).then(function (reply)
    {
      if (item.token === token && reply && reply.error === "InspectionVisibilityChanged" && reply.result &&
          typeof reply.result.visibilityEpoch === "string" && /^(0|[1-9][0-9]{0,19})$/.test(reply.result.visibilityEpoch) &&
          BigInt(reply.result.visibilityEpoch) > BigInt(item.epoch))
      {
        item.epoch = reply.result.visibilityEpoch;
        dockInspectionView(item.view, true);
      }
      return reply;
    });
  }

  function updateIndependentInspectionLayout()
  {
    var detached = false;
    inspectionViews.forEach(function (view)
    {
      var item = inspectionPanels[view];
      var active = !!(item.window || item.opening);
      detached = detached || active;
      var button = uiElement("btn-float-" + view);
      button.textContent = item.window ? "Dock" : item.opening ? "Opening..." : "Float";
      button.title = item.window ? "Return " + view + " to the inspection tabs" : "Open " + view + " in its own window";
      button.disabled = !state.ready || !!item.opening || !!inspectionFloat.opening || typeof window.open !== "function";
      var tab = inspectionTab(view);
      tab.classList[item.window ? "add" : "remove"]("detached");
      if (item.window)
      {
        tab.removeAttribute("aria-controls");
      }
      else
      {
        tab.setAttribute("aria-controls", inspectionPanel(view).id);
      }
      setHidden(inspectionPanel(view), !item.window && state.memoryPanel.tab !== view);
    });
    var current = inspectionPanels[state.memoryPanel.tab];
    setHidden(uiElement("inspection-detached"), !current.window);
    uiElement("inspection-detached-text").textContent = inspectionLabel(state.memoryPanel.tab) + " is open in a separate window.";
    uiElement("btn-inspection-float").title = inspectionFloat.window ? "Return the inspection group to the main window" :
      "Float the inspection group while keeping independent views open";
    setHidden(uiElement("btn-inspection-dock"), !detached && !inspectionFloat.window && !inspectionFloat.opening);
    uiElement("btn-inspection-dock").textContent = detached ? "Dock all" : "Dock Inspect";
  }

  function inspectionLabel(view)
  {
    return view.charAt(0).toUpperCase() + view.slice(1);
  }

  function restoreSharedInspectionNodes(doc)
  {
    var menu = uiElement("cell-copy-menu");
    var fallback = uiElement("copy-fallback");
    if (menu.ownerDocument === doc)
    {
      closeCopyMenu(false);
      els.root.appendChild(menu);
    }
    if (fallback.ownerDocument === doc)
    {
      uiElement("main").insertBefore(fallback, uiElement("workspace-split"));
    }
  }

  function dockInspectionView(view, reveal)
  {
    clearInspectionDockGuides();
    var item = inspectionPanels[view];
    var popup = item.window || item.opening;
    if (!popup)
    {
      return;
    }
    // Docking chooses a new focus target, including native frame closes.
    ++inspectionFloat.interaction;
    clearTimeout(item.timeout);
    item.timeout = null;
    var panel = item.panel || inspectionPanel(view);
    var owner = panel.ownerDocument;
    var saved = Array.from(panel.querySelectorAll("*")).map(function (node)
    {
      return [node, node.scrollTop, node.scrollLeft];
    });
    hideSuggest();
    restoreSharedInspectionNodes(owner);
    panel.inert = false;
    panel.setAttribute("role", "tabpanel");
    panel.setAttribute("aria-labelledby", inspectionTab(view).id);
    uiElement("memory").appendChild(panel);
    if (item.window)
    {
      inspectionFloat.documents.forEach(function (entry)
      {
        owner.removeEventListener(entry[0], entry[1], entry[2]);
      });
      inspectionFloat.windows.forEach(function (entry)
      {
        popup.removeEventListener(entry[0], entry[1], entry[2]);
      });
    }
    if (item.observer)
    {
      item.observer.disconnect();
      item.observer = null;
    }
    if (reveal && !els.root.inert && !inspectionFloat.window)
    {
      independentInspectionControl(item, "focus-main");
    }
    independentInspectionControl(item, "close");
    item.window = item.opening = null;
    item.chrome = item.status = null;
    item.suspended = false;
    ++item.visibility;
    item.token = "";
    if (reveal)
    {
      state.memoryPanel.visible = true;
      setInspectionTab(view);
    }
    updateLayout();
    restoreInspectionViewport(saved);
    saveMemoryPanel();
    if (reveal && !els.root.inert)
    {
      if (inspectionFloat.window)
      {
        var token = String(inspectionFloat.serial);
        var visibility = ++inspectionFloat.visibilityToken;
        inspectionControl("show", token, true).then(function (reply)
        {
          recoverFloatingInspection(reply, token, false, visibility);
        });
      }
      uiView(inspectionTab(view)).focus();
      inspectionTab(view).focus();
    }
    try
    {
      popup.close();
    }
    catch (error)
    {
      // The native close request also releases a disconnected proxy.
    }
  }

  function floatInspectionView(view)
  {
    var item = inspectionPanels[view];
    if (!item || !state.ready || els.root.inert || item.opening || inspectionFloat.opening)
    {
      return;
    }
    if (item.window)
    {
      dockInspectionView(view, true);
      return;
    }
    hideSuggest();
    closeCopyMenu(false);
    var token = item.token = String(++inspectionSerial);
    item.epoch = "0";
    var url = "about:blank#kndbgx-inspect-" + view + "-" + token;
    var popup;
    try
    {
      popup = window.open(url, "kndbgx-inspect-" + view, "popup,width=640,height=740");
    }
    catch (error)
    {
      popup = null;
    }
    if (!popup)
    {
      workspaceFeedback("The " + view + " window could not be opened. The view is still docked.", true);
      return;
    }
    item.opening = popup;
    item.panel = inspectionPanel(view);
    updateMemoryPanelLayout();
    function failed()
    {
      if (item.token === token)
      {
        dockInspectionView(view, false);
        workspaceFeedback("The " + view + " window did not become ready. The view is docked.", true);
      }
    }
    item.timeout = setTimeout(failed, 8000);
    function prepare()
    {
      if (item.token !== token || item.opening !== popup)
      {
        return;
      }
      try
      {
        if (popup.closed)
        {
          failed();
          return;
        }
        if (popup.location.href !== url || !popup.document.body || popup.document.readyState === "loading")
        {
          setTimeout(prepare, 25);
          return;
        }
        var doc = popup.document;
        doc.title = "KNDbgX - " + inspectionLabel(view);
        doc.documentElement.lang = "en";
        doc.body.className = "inspection-floating inspection-independent inspection-styled";
        var css = doc.createElement("link");
        css.rel = "stylesheet";
        css.href = new URL("/app.css", window.location.href).href;
        css.onerror = failed;
        css.onload = function ()
        {
          if (item.token !== token || item.opening !== popup || popup.closed)
          {
            return;
          }
          try
          {
            clearTimeout(item.timeout);
            item.timeout = null;
            var panel = item.panel;
            var saved = Array.from(panel.querySelectorAll("*")).map(function (node)
            {
              return [node, node.scrollTop, node.scrollLeft];
            });
            rememberInspectionNodes(panel);
            item.window = popup;
            item.opening = null;
            panel.setAttribute("role", "region");
            panel.removeAttribute("aria-labelledby");
            panel.setAttribute("aria-label", inspectionLabel(view));
            var status = createInspectionStatus(doc, item);
            doc.body.appendChild(panel);
            doc.body.appendChild(status);
            if (typeof window.MutationObserver === "function")
            {
              item.observer = new MutationObserver(updateFloatingInspectionStatus);
              [els.status, uiElement("current-process-bar"), uiElement("workspace-feedback"), uiElement("copy-status")].forEach(function (node)
              {
                item.observer.observe(node, { subtree: true, childList: true, characterData: true, attributes: true });
              });
            }
            inspectionFloat.documents.forEach(function (entry)
            {
              doc.addEventListener(entry[0], entry[1], entry[2]);
            });
            inspectionFloat.windows.forEach(function (entry)
            {
              popup.addEventListener(entry[0], entry[1], entry[2]);
            });
            popup.addEventListener("pagehide", function ()
            {
              if (item.window === popup)
              {
                dockInspectionView(view, true);
              }
            });
            updateLayout();
            restoreInspectionViewport(saved);
            updateFloatingInspectionStatus();
            var visibility = ++item.visibility;
            independentInspectionControl(item, "show").then(function (reply)
            {
              if (item.token === token && item.visibility === visibility && (!reply || !reply.ok))
              {
                failed();
              }
            });
            uiElement(inspectionGrid(view)).focus();
          }
          catch (error)
          {
            failed();
          }
        };
        doc.head.appendChild(css);
      }
      catch (error)
      {
        failed();
      }
    }
    prepare();
  }

  function suspendIndependentInspections()
  {
    inspectionViews.forEach(function (view)
    {
      var item = inspectionPanels[view];
      if (item.opening)
      {
        dockInspectionView(view, false);
      }
      if (item.window)
      {
        item.suspended = true;
        item.panel.inert = true;
        var token = item.token;
        var visibility = ++item.visibility;
        independentInspectionControl(item, "hide").then(function (reply)
        {
          if (item.token === token && item.visibility === visibility && (!reply || !reply.ok))
          {
            dockInspectionView(view, false);
          }
        });
      }
    });
    focusMainWorkspace();
  }

  function resumeIndependentInspections(target)
  {
    inspectionViews.forEach(function (view)
    {
      var item = inspectionPanels[view];
      if (item.window && item.suspended)
      {
        item.suspended = false;
        item.panel.inert = false;
        var token = item.token;
        var visibility = ++item.visibility;
        var interaction = inspectionFloat.interaction;
        independentInspectionControl(item, uiView(target) === item.window ? "show" : "restore").then(function (reply)
        {
          if (item.token !== token || item.visibility !== visibility)
          {
            return;
          }
          if (!reply || !reply.ok)
          {
            dockInspectionView(view, false);
          }
          else if (target && uiView(target) === item.window && interaction === inspectionFloat.interaction && !els.root.inert)
          {
            target.focus();
          }
        });
      }
    });
  }

  inspectionViews.forEach(function (view)
  {
    uiElement("btn-float-" + view).addEventListener("click", function ()
    {
      floatInspectionView(view);
    });
  });
  uiElement("btn-inspection-show-view").addEventListener("click", function ()
  {
    var item = inspectionPanels[state.memoryPanel.tab];
    if (item.window)
    {
      independentInspectionControl(item, "show");
    }
  });
  uiElement("btn-inspection-dock-view").addEventListener("click", function ()
  {
    dockInspectionView(state.memoryPanel.tab, true);
  });


  function rememberInspectionNodes(node)
  {
    if (node.id)
    {
      inspectionFloat.nodes[node.id] = node;
    }
    node.querySelectorAll("[id]").forEach(function (child)
    {
      inspectionFloat.nodes[child.id] = child;
    });
  }

  function inspectionControl(action, token, quiet)
  {
    token = token || String(inspectionFloat.serial);
    var visibility = inspectionFloat.visibilityToken;
    return send("inspectionWindow", { action: action, token: token, visibilityEpoch: inspectionFloat.visibilityEpoch }).then(function (reply)
    {
      if (reply && reply.error === "InspectionVisibilityChanged" && token === String(inspectionFloat.serial) && reply.result)
      {
        if (acceptInspectionEpoch(reply.result.visibilityEpoch))
        {
          setMemoryPanel(reply.result.visible === true, true);
        }
        return reply;
      }
      if ((!reply || !reply.ok) && !quiet && inspectionFloat.window &&
          token === String(inspectionFloat.serial) && visibility === inspectionFloat.visibilityToken)
      {
        workspaceFeedback("Inspection window: " + (reply && reply.error || "request failed"), true);
      }
      return reply;
    });
  }

  function acceptInspectionEpoch(epoch)
  {
    if (typeof epoch !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(epoch) ||
        BigInt(epoch) <= BigInt(inspectionFloat.visibilityEpoch))
    {
      return false;
    }
    inspectionFloat.visibilityEpoch = epoch;
    return true;
  }

  function focusMainWorkspace(target)
  {
    var independent = inspectionViews.map(function (view)
    {
      return inspectionPanels[view];
    }).find(function (item)
    {
      return !!item.window;
    });
    if (independent)
    {
      var interactionRevision = inspectionFloat.interaction;
      var independentToken = independent.token;
      var independentWindow = independent.window;
      independentInspectionControl(independent, "focus-main").then(function ()
      {
        if (target && target.focus && target.isConnected !== false && interactionRevision === inspectionFloat.interaction &&
            independent.token === independentToken && independent.window === independentWindow)
        {
          target.focus();
        }
      });
    }
    if (inspectionFloat.window)
    {
      var interaction = inspectionFloat.interaction;
      var token = String(inspectionFloat.serial);
      inspectionControl("focus-main", null, true).then(function ()
      {
        if (target && target.focus && target.isConnected !== false && token === String(inspectionFloat.serial) &&
            interaction === inspectionFloat.interaction)
        {
          target.focus();
        }
      });
    }
    if (target && target.focus)
    {
      target.focus();
    }
  }

  function suspendFloatingInspection()
  {
    clearInspectionDockGuides();
    suspendIndependentInspections();
    if (inspectionFloat.opening)
    {
      cancelInspectionFloat();
    }
    if (!inspectionFloat.window)
    {
      return;
    }
    inspectionFloat.suspended = true;
    uiElement("memory").inert = true;
    var token = String(inspectionFloat.serial);
    var visibility = ++inspectionFloat.visibilityToken;
    inspectionControl("hide", token, true).then(function (reply)
    {
      recoverFloatingInspection(reply, token, true, visibility);
    });
    focusMainWorkspace();
  }

  function recoverFloatingInspection(reply, token, suspended, visibility)
  {
    if ((reply && (reply.ok || reply.error === "InspectionVisibilityChanged")) || !inspectionFloat.window ||
        token !== String(inspectionFloat.serial) || visibility !== inspectionFloat.visibilityToken ||
        inspectionFloat.suspended !== suspended ||
        (!suspended && !state.memoryPanel.visible))
    {
      return false;
    }
    if (els.root.inert)
    {
      inspectionControl("focus-main", token, true);
    }
    dockInspection(!els.root.inert);
    workspaceFeedback("The floating inspection window could not be updated and was docked. Your view is retained.", true);
    return true;
  }

  function resumeFloatingInspection(target)
  {
    resumeIndependentInspections(target);
    if (!inspectionFloat.window || !inspectionFloat.suspended)
    {
      return;
    }
    inspectionFloat.suspended = false;
    uiElement("memory").inert = false;
    if (state.memoryPanel.visible)
    {
      var token = String(inspectionFloat.serial);
      var interaction = inspectionFloat.interaction;
      var visibility = ++inspectionFloat.visibilityToken;
      inspectionControl(uiView(target) === inspectionFloat.window ? "show" : "restore", token, true).then(function (reply)
      {
        if (recoverFloatingInspection(reply, token, false, visibility))
        {
          return;
        }
        if (target && target.focus && inspectionFloat.window && !inspectionFloat.suspended && !els.root.inert &&
            token === String(inspectionFloat.serial) && interaction === inspectionFloat.interaction &&
            visibility === inspectionFloat.visibilityToken)
        {
          target.focus();
        }
      });
    }
  }

  function inspectionViewport()
  {
    return Array.from(uiElement("memory").querySelectorAll("*")).map(function (node)
    {
      return [node, node.scrollTop, node.scrollLeft];
    });
  }

  function restoreInspectionViewport(saved)
  {
    saved.forEach(function (entry)
    {
      entry[0].scrollTop = entry[1];
      entry[0].scrollLeft = entry[2];
    });
    syncProcessViewport();
  }

  function createInspectionStatus(doc, item)
  {
    var status = doc.createElement("footer");
    status.className = "independent-inspection-status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-label", "Debugger status");
    item.chrome = {};
    ["state", "process", "pid", "session", "feedback"].forEach(function (part)
    {
      var node = doc.createElement("span");
      node.className = "inspection-status-" + part;
      status.appendChild(node);
      item.chrome[part] = node;
    });
    item.status = status;
    return status;
  }

  function updateFloatingInspectionStatus()
  {
    inspectionViews.map(function (view)
    {
      return inspectionPanels[view];
    }).concat([inspectionFloat]).forEach(function (item)
    {
      if (item.window && !item.window.closed && item.status)
      {
        var feedback = !uiElement("workspace-feedback").classList.contains("hidden") ? uiElement("workspace-feedback-text").textContent : "";
        var copy = !uiElement("copy-status").classList.contains("hidden") ? uiElement("copy-status").textContent : "";
        var status = state.sessionStatus;
        var mode = state.statusBusy ? "busy" : !state.statusKnown ? "unavailable" : !state.connected ? "disconnected" :
          status.stopped === false ? "running" : state.busy ? "working" : "stopped";
        var labels = { busy: "Debugger busy", unavailable: "Status unavailable", disconnected: "No session",
          running: "Running", working: "Working", stopped: "Stopped" };
        var values = { state: labels[mode], process: uiElement("current-process-image").textContent,
          pid: "PID " + uiElement("current-process-pid").textContent,
          session: state.connected ? status.sessionKind || ((status.kernelMode ? "kernel" : "user") + (status.dumpFile ? " dump" : " live")) : "",
          feedback: item === inspectionFloat ? "" : [feedback, copy].filter(Boolean).join(" / ") };
        Object.keys(values).forEach(function (part)
        {
          if (item.chrome[part].textContent !== values[part])
          {
            item.chrome[part].textContent = values[part];
          }
        });
        item.chrome.state.setAttribute("data-state", mode);
        item.chrome.process.title = values.process;
        item.chrome.session.title = els.status.textContent;
        setHidden(item.chrome.feedback, !values.feedback);
      }
    });
    var popup = inspectionFloat.window;
    if (!popup || popup.closed)
    {
      return;
    }
    var doc = popup.document;
    var feedback = doc.getElementById("floating-inspection-feedback");
    var messages = [];
    if (!uiElement("workspace-feedback").classList.contains("hidden"))
    {
      messages.push(uiElement("workspace-feedback-text").textContent);
    }
    if (!uiElement("copy-status").classList.contains("hidden"))
    {
      messages.push(uiElement("copy-status").textContent);
    }
    doc.getElementById("floating-inspection-feedback-text").textContent = messages.join("\n");
    setHidden(feedback, !messages.length);
  }

  function cancelInspectionFloat()
  {
    var popup = inspectionFloat.opening;
    if (!popup)
    {
      return;
    }
    var token = String(inspectionFloat.serial);
    inspectionFloat.opening = null;
    (inspectionFloat.serial = ++inspectionSerial);
    clearTimeout(inspectionFloat.timeout);
    inspectionFloat.timeout = null;
    try
    {
      popup.close();
    }
    catch (error)
    {
      // Native cleanup also handles a proxy whose controller is still pending.
    }
    inspectionControl("close", token, true);
    updateMemoryPanelLayout();
  }

  function dockInspection(reveal)
  {
    clearInspectionDockGuides();
    if (inspectionFloat.opening)
    {
      cancelInspectionFloat();
      return;
    }
    var popup = inspectionFloat.window;
    if (!popup)
    {
      return;
    }
    var token = String(inspectionFloat.serial);
    var saved = inspectionViewport();
    hideSuggest();
    closeCopyMenu(false);
    if (inspectionFloat.observer)
    {
      inspectionFloat.observer.disconnect();
      inspectionFloat.observer = null;
    }
    var panel = uiElement("memory");
    panel.inert = false;
    uiElement("workspace-split").appendChild(panel);
    els.root.appendChild(uiElement("cell-copy-menu"));
    uiElement("main").insertBefore(uiElement("copy-fallback"), uiElement("workspace-split"));
    inspectionFloat.documents.forEach(function (entry)
    {
      popup.document.removeEventListener(entry[0], entry[1], entry[2]);
    });
    inspectionFloat.windows.forEach(function (entry)
    {
      popup.removeEventListener(entry[0], entry[1], entry[2]);
    });
    inspectionFloat.window = null;
    inspectionFloat.status = inspectionFloat.chrome = null;
    inspectionFloat.suspended = false;
    (inspectionFloat.serial = ++inspectionSerial);
    if (reveal)
    {
      state.memoryPanel.visible = true;
    }
    inspectionFloat.nodes = Object.create(null);
    updateLayout();
    restoreInspectionViewport(saved);
    saveMemoryPanel();
    if (reveal)
    {
      inspectionControl("focus-main", token, true);
    }
    inspectionControl("close", token, true);
    if (reveal)
    {
      focusMainWorkspace(inspectionTab(state.memoryPanel.tab));
    }
    try
    {
      popup.close();
    }
    catch (error)
    {
      // The native host closes an already disconnected child controller.
    }
  }

  function floatInspection()
  {
    if (inspectionFloat.window)
    {
      dockInspection(true);
      return;
    }
    if (!state.ready || inspectionFloat.opening || els.root.inert || typeof window.open !== "function")
    {
      return;
    }
    endMemoryResize(false);
    hideSuggest();
    closeCopyMenu(false);
    var token = String((inspectionFloat.serial = ++inspectionSerial));
    inspectionFloat.visibilityEpoch = "0";
    var url = "about:blank#kndbgx-inspect-" + token;
    var popup;
    try
    {
      popup = window.open(url, "kndbgx-inspect", "popup,width=" + Math.max(360, state.memoryPanel.width) + ",height=720");
    }
    catch (error)
    {
      popup = null;
    }
    if (!popup)
    {
      workspaceFeedback("The inspection window could not be opened. The panel is still docked.", true);
      return;
    }
    inspectionFloat.opening = popup;
    updateMemoryPanelLayout();
    inspectionFloat.timeout = setTimeout(function ()
    {
      if (inspectionFloat.opening === popup)
      {
        cancelInspectionFloat();
        workspaceFeedback("The inspection window did not become ready. The panel is still docked.", true);
      }
    }, 8000);
    function prepare()
    {
      if (inspectionFloat.opening !== popup || token !== String(inspectionFloat.serial))
      {
        return;
      }
      try
      {
        if (popup.closed)
        {
          cancelInspectionFloat();
          return;
        }
        if (popup.location.href !== url || !popup.document.body || popup.document.readyState === "loading")
        {
          setTimeout(prepare, 25);
          return;
        }
        var doc = popup.document;
        doc.title = "KNDbgX - Inspect";
        doc.documentElement.lang = "en";
        doc.body.className = "inspection-floating inspection-group inspection-styled";
        var css = doc.createElement("link");
        css.rel = "stylesheet";
        css.href = new URL("/app.css", window.location.href).href;
        css.onerror = function ()
        {
          if (inspectionFloat.opening === popup)
          {
            cancelInspectionFloat();
            workspaceFeedback("Inspection window styles could not be loaded. The panel is still docked.", true);
          }
        };
        css.onload = function ()
        {
          if (inspectionFloat.opening !== popup || token !== String(inspectionFloat.serial) || popup.closed)
          {
            return;
          }
          try
          {
            clearTimeout(inspectionFloat.timeout);
            inspectionFloat.timeout = null;
            var saved = inspectionViewport();
            var panel = uiElement("memory");
            rememberInspectionNodes(panel);
            inspectionFloat.opening = null;
            inspectionFloat.window = popup;
            var status = createInspectionStatus(doc, inspectionFloat);
            status.id = "floating-inspection-status";
            var feedback = doc.createElement("div");
            feedback.id = "floating-inspection-feedback";
            feedback.className = "notice hidden";
            feedback.setAttribute("role", "status");
            var feedbackText = doc.createElement("span");
            feedbackText.id = "floating-inspection-feedback-text";
            var dismiss = doc.createElement("button");
            dismiss.textContent = "Dismiss";
            dismiss.className = "quiet notice-dismiss";
            dismiss.addEventListener("click", function ()
            {
              uiElement("btn-workspace-dismiss").click();
              setHidden(uiElement("copy-status"), true);
              clearTimeout(state.copyStatusTimer);
              uiElement(inspectionGrid(state.memoryPanel.tab)).focus();
            });
            feedback.appendChild(feedbackText);
            feedback.appendChild(dismiss);
            doc.body.appendChild(panel);
            doc.body.appendChild(feedback);
            doc.body.appendChild(status);
            inspectionFloat.documents.forEach(function (entry)
            {
              doc.addEventListener(entry[0], entry[1], entry[2]);
            });
            inspectionFloat.windows.forEach(function (entry)
            {
              popup.addEventListener(entry[0], entry[1], entry[2]);
            });
            popup.addEventListener("pagehide", function ()
            {
              if (inspectionFloat.window === popup)
              {
                dockInspection(false);
              }
            });
            if (typeof window.MutationObserver === "function")
            {
              inspectionFloat.observer = new MutationObserver(updateFloatingInspectionStatus);
              [els.status, uiElement("current-process-bar"), uiElement("workspace-feedback"), uiElement("copy-status")].forEach(function (node)
              {
                inspectionFloat.observer.observe(node, { subtree: true, childList: true, characterData: true, attributes: true });
              });
            }
            updateLayout();
            restoreInspectionViewport(saved);
            updateFloatingInspectionStatus();
            var visibility = ++inspectionFloat.visibilityToken;
            inspectionControl("show", token, true).then(function (reply)
            {
              recoverFloatingInspection(reply, token, false, visibility);
            });
            inspectionTab(state.memoryPanel.tab).focus();
          }
          catch (error)
          {
            if (inspectionFloat.window === popup)
            {
              dockInspection(true);
            }
            else
            {
              cancelInspectionFloat();
            }
            workspaceFeedback("The inspection window is unavailable. The panel is still docked.", true);
          }
        };
        doc.head.appendChild(css);
      }
      catch (error)
      {
        cancelInspectionFloat();
        workspaceFeedback("The inspection window is unavailable. The panel is still docked.", true);
      }
    }
    prepare();
  }

  function updateMemoryPanelLayout()
  {
    var panel = state.memoryPanel;
    var bounds = memoryPanelBounds();
    var memory = uiElement("memory");
    var splitter = uiElement("memory-splitter");
    var floating = !!inspectionFloat.window;
    var floatButton = uiElement("btn-inspection-float");
    floatButton.textContent = floating ? "Dock" : inspectionFloat.opening ? "Opening..." : "Float group";
    floatButton.title = floating ? "Return inspection to the main window" : "Move inspection to a separate window";
    floatButton.disabled = !state.ready || !!inspectionFloat.opening || typeof window.open !== "function";
    setHidden(uiElement("btn-inspection-dock"), !floating && !inspectionFloat.opening);
    updateIndependentInspectionLayout();
    updateWorkspaceWindows();
    panel.effectiveWidth = Math.round(Math.max(bounds.minimum, Math.min(bounds.maximum, panel.width)));
    panel.overlay = !floating && bounds.overlay;
    els.root.classList[panel.visible && !floating ? "add" : "remove"]("memory-open");
    els.root.classList[panel.visible && !floating && bounds.overlay ? "add" : "remove"]("memory-overlay");
    els.root.classList[panel.visible && !floating && (bounds.overlay || bounds.available - panel.effectiveWidth - 6 < 760) ? "add" : "remove"]("memory-compact");
    setHidden(memory, !panel.visible);
    setHidden(splitter, !panel.visible || floating);
    memory.style.width = floating ? "" : panel.effectiveWidth + "px";
    splitter.setAttribute("aria-valuemin", String(bounds.minimum));
    splitter.setAttribute("aria-valuemax", String(bounds.maximum));
    splitter.setAttribute("aria-valuenow", String(panel.effectiveWidth));
    splitter.setAttribute("aria-valuetext", panel.effectiveWidth + " pixels");
    var button = uiElement("btn-memory-panel");
    if (floating)
    {
      button.removeAttribute("aria-controls");
    }
    else
    {
      button.setAttribute("aria-controls", "memory");
    }
    button.setAttribute("aria-expanded", String(panel.visible));
    button.classList[panel.visible ? "add" : "remove"]("active");
    button.title = (panel.visible ? "Hide" : "Show") + (floating ? " floating inspection window" : " inspection panel") +
      " (Ctrl+M). Float views from Inspect; drag their title bars to dock.";
    positionInspectionOverlay();
    updateInspectorLayout();
    scheduleWorkspaceGeometry();
  }

  var workspaceGeometryPending = false;
  function scheduleWorkspaceGeometry()
  {
    if (workspaceGeometryPending || typeof window.requestAnimationFrame !== "function")
    {
      return;
    }
    workspaceGeometryPending = true;
    window.requestAnimationFrame(function ()
    {
      workspaceGeometryPending = false;
      positionInspectionOverlay();
      positionToolMenus();
    });
  }

  function positionInspectionOverlay()
  {
    var panel = state.memoryPanel;
    var memory = uiElement("memory");
    var splitter = uiElement("memory-splitter");
    var overlay = panel.visible && !inspectionFloat.window && panel.overlay;
    var top = "";
    var bottom = "";
    if (overlay)
    {
      var height = window.innerHeight || 720;
      var bar = uiElement("current-process-bar").getBoundingClientRect();
      var workspace = uiElement("workspace-split").getBoundingClientRect();
      var command = els.commandArea.getBoundingClientRect();
      top = Math.max(0, Math.min(height - 160, Math.max(bar.bottom, workspace.top)));
      bottom = Math.max(27, height - Math.max(top + 96, Math.min(height, command.top))) + "px";
      top += "px";
    }
    memory.style.top = splitter.style.top = top;
    memory.style.bottom = splitter.style.bottom = bottom;
    splitter.style.right = overlay ?
      "calc(" + panel.effectiveWidth + "px + var(--window-inset))" : "";
  }

  function saveMemoryPanel()
  {
    try
    {
      window.localStorage.setItem("kndbgx.memory-panel", JSON.stringify({ visible: state.memoryPanel.visible,
        width: state.memoryPanel.width, tab: state.memoryPanel.tab }));
    }
    catch (error)
    {
      // Panel controls remain available when preferences cannot be saved.
    }
  }

  function setMemoryPanelWidth(width, remember)
  {
    var bounds = memoryPanelBounds();
    state.memoryPanel.width = Math.round(Math.max(bounds.minimum, Math.min(bounds.maximum, width)));
    updateMemoryPanelLayout();
    syncTableViewport();
    syncProcessViewport();
    positionToolMenus();
    if (remember)
    {
      saveMemoryPanel();
    }
  }

  function endMemoryResize(cancelled)
  {
    var drag = state.memoryPanel.drag;
    if (!drag)
    {
      return;
    }
    state.memoryPanel.drag = null;
    els.root.classList.remove("memory-resizing");
    var splitter = uiElement("memory-splitter");
    if (typeof splitter.hasPointerCapture === "function" && splitter.hasPointerCapture(drag.pointerId))
    {
      splitter.releasePointerCapture(drag.pointerId);
    }
    if (cancelled)
    {
      state.memoryPanel.width = drag.previousWidth;
      updateMemoryPanelLayout();
      syncTableViewport();
      syncProcessViewport();
      positionToolMenus();
    }
    saveMemoryPanel();
  }

  function setMemoryPanel(visible, fromHost)
  {
    var visibility = ++inspectionFloat.visibilityToken;
    if (inspectionFloat.opening && !visible)
    {
      cancelInspectionFloat();
    }
    endMemoryResize(false);
    if (!visible)
    {
      hideSuggest();
      if (state.copyMenu && ["process-grid", "memory-grid", "disassembly-grid", "registers-grid"].indexOf(state.copyMenu.grid) >= 0)
      {
        closeCopyMenu(false);
        uiElement("btn-memory-panel").focus();
      }
      if (uiElement("memory").contains(uiActiveElement()) ||
          uiActiveElement() === uiElement("memory-splitter"))
      {
        uiElement("btn-memory-panel").focus();
      }
    }
    state.memoryPanel.visible = visible;
    updateLayout();
    updateMemorySummary();
    updateRegistersSummary();
    updateDisassemblySummary();
    saveMemoryPanel();
    if (inspectionFloat.window && !fromHost)
    {
      var token = String(inspectionFloat.serial);
      inspectionControl(visible && !inspectionFloat.suspended ? "show" : "hide", token).then(function (reply)
      {
        if ((!reply || !reply.ok) && inspectionFloat.window && token === String(inspectionFloat.serial) &&
            visibility === inspectionFloat.visibilityToken && state.memoryPanel.visible === visible)
        {
          state.memoryPanel.visible = !visible;
          updateLayout();
          saveMemoryPanel();
        }
      });
    }
    if (visible)
    {
      refreshStatus();
    }
  }

  uiElement("btn-memory-panel").addEventListener("click", function ()
  {
    setMemoryPanel(!state.memoryPanel.visible);
  });

  uiElement("btn-inspection-float").addEventListener("click", floatInspection);
  uiElement("btn-inspection-dock").addEventListener("click", function ()
  {
    dockInspection(true);
    inspectionViews.forEach(function (view)
    {
      dockInspectionView(view, true);
    });
  });

  function inspectionPanel(view)
  {
    return uiElement(view === "processes" ? "processes" : view + "-view");
  }

  function inspectionTab(view)
  {
    return uiElement(view === "memory" ? "tab-memory-view" : "tab-" + view);
  }

  function inspectionGrid(view)
  {
    return view === "processes" ? "process-grid" : view + "-grid";
  }

  function setInspectionTab(view)
  {
    if (inspectionViews.indexOf(view) < 0)
    {
      return;
    }
    closeCopyMenu();
    var previous = inspectionPanel(state.memoryPanel.tab);
    if (view !== state.memoryPanel.tab)
    {
      hideSuggest();
    }
    var restoreFocus = previous.contains(uiActiveElement());
    state.memoryPanel.tab = view;
    inspectionViews.forEach(function (name)
    {
      var tab = inspectionTab(name);
      tab.setAttribute("aria-selected", String(name === view));
      tab.tabIndex = name === view ? 0 : -1;
      setHidden(inspectionPanel(name), name !== view && !inspectionPanels[name].window);
    });
    if (restoreFocus)
    {
      inspectionTab(view).focus();
    }
    saveMemoryPanel();
    updateMemoryPanelLayout();
    if ((view === "processes" || view === "registers") && inspectionVisible(view))
    {
      renderProcessRows();
      if (state.ready && !state.busy)
      {
        refreshStatus();
      }
    }
  }

  inspectionViews.forEach(function (name, index)
  {
    var tab = inspectionTab(name);
    tab.addEventListener("click", function ()
    {
      setInspectionTab(name);
    });
    tab.addEventListener("keydown", function (event)
    {
      if (event.isComposing || event.altKey || event.ctrlKey || event.metaKey ||
          ["ArrowLeft", "ArrowRight", "Home", "End"].indexOf(event.key) < 0)
      {
        return;
      }
      event.preventDefault();
      var next = event.key === "Home" ? inspectionViews[0] : event.key === "End" ? inspectionViews[inspectionViews.length - 1] :
        inspectionViews[(index + (event.key === "ArrowLeft" ? -1 : 1) + inspectionViews.length) % inspectionViews.length];
      setInspectionTab(next);
      inspectionTab(next).focus();
    });
  });
  uiElement("btn-memory-close").addEventListener("click", function ()
  {
    setMemoryPanel(false);
  });
  uiElement("memory-splitter").addEventListener("pointerdown", function (event)
  {
    if (!state.memoryPanel.visible || state.memoryPanel.drag || state.columnDrag || state.inspectorPanel.drag || event.button !== 0 || event.isPrimary === false || !Number.isFinite(event.clientX))
    {
      return;
    }
    event.preventDefault();
    var splitter = uiElement("memory-splitter");
    splitter.focus({ preventScroll: true });
    if (typeof splitter.setPointerCapture === "function")
    {
      try
      {
        splitter.setPointerCapture(event.pointerId);
      }
      catch (error)
      {
        workspaceFeedback("Drag unavailable. Focus the divider and use Left/Right to resize the inspection panel.");
        return;
      }
    }
    state.memoryPanel.drag = { pointerId: event.pointerId, startX: event.clientX,
      startWidth: state.memoryPanel.effectiveWidth, previousWidth: state.memoryPanel.width };
    els.root.classList.add("memory-resizing");
  });
  uiElement("inspector-splitter").addEventListener("pointerdown", function (event)
  {
    if (!state.inspectorPanel.resizable || state.inspectorPanel.drag || state.memoryPanel.drag || state.columnDrag || state.resultTabDrag ||
        event.button !== 0 || event.isPrimary === false || !Number.isFinite(event.clientX))
    {
      return;
    }
    event.preventDefault();
    var splitter = uiElement("inspector-splitter");
    splitter.focus({ preventScroll: true });
    if (typeof splitter.setPointerCapture === "function")
    {
      try
      {
        splitter.setPointerCapture(event.pointerId);
      }
      catch (error)
      {
        workspaceFeedback("Drag unavailable. Focus the divider and use Left/Right to resize Row details.");
        return;
      }
    }
    state.inspectorPanel.drag = { pointerId: event.pointerId, startX: event.clientX,
      startWidth: state.inspectorPanel.effectiveWidth, previousWidth: state.inspectorPanel.width };
    els.root.classList.add("inspector-resizing");
  });
  uiElement("inspector-splitter").addEventListener("lostpointercapture", function ()
  {
    endInspectorResize(false);
  });
  uiElement("inspector-splitter").addEventListener("blur", function (event)
  {
    if (!event.relatedTarget && !inspectorPanelBounds().resizable)
    {
      uiElement("btn-inspector").focus();
    }
  });
  uiElement("inspector-splitter").addEventListener("dblclick", function (event)
  {
    if (state.inspectorPanel.resizable && event.button === 0)
    {
      event.preventDefault();
      endInspectorResize(false);
      setInspectorWidth(null, true);
    }
  });
  uiElement("inspector-splitter").addEventListener("keydown", function (event)
  {
    if (!state.inspectorPanel.resizable || state.inspectorPanel.drag || event.ctrlKey || event.altKey || event.metaKey || event.isComposing)
    {
      return;
    }
    if (["ArrowLeft", "ArrowRight", "Home", "End"].indexOf(event.key) >= 0)
    {
      event.preventDefault();
      var bounds = inspectorPanelBounds();
      var step = event.shiftKey ? 64 : 16;
      var width = event.key === "Home" ? bounds.minimum : event.key === "End" ? bounds.maximum :
        state.inspectorPanel.effectiveWidth + (event.key === "ArrowLeft" ? step : -step);
      setInspectorWidth(width, true);
    }
  });
  listenDocument("pointermove", function (event)
  {
    moveResultTabDrag(event);
    moveColumnResize(event);
    moveInspectorResize(event);
    var drag = state.memoryPanel.drag;
    if (drag && event.pointerId === drag.pointerId && Number.isFinite(event.clientX))
    {
      event.preventDefault();
      setMemoryPanelWidth(drag.startWidth + drag.startX - event.clientX, false);
    }
  });
  ["pointerup", "pointercancel"].forEach(function (name)
  {
    listenDocument(name, function (event)
    {
      if (state.resultTabDrag && event.pointerId === state.resultTabDrag.pointerId)
      {
        if (name === "pointerup")
        {
          moveResultTabDrag(event);
        }
        endResultTabDrag(name === "pointercancel");
      }
      if (state.columnDrag && event.pointerId === state.columnDrag.pointerId)
      {
        if (name === "pointerup")
        {
          moveColumnResize(event);
        }
        endColumnResize(name === "pointercancel");
      }
      if (state.memoryPanel.drag && event.pointerId === state.memoryPanel.drag.pointerId)
      {
        endMemoryResize(name === "pointercancel");
      }
      if (state.inspectorPanel.drag && event.pointerId === state.inspectorPanel.drag.pointerId)
      {
        if (name === "pointerup")
        {
          moveInspectorResize(event);
        }
        endInspectorResize(name === "pointercancel");
      }
    });
  });
  uiElement("memory-splitter").addEventListener("lostpointercapture", function ()
  {
    endMemoryResize(false);
  });
  uiElement("memory-splitter").addEventListener("keydown", function (event)
  {
    if (!state.memoryPanel.visible || event.ctrlKey || event.altKey || event.metaKey || event.isComposing)
    {
      return;
    }
    var bounds = memoryPanelBounds();
    var step = event.shiftKey ? 64 : 16;
    var width = event.key === "Home" ? bounds.minimum : event.key === "End" ? bounds.maximum :
      state.memoryPanel.effectiveWidth + (event.key === "ArrowLeft" ? step : event.key === "ArrowRight" ? -step : 0);
    if (["ArrowLeft", "ArrowRight", "Home", "End"].indexOf(event.key) >= 0)
    {
      event.preventDefault();
      setMemoryPanelWidth(width, true);
    }
  });
  listenWindow("blur", function ()
  {
    endColumnResize(false);
    endMemoryResize(false);
    endInspectorResize(false);
  });
  listenWindow("scroll", function ()
  {
    if (state.memoryPanel.visible && state.memoryPanel.overlay)
    {
      updateMemoryPanelLayout();
    }
  }, true);

  function updateLayout()
  {
    var libraryOverlay = isNarrow() || !state.libraryPinned && state.memoryPanel.visible &&
      !inspectionFloat.window && (window.innerWidth || 900) < 1500;
    var library = state.libraryVisible === null ? !libraryOverlay : state.libraryVisible;
    [["sidebar", library, "btn-sidebar"], ["console-wrap", state.consoleVisible, "btn-console"],
      ["inspector", state.inspectorVisible, "btn-inspector"]].forEach(function (panel)
    {
      var node = uiElement(panel[0]);
      if (!panel[1] && node.contains && node.contains(uiActiveElement()))
      {
        uiElement(panel[2]).focus();
      }
    });
    els.root.classList[library ? "remove" : "add"]("library-hidden");
    els.root.classList[library ? "add" : "remove"]("library-open");
    els.root.classList[libraryOverlay ? "add" : "remove"]("library-overlay");
    uiElement("sidebar").style.top = libraryOverlay ? uiElement("toolbar").getBoundingClientRect().bottom + "px" : "";
    uiElement("btn-library-pin").setAttribute("aria-pressed", String(state.libraryPinned));
    uiElement("btn-library-pin").title = state.libraryPinned ? "Unpin Library and restore adaptive placement" :
      "Keep Library beside Results. Narrow windows use an overlay.";
    uiElement("library-layout-status").textContent = libraryOverlay ? state.libraryPinned ? "Pinned / narrow overlay" : "Overlay" :
      state.libraryPinned ? "Pinned" : "Docked";
    els.root.classList[state.consoleVisible ? "remove" : "add"]("console-hidden");
    els.root.classList[state.inspectorVisible ? "remove" : "add"]("inspector-hidden");
    uiElement("btn-sidebar").setAttribute("aria-expanded", String(library));
    uiElement("btn-console").setAttribute("aria-expanded", String(state.consoleVisible));
    uiElement("btn-inspector").setAttribute("aria-expanded", String(state.inspectorVisible));
    updateMemoryPanelLayout();
    syncProcessViewport();
    positionToolMenus();
    showRows();
  }

  function toggleLibrary()
  {
    state.libraryVisible = uiElement("btn-sidebar").getAttribute("aria-expanded") !== "true";
    updateLayout();
    saveWorkspacePreferences();
    if (state.libraryVisible)
    {
      els.filter.focus();
    }
  }

  function toggleConsole()
  {
    state.consoleVisible = !state.consoleVisible;
    updateLayout();
    saveWorkspacePreferences();
  }

  function saveWorkspacePreferences()
  {
    try
    {
      window.localStorage.setItem("kndbgx.workspace-layout", JSON.stringify({ console: state.consoleVisible,
        details: state.inspectorVisible, library: state.libraryVisible, libraryPinned: state.libraryPinned, density: state.workspaceDensity }));
    }
    catch (error)
    {
      // The current document remains usable without persistent settings.
    }
  }

  function workspaceRowHeight()
  {
    return state.workspaceDensity === "comfortable" ? 34 : 28;
  }

  function applyWorkspaceDensity()
  {
    var roots = [els.root];
    if (inspectionFloat.window && inspectionFloat.window.document.body)
    {
      roots.push(inspectionFloat.window.document.body);
    }
    inspectionViews.forEach(function (view)
    {
      var item = inspectionPanels[view];
      if (item.window && item.window.document.body)
      {
        roots.push(item.window.document.body);
      }
    });
    roots.forEach(function (root)
    {
      root.classList[state.workspaceDensity === "comfortable" ? "add" : "remove"]("comfortable");
    });
    uiElement("workspace-density").value = state.workspaceDensity;
  }

  uiElement("workspace-density").addEventListener("change", function (event)
  {
    var previous = workspaceRowHeight();
    state.workspaceDensity = event.target.value === "comfortable" ? "comfortable" : "compact";
    applyWorkspaceDensity();
    var ratio = workspaceRowHeight() / previous;
    els.resultSpacer.style.height = state.rowCount * workspaceRowHeight() + "px";
    els.resultView.scrollTop *= ratio;
    uiElement("process-spacer").style.height = state.processes.filtered.length * workspaceRowHeight() + "px";
    uiElement("process-view").scrollTop *= ratio;
    renderProcessRows();
    state.rowOffset = -1;
    updateLayout();
    syncTableViewport();
    saveWorkspacePreferences();
  });

  function setRowDetails(visible)
  {
    state.inspectorVisible = visible;
    updateLayout();
    saveWorkspacePreferences();
  }

  function updateWorkspaceWindows()
  {
    applyWorkspaceDensity();
    var container = uiElement("workspace-windows");
    inspectionViews.forEach(function (view)
    {
      var item = inspectionPanels[view];
      var row = state.windowRows[view];
      if (!row)
      {
        row = state.windowRows[view] = {};
        row.node = document.createElement("div");
        row.node.className = "workspace-window";
        row.label = document.createElement("span");
        row.show = document.createElement("button");
        row.show.textContent = "Show";
        row.show.setAttribute("aria-label", "Show " + inspectionLabel(view));
        row.show.addEventListener("click", function ()
        {
          uiElement("workspace-layout").open = false;
          if (item.window)
          {
            independentInspectionControl(item, "show").then(function (reply)
            {
              if (!reply || !reply.ok)
              {
                workspaceFeedback("Could not show " + inspectionLabel(view) + ". Use Dock to return the view.", true);
              }
            });
          }
          else
          {
            setInspectionTab(view);
            setMemoryPanel(true);
            inspectionTab(view).focus();
          }
        });
        row.dock = document.createElement("button");
        row.dock.textContent = "Dock";
        row.dock.setAttribute("aria-label", "Dock " + inspectionLabel(view));
        row.dock.addEventListener("click", function ()
        {
          uiElement("workspace-layout").open = false;
          dockInspectionView(view, true);
        });
        row.node.appendChild(row.label);
        row.node.appendChild(row.show);
        row.node.appendChild(row.dock);
        container.appendChild(row.node);
      }
      row.label.textContent = inspectionLabel(view) + " / " + (item.opening ? "Opening" : item.window ? "Floating" :
        inspectionFloat.window ? "Inspect window" : state.memoryPanel.visible && state.memoryPanel.tab === view ? "Docked" : "Hidden tab");
      row.show.disabled = !state.ready || !!item.opening || !!inspectionFloat.opening || els.root.inert;
      row.dock.disabled = !item.window || !!item.opening || els.root.inert;
    });
    uiElement("btn-layout-dock-all").disabled = !state.ready || !!inspectionFloat.opening ||
      !inspectionFloat.window && !inspectionViews.some(function (view)
      {
        return !!inspectionPanels[view].window;
      });
    uiElement("btn-layout-recover").disabled = uiElement("btn-layout-dock-all").disabled;
  }

  uiElement("btn-layout-auto").addEventListener("click", function ()
  {
    state.libraryVisible = null;
    state.libraryPinned = false;
    state.consoleVisible = false;
    state.inspectorVisible = false;
    state.inspectorPanel.width = null;
    state.memoryPanel.width = 520;
    uiElement("workspace-layout").open = false;
    updateLayout();
    saveWorkspacePreferences();
    saveMemoryPanel();
    saveInspectorWidth();
    uiElement("workspace-layout-toggle").focus();
    workspaceFeedback("Adaptive layout restored. Captures and command drafts are unchanged.");
  });
  uiElement("btn-layout-dock-all").addEventListener("click", function ()
  {
    uiElement("workspace-layout").open = false;
    dockInspection(true);
    inspectionViews.forEach(function (view)
    {
      dockInspectionView(view, true);
    });
  });
  uiElement("btn-layout-recover").addEventListener("click", function ()
  {
    uiElement("workspace-layout").open = false;
    var requests = [];
    if (inspectionFloat.window)
    {
      state.memoryPanel.visible = true;
      requests.push(inspectionControl("recover"));
    }
    inspectionViews.forEach(function (view)
    {
      if (inspectionPanels[view].window)
      {
        requests.push(independentInspectionControl(inspectionPanels[view], "recover"));
      }
    });
    Promise.all(requests).then(function (replies)
    {
      updateLayout();
      workspaceFeedback(replies.every(function (reply)
      {
        return reply && reply.ok;
      }) ? "Inspection windows are on the current monitor." : "Some windows could not be moved. Use Dock all views to recover them.",
      replies.some(function (reply)
      {
        return !reply || !reply.ok;
      }));
    });
  });

  function applyConsoleOutput()
  {
    var button = uiElement("btn-console-output");
    button.textContent = state.consoleEnabled ? "Output On" : "Output Off";
    button.setAttribute("aria-checked", String(state.consoleEnabled));
  }

  function setConsoleOutput(enabled)
  {
    state.consoleEnabled = enabled;
    if (!state.consoleEnabled)
    {
      state.stopStream = true;
      ++state.consoleEpoch;
    }
    applyConsoleOutput();
    try
    {
      window.localStorage.setItem("kndbgx.console-output", state.consoleEnabled ? "on" : "off");
    }
    catch (error)
    {
      // The current document preference still applies if storage is unavailable.
    }
  }

  uiElement("btn-console-output").addEventListener("click", function ()
  {
    setConsoleOutput(!state.consoleEnabled);
    workspaceFeedback(state.consoleEnabled ? "Console output is on for subsequent commands." :
      "Console output is off. Use View output to read a saved result, or Export to save it.");
  });

  function viewResultOutput()
  {
    if (state.busy || !state.resultId || state.resultOutputLength === "0")
    {
      return;
    }
    invalidateResultLoad();
    state.busy = true;
    state.stopStream = false;
    setConsoleOutput(true);
    revealConsole();
    uiElement("result-info").open = false;
    setStatusBusy(true);
    phase("Streaming");
    appendLine("[saved output] " + state.resultCommand);
    pullOutput(state.resultId, "0").then(finishRequest, function (error)
    {
      appendLine("[output] " + error.message, "t-error");
      finishRequest();
    });
  }

  ["btn-empty-output", "btn-result-output"].forEach(function (id)
  {
    uiElement(id).addEventListener("click", viewResultOutput);
  });
  uiElement("result-info").addEventListener("keydown", function (event)
  {
    if (event.key === "Escape")
    {
      event.preventDefault();
      uiElement("result-info").open = false;
      uiElement("result-info-toggle").focus();
    }
  });
  var resultMenus = [["result-open", "result-open-toggle", "result-open-popover"],
    ["result-info", "result-info-toggle", "result-info-popover"], ["result-columns", "columns-toggle", "column-popover"],
    ["address-navigation", "address-navigation-toggle", "address-navigation-popover"],
    ["workspace-layout", "workspace-layout-toggle", "workspace-layout-popover"],
    ["breakpoint-create", "breakpoint-create-toggle", "breakpoint-create-popover"]];

  function closeToolMenus(inside)
  {
    (resultMenus || []).forEach(function (ids)
    {
      var menu = uiElement(ids[0]);
      if (menu.open && (!inside || !menu.contains(inside)))
      {
        menu.open = false;
      }
    });
  }

  resultMenus.forEach(function (ids)
  {
    var menu = uiElement(ids[0]);
    menu.addEventListener("toggle", positionToolMenus);
    menu.addEventListener("keydown", function (event)
    {
      if (event.key === "Escape" && menu.open)
      {
        event.preventDefault();
        menu.open = false;
        uiElement(ids[1]).focus();
      }
    });
    uiElement(ids[1]).addEventListener("click", function (event)
    {
      event.preventDefault();
      var open = !menu.open;
      if (open)
      {
        closeToolMenus(menu);
        if (state.contextView.open)
        {
          setContextOpen(false);
        }
        if (state.operations.open)
        {
          setOperationsOpen(false);
        }
      }
      menu.open = open;
      positionToolMenus();
    });
  });

  function openPalette()
  {
    if (state.busy || debuggerBusy() || !els.modalBackdrop.classList.contains("hidden"))
    {
      return;
    }
    state.paletteRestoreFocus = uiActiveElement() || els.prompt;
    els.paletteInput.value = "";
    state.paletteComposing = false;
    hideSuggest();
    suspendFloatingInspection();
    els.root.inert = true;
    els.paletteBackdrop.setAttribute("aria-hidden", "false");
    setHidden(els.paletteBackdrop, false);
    renderPalette();
    els.paletteInput.focus();
  }

  function closePalette(restore)
  {
    setHidden(els.paletteBackdrop, true);
    els.paletteBackdrop.setAttribute("aria-hidden", "true");
    els.root.inert = false;
    resumeFloatingInspection(restore ? state.paletteRestoreFocus : null);
    if (restore)
    {
      (state.paletteRestoreFocus || els.prompt).focus();
    }
  }

  function renderPalette()
  {
    var query = els.paletteInput.value.trim();
    var items = [];
    var seen = Object.create(null);
    state.history.slice().reverse().forEach(function (command)
    {
      if (items.length < 8 && !seen[command] && commandMatches(query, command, "Recent input"))
      {
        seen[command] = true;
        items.push({ command: command, synopsis: "Recent input / insert to edit", support: "Recent" });
      }
    });
    Object.keys(state.commandsByName).sort().forEach(function (name)
    {
      var cmd = state.commandsByName[name];
      if (!seen[name] && commandMatches(query, name, (cmd.grammar || "") + " " + cmd.synopsis))
      {
        items.push({ command: name, synopsis: (cmd.grammar ? cmd.grammar + " / " : "") + cmd.synopsis, support: cmd.support });
      }
    });
    if (query)
    {
      var needle = query.toLowerCase();
      function rank(item)
      {
        var command = item.command.toLowerCase();
        if (command === needle)
        {
          return 0;
        }
        if (firstToken(command) === needle)
        {
          return 1;
        }
        if (command.indexOf(needle) === 0)
        {
          return 2;
        }
        return command.indexOf(needle) >= 0 ? 3 : 4;
      }
      // Stable sorting retains recent-input order within each match strength.
      items.sort(function (left, right)
      {
        return rank(left) - rank(right);
      });
    }
    state.paletteItems = items.slice(0, 40);
    state.paletteActive = 0;
    els.paletteResults.textContent = "";
    uiElement("palette-count").textContent = !items.length ? "No matches. Try a command name or argument." :
      items.length + " matches" + (items.length > 40 ? " / showing the first 40; type to narrow" : "");
    state.paletteItems.forEach(function (item, index)
    {
      var entry = document.createElement("button");
      entry.className = "palette-item";
      entry.id = "palette-option-" + index;
      entry.tabIndex = -1;
      entry.setAttribute("role", "option");
      var name = document.createElement("span");
      name.className = "name";
      name.textContent = item.command;
      var hint = document.createElement("span");
      hint.className = "hint";
      hint.textContent = item.synopsis;
      var support = document.createElement("span");
      support.className = "support tag-" + item.support;
      support.textContent = item.support;
      entry.appendChild(support);
      entry.appendChild(name);
      entry.appendChild(hint);
      entry.addEventListener("click", function ()
      {
        choosePalette(index);
      });
      els.paletteResults.appendChild(entry);
    });
    updatePaletteSelection();
  }

  function updatePaletteSelection()
  {
    Array.prototype.forEach.call(els.paletteResults.children, function (entry, index)
    {
      var selected = index === state.paletteActive;
      entry.className = "palette-item" + (selected ? " active" : "");
      entry.setAttribute("aria-selected", String(selected));
      if (selected && entry.scrollIntoView)
      {
        entry.scrollIntoView({ block: "nearest" });
      }
    });
    els.paletteInput.setAttribute("aria-activedescendant", state.paletteItems.length ? "palette-option-" + state.paletteActive : "");
  }

  function choosePalette(index)
  {
    if (debuggerBusy() || state.paletteComposing || !state.paletteItems[index])
    {
      return;
    }
    var command = state.paletteItems[index].command;
    closePalette(false);
    draftCommand(command);
  }

  function updateInputUI()
  {
    renderContextDetails();
    updateResultScreens();
    var waiting = debuggerBusy();
    els.prompt.disabled = !state.ready || waiting;
    if (waiting || state.busy || state.suggestContext && state.suggestContext.stampKey !== processStampKey(state.target) ||
      state.addressCompletions.some(function (editor)
      {
        return editor.context && !symbolJobCurrent(editor.context);
      }))
    {
      hideSuggest();
    }
    updateCommandActivity();
    var command = els.prompt.value.trim();
    if (!state.composing)
    {
      selectCommand(command);
    }
    var spec = state.commandsByName[firstToken(command).toLowerCase()];
    uiElement("command-hint").textContent = waiting ?
      (!state.statusKnown && !state.statusBusy ? "Waiting for target status / Refresh context to retry" :
        "Debugger busy / Break the target in WinDbgX to enter commands") : spec ?
      (spec.grammar ? spec.grammar + " / " : "") + spec.synopsis + " / " + spec.support :
      "KNDbgX or WinDbg command / Enter to run / Tab to complete / help ui for workspace help";
    if (!waiting && command)
    {
      var routeName = command.split(/[\s;{}]/)[0].replace(/^"|"$/g, "").toLowerCase();
      var routeSpec = state.commandsByName[routeName] || (command[0] === "?" && command[1] !== "?" ? state.commandsByName["?"] : null);
      var route = command[0] === ":" ? "Workspace shortcut" : !state.groups.length ? "Route unconfirmed" :
        routeSpec ? (routeSpec.implementation === "host" ? "KNDbgX / engine command" : "KNDbgX") : "WinDbg direct / effects not classified";
      if (routeSpec && routeSpec.requiresPreview === true)
      {
        route += " / Change preview required";
      }
      else if (routeSpec && routeSpec.changesContext === true)
      {
        route += " / Changes debugger context";
      }
      if (routeSpec && routeSpec.support === "Unsupported")
      {
        route += " / Unsupported";
      }
      if (routeSpec && state.statusKnown && state.connected &&
          (routeSpec.modes === "KernelDump" && !state.sessionStatus.dumpFile ||
           routeSpec.modes === "LiveKernel" && state.sessionStatus.dumpFile ||
           routeSpec.modes === "LiveKernelLocal" && !state.sessionStatus.localKernel))
      {
        route += " / Unavailable for this target mode";
      }
      uiElement("command-hint").textContent = route + " / " + uiElement("command-hint").textContent;
    }
    var fields = parameterFields();
    if (!waiting && fields.length)
    {
      uiElement("command-hint").textContent += " / Replace <...> parameters / Tab: next parameter";
    }
    els.btnRun.disabled = !state.ready || state.busy || waiting || !command || state.composing || fields.length > 0;
    uiElement("kernel-workflow").disabled = !state.ready || state.busy || waiting;
    uiElement("btn-palette").disabled = !state.ready || state.busy || waiting;
    uiElement("btn-empty-command").disabled = !state.ready || state.busy || waiting;
    ["processes", "ip", "stack"].forEach(function (name)
    {
      uiElement("btn-empty-" + name).disabled = !state.ready || state.busy || waiting || !state.connected || !state.sessionStatus.stopped;
    });
    updateRegistersSummary();
    updateFloatingInspectionStatus();
    ["stack", "breakpoints", "event", "back", "forward", "bookmark", "bookmarks"].forEach(function (view)
    {
      uiElement("btn-" + view).disabled = !state.ready || state.busy || waiting;
    });
    uiElement("btn-breakpoint-event").disabled = !state.ready || state.busy || waiting || !state.connected || !state.sessionStatus.stopped;
    state.operations.actions.forEach(function (button)
    {
      button.disabled = !state.ready || state.busy;
    });
  }

  function loadResult(id, restore)
  {
    if (state.busy || !state.ready)
    {
      return;
    }
    if (!id)
    {
      uiElement("result-load-status").textContent = "Enter a stored result ID.";
      return;
    }
    if (!resultTabRoom(id))
    {
      return;
    }
    var token = invalidateResultLoad();
    state.resultLoadId = id;
    var selectionRevision = state.commandSelectionRevision;
    uiElement("result-load-status").textContent = "Opening result...";
    send("resultInfo", { resultId: id }).then(function (reply)
    {
      if (token !== state.resultLoadToken)
      {
        return;
      }
      state.resultLoadId = "";
      if (reply && reply.ok && reply.result && reply.result.resultId === id)
      {
        selectResult(reply.result, restore && restore.collection, selectionRevision, "results", restore);
        closeResultOpen(true);
        uiElement("result-load-status").textContent = "";
      }
      else
      {
        uiElement("result-load-status").textContent = "Result expired or unavailable. Check Operations or saved exports; the previous selection is retained.";
        state.resultLoadError = "Result expired or unavailable. The previous selection is still shown.";
        updateEvidenceSummary();
        appendLine("Result expired or unavailable", "t-error");
        els.resultHistory.value = state.resultId;
      }
    });
  }

  function closeResultOpen(focusResults)
  {
    var popover = uiElement("result-open");
    var restore = popover.contains && popover.contains(uiActiveElement());
    popover.open = false;
    if (restore)
    {
      uiElement(focusResults ? "result-table" : "result-open-toggle").focus();
    }
  }

  // ---------- suggestions ----------

  function acceptedSymbolCurrent(value)
  {
    var accepted = state.symbolCompletion.accepted;
    return accepted && accepted.value === value && accepted.cursor === els.prompt.selectionStart &&
      accepted.cursor === els.prompt.selectionEnd && accepted.stampKey === processStampKey(state.target);
  }

  function symbolCompletionContext(value)
  {
    var cursor = typeof els.prompt.selectionStart === "number" ? els.prompt.selectionStart : value.length;
    if (acceptedSymbolCurrent(value) || value.length > 32768 || !state.connected || !state.ready || state.busy || debuggerBusy() || state.composing || cursor !== els.prompt.selectionEnd ||
      cursor > 4096 || cursor < 1 || cursor < value.length && !/\s/.test(value[cursor]))
    {
      return null;
    }
    var prefix = value.slice(0, cursor);
    if (/[";{}\r\n\0]/.test(prefix) || /\s$/.test(prefix))
    {
      return null;
    }
    var words = prefix.trimStart().split(/\s+/);
    var word = words[words.length - 1];
    var command = words[0].toLowerCase();
    var spec = state.commandsByName[command];
    // Physical flags can follow the operand being completed; quoted paths are data.
    var unquoted = value.replace(/"(?:\\.|[^"\\])*"/g, '""');
    if (/(?:^|\s)\/phys(?:\s|$)/i.test(unquoted))
    {
      return null;
    }
    var operands = spec && Array.isArray(spec.symbolParameters) ? spec.symbolParameters :
      ["bp", "bu", "bm"].indexOf(command) >= 0 ? [0] : [];
    if (words.length < 2 || !/^[A-Za-z_.$][A-Za-z0-9_.$?@:]*(![A-Za-z0-9_.$?@:]*)?$/.test(word) || word.length > 512)
    {
      return null;
    }
    var operand = 0;
    var options = spec && Array.isArray(spec.completionOptions) ? spec.completionOptions : [];
    for (var i = 1; i + 1 < words.length; ++i)
    {
      var option = options.find(function (entry)
      {
        return entry && typeof entry.name === "string" && entry.name.toLowerCase() === words[i].toLowerCase();
      });
      if (option)
      {
        if (option.name.toLowerCase() === "/phys" || option.takesValue && ++i + 1 >= words.length)
        {
          return null;
        }
      }
      else
      {
        ++operand;
      }
    }
    if (operands.indexOf(operand) < 0 || command === "navigate" && words[1] === "pa")
    {
      return null;
    }
    return { value: value, cursor: cursor, prefix: prefix, word: word, head: prefix.slice(0, prefix.length - word.length) };
  }

  function symbolJobCurrent(job)
  {
    var input = job && job.editor ? job.editor.input : els.prompt;
    return job && job.token === state.suggestToken && job.value === input.value &&
      job.cursor === input.selectionStart && job.cursor === input.selectionEnd && !input.disabled &&
      job.stampKey === processStampKey(state.target) && uiActiveElement() === input && !document.hidden &&
      state.ready && state.connected && !state.busy && !debuggerBusy() &&
      (job.editor ? !job.editor.composing && addressCompletionAvailable(job.editor) : !state.composing);
  }

  function startSymbolCompletion()
  {
    var completion = state.symbolCompletion;
    var job = completion.queued;
    if (completion.active || !symbolJobCurrent(job))
    {
      return;
    }
    completion.queued = null;
    completion.active = job;
    // Optional reads do not take ownership of command activity or its recovery loop.
    send("completeSymbols", { prefix: job.prefix, suffix: job.querySuffix === undefined ? job.value.slice(job.cursor) : job.querySuffix,
      expectedStamp: job.stamp }).then(function (reply)
    {
      completion.active = null;
      if (symbolJobCurrent(job))
      {
        var items = reply && reply.ok && reply.result && processStampKey(reply.result.target) === job.stampKey &&
          Array.isArray(reply.result.items) ? reply.result.items : [];
        var details = items.filter(function (item)
        {
          if (!item || typeof item.symbol !== "string" || item.symbol.length > 512 ||
            job.head.length + item.symbol.length + job.value.length - job.cursor > (job.editor ? 32765 : 32768) ||
            !/^[A-Za-z_.$][A-Za-z0-9_.$?@:]*(![A-Za-z0-9_.$?@:]*)?$/.test(item.symbol) ||
            typeof item.address !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(item.address) || ["module", "symbol"].indexOf(item.kind) < 0)
          {
            return false;
          }
          var word = job.word.indexOf("!") >= 0 || item.kind === "module" ? item.symbol : item.symbol.split("!").pop();
          return word.toLowerCase().indexOf(job.word.toLowerCase()) === 0;
        }).slice(0, 24);
        if (job.editor)
        {
          if (details.length)
          {
            showAddressSuggest(job.editor, details, job);
            if (job.accept)
            {
              acceptAddressSuggestion(job.editor, 0);
            }
          }
          else
          {
            job.editor.accepted = { value: job.value, cursor: job.cursor, stampKey: job.stampKey };
          }
        }
        else if (details.length)
        {
          showSuggest(details.map(function (item)
          {
            return job.head + item.symbol + job.value.slice(job.cursor);
          }), "", details, job);
          if (job.accept)
          {
            acceptSuggestion(0);
          }
        }
        else if (job.template)
        {
          showSuggest([job.template], job.template);
          if (job.accept)
          {
            acceptSuggestion(0);
          }
        }
      }
      if (completion.queued && completion.timer === null)
      {
        startSymbolCompletion();
      }
    });
  }

  function queueSymbolCompletion(job, template, acceptFirst)
  {
    var completion = state.symbolCompletion;
    job.token = state.suggestToken;
    job.stamp = JSON.parse(JSON.stringify(state.target));
    job.stampKey = processStampKey(job.stamp);
    job.template = template;
    job.accept = acceptFirst === true;
    if (completion.active && completion.active.editor === job.editor && completion.active.prefix === job.prefix &&
      completion.active.value === job.value && completion.active.cursor === job.cursor &&
      completion.active.stampKey === job.stampKey)
    {
      completion.active.token = job.token;
      completion.active.accept = job.accept;
      return;
    }
    completion.queued = job;
    if (job.accept)
    {
      startSymbolCompletion();
    }
    else
    {
      completion.timer = setTimeout(function ()
      {
        completion.timer = null;
        startSymbolCompletion();
      }, 180);
    }
  }

  function addressCompletionAvailable(editor)
  {
    return inspectionVisible(editor.view) &&
      (editor.view !== "memory" || uiElement("memory-space").value === "virtual");
  }

  function addressCompletionAccepted(editor)
  {
    var accepted = editor.accepted;
    return accepted && accepted.value === editor.input.value && accepted.cursor === editor.input.selectionStart &&
      accepted.cursor === editor.input.selectionEnd && accepted.stampKey === processStampKey(state.target);
  }

  function addressCompletionContext(editor)
  {
    var input = editor.input;
    var value = input.value;
    var cursor = input.selectionStart;
    if (!addressCompletionAvailable(editor) || addressCompletionAccepted(editor) || !state.ready || !state.connected ||
      state.busy || debuggerBusy() || input.disabled || editor.composing || value.length > 32765 ||
      cursor !== input.selectionEnd || cursor < 1 || cursor > 4094 || /[";{}\r\n\0]/.test(value) ||
      cursor < value.length && !/[\s+\-*/&|^]/.test(value[cursor]))
    {
      return null;
    }
    var prefix = value.slice(0, cursor);
    var word = prefix.trimStart();
    if (word.length > 512 || !/^[A-Za-z_.$][A-Za-z0-9_.$?@:]*(![A-Za-z0-9_.$?@:]*)?$/.test(word))
    {
      return null;
    }
    var suffix = value.slice(cursor);
    return { editor: editor, value: value, cursor: cursor, prefix: "u " + prefix, word: word,
      head: prefix.slice(0, prefix.length - word.length), querySuffix: suffix && !/^\s/.test(suffix) ? " " + suffix : suffix };
  }

  function renderAddressGhost(editor)
  {
    var input = editor.input;
    var candidate = editor.items[editor.active];
    var visible = editor.context && symbolJobCurrent(editor.context) && typeof candidate === "string" &&
      input.selectionStart === input.value.length && candidate.length > input.value.length &&
      candidate.toLowerCase().indexOf(input.value.toLowerCase()) === 0;
    setHidden(editor.ghost, !visible);
    editor.ghostPrefix.textContent = visible ? input.value : "";
    editor.ghostSuffix.textContent = visible ? candidate.slice(input.value.length) : "";
    editor.ghostText.style.transform = "translateX(" + -(input.scrollLeft || 0) + "px)";
  }

  function showAddressSuggest(editor, details, job)
  {
    editor.context = job;
    editor.active = 0;
    editor.items = details.map(function (item)
    {
      return job.head + item.symbol + job.value.slice(job.cursor);
    });
    editor.list.textContent = "";
    details.forEach(function (detail, index)
    {
      var item = document.createElement("div");
      item.className = "suggest-item" + (index === 0 ? " active" : "");
      item.id = editor.view + "-symbol-option-" + index;
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", String(index === 0));
      item.textContent = detail.symbol;
      var address = document.createElement("span");
      address.className = "suggest-address";
      address.textContent = detail.address;
      item.appendChild(address);
      item.addEventListener("mousedown", function (event)
      {
        if (event.button !== 0)
        {
          return;
        }
        event.preventDefault();
        acceptAddressSuggestion(editor, index);
      });
      editor.list.appendChild(item);
    });
    setHidden(editor.list, false);
    editor.input.setAttribute("aria-expanded", "true");
    editor.input.setAttribute("aria-activedescendant", editor.view + "-symbol-option-0");
    renderAddressGhost(editor);
  }

  function acceptAddressSuggestion(editor, index)
  {
    var context = editor.context;
    if (!symbolJobCurrent(context) || index < 0 || index >= editor.items.length)
    {
      hideSuggest();
      return;
    }
    var candidate = editor.items[index];
    var cursor = candidate.length - (context.value.length - context.cursor);
    editor.input.value = candidate;
    hideSuggest();
    editor.input.setSelectionRange(cursor, cursor);
    editor.accepted = { value: candidate, cursor: cursor, stampKey: context.stampKey };
    editor.input.scrollIntoView({ block: "nearest", inline: "nearest" });
    if (editor.view === "memory")
    {
      updateMemoryActions();
    }
    else
    {
      setDisassemblyFollow(false);
      updateDisassemblyActions();
    }
  }

  function updateAddressSuggest(editor, acceptFirst)
  {
    hideSuggest();
    var job = addressCompletionContext(editor);
    if (!job || uiActiveElement() !== editor.input || document.hidden)
    {
      return false;
    }
    queueSymbolCompletion(job, "", acceptFirst);
    return true;
  }

  function bindAddressCompletion(view)
  {
    var editor = { view: view, input: uiElement(view + "-address"),
      list: uiElement(view + "-symbol-suggest"), ghost: uiElement(view + "-address-ghost"),
      ghostText: uiElement(view + "-address-ghost-text"),
      ghostPrefix: uiElement(view + "-address-ghost-prefix"),
      ghostSuffix: uiElement(view + "-address-ghost-suffix"),
      items: [], active: -1, context: null, accepted: null, composing: false };
    state.addressCompletions.push(editor);
    editor.input.addEventListener("input", function ()
    {
      editor.accepted = null;
      updateAddressSuggest(editor);
    });
    ["focus", "click"].forEach(function (name)
    {
      editor.input.addEventListener(name, function ()
      {
        editor.accepted = null;
        updateAddressSuggest(editor);
      });
    });
    editor.input.addEventListener("blur", function ()
    {
      editor.composing = false;
      hideSuggest();
    });
    editor.input.addEventListener("scroll", function ()
    {
      renderAddressGhost(editor);
    });
    editor.input.addEventListener("compositionstart", function ()
    {
      editor.composing = true;
      hideSuggest();
    });
    editor.input.addEventListener("compositionend", function ()
    {
      editor.composing = false;
      updateAddressSuggest(editor);
    });
    editor.input.addEventListener("select", function ()
    {
      if (editor.input.selectionStart !== editor.input.selectionEnd)
      {
        hideSuggest();
      }
    });
    editor.input.addEventListener("keyup", function (event)
    {
      if (["ArrowLeft", "ArrowRight", "Home", "End"].indexOf(event.key) >= 0 && !event.isComposing && !editor.composing)
      {
        updateAddressSuggest(editor);
      }
    });
    editor.input.addEventListener("keydown", function (event)
    {
      if (state.busy || debuggerBusy() || editor.composing || event.isComposing || event.keyCode === 229)
      {
        return;
      }
      if (event.key === "Enter")
      {
        event.preventDefault();
        hideSuggest();
        if (view === "memory")
        {
          readMemory();
        }
        else
        {
          readDisassembly();
        }
        return;
      }
      var visible = !editor.list.classList.contains("hidden");
      if (event.key === "Tab" && !event.shiftKey && !event.ctrlKey && !event.altKey && !event.metaKey)
      {
        if (visible)
        {
          event.preventDefault();
          acceptAddressSuggestion(editor, editor.active);
        }
        else if (updateAddressSuggest(editor, true))
        {
          event.preventDefault();
        }
      }
      else if (visible && ["ArrowUp", "ArrowDown"].indexOf(event.key) >= 0 && !event.ctrlKey && !event.altKey && !event.metaKey)
      {
        event.preventDefault();
        editor.active = (editor.active + (event.key === "ArrowDown" ? 1 : -1) + editor.items.length) % editor.items.length;
        Array.prototype.forEach.call(editor.list.children, function (item, index)
        {
          item.className = "suggest-item" + (index === editor.active ? " active" : "");
          item.setAttribute("aria-selected", String(index === editor.active));
          if (index === editor.active)
          {
            item.scrollIntoView({ block: "nearest" });
          }
        });
        editor.input.setAttribute("aria-activedescendant", view + "-symbol-option-" + editor.active);
        renderAddressGhost(editor);
      }
      else if (["ArrowLeft", "ArrowRight", "Home", "End", "Escape"].indexOf(event.key) >= 0)
      {
        hideSuggest();
      }
    });
  }

  ["memory", "disassembly"].forEach(bindAddressCompletion);
  ["input", "change"].forEach(function (name)
  {
    uiElement("memory-space").addEventListener(name, hideSuggest);
  });

  function parameterSuggestion(value)
  {
    if (value.length > 32768 || /[";{}\r\n\0]/.test(value))
    {
      return "";
    }
    var spec = state.commandsByName[firstToken(value).toLowerCase()];
    if (!spec || typeof spec.grammar !== "string")
    {
      return "";
    }
    var required = spec.grammar.slice(firstToken(spec.grammar).length).split("[")[0].trim().split(/\s+/).filter(Boolean);
    var tail = value.trimStart().slice(firstToken(value).length);
    var entered = tail.trim().split(/\s+/).filter(Boolean);
    if (!required.length || entered.length > required.length || entered.some(function (argument)
    {
      return argument[0] === "/";
    }))
    {
      return "";
    }
    var candidate = value;
    for (var i = 0; i < entered.length; ++i)
    {
      if (required[i].indexOf("<") >= 0)
      {
        continue;
      }
      var choices = required[i].split("|");
      var word = entered[i];
      if (choices.some(function (choice)
      {
        return choice === word;
      }))
      {
        continue;
      }
      var choice = choices.find(function (part)
      {
        return part.indexOf(word) === 0;
      });
      if (!choice || i !== entered.length - 1 || /\s$/.test(value))
      {
        return "";
      }
      candidate += choice.slice(entered[i].length);
    }
    for (var next = entered.length; next < required.length; ++next)
    {
      candidate += (/\s$/.test(candidate) ? "" : " ") +
        (required[next].indexOf("<") >= 0 ? required[next] : required[next].split("|")[0]);
    }
    return candidate.length > value.length && candidate.length <= 32768 ? candidate : "";
  }

  function parameterFields()
  {
    var draft = state.parameterDraft;
    if (!draft || firstToken(els.prompt.value).toLowerCase() !== draft.command)
    {
      state.parameterDraft = null;
      return [];
    }
    var fields = [];
    var pattern = /<[^<>]+>/g;
    var match;
    while ((match = pattern.exec(els.prompt.value)))
    {
      if (draft.markers.indexOf(match[0]) >= 0)
      {
        fields.push({ start: match.index, end: match.index + match[0].length });
      }
    }
    return fields;
  }

  function selectParameter(field)
  {
    hideSuggest();
    els.prompt.focus();
    if (typeof els.prompt.setSelectionRange === "function")
    {
      els.prompt.setSelectionRange(field.start, field.end);
    }
    updateInputUI();
  }

  function renderPromptGhost()
  {
    var value = els.prompt.value;
    var candidate = state.suggestItems[state.suggestActive];
    var visible = !state.busy && !debuggerBusy() && !state.composing && uiActiveElement() === els.prompt &&
      state.suggestInput === value && typeof candidate === "string" && candidate.length > value.length &&
      candidate.toLowerCase().indexOf(value.toLowerCase()) === 0 &&
      (typeof els.prompt.selectionStart !== "number" || els.prompt.selectionStart === value.length && els.prompt.selectionEnd === value.length);
    setHidden(els.promptGhost, !visible);
    els.promptGhostPrefix.textContent = visible ? value : "";
    els.promptGhostSuffix.textContent = visible ? candidate.slice(value.length) : "";
    els.promptGhostText.style.transform = "translateX(" + -(els.prompt.scrollLeft || 0) + "px)";
  }

  function updateSuggest(acceptFirst)
  {
    updateInputUI();
    var value = els.prompt.value;
    hideSuggest();

    if (!value.trim() || state.composing || state.busy || debuggerBusy())
    {
      return false;
    }

    var template = parameterSuggestion(value);
    var symbolContext = symbolCompletionContext(value);
    if (symbolContext)
    {
      queueSymbolCompletion(symbolContext, symbolContext.cursor === value.length ? template : "", acceptFirst);
      return true;
    }
    if (typeof els.prompt.selectionStart === "number" &&
      (els.prompt.selectionStart !== value.length || els.prompt.selectionEnd !== value.length))
    {
      return false;
    }

    if (template)
    {
      showSuggest([template], template);
      if (acceptFirst === true)
      {
        acceptSuggestion(0);
      }
      return true;
    }

    if (/\s/.test(value.trimStart()))
    {
      if (!state.commandsByName[firstToken(value).toLowerCase()])
      {
        return false;
      }
      var token = state.suggestToken;
      send("complete", { prefix: value }).then(function (reply)
      {
        if (token !== state.suggestToken || els.prompt.value !== value || state.composing || state.busy || debuggerBusy() ||
          uiActiveElement() !== els.prompt ||
          (typeof els.prompt.selectionStart === "number" &&
            (els.prompt.selectionStart !== value.length || els.prompt.selectionEnd !== value.length)))
        {
          return;
        }
        var items = reply && reply.ok && reply.result && reply.result.items;
        if (!Array.isArray(items))
        {
          return;
        }
        var matches = items.filter(function (item)
        {
          return typeof item === "string" && item.length <= 32768 && item.toLowerCase().indexOf(value.toLowerCase()) === 0;
        }).slice(0, 12);
        if (matches.length)
        {
          showSuggest(matches);
          if (acceptFirst === true)
          {
            acceptSuggestion(0);
          }
        }
      });
      return true;
    }

    var matches = [];
    var leading = value.slice(0, value.length - value.trimStart().length);
    Object.keys(state.commandsByName).concat([":help", ":clear", ":cls"]).forEach(function (name)
    {
      if (name.toLowerCase().indexOf(value.trimStart().toLowerCase()) === 0)
      {
        matches.push(leading + name);
      }
    });

    matches.sort();

    if (matches.length === 0)
    {
      return false;
    }

    showSuggest(matches.slice(0, 12));
    if (acceptFirst === true)
    {
      acceptSuggestion(0);
    }
    return true;
  }

  function showSuggest(matches, template, details, context)
  {
    state.suggestItems = matches;
    state.suggestInput = els.prompt.value;
    state.suggestActive = 0;
    state.suggestTemplate = template || "";
    state.suggestContext = context || null;
    els.suggest.textContent = "";

    matches.forEach(function (name, index) {
      var item = document.createElement("div");
      item.className = "suggest-item" + (index === 0 ? " active" : "");
      item.id = "suggest-option-" + index;
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", String(index === 0));
      item.textContent = name;
      if (details && details[index])
      {
        var address = document.createElement("span");
        address.className = "suggest-address";
        address.textContent = details[index].address;
        item.appendChild(address);
      }

      item.addEventListener("mousedown", function (event) {
        event.preventDefault();
        acceptSuggestion(index);
      });

      els.suggest.appendChild(item);
    });

    els.suggest.classList.remove("hidden");
    els.prompt.setAttribute("aria-expanded", "true");
    els.prompt.setAttribute("aria-activedescendant", "suggest-option-0");
    renderPromptGhost();
  }

  function hideSuggest()
  {
    state.addressCompletions.forEach(function (editor)
    {
      editor.context = null;
      editor.items = [];
      editor.active = -1;
      editor.list.textContent = "";
      setHidden(editor.list, true);
      editor.input.setAttribute("aria-expanded", "false");
      editor.input.setAttribute("aria-activedescendant", "");
      renderAddressGhost(editor);
    });
    clearTimeout(state.symbolCompletion.timer);
    state.symbolCompletion.timer = null;
    state.symbolCompletion.queued = null;
    ++state.suggestToken;
    els.suggest.classList.add("hidden");
    state.suggestItems = [];
    state.suggestActive = -1;
    state.suggestTemplate = "";
    state.suggestContext = null;
    els.prompt.setAttribute("aria-expanded", "false");
    els.prompt.setAttribute("aria-activedescendant", "");
    renderPromptGhost();
  }

  function acceptSuggestion(index)
  {
    var context = state.suggestContext;
    if (debuggerBusy() || index < 0 || index >= state.suggestItems.length || els.prompt.value !== state.suggestInput || state.composing ||
      (context ? !symbolJobCurrent(context) : typeof els.prompt.selectionStart === "number" &&
        (els.prompt.selectionStart !== els.prompt.value.length || els.prompt.selectionEnd !== els.prompt.value.length)))
    {
      hideSuggest();
      return;
    }

    var candidate = state.suggestItems[index];
    var template = candidate === state.suggestTemplate;
    els.prompt.value = candidate;
    if (template)
    {
      state.parameterDraft = { command: firstToken(candidate).toLowerCase(), markers: candidate.match(/<[^<>]+>/g) || [] };
    }
    hideSuggest();
    if (context)
    {
      var cursor = candidate.length - (context.value.length - context.cursor);
      els.prompt.setSelectionRange(cursor, cursor);
      state.symbolCompletion.accepted = { value: candidate, cursor: cursor, stampKey: context.stampKey };
    }
    updateInputUI();
    els.prompt.focus();
    var fields = parameterFields();
    if (fields.length)
    {
      selectParameter(fields[0]);
    }
  }

  function moveSuggest(delta) {
    if (state.suggestItems.length === 0) {
      return;
    }

    var count = state.suggestItems.length;
    state.suggestActive = (state.suggestActive + delta + count) % count;

    var children = els.suggest.querySelectorAll(".suggest-item");

    for (var i = 0; i < children.length; i++) {
      children[i].className =
        "suggest-item" + (i === state.suggestActive ? " active" : "");
      children[i].setAttribute("aria-selected", String(i === state.suggestActive));
      if (i === state.suggestActive && children[i].scrollIntoView)
      {
        children[i].scrollIntoView({ block: "nearest" });
      }
    }
    els.prompt.setAttribute("aria-activedescendant", "suggest-option-" + state.suggestActive);
    renderPromptGhost();
  }

  // ---------- execution ----------

  function executeCurrentInput(binding, screen, viewCommand)
  {
    var fromView = typeof viewCommand === "string";
    var command = fromView ? viewCommand : els.prompt.value.trim();

    if (!state.ready || debuggerBusy() || state.composing || command === "")
    {
      return;
    }
    var fields = fromView ? [] : parameterFields();
    if (fields.length && !binding)
    {
      selectParameter(fields[0]);
      return;
    }

    if (command === ":clear" || command === ":cls") {
      clearOutput();
      els.prompt.value = "";
      hideSuggest();
      updateInputUI();
      return;
    }

    if (command === ":help")
    {
      command = "help ui";
    }
    if (!screen && !resultTabRoom())
    {
      return;
    }

    if (state.busy || state.statusBusy)
    {
      appendLine("[kndbgx] busy - wait for the current command to finish", "t-warn");
      return;
    }

    state.busy = true;
    state.preparedDebuggerRevision = state.debuggerRevision;
    selectCommand(command);
    state.stopStream = !state.consoleEnabled;
    workspaceFeedback("");
    invalidateResultLoad();
    phase("Planning");
    ++state.runToken;
    setStatusBusy(true);
    var browsingHistory = fromView && state.historyDraft !== null && state.historyIndex < state.history.length &&
      els.prompt.value === state.historyRecalled;
    state.history.push(command);
    if (state.history.length > 200)
    {
      state.history.shift();
      if (browsingHistory)
      {
        state.historyIndex = Math.max(-1, state.historyIndex - 1);
      }
    }
    if (!browsingHistory)
    {
      state.historyIndex = state.history.length;
      state.historyDraft = null;
      state.historyRecalled = null;
    }
    if (!fromView)
    {
      els.prompt.value = "";
    }
    hideSuggest();
    updateInputUI();

    appendCommandEcho(command);

    if (binding && binding.resultId)
    {
      executeNow(command, null, binding, screen);
    }
    else
    {
      maybeConfirmThenExecute(command, screen);
    }
  }

  var pendingCommand = null;
  var pendingResultScreen;

  function rejectPreparedCommand(plan)
  {
    if (plan)
    {
      send("discardPlan", { planId: plan.planId, approvalToken: plan.approvalToken });
    }
    pendingCommand = null;
    var restore = !els.modalBackdrop.classList.contains("hidden");
    els.modalBackdrop.classList.add("hidden");
    appendLine("[kndbgx] target status changed; command was not submitted", "t-warn");
    finishRequest();
    if (restore)
    {
      restoreModalFocus();
    }
  }

  function finishRequest()
  {
    state.busy = false;
    state.cancelRequested = false;
    phase("Idle");
    state.currentRequest = "";
    setStatusBusy(false);
    followDisassemblyStop();
    maybeRefreshRegisters();
  }

  function restoreModalFocus() {
    uiElement("root").inert = false;
    els.modalBackdrop.setAttribute("aria-hidden", "true");
    var target = state.restoreFocus || els.prompt;
    resumeFloatingInspection(target);
    if (target.focus) { target.focus(); }
  }

  function cancelPlan() {
    ++state.runToken;
    if (state.currentRequest) { send("interrupt", { requestId: state.currentRequest }); }
    if (pendingCommand && pendingCommand.planId) {
      send("discardPlan", { planId: pendingCommand.planId, approvalToken: pendingCommand.approvalToken });
    }
    pendingCommand = null;
    els.modalBackdrop.classList.add("hidden");
    finishRequest();
    restoreModalFocus();
  }

  function maybeConfirmThenExecute(command, screen)
  {
    var run = state.runToken;
    send("classify", { command: command }).then(function (reply) {
      if (run !== state.runToken) { return; }
      if (!preparedCommandCurrent())
      {
        rejectPreparedCommand();
        return;
      }
      if (!reply || !reply.ok) {
        appendLine((reply && reply.error) || "classification unavailable", "t-error");
        finishRequest();
        return;
      }
      if (!reply.result.write) {
        executeNow(command, null, null, screen);
        return;
      }
      send("previewWrite", { command: command }).then(function (previewReply) {
        if (run !== state.runToken || state.cancelRequested)
        {
          if (previewReply && previewReply.ok && previewReply.result.plan) {
            var abandoned = previewReply.result.plan;
            send("discardPlan", { planId: abandoned.planId, approvalToken: abandoned.approvalToken });
          }
          if (run === state.runToken) { finishRequest(); }
          return;
        }
        if (!preparedCommandCurrent())
        {
          rejectPreparedCommand(previewReply && previewReply.ok && previewReply.result && previewReply.result.plan);
          return;
        }
        if (!previewReply || !previewReply.ok || !previewReply.result.plan) {
          appendLine((previewReply && previewReply.error) || "The complete change preview is unavailable.", "t-error");
          finishRequest();
          return;
        }
        pendingCommand = previewReply.result.plan;
        pendingResultScreen = screen;
        function presentPreview(text)
        {
          if (run !== state.runToken)
          {
            return;
          }
          if (!preparedCommandCurrent())
          {
            rejectPreparedCommand(pendingCommand);
            return;
          }
          if (state.cancelRequested)
          {
            cancelPlan();
            return;
          }
          phase("AwaitingApproval");
          state.currentRequest = "";
          state.restoreFocus = uiActiveElement() || els.prompt;
          suspendFloatingInspection();
          uiElement("root").inert = true;
          els.modalBackdrop.setAttribute("aria-hidden", "false");
          els.modalPreview.textContent = "$ " + command + "\n" + text;
          uiElement("modal-title").textContent = "Review " + firstToken(command);
          els.modalConfirm.textContent = "Run approved " + firstToken(command);
          els.modalBackdrop.classList.remove("hidden");
          els.modalCancel.focus();
        }
        if (previewReply.result.previewResultId)
        {
          readPlanPreview(previewReply.result.previewResultId, "0", "", run).then(presentPreview).catch(function (error)
          {
            if (run !== state.runToken)
            {
              return;
            }
            cancelPlan();
            appendLine(error.message, "t-error");
            finishRequest();
          });
        }
        else
        {
          presentPreview(previewReply.result.preview);
        }
      });
    });
  }

  function readPlanPreview(id, cursor, text, run)
  {
    if (run !== state.runToken || state.cancelRequested)
    {
      return Promise.reject(new Error("Plan preview cancelled"));
    }
    return send("outputChunk", { resultId: id, cursor: String(cursor) }).then(function (reply)
    {
      if (!reply || !reply.ok || reply.result.offset !== String(cursor) || reply.result.resultId !== id)
      {
        throw new Error("Complete plan preview unavailable");
      }
      var chunk = reply.result;
      text += chunk.text || "";
      if (text.length > 1048576)
      {
        throw new Error("Plan preview exceeds display budget");
      }
      if (chunk.complete)
      {
        return text;
      }
      if (!(Number(chunk.next) > Number(cursor)))
      {
        throw new Error("Invalid preview sequence");
      }
      return readPlanPreview(id, chunk.next, text, run);
    });
  }

  function executeNow(command, plan, binding, screen)
  {
    if (!preparedCommandCurrent())
    {
      rejectPreparedCommand(plan);
      return;
    }
    state.busy = true;
    setStatusBusy(true);
    phase("Queued");
    var method = binding ? "navigateResult" : (plan ? "executePlan" : "execute");
    var params = binding || (plan ? { planId: plan.planId, approvalToken: plan.approvalToken } : { command: command });
    send(method, params).then(function (reply) {
      state.currentRequest = "";
      if (!reply || !reply.ok) {
        appendLine("[kndbgx] " + ((reply && reply.error) || "request failed"), reply && reply.outcomeUnknown ? "t-warn" : "t-error");
        phase("Failed");
        finishRequest();
        if (reply && reply.outcomeUnknown) { phase("Outcome unknown"); }
        return;
      }
      var result = reply.result || {};
      if (result.currentTarget)
      {
        state.target = result.currentTarget;
        state.statusKnown = false;
        ++state.debuggerRevision;
        ++state.statusToken;
        state.statusPending = true;
        updateInputUI();
      }
      if (result.cls) { clearOutput(); }
      if (result.ok === false) { appendLine("[kndbgx] " + (result.error || result.retentionError || "execution incomplete"), "t-error"); }
      var capture = result.data && result.data.commandId === "breakpoints" ? captureBreakpoints(result).catch(function (error)
      {
        state.breakpoints.error = error.message;
      }) : Promise.resolve();
      return capture.then(function ()
      {
        selectResult(result, undefined, undefined, screen);
        if (result.resultId) {
          phase("Streaming");
          return pullOutput(result.resultId, "0").then(function () {
            phase("Completed");
            finishRequest();
          });
        }
        if (result.output && !state.stopStream)
        {
          appendOutput(result.output);
        }
        finishRequest();
      });
    });
  }

  function setStatusBusy(busy) {
    updateCommandActivity();
    updateCurrentProcess();
    updateProcessActions();
    updateMemoryActions();
    updateRegistersSummary();
    updateDisassemblyActions();
    els.btnSave.disabled = busy || !state.resultId;
    if (els.btnCancel) {
      els.btnCancel.disabled = !busy;
    }

    els.resultHistory.disabled = busy || !state.recentResults.length;
    uiElement("btn-result-load").disabled = busy;
    uiElement("btn-palette").disabled = busy;
    uiElement("btn-empty-command").disabled = busy;
    ["btn-empty-output", "btn-result-output"].forEach(function (id)
    {
      uiElement(id).disabled = busy || !state.resultId || state.resultOutputLength === "0";
    });
    uiElement("kernel-workflow").disabled = busy || !state.ready;
    updateInputUI();
    if (!busy) {
      refreshStatus();
    }
    selectObservation(state.selectedRow);
  }

  // ---------- history ----------

  function recallHistory(delta)
  {
    if (state.history.length === 0)
    {
      return;
    }
    if (state.historyIndex < state.history.length && els.prompt.value !== state.historyRecalled)
    {
      state.historyIndex = state.history.length;
    }
    if (state.historyIndex === state.history.length)
    {
      if (delta > 0)
      {
        return;
      }
      state.historyDraft = { value: els.prompt.value, start: els.prompt.selectionStart,
        end: els.prompt.selectionEnd, direction: els.prompt.selectionDirection, parameters: state.parameterDraft };
    }
    if (state.historyIndex < 0 && delta < 0)
    {
      return;
    }
    state.historyIndex = Math.max(0, Math.min(state.history.length, state.historyIndex + delta));
    var draft = state.historyIndex === state.history.length ? state.historyDraft : null;
    hideSuggest();
    state.symbolCompletion.accepted = null;
    els.prompt.value = draft ? draft.value : state.history[state.historyIndex];
    state.historyRecalled = draft ? null : els.prompt.value;
    state.parameterDraft = draft ? draft.parameters : null;
    updateInputUI();
    if (typeof els.prompt.setSelectionRange === "function")
    {
      els.prompt.setSelectionRange(draft && typeof draft.start === "number" ? draft.start : els.prompt.value.length,
        draft && typeof draft.end === "number" ? draft.end : els.prompt.value.length, draft ? draft.direction : "none");
    }
  }

  // ---------- events ----------

  uiElement("btn-palette").addEventListener("click", openPalette);
  uiElement("btn-execution-toggle").addEventListener("click", function ()
  {
    if (state.sessionStatus.stopped === false)
    {
      breakExecution();
    }
    else
    {
      controlExecution("go");
    }
  });
  uiElement("btn-empty-command").addEventListener("click", openPalette);
  uiElement("library-favorites").addEventListener("change", renderCatalog);
  uiElement("btn-empty-processes").addEventListener("click", function ()
  {
    if (!uiElement("btn-empty-processes").disabled)
    {
      setInspectionTab("processes");
      setMemoryPanel(true);
    }
  });
  uiElement("btn-empty-ip").addEventListener("click", function ()
  {
    if (!uiElement("btn-empty-ip").disabled)
    {
      setInspectionTab("disassembly");
      setMemoryPanel(true);
      uiElement("btn-disassembly-ip").click();
    }
  });
  uiElement("btn-empty-stack").addEventListener("click", function ()
  {
    if (!uiElement("btn-empty-stack").disabled)
    {
      runView("stack", null, "results");
    }
  });
  els.paletteClose.addEventListener("click", function () { closePalette(true); });
  els.paletteInput.addEventListener("input", renderPalette);
  els.paletteInput.addEventListener("compositionstart", function () { state.paletteComposing = true; });
  els.paletteInput.addEventListener("compositionend", function () { state.paletteComposing = false; renderPalette(); });
  els.paletteInput.addEventListener("keydown", function (event)
  {
    if (event.isComposing || event.keyCode === 229 || state.paletteComposing)
    {
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp")
    {
      event.preventDefault();
      var length = state.paletteItems.length;
      state.paletteActive = length ? (state.paletteActive + (event.key === "ArrowDown" ? 1 : -1) + length) % length : 0;
      updatePaletteSelection();
    }
    else if (event.key === "Enter")
    {
      event.preventDefault();
      choosePalette(state.paletteActive);
    }
  });
  els.paletteBackdrop.addEventListener("click", function (event)
  {
    if (event.target === els.paletteBackdrop)
    {
      closePalette(true);
    }
  });
  uiElement("btn-sidebar").addEventListener("click", toggleLibrary);
  uiElement("btn-library-pin").addEventListener("click", function ()
  {
    state.libraryPinned = !state.libraryPinned;
    state.libraryVisible = true;
    updateLayout();
    saveWorkspacePreferences();
  });
  uiElement("btn-library-close").addEventListener("click", function ()
  {
    state.libraryVisible = false;
    updateLayout();
    saveWorkspacePreferences();
    uiElement("btn-sidebar").focus();
  });
  uiElement("sidebar").addEventListener("keydown", function (event)
  {
    if (event.key === "Escape" && els.root.classList.contains("library-overlay"))
    {
      event.preventDefault();
      uiElement("btn-library-close").click();
    }
  });
  uiElement("btn-console").addEventListener("click", toggleConsole);
  uiElement("btn-inspector").addEventListener("click", function ()
  {
    setRowDetails(!state.inspectorVisible);
  });
  uiElement("btn-inspector-close").addEventListener("click", function ()
  {
    setRowDetails(false);
  });
  listenWindow("resize", updateLayout);
  if (typeof window.ResizeObserver === "function")
  {
    // Native docking and asynchronous context text can reflow without a window resize.
    var workspaceGeometryObserver = new window.ResizeObserver(scheduleWorkspaceGeometry);
    ["toolbar", "current-process-bar", "workspace-split", "command-area"].forEach(function (id)
    {
      workspaceGeometryObserver.observe(uiElement(id));
    });
  }
  els.btnRun.addEventListener("click", executeCurrentInput);
  els.resultHistory.addEventListener("change", function () { loadResult(els.resultHistory.value); });
  uiElement("result-id-input").addEventListener("keydown", function (event)
  {
    if (event.key === "Enter" && !event.isComposing && event.keyCode !== 229)
    {
      event.preventDefault();
      loadResult(uiElement("result-id-input").value.trim());
    }
  });
  uiElement("result-table").addEventListener("keydown", function (event)
  {
    if (event.target && (event.target.classList.contains("table-sort") || event.target.classList.contains("table-resize")))
    {
      return;
    }
    var fromCopy = event.target && (event.target.classList.contains("copyable") || event.target.classList.contains("breakpoint-row-toggle"));
    if (fromCopy && event.key === "Escape")
    {
      event.preventDefault();
      uiElement("result-table").focus();
      return;
    }
    if (!state.rowCount || event.altKey || event.ctrlKey || event.metaKey || event.isComposing)
    {
      return;
    }
    var index = state.pendingSelection >= 0 ? state.pendingSelection : state.selectedIndex;
    var page = Math.max(1, Math.floor(els.resultView.clientHeight / workspaceRowHeight()));
    switch (event.key)
    {
      case "ArrowDown": index = index < 0 ? Math.floor(els.resultView.scrollTop / workspaceRowHeight()) : index + 1; break;
      case "ArrowUp": index = index < 0 ? Math.floor(els.resultView.scrollTop / workspaceRowHeight()) : index - 1; break;
      case "Home": index = 0; break;
      case "End": index = state.rowCount - 1; break;
      case "PageDown": index = Math.max(0, index) + page; break;
      case "PageUp": index = Math.max(0, index) - page; break;
      default: return;
    }
    event.preventDefault();
    if (fromCopy)
    {
      uiElement("result-table").focus();
    }
    index = Math.min(state.rowCount - 1, Math.max(0, index));
    if (index * workspaceRowHeight() < els.resultView.scrollTop)
    {
      els.resultView.scrollTop = index * workspaceRowHeight();
    }
    else if ((index + 1) * workspaceRowHeight() > els.resultView.scrollTop + els.resultView.clientHeight)
    {
      els.resultView.scrollTop = (index + 1) * workspaceRowHeight() - els.resultView.clientHeight;
    }
    chooseRow(index);
  });

  els.prompt.addEventListener("compositionstart", function () { state.composing = true; hideSuggest(); updateInputUI(); });
  els.prompt.addEventListener("compositionend", function () { state.composing = false; updateSuggest(); });
  els.prompt.addEventListener("blur", hideSuggest);
  els.prompt.addEventListener("focus", function ()
  {
    updateSuggest();
  });
  els.prompt.addEventListener("click", function ()
  {
    updateSuggest();
  });
  els.prompt.addEventListener("scroll", renderPromptGhost);
  els.prompt.addEventListener("select", function ()
  {
    if ((els.prompt.selectionStart !== els.prompt.value.length || els.prompt.selectionEnd !== els.prompt.value.length) &&
      !symbolCompletionContext(els.prompt.value))
    {
      hideSuggest();
    }
  });
  els.prompt.addEventListener("keyup", function (event)
  {
    if (["ArrowLeft", "ArrowRight", "Home", "End"].indexOf(event.key) >= 0 && !event.isComposing && !state.composing)
    {
      updateSuggest();
    }
  });
  els.prompt.addEventListener("keydown", function (event)
  {
    if (debuggerBusy() || event.isComposing || state.composing || event.keyCode === 229)
    {
      return;
    }
    var suggestVisible = !els.suggest.classList.contains("hidden");

    if (event.key === "Enter") {
      event.preventDefault();
      executeCurrentInput();
      return;
    }

    if (["ArrowLeft", "ArrowRight", "Home", "End"].indexOf(event.key) >= 0)
    {
      hideSuggest();
    }

    if (event.key === "Tab" && !event.shiftKey && !event.ctrlKey && !event.altKey && !event.metaKey)
    {
      if (!suggestVisible && acceptedSymbolCurrent(els.prompt.value) && !parameterSuggestion(els.prompt.value) && !parameterFields().length)
      {
        return;
      }
      if (symbolCompletionContext(els.prompt.value) && (!suggestVisible || state.suggestContext))
      {
        event.preventDefault();
        if (suggestVisible)
        {
          acceptSuggestion(state.suggestActive);
        }
        else
        {
          updateSuggest(true);
        }
        return;
      }
      var fields = parameterFields();
      var end = typeof els.prompt.selectionEnd === "number" ? els.prompt.selectionEnd : els.prompt.value.length;
      var next = fields.find(function (field)
      {
        return field.start >= end;
      });
      if (next)
      {
        event.preventDefault();
        selectParameter(next);
        return;
      }
      if (state.parameterDraft && !suggestVisible)
      {
        return;
      }

      if (suggestVisible) {
        event.preventDefault();
        acceptSuggestion(state.suggestActive);
      } else {
        if (updateSuggest(true)) {
          event.preventDefault();
        }
      }

      return;
    }

    if (event.key === "ArrowUp") {
      event.preventDefault();

      if (suggestVisible) {
        moveSuggest(-1);
      } else {
        recallHistory(-1);
      }

      return;
    }

    if (event.key === "ArrowDown") {
      event.preventDefault();

      if (suggestVisible) {
        moveSuggest(1);
      } else {
        recallHistory(1);
      }

      return;
    }

    if (event.key === "Escape") {
      hideSuggest();
      updateInputUI();
    }
  });

  els.prompt.addEventListener("input", function ()
  {
    state.symbolCompletion.accepted = null;
    updateSuggest();
  });
  els.filter.addEventListener("input", applyFilter);

  els.btnClear.addEventListener("click", function () {
    clearOutput();
  });

  if (els.btnCancel)
  {
    els.btnCancel.addEventListener("click", function ()
    {
      if (!state.busy || state.phase === "Cancelling")
      {
        return;
      }
      state.cancelRequested = true;
      state.disassembly.pendingFollow = null;
      state.disassembly.awaitingStop = false;
      ++state.disassembly.followSerial;
      if (state.disassembly.loading)
      {
        state.disassembly.cancelled = true;
        if (!state.currentRequest)
        {
          phase("Cancelling");
          return;
        }
      }
      if (state.memory.loading)
      {
        state.memory.cancelled = true;
        if (!state.currentRequest)
        {
          phase("Cancelling");
          return;
        }
      }
      if (state.registers.loading)
      {
        state.registers.cancelled = true;
        if (!state.currentRequest)
        {
          phase("Cancelling");
          return;
        }
      }
      if (state.processes.loading)
      {
        state.processes.cancelled = true;
        if (!state.currentRequest)
        {
          phase("Cancelling");
          return;
        }
      }
      if (state.breakpoints.loading && !state.currentRequest)
      {
        phase("Cancelling");
        return;
      }
      if ((state.phase === "Planning" && !state.currentRequest) || state.phase === "AwaitingApproval")
      {
        cancelPlan();
        return;
      }
      if (state.phase === "Streaming")
      {
        state.stopStream = true;
        phase("Cancelling");
        return;
      }
      var requestId = state.currentRequest;
      phase("Cancelling");
      send("interrupt", { requestId: requestId }).then(function (reply)
      {
        if (!state.busy || state.currentRequest !== requestId)
        {
          return;
        }
        var requested = reply && reply.ok && reply.result && reply.result.requested === true;
        if (!requested)
        {
          phase("Cancellation unconfirmed");
        }
        appendLine(requested
          ? "[kndbgx] cancellation requested; waiting for completion"
          : "[kndbgx] cancellation was not confirmed; checking completion", "t-warn");
        queryOperation(requestId);
      });
    });
  }

  els.btnSave.addEventListener("click", function ()
  {
    if (state.busy || !state.ready)
    {
      return;
    }
    if (!state.resultId)
    {
      appendLine("[kndbgx] no stored result selected", "t-warn");
      return;
    }
    state.busy = true;
    phase("Queued");
    setStatusBusy(true);
    updateInputUI();
    var exportedId = state.resultId;
    send("saveLog", { resultId: exportedId }).then(function (reply)
    {
      var saved = reply && reply.ok && reply.result && reply.result.path;
      if (typeof saved === "string" && saved)
      {
        state.savedExports[exportedId] = saved;
        state.detailsRevision = -1;
        workspaceFeedback("Export saved: " + saved + " / Capture info > Copy saved path", false);
        updateEvidenceSummary();
      }
      appendLine(saved
        ? "[kndbgx] saved complete result " + reply.result.path
        : (reply && reply.outcomeUnknown ? "[kndbgx] save outcome unknown: " : "[kndbgx] save failed: ") +
          ((reply && reply.error) || "unknown"), saved ? "t-tag" : reply && reply.outcomeUnknown ? "t-warn" : "t-error");
      finishRequest();
      if (reply && reply.outcomeUnknown) { phase("Outcome unknown"); }
    });
  });

  bindCopyValue(uiElement("btn-result-export-path"), function ()
  {
    return state.savedExports[state.resultId] || null;
  }, "saved path", "Copy complete saved path");
  bindCopyValue(uiElement("event-address"), function ()
  {
    var event = (state.resultMeta.analysis || {}).lastEvent;
    return eventLocation(event).value;
  }, "event address", "Copy displayed event or current setting address");

  function operationTitle(operation)
  {
    var phaseLabel = operation.phase === "CancelRequested" ? "Cancellation requested" : operation.phase;
    var methodLabel = { execute: "Command", saveLog: "Export", memoryRead: "Read memory", disassemblyRead: "Read disassembly",
      navigateResult: "Open address", processAction: "Process action", previewWrite: "Review change", executePlan: "Apply change",
      breakpointPlan: "Review breakpoint", breakpointApply: "Change breakpoint", debuggerAction: "Execution control",
      status: "Check context", completeSymbols: "Find symbols", symbolModules: "Read module inventory",
      symbolHealth: "Inspect symbol health" }[operation.method] || operation.method;
    return "#" + operation.operationId + " / " + methodLabel + " / " + phaseLabel +
      (operation.phase === "Completed" ? " / " + (operation.outcome || (operation.ok ? "Success" : "Failed")) : "");
  }

  function observedDuration(value)
  {
    return typeof value === "string" && /^\d{1,15}$/.test(value) ? (Number(value) / 1000).toFixed(1) + "s" : "unknown";
  }

  function operationObservation(operation)
  {
    if (operation.phase === "Unknown")
    {
      return "Current outcome unconfirmed. Refresh outcomes to check again.";
    }
    var observation = operation.observation;
    if (!observation)
    {
      return "Stage timing was not reported by this host.";
    }
    var label = { Queued: "Waiting for workspace worker", Worker: "Worker processing",
      ContextQuery: "Checking debugger context", SymbolQuery: "Symbol API call", MemoryIo: "Target memory API call",
      EngineCommand: "Engine command call", ResultReady: "Outcome retained" }[observation.stage] || "Unknown stage";
    var completed = operation.phase === "Completed";
    return "Last observed: " + label + " / elapsed " + observedDuration(observation.elapsedMs) +
      (completed ? " / delivery " + diagnosticValue(operation.delivery) :
        "\nIn stage " + observedDuration(observation.stageElapsedMs) + " / since progress " + observedDuration(observation.sinceProgressMs) +
        " / wait cause unconfirmed") + (operation.phase === "CancelRequested" ?
        "\nCancellation requested " + observedDuration(observation.cancelElapsedMs) + " ago; execution has not completed." : "");
  }

  function showOperation(operation)
  {
    var row = document.createElement("article");
    row.className = "operation-row" + (operation.phase === "Unknown" ? " unknown" : "");
    var title = document.createElement("strong");
    title.textContent = operationTitle(operation);
    row.appendChild(title);
    var observation = document.createElement("p");
    observation.className = "operation-observation";
    observation.textContent = operationObservation(operation);
    row.appendChild(observation);
    state.operations.nodes[operation.operationId] = { title: title, observation: observation };
    if (operation.error || operation.path)
    {
      var detail = document.createElement("p");
      detail.textContent = (operation.path ? "Saved: " + operation.path : "") + (operation.error ? "\n" + operation.error : "");
      row.appendChild(detail);
    }
    var actions = document.createElement("div");
    actions.className = "operation-actions";
    if (operation.resultId)
    {
      var open = document.createElement("button");
      open.textContent = "Open result";
      open.disabled = !state.ready || state.busy;
      open.addEventListener("click", function ()
      {
        if (!state.ready || state.busy)
        {
          return;
        }
        setOperationsOpen(false);
        loadResult(operation.resultId);
      });
      actions.appendChild(open);
      state.operations.actions.push(open);
      var copyId = document.createElement("button");
      copyId.textContent = "Copy result ID";
      bindCopyValue(copyId, function ()
      {
        return operation.resultId;
      }, "result ID", "Copy complete result ID");
      actions.appendChild(copyId);
    }
    if (operation.path)
    {
      var copyPath = document.createElement("button");
      copyPath.textContent = "Copy saved path";
      bindCopyValue(copyPath, function ()
      {
        return operation.path;
      }, "saved path", "Copy complete saved path");
      actions.appendChild(copyPath);
    }
    row.appendChild(actions);
    uiElement("operations-list").appendChild(row);
  }

  function renderOperations()
  {
    closeCopyMenu();
    uiElement("operations-list").textContent = "";
    state.operations.actions = [];
    state.operations.nodes = Object.create(null);
    state.operations.records.slice().reverse().forEach(showOperation);
    uiElement("operations-status").textContent = state.operations.loading ? "Checking operation outcomes..." :
      (state.operations.error ? state.operations.error + " " : "") +
      (state.operations.records.length ? state.operations.records.length + " retained operations. " : "No retained operations found. ") +
      (state.operations.checked ? "Last checked " + state.operations.checked + "." : "");
    uiElement("btn-operations-refresh").disabled = state.operations.loading || !state.ready;
  }

  function operationRecord(source)
  {
    var record = {};
    ["operationId", "method", "phase", "outcome", "resultId", "path", "error", "delivery"].forEach(function (field)
    {
      record[field] = source && typeof source[field] === "string" ? source[field] : "";
    });
    record.ok = source && source.ok === true;
    record.observation = source && source.observation && typeof source.observation === "object" ? source.observation : null;
    if (["Queued", "Running", "CancelRequested", "Completed"].indexOf(record.phase) < 0)
    {
      record.phase = "Unknown";
    }
    return record;
  }

  function scheduleOperationObservation()
  {
    clearTimeout(state.operations.timer);
    if (!state.operations.open || state.capabilities.indexOf("operationObservation.v1") < 0)
    {
      return;
    }
    state.operations.timer = setTimeout(function ()
    {
      var serial = state.operations.serial;
      var active = state.operations.records.filter(function (operation)
      {
        return operation.phase !== "Completed" && operation.phase !== "Unknown";
      }).map(function (operation)
      {
        return { operationId: operation.operationId, requestId: "" };
      });
      if (state.currentRequest)
      {
        var pending = state.pending[state.currentRequest];
        if (!pending || !active.some(function (operation)
        {
          return operation.operationId === pending.operationId;
        }))
        {
          active.push({ operationId: "", requestId: state.currentRequest });
        }
      }
      var chain = Promise.resolve();
      if (!state.operations.loading && !document.hidden)
      {
        active.slice(0, 128).forEach(function (query)
        {
          chain = chain.then(function ()
          {
            if (!state.operations.open || serial !== state.operations.serial || document.hidden)
            {
              return;
            }
            return send("operationStatus", query).then(function (reply)
            {
              if (!state.operations.open || serial !== state.operations.serial)
              {
                return;
              }
              var operation = operationRecord(reply && reply.ok && reply.result);
              var identity = query.operationId || operation.operationId;
              var index = state.operations.records.findIndex(function (record)
              {
                return record.operationId === identity;
              });
              var previous = index >= 0 ? state.operations.records[index] : null;
              if (!reply || !reply.ok || !reply.result || !operation.operationId || operation.phase === "Unknown" ||
                query.operationId && query.operationId !== operation.operationId)
              {
                var error = "Operation receipt unavailable or unconfirmed. Refresh outcomes before submitting again.";
                if (!previous)
                {
                  state.operations.error = error;
                  renderOperations();
                  return;
                }
                operation = operationRecord(previous);
                operation.phase = "Unknown";
                operation.error = error;
              }
              if (index >= 0)
              {
                state.operations.records[index] = operation;
              }
              else
              {
                state.operations.records.push(operation);
                state.operations.records = state.operations.records.slice(-128);
              }
              var nodes = state.operations.nodes[operation.operationId];
              if (nodes && previous && previous.phase !== "Completed" && previous.phase !== "Unknown" &&
                operation.phase !== "Completed" && operation.phase !== "Unknown")
              {
                nodes.title.textContent = operationTitle(operation);
                nodes.observation.textContent = operationObservation(operation);
              }
              else
              {
                renderOperations();
              }
              if (operation.phase === "Completed")
              {
                return send("operationAck", { operationId: operation.operationId }).then(function (ack)
                {
                  if (state.operations.open && serial === state.operations.serial && ack && ack.ok && ack.result === true)
                  {
                    operation.delivery = "Acknowledged";
                    var current = state.operations.nodes[operation.operationId];
                    if (current)
                    {
                      current.observation.textContent = operationObservation(operation);
                    }
                  }
                });
              }
            });
          });
        });
      }
      chain.then(scheduleOperationObservation, scheduleOperationObservation);
    }, 1500);
  }

  function recoverOperationPage(cursor, pages, serial, collected)
  {
    return send("operations", { cursor: cursor }).then(function (reply)
    {
      if (serial !== state.operations.serial || !state.operations.open)
      {
        return;
      }
      var page = reply && reply.ok && reply.result;
      if (!page || !Array.isArray(page.records) || page.records.length > 16 || typeof page.complete !== "boolean")
      {
        state.operations.error = "Outcomes could not be checked. Existing records are retained; no commands were replayed.";
        return;
      }
      var chain = Promise.resolve();
      page.records.slice(0, 16).forEach(function (entry)
      {
        chain = chain.then(function ()
        {
          var operation = operationRecord(entry);
          if (serial !== state.operations.serial || !state.operations.open || !operation.operationId || collected.length >= 128)
          {
            return;
          }
          return send("operationStatus", { operationId: operation.operationId, requestId: "" }).then(function (status)
          {
            if (serial !== state.operations.serial || !state.operations.open)
            {
              return;
            }
            if (!status || !status.ok || !status.result)
            {
              operation.phase = "Unknown";
              operation.error = "Outcome unavailable or expired. Check retained results and saved files before submitting again.";
            }
            else
            {
              var current = operationRecord(status.result);
              if (current.operationId === operation.operationId)
              {
                operation = current;
              }
              else
              {
                operation.phase = "Unknown";
                operation.error = "Operation identity could not be confirmed. Refresh outcomes to check again.";
              }
            }
            if (!collected.some(function (record)
            {
              return record.operationId === operation.operationId;
            }))
            {
              collected.push(operation);
            }
          });
        });
      });
      return chain.then(function ()
      {
        if (serial !== state.operations.serial || !state.operations.open || page.complete)
        {
          return;
        }
        if (typeof page.next === "string" && /^\d{1,20}$/.test(page.next) &&
          BigInt(page.next) > BigInt(cursor) && pages < 8 && collected.length < 128)
        {
          return recoverOperationPage(page.next, pages + 1, serial, collected);
        }
        state.operations.error = "The operation list is incomplete. Existing records are retained; refresh outcomes to check again.";
      });
    });
  }

  function refreshOperations()
  {
    if (!state.ready || !state.operations.open || state.operations.loading)
    {
      return;
    }
    var serial = ++state.operations.serial;
    var collected = [];
    state.operations.loading = true;
    state.operations.error = "";
    uiElement("btn-operations-refresh").disabled = true;
    uiElement("operations-status").textContent = "Checking operation outcomes...";
    queryOperation(state.currentRequest);
    recoverOperationPage("0", 1, serial, collected).then(function ()
    {
      if (serial !== state.operations.serial || !state.operations.open)
      {
        return;
      }
      state.operations.loading = false;
      var displayed = !state.operations.error || !state.operations.records.length;
      if (displayed)
      {
        state.operations.records = collected;
      }
      if (!state.operations.error)
      {
        state.operations.checked = new Date().toLocaleTimeString();
      }
      renderOperations();
      var acknowledgements = Promise.resolve();
      (displayed ? collected : []).forEach(function (operation)
      {
        if (operation.phase === "Completed")
        {
          acknowledgements = acknowledgements.then(function ()
          {
            if (serial === state.operations.serial && state.operations.open)
            {
              return send("operationAck", { operationId: operation.operationId });
            }
          });
        }
      });
      return acknowledgements;
    });
  }

  function setOperationsOpen(open)
  {
    var panel = uiElement("operations-panel");
    var focused = panel.contains && panel.contains(uiActiveElement());
    state.operations.open = open;
    setHidden(panel, !open);
    uiElement("btn-operations").setAttribute("aria-expanded", String(open));
    if (open)
    {
      closeToolMenus();
      setContextOpen(false);
      refreshOperations();
      uiElement("btn-operations-close").focus();
    }
    else
    {
      ++state.operations.serial;
      state.operations.loading = false;
      if (focused)
      {
        uiElement("btn-operations").focus();
      }
    }
    scheduleOperationObservation();
  }

  function applyInspectionPause()
  {
    uiElement("pause-inspection-reads").checked = state.pauseInspectionReads;
    uiElement("btn-context").textContent = state.pauseInspectionReads ? "Context / reads paused" : "Context details";
    if (state.pauseInspectionReads)
    {
      uiElement("btn-context").classList.add("reads-paused");
    }
    else
    {
      uiElement("btn-context").classList.remove("reads-paused");
    }
    updateProcessSummary();
    updateRegistersSummary();
    updateDisassemblySummary();
    renderContextDetails();
  }

  uiElement("pause-inspection-reads").addEventListener("change", function ()
  {
    state.pauseInspectionReads = uiElement("pause-inspection-reads").checked === true;
    try
    {
      window.localStorage.setItem("kndbgx.pause-inspection-reads", state.pauseInspectionReads ? "on" : "off");
    }
    catch (error)
    {
      // Session behavior remains available when preferences cannot be saved.
    }
    applyInspectionPause();
    if (!state.pauseInspectionReads)
    {
      followDisassemblyStop();
      maybeRefreshRegisters();
    }
  });

  uiElement("btn-operations").addEventListener("click", function ()
  {
    setOperationsOpen(!state.operations.open);
  });
  uiElement("btn-operations-close").addEventListener("click", function ()
  {
    setOperationsOpen(false);
  });
  uiElement("btn-operations-refresh").addEventListener("click", refreshOperations);
  uiElement("operations-panel").addEventListener("keydown", function (event)
  {
    if (event.key === "Escape")
    {
      event.preventDefault();
      setOperationsOpen(false);
    }
  });

  // ---------- approval modal ----------

  els.modalConfirm.addEventListener("click", function () {
    if (state.phase !== "AwaitingApproval")
    {
      return;
    }
    var command = pendingCommand;
    pendingCommand = null;
    els.modalBackdrop.classList.add("hidden");

    restoreModalFocus();
    if (command) {
      if (command.breakpoint)
      {
        applyBreakpoint(command);
      }
      else
      {
        executeNow(null, command, null, pendingResultScreen);
      }
    }
  });

  listenDocument("keydown", function (event)
  {
    if (event.key === "Escape" && state.resultTabDrag)
    {
      event.preventDefault();
      event.stopPropagation();
      endResultTabDrag(true);
      return;
    }
    if (event.key === "Escape" && state.columnDrag)
    {
      event.preventDefault();
      endColumnResize(true);
      return;
    }
    if (event.key === "Escape" && state.memoryPanel.drag)
    {
      event.preventDefault();
      endMemoryResize(true);
      return;
    }
    if (event.key === "Escape" && state.inspectorPanel.drag)
    {
      event.preventDefault();
      endInspectorResize(true);
      return;
    }
    if (event.isComposing || event.keyCode === 229 || state.composing || state.paletteComposing ||
      state.addressCompletions.some(function (editor)
      {
        return editor.composing;
      }))
    {
      return;
    }
    var paletteOpen = !els.paletteBackdrop.classList.contains("hidden");
    var approvalOpen = !els.modalBackdrop.classList.contains("hidden");
    if (paletteOpen || approvalOpen)
    {
      if (event.key === "Tab")
      {
        event.preventDefault();
        var controls = paletteOpen ? [els.paletteInput, els.paletteClose] : [els.modalPreview, els.modalCancel, els.modalConfirm];
        var current = controls.indexOf(uiActiveElement());
        controls[(current + (event.shiftKey ? -1 : 1) + controls.length) % controls.length].focus();
      }
      else if (event.key === "Escape")
      {
        event.preventDefault();
        if (paletteOpen)
        {
          closePalette(true);
        }
        else
        {
          cancelPlan();
          appendLine("[plan] cancelled", "t-dim");
        }
      }
      return;
    }
    if (!event.defaultPrevented && !event.repeat && !event.ctrlKey && !event.metaKey && !event.altKey && !event.shiftKey &&
        (event.key === "F5" || (inspectionVisible("disassembly") &&
        ["F10", "F11"].indexOf(event.key) >= 0)))
    {
      event.preventDefault();
      controlExecution(event.key === "F5" ? "go" : event.key === "F10" ? "step-over" : "step-into");
      return;
    }
    if ((event.ctrlKey || event.metaKey) && !event.altKey)
    {
      var key = event.key.toLowerCase();
      if (key === "k" || (key === "p" && event.shiftKey))
      {
        event.preventDefault();
        openPalette();
      }
      else if (key === "l")
      {
        event.preventDefault();
        focusMainWorkspace(els.prompt);
      }
      else if (key === "j")
      {
        event.preventDefault();
        toggleConsole();
        focusMainWorkspace();
      }
      else if (key === "b")
      {
        event.preventDefault();
        toggleLibrary();
        focusMainWorkspace();
      }
      else if (key === "m")
      {
        event.preventDefault();
        setMemoryPanel(!state.memoryPanel.visible);
      }
    }
    if (event.key === "Escape")
    {
      closeResultOpen(false);
      if (isNarrow() && state.libraryVisible)
      {
        state.libraryVisible = false;
        updateLayout();
        uiElement("btn-sidebar").focus();
      }
    }
  });

  els.modalCancel.addEventListener("click", function () {
    cancelPlan();
    appendLine("[plan] cancelled", "t-dim");
  });

  // ---------- startup ----------

  function showCatalogError(text) {
    els.catalog.textContent = "";
    var node = document.createElement("div");
    node.className = "group-title";
    node.textContent = text;
    els.catalog.appendChild(node);
  }

  loadLibraryPreferences();
  try
  {
    var workspaceSettings = window.localStorage.getItem("kndbgx.workspace-layout");
    if (typeof workspaceSettings === "string" && workspaceSettings.length <= 256)
    {
      var preferences = JSON.parse(workspaceSettings);
      if (preferences && typeof preferences === "object")
      {
        if (typeof preferences.console === "boolean")
        {
          state.consoleVisible = preferences.console;
        }
        if (typeof preferences.details === "boolean")
        {
          state.inspectorVisible = preferences.details;
        }
        if (typeof preferences.library === "boolean")
        {
          state.libraryVisible = preferences.library;
        }
        if (typeof preferences.libraryPinned === "boolean")
        {
          state.libraryPinned = preferences.libraryPinned;
        }
        state.workspaceDensity = preferences.density === "comfortable" ? "comfortable" : "compact";
      }
    }
  }
  catch (error)
  {
    // Invalid or unavailable settings do not prevent workspace startup.
  }
  try
  {
    var favorites = window.localStorage.getItem("kndbgx.command-favorites");
    var savedFavorites = typeof favorites === "string" && favorites.length <= 32768 ? JSON.parse(favorites) : [];
    if (Array.isArray(savedFavorites) && savedFavorites.length <= 128 && savedFavorites.every(function (name)
    {
      return typeof name === "string" && name.length > 0 && name.length <= 128;
    }))
    {
      state.libraryFavorites = savedFavorites;
    }
  }
  catch (error)
  {
    // A malformed favorites file does not hide or change commands.
  }
  loadAddressHistory();
  ["memory", "disassembly"].forEach(renderAddressHistory);
  uiElement("library-sort").value = state.librarySort;
  try
  {
    var inspectorPreference = window.localStorage.getItem("kndbgx.inspector-width");
    if (typeof inspectorPreference === "string" && inspectorPreference.length <= 32)
    {
      var inspectorWidth = JSON.parse(inspectorPreference);
      if (Number.isFinite(inspectorWidth) && inspectorWidth >= 240 && inspectorWidth <= 800)
      {
        state.inspectorPanel.width = Math.round(inspectorWidth);
      }
    }
  }
  catch (error)
  {
    // Keep the responsive default when the saved width is unavailable or invalid.
  }
  try
  {
    state.disassembly.followIP = window.localStorage.getItem("kndbgx.disassembly-follow") !== "off";
    var memoryPreference = window.localStorage.getItem("kndbgx.memory-panel");
    if (typeof memoryPreference === "string" && memoryPreference.length <= 128)
    {
      var memorySettings = JSON.parse(memoryPreference);
      if (memorySettings && typeof memorySettings === "object")
      {
        if (typeof memorySettings.visible === "boolean")
        {
          state.memoryPanel.visible = memorySettings.visible;
        }
        state.memoryPanel.tab = inspectionViews.indexOf(memorySettings.tab) >= 0 ? memorySettings.tab : "memory";
        if (Number.isFinite(memorySettings.width) && memorySettings.width >= 280 && memorySettings.width <= 1000)
        {
          state.memoryPanel.width = Math.round(memorySettings.width);
        }
      }
    }
  }
  catch (error)
  {
    // Keep the default panel layout when preferences are unavailable or invalid.
  }
  try
  {
    state.consoleEnabled = window.localStorage.getItem("kndbgx.console-output") !== "off";
  }
  catch (error)
  {
    // Default to visible output when the runtime has disabled storage.
  }
  applyConsoleOutput();
  try
  {
    state.pauseInspectionReads = window.localStorage.getItem("kndbgx.pause-inspection-reads") === "on";
  }
  catch (error)
  {
    // Automatic inspection reads remain enabled when preferences are unavailable.
  }
  applyInspectionPause();
  setInspectionTab(state.memoryPanel.tab);
  updateInputUI();
  updateLayout();
  renderCatalogPlaceholder();
  send("hello", { documentToken: window.knDbgXDocumentToken || "" }).then(function (hello) {
    if (!hello || !hello.ok) {
      els.status.textContent = "bridge handshake failed; close and reopen UI";
      return;
    }
    state.ready = true;
    state.capabilities = Array.isArray(hello.result.capabilities) ? hello.result.capabilities.slice(0, 32) : [];
    updateMemoryPanelLayout();
    state.target = hello.result.target || state.target;
    phase("Idle");
    updateInputUI();
    startup();
  });

  function startup() {


  send("catalog", {}).then(function (reply) {
    if (!reply || !reply.ok) {
      showCatalogError("catalog load failed");
      appendLine("[kndbgx] catalog load failed" +
        (reply && reply.error ? (": " + reply.error) : ""), "t-error");
      return;
    }

    var groups = reply.result && reply.result.groups;
    state.groups = [];

    if (!groups || typeof groups !== "object") {
      showCatalogError("catalog malformed");
      appendLine("[kndbgx] catalog malformed", "t-error");
      return;
    }

    Object.keys(groups).forEach(function (name) {
      var commands = groups[name];
      if (!commands || !commands.length) {
        return;
      }
      state.groups.push({ name: name, commands: commands });
    });

    var groupOrder = ["Kernel Analysis", "Files", "Debugger", "Memory", "Symbols", "Code", "Kernel", "Results", "Session", "Dumps", "Jobs"];
    state.groups.sort(function (a, b)
    {
      var left = groupOrder.indexOf(a.name);
      var right = groupOrder.indexOf(b.name);
      return (left < 0 ? groupOrder.length : left) - (right < 0 ? groupOrder.length : right);
    });
    state.groups.forEach(function (group)
    {
      group.commands = group.commands.slice().sort(function (a, b)
      {
        return (a.support === "Stable" ? 0 : 1) - (b.support === "Stable" ? 0 : 1);
      });
    });

    if (state.groups.length === 0) {
      showCatalogError("catalog empty");
    }

    renderCatalog();
    uiElement("library-sort").disabled = state.groups.length === 0;
  });

  refreshStatus();
  scheduleWorkspaceStatus();
  }

  function renderCatalogPlaceholder() {
    els.catalog.textContent = "";
    var loading = document.createElement("div");
    loading.className = "group-title";
    loading.textContent = "loading catalog...";
    els.catalog.appendChild(loading);
  }
})();




