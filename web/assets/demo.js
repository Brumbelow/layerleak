(() => {
  const commandEl = document.getElementById("demo-command");
  const startButton = document.getElementById("demo-start");
  const replayButton = document.getElementById("demo-replay");
  const terminalEl = document.getElementById("demo-terminal");
  const statusEl = document.getElementById("demo-status");
  const statsEl = document.getElementById("demo-stats");
  const tabsEl = document.getElementById("demo-tabs");
  const tableWrapEl = document.getElementById("demo-table-wrap");
  const tableMetaEl = document.getElementById("table-meta");

  if (!commandEl || !startButton || !replayButton || !terminalEl || !statusEl || !statsEl || !tabsEl || !tableWrapEl || !tableMetaEl) {
    return;
  }

  const state = {
    data: null,
    timers: [],
    running: false,
    activeTable: null,
    complete: false,
  };

  const fixtureURL = new URL("demo-data.json", document.currentScript.src);

  fetch(fixtureURL, { cache: "no-store" })
    .then((response) => {
      if (!response.ok) {
        throw new Error("demo fixture request failed");
      }
      return response.json();
    })
    .then((data) => {
      state.data = data;
      initializeDemo();
    })
    .catch(() => {
      commandEl.textContent = "demo fixture unavailable";
      statusEl.innerHTML = "<strong>Status:</strong> failed to load the simulation fixture";
      tableWrapEl.innerHTML = '<div class="table-empty">The simulated demo fixture could not be loaded.</div>';
      startButton.disabled = true;
    });

  function initializeDemo() {
    commandEl.textContent = state.data.command;
    renderIdleState();
    buildTabs();

    startButton.addEventListener("click", () => {
      if (!state.data || state.running) {
        return;
      }
      runDemo();
    });

    replayButton.addEventListener("click", () => {
      if (!state.data || state.running) {
        return;
      }
      runDemo();
    });
  }

  function runDemo() {
    clearTimers();
    state.running = true;
    state.complete = false;
    startButton.disabled = true;
    replayButton.disabled = true;
    setTabsEnabled(false);
    renderStatsPlaceholder("Replaying simulated scan");
    tableMetaEl.textContent = "Replay in progress";
    tableWrapEl.innerHTML = '<div class="table-empty">The fake local Postgres snapshot will appear after the replay completes.</div>';
    statusEl.innerHTML = "<strong>Status:</strong> booting replay";

    stepFrame(0);
  }

  function stepFrame(index) {
    const frame = state.data.frames[index];
    terminalEl.textContent = frame.terminal;
    statusEl.innerHTML = "<strong>Status:</strong> " + frame.status;
    terminalEl.scrollTop = terminalEl.scrollHeight;

    const next = index + 1;
    if (next >= state.data.frames.length) {
      state.timers.push(window.setTimeout(finishDemo, frame.delay_ms));
      return;
    }

    state.timers.push(
      window.setTimeout(() => {
        stepFrame(next);
      }, frame.delay_ms)
    );
  }

  function finishDemo() {
    state.running = false;
    state.complete = true;
    replayButton.disabled = false;
    renderStats(state.data.stats);
    setTabsEnabled(true);
    const initialTable = state.data.table_order[0];
    state.activeTable = initialTable;
    renderTabs();
    renderTable(initialTable);
  }

  function renderIdleState() {
    state.running = false;
    state.complete = false;
    state.activeTable = null;
    startButton.disabled = false;
    replayButton.disabled = true;
    terminalEl.textContent =
      "$ " +
      (state.data ? state.data.command : "layerleak scan vulnerableHost:latest --platform linux/amd64") +
      "\n\n# Click \"Try it out\" to replay a static layerleak run.\n# The transcript and the database rows below are simulated.";
    statusEl.innerHTML = "<strong>Status:</strong> waiting to replay";
    renderStatsPlaceholder("Awaiting replay");
    tableMetaEl.textContent = "Run the replay to load rows";
    tableWrapEl.innerHTML = '<div class="table-empty">Run the simulated scan to load the fake Postgres snapshot.</div>';
  }

  function renderStatsPlaceholder(text) {
    statsEl.innerHTML = "";
    const labels = ["Repository", "Platform", "Actionable findings", "Output file"];
    labels.forEach((label) => {
      const card = document.createElement("article");
      card.className = "stat-card";
      const heading = document.createElement("h3");
      heading.textContent = label;
      const body = document.createElement("p");
      body.textContent = text;
      card.append(heading, body);
      statsEl.appendChild(card);
    });
  }

  function renderStats(items) {
    statsEl.innerHTML = "";
    items.forEach((item) => {
      const card = document.createElement("article");
      card.className = "stat-card";
      const heading = document.createElement("h3");
      heading.textContent = item.label;
      const body = document.createElement("p");
      body.textContent = item.value;
      card.append(heading, body);
      statsEl.appendChild(card);
    });
  }

  function buildTabs() {
    tabsEl.innerHTML = "";
    state.data.table_order.forEach((tableName) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "tab-button";
      button.dataset.table = tableName;
      button.textContent = tableName;
      button.disabled = true;
      button.addEventListener("click", () => {
        if (!state.complete || state.activeTable === tableName) {
          return;
        }
        state.activeTable = tableName;
        renderTabs();
        renderTable(tableName);
      });
      tabsEl.appendChild(button);
    });
  }

  function renderTabs() {
    tabsEl.querySelectorAll(".tab-button").forEach((button) => {
      const active = button.dataset.table === state.activeTable;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
    });
  }

  function setTabsEnabled(enabled) {
    tabsEl.querySelectorAll(".tab-button").forEach((button) => {
      button.disabled = !enabled;
    });
  }

  function renderTable(tableName) {
    const table = state.data.tables[tableName];
    if (!table) {
      tableWrapEl.innerHTML = '<div class="table-empty">Unknown table.</div>';
      tableMetaEl.textContent = "Missing table fixture";
      return;
    }

    tableMetaEl.textContent = `${table.description} · ${table.rows.length}${table.rows.length === 1 ? " row" : " rows"}`;

    const tableEl = document.createElement("table");
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    table.columns.forEach((column) => {
      const th = document.createElement("th");
      th.scope = "col";
      th.textContent = column;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);

    const tbody = document.createElement("tbody");
    table.rows.forEach((row) => {
      const tr = document.createElement("tr");
      table.columns.forEach((column) => {
        const td = document.createElement("td");
        const value = formatCellValue(row[column]);
        if (value.length > 28) {
          const code = document.createElement("code");
          code.textContent = value;
          td.appendChild(code);
        } else {
          td.textContent = value;
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });

    tableEl.append(thead, tbody);
    tableWrapEl.innerHTML = "";
    tableWrapEl.appendChild(tableEl);
  }

  function formatCellValue(value) {
    if (value === null || value === undefined || value === "") {
      return "—";
    }
    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }
    if (typeof value === "object") {
      return JSON.stringify(value);
    }
    return String(value);
  }

  function clearTimers() {
    state.timers.forEach((timer) => {
      window.clearTimeout(timer);
    });
    state.timers = [];
  }
})();
