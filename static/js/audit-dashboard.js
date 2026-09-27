const auditUi = window.ForensicAudit;

const loading = document.getElementById("audit-dashboard-loading");
const errorPanel = document.getElementById("audit-dashboard-error");
const errorMessage = document.getElementById("audit-dashboard-error-message");
const content = document.getElementById("audit-dashboard-content");
const summaryGrid = document.getElementById("audit-summary-grid");
const evidenceBody = document.getElementById("audit-evidence-body");
const recentEvents = document.getElementById("audit-recent-events");
const recentCount = document.getElementById("audit-recent-count");
const chainCount = document.getElementById("audit-chain-count");
const refreshButton = document.getElementById("audit-refresh-button");
const search = document.getElementById("audit-search");
const inspectorTitle = document.getElementById("audit-inspector-title");
const inspectorDescription = document.getElementById("audit-inspector-description");
const inspectorBadge = document.getElementById("audit-inspector-badge");
const inspectorMetrics = document.getElementById("audit-inspector-metrics");
const inspectorEvents = document.getElementById("audit-inspector-events");

let dashboardData = null;

async function loadDashboard() {
    loading.classList.remove("hidden");
    errorPanel.classList.add("hidden");
    refreshButton.disabled = true;

    try {
        const response = await fetch("/api/audit/overview?recent_limit=60&evidence_limit=200");
        if (!response.ok) throw new Error("The audit overview API could not be loaded.");
        dashboardData = await response.json();
        renderDashboard();
        content.classList.remove("hidden");
    } catch (error) {
        errorMessage.textContent = error.message;
        errorPanel.classList.remove("hidden");
    } finally {
        loading.classList.add("hidden");
        refreshButton.disabled = false;
    }
}

function renderDashboard() {
    renderSummary(dashboardData.summary || {});
    renderEvidenceRows();
    renderRecent(dashboardData.recent_events || []);
}

function renderSummary(summary) {
    summaryGrid.innerHTML = "";
    [
        ["Audit events", summary.total_events ?? 0, "Recorded activity"],
        ["Evidence chains", summary.evidence_count ?? 0, "Distinct evidence IDs"],
        ["Verified chains", summary.verified_chains ?? 0, "Hash chain passes"],
        ["Chain warnings", summary.failed_chains ?? 0, "Hash chain failures", summary.failed_chains ? "danger" : "good"],
        ["Integrity failures", summary.integrity_failures ?? 0, "Recorded evidence failures", summary.integrity_failures ? "danger" : "good"],
        ["Reports generated", summary.reports_generated ?? 0, "Recorded exports"],
    ].forEach(([label, value, caption, state]) => {
        const card = document.createElement("article");
        card.className = `audit-summary-card ${state || ""}`.trim();
        const name = document.createElement("span");
        name.textContent = label;
        const number = document.createElement("strong");
        number.textContent = value;
        const copy = document.createElement("small");
        copy.textContent = caption;
        card.append(name, number, copy);
        summaryGrid.appendChild(card);
    });
}

function filteredEvidence() {
    const query = (search.value || "").trim().toLowerCase();
    const rows = dashboardData?.evidence || [];
    if (!query) return rows;
    return rows.filter(item => [
        item.evidence_id,
        item.case_reference,
        item.actor,
        item.filename,
        item.latest_event_type,
    ].some(value => String(value || "").toLowerCase().includes(query)));
}

function renderEvidenceRows() {
    evidenceBody.innerHTML = "";
    const rows = filteredEvidence();
    chainCount.textContent = `${rows.length} chain${rows.length === 1 ? "" : "s"}`;

    if (!rows.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 6;
        cell.textContent = "No audit chains match the current filter.";
        row.appendChild(cell);
        evidenceBody.appendChild(row);
        return;
    }

    rows.forEach(item => {
        const row = document.createElement("tr");
        row.className = "audit-evidence-row";

        const status = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = `badge ${item.chain_verified ? "good" : "warning"}`;
        badge.textContent = item.chain_verified ? "Verified" : "Warning";
        status.appendChild(badge);

        const evidence = document.createElement("td");
        const filename = document.createElement("strong");
        filename.textContent = item.filename || "Evidence";
        const id = document.createElement("span");
        id.className = "audit-table-subtext audit-mono";
        id.textContent = item.evidence_id;
        evidence.append(filename, id);

        const caseCell = document.createElement("td");
        caseCell.textContent = item.case_reference || "—";

        const last = document.createElement("td");
        const event = document.createElement("strong");
        event.textContent = auditUi.humanEventType(item.latest_event_type);
        const time = document.createElement("span");
        time.className = "audit-table-subtext";
        time.textContent = auditUi.formatTime(item.latest_timestamp_utc);
        last.append(event, time);

        const count = document.createElement("td");
        count.textContent = item.event_count;

        const action = document.createElement("td");
        const button = document.createElement("button");
        button.className = "secondary-button audit-inspect-button";
        button.textContent = "Inspect";
        button.addEventListener("click", () => inspectEvidence(item));
        action.appendChild(button);

        row.append(status, evidence, caseCell, last, count, action);
        evidenceBody.appendChild(row);
    });
}

function renderRecent(events) {
    recentEvents.innerHTML = "";
    recentCount.textContent = `${events.length} shown`;
    events.slice(0, 20).forEach(event => recentEvents.appendChild(auditUi.makeEvent(event)));
}

async function inspectEvidence(summary) {
    inspectorTitle.textContent = summary.filename || "Evidence audit trail";
    inspectorDescription.textContent = `Evidence ID: ${summary.evidence_id}`;
    inspectorBadge.className = "badge";
    inspectorBadge.textContent = "Loading…";
    inspectorMetrics.innerHTML = "";
    inspectorEvents.innerHTML = "";

    try {
        const response = await fetch(`/api/audit/evidence/${encodeURIComponent(summary.evidence_id)}?limit=1000`);
        if (!response.ok) throw new Error("Evidence audit trail could not be loaded.");
        const data = await response.json();
        const chain = data.chain || {};

        inspectorBadge.className = `badge ${chain.verified ? "good" : "warning"}`;
        inspectorBadge.textContent = chain.verified ? "Chain verified" : "Chain warning";

        [
            ["Events", data.event_count ?? 0],
            ["Case", summary.case_reference || "—"],
            ["Actor", summary.actor || "—"],
            ["Head hash", auditUi.shortHash(chain.head_hash, 22)],
        ].forEach(([label, value]) => {
            const card = document.createElement("div");
            card.className = "audit-metric";
            const name = document.createElement("span");
            name.textContent = label;
            const val = document.createElement("strong");
            val.textContent = value;
            if (label === "Head hash") val.title = chain.head_hash || "";
            card.append(name, val);
            inspectorMetrics.appendChild(card);
        });

        [...(data.events || [])].reverse().forEach(event => {
            inspectorEvents.appendChild(auditUi.makeEvent(event));
        });
    } catch (error) {
        inspectorBadge.className = "badge warning";
        inspectorBadge.textContent = "Unavailable";
        inspectorDescription.textContent = error.message;
    }
}

refreshButton.addEventListener("click", loadDashboard);
search.addEventListener("input", renderEvidenceRows);
loadDashboard();
