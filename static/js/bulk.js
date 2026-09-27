const ui = window.ForensicUI;

const bulkFileInput = document.getElementById("bulk-file-input");
const bulkButton = document.getElementById("bulk-button");
const bulkLoading = document.getElementById("bulk-loading");
const bulkResults = document.getElementById("bulk-results");
const bulkFilter = document.getElementById("bulk-filter");
const bulkTableBody = document.getElementById("bulk-table-body");
const bulkSummary = document.getElementById("bulk-summary");
const bulkSelectionNote = document.getElementById("bulk-selection-note");

let bulkRows = [];
let bulkSortField = "filename";
let bulkSortDirection = 1;

bulkFileInput?.addEventListener("change", () => {
    const count = bulkFileInput.files.length;
    bulkButton.disabled = count === 0;
    bulkSelectionNote.textContent = count
        ? `${count} file${count === 1 ? "" : "s"} selected`
        : "No files selected.";
    bulkResults?.classList.add("hidden");
});

bulkButton?.addEventListener("click", bulkAnalyze);
bulkFilter?.addEventListener("input", renderBulkTable);

document
    .querySelectorAll("#bulk-table th[data-sort]")
    .forEach(header => {
        header.addEventListener("click", () => {
            const field = header.dataset.sort;

            if (bulkSortField === field) {
                bulkSortDirection *= -1;
            } else {
                bulkSortField = field;
                bulkSortDirection = 1;
            }

            renderBulkTable();
        });
    });

async function bulkAnalyze() {
    if (!bulkFileInput?.files?.length || !bulkButton) {
        return;
    }

    bulkButton.disabled = true;
    bulkButton.textContent = "Analysing...";
    bulkLoading?.classList.remove("hidden");
    bulkResults?.classList.add("hidden");

    const form = new FormData();

    Array.from(bulkFileInput.files).forEach(file => {
        form.append("files", file);
    });

    try {
        const response = await fetch(
            "/api/bulk-analyze",
            {
                method: "POST",
                body: form,
            }
        );

        if (!response.ok) {
            throw new Error(
                await ui.responseError(response, "Bulk analysis failed.")
            );
        }

        const data = await response.json();
        bulkRows = data.rows || [];
        renderBulkSummary();
        renderBulkTable();
        bulkResults.classList.remove("hidden");
        bulkResults.scrollIntoView({ behavior: "smooth", block: "start" });

    } catch (error) {
        alert(`Bulk analysis failed: ${error.message}`);

    } finally {
        bulkLoading?.classList.add("hidden");
        bulkButton.disabled = false;
        bulkButton.textContent = "Analyse selected files";
    }
}

function renderBulkSummary() {
    bulkSummary.innerHTML = "";

    const typeCount = new Set(
        bulkRows.map(row => row.type).filter(Boolean)
    ).size;

    const withArtefacts = bulkRows.filter(
        row => Number(row.artefact_count || 0) > 0
    ).length;

    const withObservations = bulkRows.filter(
        row => Array.isArray(row.observations) && row.observations.length > 0
    ).length;

    ui.addMetric(bulkSummary, "Files", bulkRows.length);
    ui.addMetric(bulkSummary, "Detected types", typeCount);
    ui.addMetric(bulkSummary, "With artefacts", withArtefacts);
    ui.addMetric(bulkSummary, "With observations", withObservations);
}

function renderBulkTable() {
    if (!bulkTableBody) {
        return;
    }

    const filter = (bulkFilter?.value || "").toLowerCase();

    const filtered = bulkRows.filter(row => {
        return JSON.stringify(row).toLowerCase().includes(filter);
    });

    filtered.sort((a, b) => {
        const valueA = a[bulkSortField] ?? "";
        const valueB = b[bulkSortField] ?? "";

        if (typeof valueA === "number" && typeof valueB === "number") {
            return (valueA - valueB) * bulkSortDirection;
        }

        return String(valueA).localeCompare(String(valueB)) * bulkSortDirection;
    });

    bulkTableBody.innerHTML = "";

    filtered.forEach(row => {
        const tr = document.createElement("tr");

        appendBulkCell(tr, row.filename);
        appendBulkCell(tr, row.type);
        appendBulkCell(tr, row.sha256, "bulk-hash");
        appendBulkCell(tr, ui.formatBytes(row.size_bytes));
        appendBulkCell(tr, row.created || "Unavailable");
        appendBulkCell(tr, row.modified || "Unavailable");
        appendBulkCell(tr, row.artefact_count ?? 0);
        appendBulkCell(
            tr,
            (row.observations || []).join("; ") || "None"
        );

        bulkTableBody.appendChild(tr);
    });
}

function appendBulkCell(row, value, className = null) {
    const cell = document.createElement("td");

    if (className) {
        cell.className = className;
    }

    cell.textContent = value ?? "Unavailable";
    row.appendChild(cell);
}
