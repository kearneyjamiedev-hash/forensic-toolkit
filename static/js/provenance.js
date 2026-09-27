const ui = window.ForensicUI;

const fileInput = document.getElementById("provenance-file-input");
const dropZone = document.getElementById("provenance-drop-zone");
const selectedFile = document.getElementById("provenance-selected-file");
const analyseButton = document.getElementById("provenance-analyse-button");
const loading = document.getElementById("provenance-loading");
const results = document.getElementById("provenance-results");

const filenameElement = document.getElementById("provenance-filename");
const metadataCount = document.getElementById("provenance-metadata-count");
const overview = document.getElementById("provenance-overview");
const highlightsContainer = document.getElementById("provenance-highlights");
const highlightCount = document.getElementById("provenance-highlight-count");
const timelineCount = document.getElementById("provenance-timeline-count");
const timelineContainer = document.getElementById("provenance-timeline");
const observationsContainer = document.getElementById("provenance-observations");
const filesystemNote = document.getElementById("provenance-filesystem-note");
const filesystemContainer = document.getElementById("provenance-filesystem");
const allMetadataContainer = document.getElementById("provenance-all-metadata");

const uploader = ui.makeUploadController({
    input: fileInput,
    dropZone,
    selectedLabel: selectedFile,
    actionButton: analyseButton,
    onSelected: () => {
        results.classList.add("hidden");
    },
});

analyseButton.addEventListener("click", analyseProvenance);

async function analyseProvenance() {
    const file = uploader.getFile();

    if (!file) {
        return;
    }

    loading.classList.remove("hidden");
    results.classList.add("hidden");
    analyseButton.disabled = true;
    analyseButton.textContent = "Analysing...";

    const form = new FormData();
    form.append("file", file);
    form.append("browser_last_modified_ms", file.lastModified.toString());

    try {
        const response = await fetch(
            "/api/analyze",
            {
                method: "POST",
                body: form,
            }
        );

        if (!response.ok) {
            throw new Error(
                await ui.responseError(response, "Provenance analysis failed.")
            );
        }

        const data = await response.json();
        renderProvenance(data);
        results.classList.remove("hidden");
        results.scrollIntoView({ behavior: "smooth", block: "start" });

    } catch (error) {
        alert(`Provenance analysis failed: ${error.message}`);

    } finally {
        loading.classList.add("hidden");
        analyseButton.disabled = false;
        analyseButton.textContent = "Analyse provenance";
    }
}

function renderProvenance(data) {
    filenameElement.textContent = data.overview?.filename || "Unknown file";

    const metadata = data.metadata || {};
    metadataCount.textContent = `${metadata.field_count ?? 0} metadata ${metadata.field_count === 1 ? "field" : "fields"}`;

    renderOverview(data);
    renderHighlights(metadata);
    renderTimeline(data.timeline || {});
    renderFilesystem(data);
    renderAllMetadata(metadata);

    ui.configureEvidenceReportLinks(
        data.evidence?.id,
        {
            "provenance-pdf-link": "pdf",
            "provenance-json-link": "json",
            "provenance-timeline-link": "timeline.csv",
            "provenance-html-link": "html",
        }
    );
}

function renderOverview(data) {
    overview.innerHTML = "";

    ui.addMetric(overview, "Filename", data.overview?.filename || "Unavailable");
    ui.addMetric(overview, "Detected type", data.signature?.detected_type || "Unknown");
    ui.addMetric(overview, "MIME type", data.signature?.detected_mime || "Unknown");
    ui.addMetric(overview, "File size", ui.formatBytes(data.overview?.size_bytes));
    ui.addMetric(overview, "SHA-256", shortenHash(data.hashes?.sha256));
    ui.addMetric(overview, "Timeline events", data.timeline?.event_count ?? 0);
}

function renderHighlights(metadata) {
    highlightsContainer.innerHTML = "";

    const fields = flattenMetadata(metadata);
    const highlights = fields
        .filter(field => isProvenanceField(field))
        .sort((a, b) => provenancePriority(a) - provenancePriority(b));

    highlightCount.textContent = `${highlights.length} ${highlights.length === 1 ? "signal" : "signals"}`;

    if (!highlights.length) {
        const empty = document.createElement("div");
        empty.className = "provenance-empty-state";
        empty.innerHTML = "<strong>No high-value provenance fields were identified.</strong><span>The complete metadata remains available below.</span>";
        highlightsContainer.appendChild(empty);
        return;
    }

    highlights.slice(0, 30).forEach(field => {
        const card = document.createElement("article");
        card.className = "provenance-highlight-card";

        const label = document.createElement("span");
        label.className = "provenance-highlight-label";
        label.textContent = `${field.group}: ${field.name}`;

        const value = document.createElement("strong");
        value.textContent = formatMetadataValue(field.value);

        const category = document.createElement("span");
        category.className = "provenance-highlight-category";
        category.textContent = provenanceLabel(field);

        card.append(label, value, category);
        highlightsContainer.appendChild(card);
    });
}

function renderTimeline(timeline) {
    timelineContainer.innerHTML = "";
    observationsContainer.innerHTML = "";

    const events = Array.isArray(timeline.events) ? timeline.events : [];
    const observations = Array.isArray(timeline.observations) ? timeline.observations : [];

    timelineCount.textContent = `${events.length} ${events.length === 1 ? "timestamp" : "timestamps"}`;

    observations.forEach(observation => {
        const item = document.createElement("div");
        item.className = `timeline-observation ${observation.severity || "info"}`;

        const title = document.createElement("span");
        title.className = "timeline-observation-title";
        title.textContent = observation.title || "Timeline observation";

        const message = document.createElement("span");
        message.textContent = observation.message || "";

        item.append(title, message);
        observationsContainer.appendChild(item);
    });

    if (!events.length) {
        const empty = document.createElement("div");
        empty.className = "info-box";
        empty.textContent = "No recognised provenance timestamps were identified.";
        timelineContainer.appendChild(empty);
        return;
    }

    events.forEach(event => {
        const row = document.createElement("article");
        row.className = "provenance-timeline-item";

        const time = document.createElement("div");
        time.className = "provenance-timeline-time";
        time.textContent = event.timestamp_utc || event.timestamp_original || "Unavailable";

        const copy = document.createElement("div");
        const title = document.createElement("strong");
        const source = document.createElement("span");
        const scope = document.createElement("span");

        title.textContent = event.label || event.event_type || "Timestamp";
        source.textContent = `${event.source_group || event.source || "Unknown"}: ${event.source_field || "unknown"}`;
        scope.textContent = ui.formatCategory(event.scope || "unknown_scope");

        copy.append(title, source, scope);
        row.append(time, copy);
        timelineContainer.appendChild(row);
    });
}

function renderFilesystem(data) {
    filesystemContainer.innerHTML = "";

    const filesystem = data.filesystem || {};
    const browserModified = data.evidence?.browser_reported_last_modified;

    filesystemNote.textContent = filesystem.warning
        || "These timestamps describe the analyzer-managed upload copy. Original source filesystem metadata is not preserved by a normal browser upload; use Logical Evidence Collection when that context matters.";

    ui.addProperty(filesystemContainer, "Analyzer copy created", filesystem.created);
    ui.addProperty(filesystemContainer, "Analyzer copy modified", filesystem.modified);
    ui.addProperty(filesystemContainer, "Analyzer copy accessed", filesystem.accessed);
    ui.addProperty(filesystemContainer, "Browser-reported last modified", browserModified || "Unavailable");
    ui.addProperty(filesystemContainer, "Scope", ui.formatCategory(filesystem.scope || "evidence_copy"));
}

function renderAllMetadata(metadata) {
    allMetadataContainer.innerHTML = "";

    if (metadata.status !== "ok") {
        const warning = document.createElement("div");
        warning.className = "warning-box";
        warning.textContent = metadata.error || "Metadata extraction failed.";
        allMetadataContainer.appendChild(warning);
        return;
    }

    const categories = Object.entries(metadata.categories || {});

    if (!categories.length) {
        const empty = document.createElement("div");
        empty.className = "info-box";
        empty.textContent = "No embedded metadata was identified for this file.";
        allMetadataContainer.appendChild(empty);
        return;
    }

    categories.forEach(([category, fields], index) => {
        const details = document.createElement("details");
        details.className = "metadata-section";
        details.open = index === 0;

        const summary = document.createElement("summary");
        summary.textContent = `${ui.formatCategory(category)} (${fields.length})`;

        const table = document.createElement("table");
        table.className = "metadata-table";

        fields.forEach(field => {
            const row = document.createElement("tr");
            const key = document.createElement("th");
            const value = document.createElement("td");

            key.textContent = `${field.group}: ${field.name}`;
            value.textContent = formatMetadataValue(field.value);

            row.append(key, value);
            table.appendChild(row);
        });

        details.append(summary, table);
        allMetadataContainer.appendChild(details);
    });
}

function flattenMetadata(metadata) {
    const fields = [];

    Object.entries(metadata.categories || {}).forEach(([category, categoryFields]) => {
        (categoryFields || []).forEach(field => {
            fields.push({
                ...field,
                category,
                group: field.group || "Metadata",
                name: field.name || "Field",
            });
        });
    });

    return fields;
}

function isProvenanceField(field) {
    const key = `${field.group} ${field.name}`.toLowerCase();

    return /author|creator|created by|producer|software|application|toolkit|device|make|model|camera|lens|serial|document.?id|instance.?id|original.?document|gps|latitude|longitude|location|city|country|owner|artist|copyright|company|organization|organisation/.test(key);
}

function provenancePriority(field) {
    const key = `${field.group} ${field.name}`.toLowerCase();

    if (/author|creator|artist|owner/.test(key)) {
        return 1;
    }

    if (/software|application|producer|toolkit/.test(key)) {
        return 2;
    }

    if (/device|make|model|camera|lens|serial/.test(key)) {
        return 3;
    }

    if (/document.?id|instance.?id|original.?document/.test(key)) {
        return 4;
    }

    if (/gps|latitude|longitude|location|city|country/.test(key)) {
        return 5;
    }

    return 10;
}

function provenanceLabel(field) {
    const key = `${field.group} ${field.name}`.toLowerCase();

    if (/author|creator|artist|owner/.test(key)) {
        return "Authorship field";
    }

    if (/software|application|producer|toolkit/.test(key)) {
        return "Creator software";
    }

    if (/device|make|model|camera|lens|serial/.test(key)) {
        return "Device information";
    }

    if (/document.?id|instance.?id|original.?document/.test(key)) {
        return "Document identifier";
    }

    if (/gps|latitude|longitude|location|city|country/.test(key)) {
        return "Location metadata";
    }

    return "Provenance metadata";
}

function formatMetadataValue(value) {
    if (value === null || value === undefined) {
        return "Unavailable";
    }

    if (typeof value === "object") {
        return JSON.stringify(value, null, 2);
    }

    return String(value);
}

function shortenHash(value) {
    if (!value) {
        return "Unavailable";
    }

    return `${value.slice(0, 12)}…${value.slice(-8)}`;
}
