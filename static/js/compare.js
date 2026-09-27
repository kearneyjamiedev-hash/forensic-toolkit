const ui = window.ForensicUI;

const compareFileA = document.getElementById("compare-file-a");
const compareFileB = document.getElementById("compare-file-b");
const compareButton = document.getElementById("compare-button");
const comparisonLoading = document.getElementById("comparison-loading");
const comparisonResults = document.getElementById("comparison-results");
const comparisonSummary = document.getElementById("comparison-summary");
const comparisonDetails = document.getElementById("comparison-details");

[compareFileA, compareFileB].forEach(input => {
    input?.addEventListener("change", updateCompareButton);
});

compareButton?.addEventListener("click", compareFiles);

function updateCompareButton() {
    compareButton.disabled = !(
        compareFileA?.files?.length
        && compareFileB?.files?.length
    );

    comparisonResults?.classList.add("hidden");
}

async function compareFiles() {
    if (
        !compareFileA?.files?.length
        || !compareFileB?.files?.length
        || !compareButton
    ) {
        return;
    }

    compareButton.disabled = true;
    compareButton.textContent = "Comparing...";
    comparisonLoading?.classList.remove("hidden");
    comparisonResults?.classList.add("hidden");

    const form = new FormData();
    form.append("file_a", compareFileA.files[0]);
    form.append("file_b", compareFileB.files[0]);

    try {
        const response = await fetch(
            "/api/compare",
            {
                method: "POST",
                body: form,
            }
        );

        if (!response.ok) {
            throw new Error(
                await ui.responseError(response, "Comparison failed.")
            );
        }

        const data = await response.json();
        renderComparison(data);
        comparisonResults.classList.remove("hidden");
        comparisonResults.scrollIntoView({ behavior: "smooth", block: "start" });

    } catch (error) {
        alert(`Comparison failed: ${error.message}`);

    } finally {
        comparisonLoading?.classList.add("hidden");
        compareButton.disabled = false;
        compareButton.textContent = "Compare files";
    }
}

function renderComparison(comparison) {
    comparisonSummary.innerHTML = "";
    comparisonDetails.innerHTML = "";

    ui.addMetric(
        comparisonSummary,
        "SHA-256",
        comparison.summary?.same_sha256 ? "Identical" : "Different"
    );

    ui.addMetric(
        comparisonSummary,
        "File size",
        comparison.summary?.same_size ? "Identical" : "Different"
    );

    ui.addMetric(
        comparisonSummary,
        "Detected type",
        comparison.summary?.same_detected_type ? "Identical" : "Different"
    );

    ui.addMetric(
        comparisonSummary,
        "Metadata changes",
        comparison.summary?.metadata_changes ?? 0
    );

    ui.addMetric(
        comparisonSummary,
        "Artefact changes",
        comparison.summary?.artefact_changes ?? 0
    );

    ui.addMetric(
        comparisonSummary,
        "Timeline changes",
        comparison.summary?.timeline_changes ?? 0
    );

    renderComparisonFileOverview(comparison);
    renderMetadataDifferences(comparison.metadata || {});
    renderArtefactDifferences(comparison.artefacts || {});
    renderTimelineDifferences(comparison.timeline || {});
}

function renderComparisonFileOverview(comparison) {
    const section = document.createElement("section");
    section.className = "comparison-section";

    const title = document.createElement("h4");
    title.textContent = "File properties";

    const files = document.createElement("div");
    files.className = "comparison-files";
    files.append(
        comparisonFileCard("File A", comparison.files?.a || {}),
        comparisonFileCard("File B", comparison.files?.b || {})
    );

    section.append(title, files);
    comparisonDetails.appendChild(section);
}

function comparisonFileCard(heading, file) {
    const card = document.createElement("article");
    card.className = "comparison-file-card";

    const headingElement = document.createElement("strong");
    headingElement.textContent = heading;

    const filename = document.createElement("div");
    filename.textContent = file.filename || "Unavailable";

    const type = document.createElement("div");
    type.textContent = file.detected_type || "Unknown";

    const size = document.createElement("div");
    size.textContent = ui.formatBytes(file.size_bytes);

    const hash = document.createElement("div");
    hash.className = "comparison-hash";
    hash.textContent = file.sha256 || "Unavailable";

    card.append(headingElement, filename, type, size, hash);
    return card;
}

function renderMetadataDifferences(metadata) {
    const section = createComparisonSection("Metadata differences");
    let rendered = false;

    rendered = appendDifferenceGroup(
        section,
        "Changed",
        metadata.changed || [],
        item => `${item.field}: ${ui.formatSimpleValue(item.file_a)} → ${ui.formatSimpleValue(item.file_b)}`
    ) || rendered;

    rendered = appendDifferenceGroup(
        section,
        "Added in File B",
        metadata.added || [],
        item => `${item.field}: ${ui.formatSimpleValue(item.value)}`
    ) || rendered;

    rendered = appendDifferenceGroup(
        section,
        "Removed from File B",
        metadata.removed || [],
        item => `${item.field}: ${ui.formatSimpleValue(item.value)}`
    ) || rendered;

    if (!rendered) {
        section.appendChild(createEmptyDifference());
    }

    comparisonDetails.appendChild(section);
}

function renderArtefactDifferences(artefacts) {
    const section = createComparisonSection("Artefact differences");
    const categories = Object.entries(artefacts.categories || {});

    if (!categories.length) {
        section.appendChild(createEmptyDifference());
    } else {
        categories.forEach(([name, changes]) => {
            const group = document.createElement("div");
            group.className = "difference-group";

            const heading = document.createElement("strong");
            heading.textContent = ui.formatCategory(name);
            group.appendChild(heading);

            (changes.added || []).forEach(value => {
                group.appendChild(createDifferenceRow(`Added: ${value}`));
            });

            (changes.removed || []).forEach(value => {
                group.appendChild(createDifferenceRow(`Removed: ${value}`));
            });

            section.appendChild(group);
        });
    }

    comparisonDetails.appendChild(section);
}

function renderTimelineDifferences(timeline) {
    const section = createComparisonSection("Timeline differences");

    const items = [
        ...(timeline.added || []).map(event => `Added: ${timelineEventText(event)}`),
        ...(timeline.removed || []).map(event => `Removed: ${timelineEventText(event)}`),
    ];

    if (!items.length) {
        section.appendChild(createEmptyDifference());
    } else {
        items.forEach(text => section.appendChild(createDifferenceRow(text)));
    }

    comparisonDetails.appendChild(section);
}

function createComparisonSection(heading) {
    const section = document.createElement("section");
    section.className = "comparison-section";

    const title = document.createElement("h4");
    title.textContent = heading;
    section.appendChild(title);
    return section;
}

function appendDifferenceGroup(section, heading, items, formatter) {
    if (!items.length) {
        return false;
    }

    const group = document.createElement("div");
    group.className = "difference-group";

    const title = document.createElement("strong");
    title.textContent = `${heading} (${items.length})`;
    group.appendChild(title);

    items.forEach(item => {
        group.appendChild(createDifferenceRow(formatter(item)));
    });

    section.appendChild(group);
    return true;
}

function createDifferenceRow(text) {
    const row = document.createElement("div");
    row.className = "difference-row";
    row.textContent = text;
    return row;
}

function createEmptyDifference() {
    const empty = document.createElement("div");
    empty.className = "comparison-empty";
    empty.textContent = "No differences identified.";
    return empty;
}

function timelineEventText(event) {
    return `${event.source_group || "Unknown"}:${event.source_field || "unknown field"} — ${event.timestamp_utc || event.timestamp_original || "Unavailable"}`;
}
