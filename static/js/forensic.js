const fileInput = document.getElementById("file-input");
const dropZone = document.getElementById("drop-zone");
const analyseButton = document.getElementById("analyse-button");
const selectedFile = document.getElementById("selected-file");
const loading = document.getElementById("loading");
const results = document.getElementById("results");

const verifyButton = document.getElementById("verify-button");
const verifyFileInput = document.getElementById("verify-file-input");
const verificationResult = document.getElementById("verification-result");

const reportButtons = document.querySelectorAll(".report-button");

const compareFileA = document.getElementById("compare-file-a");
const compareFileB = document.getElementById("compare-file-b");
const compareButton = document.getElementById("compare-button");
const comparisonResults = document.getElementById("comparison-results");
const comparisonSummary = document.getElementById("comparison-summary");
const comparisonDetails = document.getElementById("comparison-details");

const bulkFileInput = document.getElementById("bulk-file-input");
const bulkButton = document.getElementById("bulk-button");
const bulkResults = document.getElementById("bulk-results");
const bulkFilter = document.getElementById("bulk-filter");
const bulkTableBody = document.getElementById("bulk-table-body");

let currentFile = null;
let currentEvidenceId = null;

let bulkRows = [];
let bulkSortField = "filename";
let bulkSortDirection = 1;


/*
|--------------------------------------------------------------------------
| File selection
|--------------------------------------------------------------------------
*/

if (fileInput) {
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length) {
            setCurrentFile(fileInput.files[0]);
        }
    });
}

if (dropZone) {
    dropZone.addEventListener("dragover", event => {
        event.preventDefault();
        dropZone.classList.add("dragging");
    });

    dropZone.addEventListener("dragleave", () => {
        dropZone.classList.remove("dragging");
    });

    dropZone.addEventListener("drop", event => {
        event.preventDefault();
        dropZone.classList.remove("dragging");

        if (event.dataTransfer.files.length) {
            setCurrentFile(event.dataTransfer.files[0]);
        }
    });
}

if (analyseButton) {
    analyseButton.addEventListener("click", analyseFile);
}

function setCurrentFile(file) {
    currentFile = file;

    if (selectedFile) {
        selectedFile.textContent =
            `${file.name} — ${formatBytes(file.size)}`;
    }

    if (analyseButton) {
        analyseButton.disabled = false;
    }
}


/*
|--------------------------------------------------------------------------
| Verification controls
|--------------------------------------------------------------------------
*/

if (verifyButton && verifyFileInput) {
    verifyButton.addEventListener("click", () => {
        verifyFileInput.click();
    });

    verifyFileInput.addEventListener("change", () => {
        if (verifyFileInput.files.length) {
            verifyEvidenceFile(verifyFileInput.files[0]);
        }
    });
}


/*
|--------------------------------------------------------------------------
| Report controls
|--------------------------------------------------------------------------
*/

reportButtons.forEach(button => {
    button.addEventListener("click", () => {
        downloadReport(button.dataset.reportFormat);
    });
});


/*
|--------------------------------------------------------------------------
| Comparison controls
|--------------------------------------------------------------------------
*/

function updateCompareButton() {
    if (!compareButton || !compareFileA || !compareFileB) {
        return;
    }

    compareButton.disabled = !(
        compareFileA.files.length
        && compareFileB.files.length
    );
}

if (compareFileA) {
    compareFileA.addEventListener("change", updateCompareButton);
}

if (compareFileB) {
    compareFileB.addEventListener("change", updateCompareButton);
}

if (compareButton) {
    compareButton.addEventListener("click", compareFiles);
}


/*
|--------------------------------------------------------------------------
| Bulk controls
|--------------------------------------------------------------------------
*/

if (bulkFileInput && bulkButton) {
    bulkFileInput.addEventListener("change", () => {
        bulkButton.disabled = !bulkFileInput.files.length;
    });

    bulkButton.addEventListener("click", bulkAnalyze);
}

if (bulkFilter) {
    bulkFilter.addEventListener("input", renderBulkTable);
}

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


/*
|--------------------------------------------------------------------------
| Single-file analysis
|--------------------------------------------------------------------------
*/

async function analyseFile() {
    if (!currentFile) {
        return;
    }

    loading?.classList.remove("hidden");
    results?.classList.add("hidden");

    if (analyseButton) {
        analyseButton.disabled = true;
    }

    const form = new FormData();

    form.append(
        "file",
        currentFile
    );

    form.append(
        "browser_last_modified_ms",
        currentFile.lastModified.toString()
    );

    try {
        const response =
            await fetch(
                "/api/analyze",
                {
                    method: "POST",
                    body: form
                }
            );

        if (!response.ok) {
            let errorMessage =
                "Analysis failed.";

            try {
                const error =
                    await response.json();

                errorMessage =
                    error.detail
                    || errorMessage;

            } catch {
                // Use default message.
            }

            throw new Error(
                errorMessage
            );
        }

        const data =
            await response.json();

        renderResults(
            data
        );

        results?.classList.remove(
            "hidden"
        );

    } catch (error) {
        alert(
            `Analysis failed: ${error.message}`
        );

    } finally {
        loading?.classList.add(
            "hidden"
        );

        if (analyseButton) {
            analyseButton.disabled =
                false;
        }
    }
}


function renderResults(data) {
    const filenameElement =
        document.getElementById(
            "result-filename"
        );

    const analysisTimeElement =
        document.getElementById(
            "analysis-time"
        );

    if (filenameElement) {
        filenameElement.textContent =
            data.overview?.filename
            || "Unknown file";
    }

    if (analysisTimeElement) {
        analysisTimeElement.textContent =
            (
                "Analysis time: "
                + (
                    data.analysis?.timestamp_utc
                    || "Unavailable"
                )
            );
    }

    currentEvidenceId =
        data.evidence?.id
        || null;

    if (verifyButton) {
        verifyButton.disabled =
            !currentEvidenceId;
    }

    if (verificationResult) {
        verificationResult.className =
            "verification-result hidden";

        verificationResult.innerHTML =
            "";
    }

    reportButtons.forEach(
        button => {
            button.disabled =
                !currentEvidenceId;
        }
    );

    renderWarnings(
        data.warnings
        || []
    );

    renderOverview(
        data
    );

    renderSignature(
        data.signature
        || {}
    );

    renderHashes(
        data.hashes
        || {}
    );

    renderFilesystem(
        data.filesystem
        || {}
    );

    renderTimeline(
        data.timeline
        || {
            event_count: 0,
            observation_count: 0,
            utc_normalised_count: 0,
            timezone_unknown_count: 0,
            events: [],
            observations: []
        }
    );

    renderArtefacts(
        data.artefacts
        || {
            total_found: 0,
            categories: {},
            limitations: []
        }
    );

    renderFormatAnalysis(
        data.format_analysis
        || {
            format: null,
            status: "not_applicable",
            properties: {},
            observations: [],
            embedded_objects: []
        }
    );

    renderMetadata(
        data.metadata
        || {
            status: "ok",
            field_count: 0,
            categories: {}
        }
    );
}


/*
|--------------------------------------------------------------------------
| Overview
|--------------------------------------------------------------------------
*/

function renderOverview(data) {
    const overview =
        document.getElementById(
            "overview-grid"
        );

    if (!overview) {
        return;
    }

    overview.innerHTML =
        "";

    addMetric(
        overview,
        "Filename",
        data.overview?.filename
    );

    addMetric(
        overview,
        "Extension",
        data.overview?.extension
        || "None"
    );

    addMetric(
        overview,
        "Detected type",
        data.signature?.detected_type
    );

    addMetric(
        overview,
        "MIME type",
        data.signature?.detected_mime
        || data.metadata?.summary?.mime_type
        || "Unknown"
    );

    addMetric(
        overview,
        "File size",
        formatBytes(
            data.overview?.size_bytes
        )
    );

    addMetric(
        overview,
        "Items extracted",
        data.analysis?.artifact_count
        ?? 0
    );
}


/*
|--------------------------------------------------------------------------
| Shared metric card
|--------------------------------------------------------------------------
*/

function addMetric(
    container,
    label,
    value
) {
    if (!container) {
        return;
    }

    const metric =
        document.createElement(
            "div"
        );

    metric.className =
        "metric";

    const labelElement =
        document.createElement(
            "span"
        );

    labelElement.className =
        "metric-label";

    labelElement.textContent =
        label;

    const valueElement =
        document.createElement(
            "span"
        );

    valueElement.className =
        "metric-value";

    valueElement.textContent =
        value
        ?? "Unavailable";

    metric.append(
        labelElement,
        valueElement
    );

    container.appendChild(
        metric
    );
}


/*
|--------------------------------------------------------------------------
| File signature
|--------------------------------------------------------------------------
*/

function renderSignature(signature) {
    const status =
        document.getElementById(
            "signature-status"
        );

    const content =
        document.getElementById(
            "signature-content"
        );

    if (
        !status
        || !content
    ) {
        return;
    }

    content.innerHTML =
        "";

    status.className =
        "badge";

    if (
        signature.extension_matches
        === true
    ) {
        status.textContent =
            "Signature matches";

        status.classList.add(
            "good"
        );

    } else if (
        signature.extension_matches
        === false
    ) {
        status.textContent =
            "Extension mismatch";

        status.classList.add(
            "warning"
        );

    } else {
        status.textContent =
            "Undetermined";
    }

    addProperty(
        content,
        "Filename extension",
        signature.extension
    );

    addProperty(
        content,
        "Detected type",
        signature.detected_type
    );

    addProperty(
        content,
        "Detected MIME",
        signature.detected_mime
    );

    addProperty(
        content,
        "Extension MIME",
        signature.extension_mime
    );
}


/*
|--------------------------------------------------------------------------
| Hashes
|--------------------------------------------------------------------------
*/

function renderHashes(hashes) {
    const container =
        document.getElementById(
            "hashes"
        );

    if (!container) {
        return;
    }

    container.innerHTML =
        "";

    [
        [
            "SHA-256",
            hashes.sha256
        ],

        [
            "SHA-1",
            hashes.sha1
        ],

        [
            "MD5",
            hashes.md5
        ]
    ]
    .forEach(
        ([name, value]) => {
            const row =
                document.createElement(
                    "div"
                );

            row.className =
                "hash-row";

            const nameElement =
                document.createElement(
                    "div"
                );

            nameElement.className =
                "hash-name";

            nameElement.textContent =
                name;

            const valueElement =
                document.createElement(
                    "div"
                );

            valueElement.className =
                "hash-value";

            valueElement.textContent =
                value
                ?? "Unavailable";

            row.append(
                nameElement,
                valueElement
            );

            container.appendChild(
                row
            );
        }
    );
}


/*
|--------------------------------------------------------------------------
| Filesystem
|--------------------------------------------------------------------------
*/

function renderFilesystem(
    filesystem
) {
    const note =
        document.getElementById(
            "filesystem-note"
        );

    const container =
        document.getElementById(
            "filesystem"
        );

    if (
        !note
        || !container
    ) {
        return;
    }

    note.textContent =
        filesystem.warning
        || "";

    container.innerHTML =
        "";

    addProperty(
        container,
        "Scope",
        formatScope(
            filesystem.scope
        )
    );

    addProperty(
        container,
        "Created",
        filesystem.created
    );

    addProperty(
        container,
        "Modified",
        filesystem.modified
    );

    addProperty(
        container,
        "Accessed",
        filesystem.accessed
    );

    addProperty(
        container,
        "Metadata changed",
        filesystem.metadata_changed
    );
}


/*
|--------------------------------------------------------------------------
| Shared property cards
|--------------------------------------------------------------------------
*/

function addProperty(
    container,
    name,
    value
) {
    if (!container) {
        return;
    }

    const element =
        document.createElement(
            "div"
        );

    element.className =
        "property";

    const nameElement =
        document.createElement(
            "span"
        );

    nameElement.className =
        "property-name";

    nameElement.textContent =
        name;

    const valueElement =
        document.createElement(
            "span"
        );

    valueElement.className =
        "property-value";

    valueElement.textContent =
        value
        ?? "Unavailable";

    element.append(
        nameElement,
        valueElement
    );

    container.appendChild(
        element
    );
}


/*
|--------------------------------------------------------------------------
| Timeline
|--------------------------------------------------------------------------
*/

function renderTimeline(timeline) {
    const count =
        document.getElementById(
            "timeline-count"
        );

    const summary =
        document.getElementById(
            "timeline-summary"
        );

    const observations =
        document.getElementById(
            "timeline-observations"
        );

    const container =
        document.getElementById(
            "timeline"
        );

    if (
        !count
        || !summary
        || !observations
        || !container
    ) {
        return;
    }

    const events =
        timeline.events
        || [];

    const timelineObservations =
        timeline.observations
        || [];

    const eventCount =
        timeline.event_count
        ?? events.length;

    const utcCount =
        timeline.utc_normalised_count
        ?? 0;

    const unknownTimezoneCount =
        timeline.timezone_unknown_count
        ?? 0;

    count.textContent =
        `${eventCount} ${
            eventCount === 1
                ? "timestamp"
                : "timestamps"
        }`;

    summary.innerHTML =
        "";

    observations.innerHTML =
        "";

    container.innerHTML =
        "";

    const summaryNote =
        document.createElement(
            "div"
        );

    summaryNote.className =
        "timeline-summary-note";

    if (
        eventCount
        === 0
    ) {
        summaryNote.textContent =
            (
                "No recognised forensic "
                + "timestamps were found."
            );

    } else if (
        unknownTimezoneCount
        > 0
    ) {
        summaryNote.textContent =
            (
                `${utcCount} ${
                    utcCount === 1
                        ? "timestamp was"
                        : "timestamps were"
                } normalised to UTC. `

                + `${unknownTimezoneCount} ${
                    unknownTimezoneCount === 1
                        ? "timestamp has"
                        : "timestamps have"
                } no recorded timezone. `

                + "Values without timezone information "
                + "are displayed using their recorded "
                + "wall-clock time and cannot be "
                + "reliably compared with UTC values."
            );

    } else {
        summaryNote.textContent =
            (
                `${utcCount} ${
                    utcCount === 1
                        ? "timestamp was"
                        : "timestamps were"
                } normalised to UTC. `

                + "Original timestamp values are "
                + "retained for forensic reference."
            );
    }

    summary.appendChild(
        summaryNote
    );

    timelineObservations.forEach(
        observation => {
            const element =
                document.createElement(
                    "div"
                );

            element.className =
                (
                    "timeline-observation "
                    + (
                        observation.severity
                        || "info"
                    )
                );

            const title =
                document.createElement(
                    "span"
                );

            title.className =
                "timeline-observation-title";

            title.textContent =
                observation.title
                || "Timeline observation";

            const message =
                document.createElement(
                    "span"
                );

            message.textContent =
                observation.message
                || "";

            element.append(
                title,
                message
            );

            observations.appendChild(
                element
            );
        }
    );

    if (!events.length) {
        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "info-box";

        empty.textContent =
            (
                "No recognised forensic "
                + "timestamps were found."
            );

        container.appendChild(
            empty
        );

        return;
    }

    events.forEach(
        event => {
            const item =
                document.createElement(
                    "div"
                );

            item.className =
                "timeline-item";

            if (
                event.scope
                === "evidence_copy"
            ) {
                item.classList.add(
                    "evidence-copy"
                );
            }

            const marker =
                document.createElement(
                    "div"
                );

            marker.className =
                "timeline-marker";

            const card =
                document.createElement(
                    "div"
                );

            card.className =
                "timeline-card";

            const time =
                document.createElement(
                    "div"
                );

            time.className =
                "timeline-time";

            time.textContent =
                event.timestamp_utc
                || event.timestamp_original
                || "Timestamp unavailable";

            card.appendChild(
                time
            );

            if (
                event.timestamp_utc
                && event.timestamp_original
                && event.timestamp_original
                    !== event.timestamp_utc
            ) {
                const original =
                    document.createElement(
                        "div"
                    );

                original.className =
                    "timeline-original";

                original.textContent =
                    (
                        "Original: "
                        + event.timestamp_original
                    );

                card.appendChild(
                    original
                );
            }

            const title =
                document.createElement(
                    "div"
                );

            title.className =
                "timeline-event-title";

            title.textContent =
                event.label
                || "Timestamp";

            const source =
                document.createElement(
                    "div"
                );

            source.className =
                "timeline-event-source";

            source.textContent =
                (
                    `${
                        event.source_group
                        || event.source
                        || "Unknown source"
                    }:`
                    + `${
                        event.source_field
                        || "unknown field"
                    }`
                );

            const badges =
                document.createElement(
                    "div"
                );

            badges.className =
                "timeline-badges";

            const scopeBadge =
                document.createElement(
                    "span"
                );

            scopeBadge.className =
                "timeline-badge";

            scopeBadge.textContent =
                formatScope(
                    event.scope
                );

            badges.appendChild(
                scopeBadge
            );

            const timezoneBadge =
                document.createElement(
                    "span"
                );

            if (
                event.timestamp_utc
            ) {
                timezoneBadge.className =
                    "timeline-badge";

                timezoneBadge.textContent =
                    "UTC normalised";

            } else {
                timezoneBadge.className =
                    (
                        "timeline-badge "
                        + "timezone-warning"
                    );

                timezoneBadge.textContent =
                    "Timezone unknown";
            }

            badges.appendChild(
                timezoneBadge
            );

            card.append(
                title,
                source,
                badges
            );

            if (
                event.notes
                && event.notes.length
            ) {
                const note =
                    document.createElement(
                        "div"
                    );

                note.className =
                    "timeline-note";

                note.textContent =
                    event.notes.join(
                        " "
                    );

                card.appendChild(
                    note
                );
            }

            item.append(
                marker,
                card
            );

            container.appendChild(
                item
            );
        }
    );
}


/*
|--------------------------------------------------------------------------
| Interesting artefacts
|--------------------------------------------------------------------------
*/

function renderArtefacts(
    artefacts
) {
    const count =
        document.getElementById(
            "artefact-count"
        );

    const note =
        document.getElementById(
            "artefact-note"
        );

    const container =
        document.getElementById(
            "artefacts"
        );

    if (
        !count
        || !note
        || !container
    ) {
        return;
    }

    const totalFound =
        artefacts.total_found
        ?? 0;

    count.textContent =
        `${totalFound} ${
            totalFound === 1
                ? "artefact"
                : "artefacts"
        }`;

    note.textContent =
        (
            "These values were extracted from "
            + "readable ASCII and UTF-16LE strings. "
            + "They are investigative leads, not "
            + "automatic indicators of malicious activity."
        );

    container.innerHTML =
        "";

    const categories =
        Object.values(
            artefacts.categories
            || {}
        );

    const populated =
        categories.filter(
            category =>
                (
                    category.count
                    ?? 0
                ) > 0
        );

    if (
        !populated.length
    ) {
        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "artefact-empty";

        empty.textContent =
            (
                "No interesting artefacts "
                + "were identified."
            );

        container.appendChild(
            empty
        );

        return;
    }

    populated.forEach(
        category => {
            const details =
                document.createElement(
                    "details"
                );

            details.className =
                "artefact-section";

            const summary =
                document.createElement(
                    "summary"
                );

            summary.textContent =
                (
                    `${category.label} `
                    + `(${category.count})`
                );

            const list =
                document.createElement(
                    "div"
                );

            list.className =
                "artefact-list";

            (
                category.items
                || []
            )
            .forEach(
                item => {
                    const row =
                        document.createElement(
                            "div"
                        );

                    row.className =
                        "artefact-item";

                    const value =
                        document.createElement(
                            "div"
                        );

                    value.className =
                        "artefact-value";

                    value.textContent =
                        item.value;

                    const metadata =
                        document.createElement(
                            "div"
                        );

                    metadata.className =
                        "artefact-meta";

                    const parts =
                        [];

                    const encodings =
                        (
                            item.encodings
                            || []
                        )
                        .join(
                            ", "
                        );

                    const offsets =
                        (
                            item.offsets_hex
                            || []
                        )
                        .join(
                            ", "
                        );

                    if (encodings) {
                        parts.push(
                            encodings
                        );
                    }

                    if (offsets) {
                        parts.push(
                            offsets
                        );
                    }

                    if (
                        (
                            item.occurrences
                            ?? 1
                        ) > 1
                    ) {
                        parts.push(
                            (
                                `${item.occurrences} `
                                + "occurrences"
                            )
                        );
                    }

                    metadata.textContent =
                        parts.join(
                            " • "
                        );

                    row.append(
                        value,
                        metadata
                    );

                    list.appendChild(
                        row
                    );
                }
            );

            details.append(
                summary,
                list
            );

            container.appendChild(
                details
            );
        }
    );
}


/*
|--------------------------------------------------------------------------
| Evidence verification
|--------------------------------------------------------------------------
*/

async function verifyEvidenceFile(
    file
) {
    if (
        !currentEvidenceId
        || !verifyButton
        || !verificationResult
    ) {
        return;
    }

    verifyButton.disabled =
        true;

    verifyButton.textContent =
        "Verifying...";

    const form =
        new FormData();

    form.append(
        "file",
        file
    );

    try {
        const response =
            await fetch(
                `/api/evidence/${currentEvidenceId}/verify`,
                {
                    method: "POST",
                    body: form
                }
            );

        if (
            !response.ok
        ) {
            let errorMessage =
                "Verification failed.";

            try {
                const error =
                    await response.json();

                errorMessage =
                    error.detail
                    || errorMessage;

            } catch {
                // Use default message.
            }

            throw new Error(
                errorMessage
            );
        }

        const data =
            await response.json();

        verificationResult.innerHTML =
            "";

        verificationResult.className =
            (
                "verification-result "
                + (
                    data.verified
                        ? "verified"
                        : "failed"
                )
            );

        const title =
            document.createElement(
                "strong"
            );

        title.textContent =
            data.message;

        const hashes =
            document.createElement(
                "div"
            );

        hashes.className =
            "verification-hashes";

        const expected =
            document.createElement(
                "div"
            );

        expected.textContent =
            (
                "Original SHA-256: "
                + data.expected_sha256
            );

        const current =
            document.createElement(
                "div"
            );

        current.textContent =
            (
                "Current SHA-256: "
                + data.current_sha256
            );

        hashes.append(
            expected,
            current
        );

        verificationResult.append(
            title,
            hashes
        );

        verificationResult.classList.remove(
            "hidden"
        );

    } catch (error) {
        alert(
            (
                "Verification failed: "
                + error.message
            )
        );

    } finally {
        verifyButton.disabled =
            false;

        verifyButton.textContent =
            "Verify file";

        if (
            verifyFileInput
        ) {
            verifyFileInput.value =
                "";
        }
    }
}


/*
|--------------------------------------------------------------------------
| Reports
|--------------------------------------------------------------------------
*/

function downloadReport(
    format
) {
    if (
        !currentEvidenceId
        || !format
    ) {
        return;
    }

    window.location.href =
        (
            `/api/evidence/`
            + `${currentEvidenceId}`
            + `/report/`
            + `${format}`
        );
}


/*
|--------------------------------------------------------------------------
| Format-specific analysis
|--------------------------------------------------------------------------
*/

function renderFormatAnalysis(
    analysis
) {
    const status =
        document.getElementById(
            "format-analysis-status"
        );

    const container =
        document.getElementById(
            "format-analysis"
        );

    if (
        !status
        || !container
    ) {
        return;
    }

    container.innerHTML =
        "";

    status.className =
        "badge";

    if (
        analysis.status
        === "ok"
    ) {
        status.textContent =
            (
                analysis.format
                ? analysis.format.toUpperCase()
                : "Analysed"
            );

        status.classList.add(
            "good"
        );

    } else if (
        analysis.status
        === "error"
    ) {
        status.textContent =
            "Parsing issue";

        status.classList.add(
            "warning"
        );

    } else {
        status.textContent =
            "Not applicable";
    }

    const properties =
        Object.entries(
            analysis.properties
            || {}
        );

    if (
        properties.length
    ) {
        const grid =
            document.createElement(
                "div"
            );

        grid.className =
            "property-grid";

        properties.forEach(
            ([name, value]) => {
                addProperty(
                    grid,
                    formatCategory(
                        name
                    ),
                    formatSimpleValue(
                        value
                    )
                );
            }
        );

        container.appendChild(
            grid
        );
    }

    (
        analysis.observations
        || []
    )
    .forEach(
        observation => {
            const item =
                document.createElement(
                    "div"
                );

            item.className =
                (
                    "format-observation "
                    + (
                        observation.severity
                        || "info"
                    )
                );

            const title =
                document.createElement(
                    "strong"
                );

            title.textContent =
                observation.title;

            const message =
                document.createElement(
                    "div"
                );

            message.textContent =
                observation.message;

            item.append(
                title,
                message
            );

            container.appendChild(
                item
            );
        }
    );

    const objects =
        analysis.embedded_objects
        || [];

    if (
        objects.length
    ) {
        const details =
            document.createElement(
                "details"
            );

        details.className =
            "metadata-section";

        const summary =
            document.createElement(
                "summary"
            );

        summary.textContent =
            (
                `Internal objects `
                + `(${objects.length})`
            );

        const table =
            document.createElement(
                "table"
            );

        table.className =
            "metadata-table";

        objects.forEach(
            object => {
                const row =
                    document.createElement(
                        "tr"
                    );

                const name =
                    document.createElement(
                        "th"
                    );

                name.textContent =
                    object.name
                    || object.type
                    || "Object";

                const value =
                    document.createElement(
                        "td"
                    );

                value.textContent =
                    JSON.stringify(
                        object,
                        null,
                        2
                    );

                row.append(
                    name,
                    value
                );

                table.appendChild(
                    row
                );
            }
        );

        details.append(
            summary,
            table
        );

        container.appendChild(
            details
        );
    }

    if (
        analysis.status
        === "not_applicable"
    ) {
        const message =
            document.createElement(
                "div"
            );

        message.className =
            "artefact-empty";

        message.textContent =
            (
                "No dedicated format analyzer "
                + "is currently required for this file."
            );

        container.appendChild(
            message
        );
    }
}


/*
|--------------------------------------------------------------------------
| Metadata
|--------------------------------------------------------------------------
*/

function renderMetadata(
    metadata
) {
    const count =
        document.getElementById(
            "metadata-count"
        );

    const container =
        document.getElementById(
            "metadata"
        );

    if (
        !count
        || !container
    ) {
        return;
    }

    const fieldCount =
        metadata.field_count
        ?? 0;

    count.textContent =
        `${fieldCount} ${
            fieldCount === 1
                ? "field"
                : "fields"
        }`;

    container.innerHTML =
        "";

    if (
        metadata.status
        !== "ok"
    ) {
        const warning =
            document.createElement(
                "div"
            );

        warning.className =
            "warning-box";

        warning.textContent =
            (
                metadata.error
                || "Metadata extraction failed."
            );

        container.appendChild(
            warning
        );

        return;
    }

    const categories =
        Object.entries(
            metadata.categories
            || {}
        );

    if (
        !categories.length
    ) {
        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "info-box";

        empty.textContent =
            (
                "No embedded metadata was "
                + "identified for this file."
            );

        container.appendChild(
            empty
        );

        return;
    }

    categories.forEach(
        ([category, fields], index) => {
            const details =
                document.createElement(
                    "details"
                );

            details.className =
                "metadata-section";

            if (
                index === 0
            ) {
                details.open =
                    true;
            }

            const summary =
                document.createElement(
                    "summary"
                );

            summary.textContent =
                (
                    `${formatCategory(category)} `
                    + `(${fields.length})`
                );

            const table =
                document.createElement(
                    "table"
                );

            table.className =
                "metadata-table";

            fields.forEach(
                field => {
                    const row =
                        document.createElement(
                            "tr"
                        );

                    const key =
                        document.createElement(
                            "th"
                        );

                    const value =
                        document.createElement(
                            "td"
                        );

                    key.textContent =
                        (
                            `${field.group}:`
                            + `${field.name}`
                        );

                    value.textContent =
                        formatMetadataValue(
                            field.value
                        );

                    row.append(
                        key,
                        value
                    );

                    table.appendChild(
                        row
                    );
                }
            );

            details.append(
                summary,
                table
            );

            container.appendChild(
                details
            );
        }
    );
}


/*
|--------------------------------------------------------------------------
| General warnings
|--------------------------------------------------------------------------
*/

function renderWarnings(
    warnings
) {
    const container =
        document.getElementById(
            "warnings"
        );

    if (!container) {
        return;
    }

    container.innerHTML =
        "";

    if (
        !warnings.length
    ) {
        return;
    }

    warnings.forEach(
        warning => {
            const element =
                document.createElement(
                    "div"
                );

            element.className =
                "warning-box";

            element.textContent =
                warning.message
                || "Analysis warning.";

            container.appendChild(
                element
            );
        }
    );
}


/*
|--------------------------------------------------------------------------
| File comparison
|--------------------------------------------------------------------------
*/

async function compareFiles() {
    if (
        !compareFileA
        || !compareFileB
        || !compareButton
        || !compareFileA.files.length
        || !compareFileB.files.length
    ) {
        return;
    }

    compareButton.disabled =
        true;

    compareButton.textContent =
        "Comparing...";

    const form =
        new FormData();

    form.append(
        "file_a",
        compareFileA.files[0]
    );

    form.append(
        "file_b",
        compareFileB.files[0]
    );

    try {
        const response =
            await fetch(
                "/api/compare",
                {
                    method: "POST",
                    body: form
                }
            );

        if (
            !response.ok
        ) {
            let errorMessage =
                "Comparison failed.";

            try {
                const error =
                    await response.json();

                errorMessage =
                    error.detail
                    || errorMessage;

            } catch {
                // Use default message.
            }

            throw new Error(
                errorMessage
            );
        }

        const data =
            await response.json();

        renderComparison(
            data
        );

        comparisonResults?.classList.remove(
            "hidden"
        );

    } catch (error) {
        alert(
            (
                "Comparison failed: "
                + error.message
            )
        );

    } finally {
        compareButton.disabled =
            false;

        compareButton.textContent =
            "Compare files";
    }
}


function renderComparison(
    comparison
) {
    if (
        !comparisonSummary
        || !comparisonDetails
    ) {
        return;
    }

    comparisonSummary.innerHTML =
        "";

    comparisonDetails.innerHTML =
        "";

    addMetric(
        comparisonSummary,
        "SHA-256",
        (
            comparison.summary?.same_sha256
                ? "Identical"
                : "Different"
        )
    );

    addMetric(
        comparisonSummary,
        "File size",
        (
            comparison.summary?.same_size
                ? "Identical"
                : "Different"
        )
    );

    addMetric(
        comparisonSummary,
        "Detected type",
        (
            comparison.summary?.same_detected_type
                ? "Identical"
                : "Different"
        )
    );

    addMetric(
        comparisonSummary,
        "Metadata changes",
        comparison.summary?.metadata_changes
        ?? 0
    );

    addMetric(
        comparisonSummary,
        "Artefact changes",
        comparison.summary?.artefact_changes
        ?? 0
    );

    addMetric(
        comparisonSummary,
        "Timeline changes",
        comparison.summary?.timeline_changes
        ?? 0
    );

    renderComparisonFileOverview(
        comparison
    );

    renderMetadataDifferences(
        comparison.metadata
        || {
            added: [],
            removed: [],
            changed: []
        }
    );

    renderArtefactDifferences(
        comparison.artefacts
        || {
            categories: {}
        }
    );

    renderTimelineDifferences(
        comparison.timeline
        || {
            added: [],
            removed: []
        }
    );
}


function renderComparisonFileOverview(
    comparison
) {
    if (!comparisonDetails) {
        return;
    }

    const section =
        document.createElement(
            "div"
        );

    section.className =
        "comparison-section";

    section.innerHTML =
        `
        <h4>
            File properties
        </h4>

        <div class="comparison-files">

            ${comparisonFileCard(
                "File A",
                comparison.files?.a
                || {}
            )}

            ${comparisonFileCard(
                "File B",
                comparison.files?.b
                || {}
            )}

        </div>
        `;

    comparisonDetails.appendChild(
        section
    );
}


function comparisonFileCard(
    heading,
    file
) {
    return `
        <div class="comparison-file-card">

            <strong>
                ${escapeHtml(heading)}
            </strong>

            <div>
                ${escapeHtml(
                    file.filename
                    || "Unavailable"
                )}
            </div>

            <div>
                ${escapeHtml(
                    file.detected_type
                    || "Unknown"
                )}
            </div>

            <div>
                ${escapeHtml(
                    formatBytes(
                        file.size_bytes
                    )
                )}
            </div>

            <div class="comparison-hash">
                ${escapeHtml(
                    file.sha256
                    || "Unavailable"
                )}
            </div>

        </div>
    `;
}


function renderMetadataDifferences(
    metadata
) {
    const section =
        createComparisonSection(
            "Metadata differences"
        );

    let rendered =
        false;

    rendered =
        (
            appendDifferenceGroup(
                section,
                "Changed",
                metadata.changed
                || [],
                item =>
                    (
                        `${item.field}: `
                        + `${formatSimpleValue(
                            item.file_a
                        )}`
                        + " → "
                        + `${formatSimpleValue(
                            item.file_b
                        )}`
                    )
            )
            || rendered
        );

    rendered =
        (
            appendDifferenceGroup(
                section,
                "Added in File B",
                metadata.added
                || [],
                item =>
                    (
                        `${item.field}: `
                        + formatSimpleValue(
                            item.value
                        )
                    )
            )
            || rendered
        );

    rendered =
        (
            appendDifferenceGroup(
                section,
                "Removed from File B",
                metadata.removed
                || [],
                item =>
                    (
                        `${item.field}: `
                        + formatSimpleValue(
                            item.value
                        )
                    )
            )
            || rendered
        );

    if (
        !rendered
    ) {
        section.appendChild(
            createEmptyDifference()
        );
    }

    comparisonDetails?.appendChild(
        section
    );
}


function renderArtefactDifferences(
    artefacts
) {
    const section =
        createComparisonSection(
            "Artefact differences"
        );

    const categories =
        Object.entries(
            artefacts.categories
            || {}
        );

    if (
        !categories.length
    ) {
        section.appendChild(
            createEmptyDifference()
        );

    } else {
        categories.forEach(
            ([name, changes]) => {
                const group =
                    document.createElement(
                        "div"
                    );

                group.className =
                    "difference-group";

                const heading =
                    document.createElement(
                        "strong"
                    );

                heading.textContent =
                    formatCategory(
                        name
                    );

                group.appendChild(
                    heading
                );

                (
                    changes.added
                    || []
                )
                .forEach(
                    value => {
                        group.appendChild(
                            createDifferenceRow(
                                `Added: ${value}`
                            )
                        );
                    }
                );

                (
                    changes.removed
                    || []
                )
                .forEach(
                    value => {
                        group.appendChild(
                            createDifferenceRow(
                                `Removed: ${value}`
                            )
                        );
                    }
                );

                section.appendChild(
                    group
                );
            }
        );
    }

    comparisonDetails?.appendChild(
        section
    );
}


function renderTimelineDifferences(
    timeline
) {
    const section =
        createComparisonSection(
            "Timeline differences"
        );

    const items = [
        ...(
            timeline.added
            || []
        )
        .map(
            event =>
                (
                    "Added: "
                    + timelineEventText(
                        event
                    )
                )
        ),

        ...(
            timeline.removed
            || []
        )
        .map(
            event =>
                (
                    "Removed: "
                    + timelineEventText(
                        event
                    )
                )
        )
    ];

    if (
        !items.length
    ) {
        section.appendChild(
            createEmptyDifference()
        );

    } else {
        items.forEach(
            text => {
                section.appendChild(
                    createDifferenceRow(
                        text
                    )
                );
            }
        );
    }

    comparisonDetails?.appendChild(
        section
    );
}


function createComparisonSection(
    heading
) {
    const section =
        document.createElement(
            "div"
        );

    section.className =
        "comparison-section";

    const title =
        document.createElement(
            "h4"
        );

    title.textContent =
        heading;

    section.appendChild(
        title
    );

    return section;
}


function appendDifferenceGroup(
    section,
    heading,
    items,
    formatter
) {
    if (
        !items.length
    ) {
        return false;
    }

    const group =
        document.createElement(
            "div"
        );

    group.className =
        "difference-group";

    const title =
        document.createElement(
            "strong"
        );

    title.textContent =
        `${heading} (${items.length})`;

    group.appendChild(
        title
    );

    items.forEach(
        item => {
            group.appendChild(
                createDifferenceRow(
                    formatter(
                        item
                    )
                )
            );
        }
    );

    section.appendChild(
        group
    );

    return true;
}


function createDifferenceRow(
    text
) {
    const row =
        document.createElement(
            "div"
        );

    row.className =
        "difference-row";

    row.textContent =
        text;

    return row;
}


function createEmptyDifference() {
    const empty =
        document.createElement(
            "div"
        );

    empty.className =
        "comparison-empty";

    empty.textContent =
        "No differences identified.";

    return empty;
}


function timelineEventText(
    event
) {
    return (
        `${event.source_group || "Unknown"}:`
        + `${event.source_field || "unknown field"} — `
        + (
            event.timestamp_utc
            || event.timestamp_original
            || "Unavailable"
        )
    );
}


/*
|--------------------------------------------------------------------------
| Bulk analysis
|--------------------------------------------------------------------------
*/

async function bulkAnalyze() {
    if (
        !bulkFileInput
        || !bulkButton
        || !bulkFileInput.files.length
    ) {
        return;
    }

    bulkButton.disabled =
        true;

    bulkButton.textContent =
        "Analysing...";

    const form =
        new FormData();

    Array.from(
        bulkFileInput.files
    )
    .forEach(
        file => {
            form.append(
                "files",
                file
            );
        }
    );

    try {
        const response =
            await fetch(
                "/api/bulk-analyze",
                {
                    method: "POST",
                    body: form
                }
            );

        if (
            !response.ok
        ) {
            let errorMessage =
                "Bulk analysis failed.";

            try {
                const error =
                    await response.json();

                errorMessage =
                    error.detail
                    || errorMessage;

            } catch {
                // Use default message.
            }

            throw new Error(
                errorMessage
            );
        }

        const data =
            await response.json();

        bulkRows =
            data.rows
            || [];

        renderBulkTable();

        bulkResults?.classList.remove(
            "hidden"
        );

    } catch (error) {
        alert(
            (
                "Bulk analysis failed: "
                + error.message
            )
        );

    } finally {
        bulkButton.disabled =
            false;

        bulkButton.textContent =
            "Analyse selected files";
    }
}


function renderBulkTable() {
    if (
        !bulkTableBody
    ) {
        return;
    }

    const filter =
        (
            bulkFilter?.value
            || ""
        )
        .toLowerCase();

    const filtered =
        bulkRows.filter(
            row => {
                const searchable =
                    JSON.stringify(
                        row
                    )
                    .toLowerCase();

                return searchable.includes(
                    filter
                );
            }
        );

    filtered.sort(
        (a, b) => {
            const valueA =
                a[
                    bulkSortField
                ]
                ?? "";

            const valueB =
                b[
                    bulkSortField
                ]
                ?? "";

            if (
                typeof valueA
                === "number"
                &&
                typeof valueB
                === "number"
            ) {
                return (
                    valueA
                    - valueB
                )
                * bulkSortDirection;
            }

            return String(
                valueA
            )
            .localeCompare(
                String(
                    valueB
                )
            )
            * bulkSortDirection;
        }
    );

    bulkTableBody.innerHTML =
        "";

    filtered.forEach(
        row => {
            const tr =
                document.createElement(
                    "tr"
                );

            appendBulkCell(
                tr,
                row.filename
            );

            appendBulkCell(
                tr,
                row.type
            );

            appendBulkCell(
                tr,
                row.sha256,
                "bulk-hash"
            );

            appendBulkCell(
                tr,
                formatBytes(
                    row.size_bytes
                )
            );

            appendBulkCell(
                tr,
                row.created
                || "Unavailable"
            );

            appendBulkCell(
                tr,
                row.modified
                || "Unavailable"
            );

            appendBulkCell(
                tr,
                row.artefact_count
            );

            appendBulkCell(
                tr,
                (
                    row.observations
                    || []
                )
                .join(
                    "; "
                )
                || "None"
            );

            bulkTableBody.appendChild(
                tr
            );
        }
    );
}


function appendBulkCell(
    row,
    value,
    className = null
) {
    const cell =
        document.createElement(
            "td"
        );

    if (
        className
    ) {
        cell.className =
            className;
    }

    cell.textContent =
        value
        ?? "Unavailable";

    row.appendChild(
        cell
    );
}


/*
|--------------------------------------------------------------------------
| Shared formatting helpers
|--------------------------------------------------------------------------
*/

function formatBytes(
    bytes
) {
    if (
        bytes === null
        || bytes === undefined
        || Number.isNaN(
            Number(
                bytes
            )
        )
    ) {
        return "Unavailable";
    }

    const numericBytes =
        Number(
            bytes
        );

    if (
        numericBytes === 0
    ) {
        return "0 B";
    }

    if (
        numericBytes < 0
    ) {
        return "Unavailable";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    ];

    const index =
        Math.floor(
            Math.log(
                numericBytes
            )
            / Math.log(
                1024
            )
        );

    const safeIndex =
        Math.max(
            0,
            Math.min(
                index,
                units.length - 1
            )
        );

    return (
        `${(
            numericBytes
            / Math.pow(
                1024,
                safeIndex
            )
        ).toFixed(2)} ${units[safeIndex]}`
    );
}


function formatMetadataValue(
    value
) {
    if (
        value === null
        || value === undefined
    ) {
        return "Unavailable";
    }

    if (
        typeof value
        === "object"
    ) {
        return JSON.stringify(
            value,
            null,
            2
        );
    }

    return String(
        value
    );
}


function formatCategory(
    category
) {
    if (
        !category
    ) {
        return "Other";
    }

    return String(
        category
    )
    .replaceAll(
        "_",
        " "
    )
    .replace(
        /\b\w/g,
        character =>
            character.toUpperCase()
    );
}


function formatScope(
    scope
) {
    if (
        !scope
    ) {
        return "Unavailable";
    }

    return String(
        scope
    )
    .replaceAll(
        "_",
        " "
    )
    .replace(
        /\b\w/g,
        character =>
            character.toUpperCase()
    );
}


function formatSimpleValue(
    value
) {
    if (
        value === null
        || value === undefined
    ) {
        return "Unavailable";
    }

    if (
        typeof value
        === "object"
    ) {
        return JSON.stringify(
            value
        );
    }

    return String(
        value
    );
}


function escapeHtml(
    value
) {
    const element =
        document.createElement(
            "div"
        );

    element.textContent =
        value
        ?? "";

    return element.innerHTML;
}

/*
|--------------------------------------------------------------------------
| Portfolio / Demo Mode
|--------------------------------------------------------------------------
*/

const demoSampleSelect =
    document.getElementById(
        "demo-sample-select"
    );

const demoLoadButton =
    document.getElementById(
        "demo-load-button"
    );

const demoDownloadButton =
    document.getElementById(
        "demo-download-button"
    );

const demoDescription =
    document.getElementById(
        "demo-description"
    );


let demoSamples = [];


/*
|--------------------------------------------------------------------------
| Load available demo evidence
|--------------------------------------------------------------------------
*/

async function loadDemoManifest() {

    if (
        !demoSampleSelect
        || !demoLoadButton
    ) {
        return;
    }


    demoSampleSelect.disabled =
        true;


    demoLoadButton.disabled =
        true;


    if (demoDownloadButton) {

        demoDownloadButton.disabled =
            true;
    }


    try {

        const response =
            await fetch(
                "/api/demo/samples"
            );


        if (!response.ok) {

            throw new Error(
                "Demo evidence catalogue could not be loaded."
            );
        }


        const data =
            await response.json();


        demoSamples =
            data.samples
            || [];


        demoSampleSelect.innerHTML =
            "";


        const placeholder =
            document.createElement(
                "option"
            );


        placeholder.value =
            "";


        placeholder.textContent =
            "Choose demonstration evidence";


        demoSampleSelect.appendChild(
            placeholder
        );


        demoSamples.forEach(
            sample => {

                const option =
                    document.createElement(
                        "option"
                    );


                option.value =
                    sample.id;


                option.textContent =
                    sample.title;


                demoSampleSelect.appendChild(
                    option
                );
            }
        );


        demoSampleSelect.disabled =
            false;


        if (demoDescription) {

            demoDescription.textContent =
                (
                    "Select a scenario to run safe "
                    + "generated evidence through the "
                    + "same analysis engine used for "
                    + "uploaded files."
                );
        }


    } catch (error) {

        demoSampleSelect.innerHTML =
            "";


        const option =
            document.createElement(
                "option"
            );


        option.value =
            "";


        option.textContent =
            "Demo evidence unavailable";


        demoSampleSelect.appendChild(
            option
        );


        if (demoDescription) {

            demoDescription.textContent =
                error.message;
        }
    }
}


/*
|--------------------------------------------------------------------------
| Demo selection
|--------------------------------------------------------------------------
*/

demoSampleSelect?.addEventListener(
    "change",
    () => {

        const selectedId =
            demoSampleSelect.value;


        const sample =
            demoSamples.find(
                item =>
                    item.id === selectedId
            );


        const hasSample =
            Boolean(
                sample
            );


        if (demoLoadButton) {

            demoLoadButton.disabled =
                !hasSample;
        }


        if (demoDownloadButton) {

            demoDownloadButton.disabled =
                !hasSample;
        }


        if (
            demoDescription
            && sample
        ) {

            demoDescription.textContent =
                sample.description;
        }


        if (
            demoDescription
            && !sample
        ) {

            demoDescription.textContent =
                (
                    "Select a scenario to see "
                    + "what it demonstrates."
                );
        }
    }
);


/*
|--------------------------------------------------------------------------
| Analyse selected demo evidence
|--------------------------------------------------------------------------
*/

demoLoadButton?.addEventListener(
    "click",
    loadDemoEvidence
);


async function loadDemoEvidence() {

    const sampleId =
        demoSampleSelect?.value;


    if (
        !sampleId
        || !demoLoadButton
    ) {
        return;
    }


    demoLoadButton.disabled =
        true;


    demoLoadButton.textContent =
        "Analysing demo...";


    try {

        loading?.classList.remove(
            "hidden"
        );


        results?.classList.add(
            "hidden"
        );


        const response =
            await fetch(
                (
                    "/api/demo/analyze/"
                    + encodeURIComponent(
                        sampleId
                    )
                ),
                {
                    method:
                        "POST"
                }
            );


        if (!response.ok) {

            let errorMessage =
                "Demo analysis failed.";


            try {

                const error =
                    await response.json();


                errorMessage =
                    error.detail
                    || errorMessage;


            } catch {

                // Keep default message.
            }


            throw new Error(
                errorMessage
            );
        }


        const data =
            await response.json();


        /*
        |--------------------------------------------------------------
        | Uses the same result renderer as normal uploaded evidence.
        | This means demo evidence also gets:
        |
        | - Overview
        | - Signature analysis
        | - Hashes
        | - Filesystem timestamps
        | - Timeline
        | - Artefacts
        | - Format-specific analysis
        | - Metadata
        |--------------------------------------------------------------
        */

        renderResults(
            data
        );


        results?.classList.remove(
            "hidden"
        );


        if (
            demoDescription
            && data.demo
        ) {

            demoDescription.textContent =
                (
                    `${data.demo.title}: `
                    + data.demo.description
                );
        }


        results?.scrollIntoView(
            {
                behavior:
                    "smooth",

                block:
                    "start"
            }
        );


    } catch (error) {

        alert(
            (
                "Demo analysis failed: "
                + error.message
            )
        );


    } finally {

        loading?.classList.add(
            "hidden"
        );


        demoLoadButton.disabled =
            false;


        demoLoadButton.textContent =
            "Load demo evidence";
    }
}


/*
|--------------------------------------------------------------------------
| Download selected demo evidence
|--------------------------------------------------------------------------
*/

demoDownloadButton?.addEventListener(
    "click",
    () => {

        const sampleId =
            demoSampleSelect?.value;


        if (!sampleId) {
            return;
        }


        window.location.href =
            (
                "/api/demo/file/"
                + encodeURIComponent(
                    sampleId
                )
            );
    }
);


/*
|--------------------------------------------------------------------------
| Initialise demo mode
|--------------------------------------------------------------------------
*/

loadDemoManifest();