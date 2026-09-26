const pageLoading = document.getElementById("analysis-page-loading");
const pageError = document.getElementById("analysis-page-error");
const pageErrorMessage = document.getElementById("analysis-page-error-message");
const workspace = document.getElementById("analysis-workspace");

const caseReference = document.getElementById("analysis-case-reference");
const evidenceIdLabel = document.getElementById("analysis-evidence-id");
const acquisitionBadge = document.getElementById("analysis-acquisition-badge");
const sourceSummary = document.getElementById("analysis-source-summary");
const acquisitionHashes = document.getElementById("analysis-acquisition-hashes");

const actionHeading = document.getElementById("analysis-action-heading");
const actionDescription = document.getElementById("analysis-action-description");
const runAnalysisButton = document.getElementById("run-analysis-button");
const analysisRunning = document.getElementById("analysis-running");

const analysisResult = document.getElementById("analysis-result");
const analysisFilename = document.getElementById("analysis-filename");
const preservationBadge = document.getElementById("analysis-preservation-badge");
const overview = document.getElementById("analysis-overview");
const timelineBody = document.getElementById("analysis-timeline-body");
const timelineNote = document.getElementById("analysis-timeline-note");

const forensicPdfLink = document.getElementById("forensic-pdf-link");
const forensicJsonLink = document.getElementById("forensic-json-link");
const timelineCsvLink = document.getElementById("timeline-csv-link");
const artefactsCsvLink = document.getElementById("artefacts-csv-link");
const forensicHtmlLink = document.getElementById("forensic-html-link");

const params = new URLSearchParams(
    window.location.search
);

const evidenceId =
    params.get(
        "evidence_id"
    );

let collectorToken = null;
let acquisitionStatus = null;


/*
|--------------------------------------------------------------------------
| Initialise analysis workspace
|--------------------------------------------------------------------------
*/

async function initialiseAnalysisPage() {

    if (!evidenceId) {

        showPageError(
            "No evidence ID was supplied. Return to Logical Evidence "
            + "Collection and select an acquired item."
        );

        return;
    }

    try {

        const sessionResponse = await fetch(
            "/api/acquisition/session"
        );

        if (!sessionResponse.ok) {

            throw new Error(
                "The local collector session could not be started."
            );
        }

        const session = await sessionResponse.json();

        collectorToken =
            session.token;

        const statusResponse = await fetch(
            `/api/acquisition/${encodeURIComponent(evidenceId)}/status`,
            {
                headers:
                    collectorHeaders(),
            }
        );

        if (!statusResponse.ok) {

            throw new Error(
                await responseError(
                    statusResponse
                )
            );
        }

        acquisitionStatus =
            await statusResponse.json();

        renderAcquisitionStatus(
            acquisitionStatus
        );

        configureReportLinks();

        workspace.classList.remove(
            "hidden"
        );

        pageLoading.classList.add(
            "hidden"
        );

        if (
            acquisitionStatus.analysis_available
        ) {

            await loadExistingAnalysis();

        } else {

            runAnalysisButton.disabled =
                false;
        }

    } catch (error) {

        showPageError(
            error.message
        );
    }
}


/*
|--------------------------------------------------------------------------
| Acquisition context
|--------------------------------------------------------------------------
*/

function renderAcquisitionStatus(
    data
) {

    const source =
        data.source
        || {};

    const integrity =
        data.integrity
        || {};

    caseReference.textContent =
        data.case_reference
        || "Acquired evidence";

    evidenceIdLabel.textContent =
        "Evidence ID: "
        + data.evidence_id;

    const verified = (
        integrity.source_content_unchanged
            === true

        && integrity.master_verified
            === true

        && integrity.working_verified
            === true
    );

    acquisitionBadge.className =
        "badge "
        + (
            verified
                ? "good"
                : "warning"
        );

    acquisitionBadge.textContent =
        verified
            ? "Acquisition verified"
            : "Integrity warning";

    sourceSummary.innerHTML =
        "";

    [
        [
            "Source file",
            source.filename
        ],

        [
            "Original path",
            source.path
        ],

        [
            "Size",
            formatBytes(
                source.size_bytes
            )
        ],

        [
            "Created",
            formatTimestamp(
                source.created
            )
        ],

        [
            "Modified",
            formatTimestamp(
                source.modified
            )
        ],

        [
            "Accessed",
            formatTimestamp(
                source.accessed
            )
        ],

        [
            "Collector",
            data.collector_name
        ],

        [
            "Evidence description",
            data.evidence_description
        ],
    ].forEach(
        ([name, value]) => {

            addProperty(
                sourceSummary,
                name,
                value
            );
        }
    );

    acquisitionHashes.innerHTML =
        "";

    [
        [
            "SOURCE SHA-256",
            integrity.source_sha256_during_copy
        ],

        [
            "MASTER SHA-256",
            integrity.master_sha256
        ],

        [
            "WORKING SHA-256",
            integrity.working_sha256
        ],

        [
            "SOURCE AFTER",
            integrity.source_sha256_after
        ],
    ].forEach(
        ([name, value]) => {

            addHashRow(
                acquisitionHashes,
                name,
                value
            );
        }
    );
}


/*
|--------------------------------------------------------------------------
| Run forensic analysis
|--------------------------------------------------------------------------
*/

runAnalysisButton.addEventListener(
    "click",
    async () => {

        if (
            !collectorToken
            || !evidenceId
        ) {
            return;
        }

        runAnalysisButton.disabled =
            true;

        analysisRunning.classList.remove(
            "hidden"
        );

        try {

            const response = await fetch(
                (
                    `/api/acquisition/`
                    + `${encodeURIComponent(evidenceId)}`
                    + `/analyze`
                ),
                {
                    method:
                        "POST",

                    headers:
                        collectorHeaders(),
                }
            );

            if (!response.ok) {

                throw new Error(
                    await responseError(
                        response
                    )
                );
            }

            const data =
                await response.json();

            renderAnalysis(
                data
            );

            actionHeading.textContent =
                "Analysis complete";

            actionDescription.textContent =
                (
                    "The working copy was examined and the master "
                    + "and working-copy hashes were verified afterward."
                );

            runAnalysisButton.textContent =
                "Re-run forensic analysis";

            runAnalysisButton.disabled =
                false;

            analysisResult.scrollIntoView(
                {
                    behavior:
                        "smooth",

                    block:
                        "start",
                }
            );

        } catch (error) {

            alert(
                "Analysis failed: "
                + error.message
            );

            runAnalysisButton.disabled =
                false;

        } finally {

            analysisRunning.classList.add(
                "hidden"
            );
        }
    }
);


/*
|--------------------------------------------------------------------------
| Existing analysis
|--------------------------------------------------------------------------
*/

async function loadExistingAnalysis() {

    actionHeading.textContent =
        "Analysis already available";

    actionDescription.textContent =
        (
            "A forensic analysis is already stored for this "
            + "acquisition. The saved result has been loaded below."
        );

    runAnalysisButton.textContent =
        "Re-run forensic analysis";

    runAnalysisButton.disabled =
        true;

    try {

        const response = await fetch(
            `/api/acquisition/${encodeURIComponent(evidenceId)}/analysis`,
            {
                headers:
                    collectorHeaders(),
            }
        );

        if (!response.ok) {

            throw new Error(
                await responseError(
                    response
                )
            );
        }

        const data =
            await response.json();

        renderAnalysis(
            data
        );

    } finally {

        runAnalysisButton.disabled =
            false;
    }
}


/*
|--------------------------------------------------------------------------
| Render forensic result
|--------------------------------------------------------------------------
*/

function renderAnalysis(
    data
) {

    const evidence =
        data.evidence
        || {};

    analysisFilename.textContent =
        (
            data.overview?.filename
            || evidence.original_filename
            || "Evidence"
        );

    const preserved = (
        evidence.master_preserved
            === true

        && evidence.working_copy_preserved
            === true
    );

    preservationBadge.className =
        "badge "
        + (
            preserved
                ? "good"
                : "warning"
        );

    preservationBadge.textContent =
        preserved
            ? "Evidence preserved"
            : "Integrity warning";

    overview.innerHTML =
        "";

    [
        [
            "Detected type",
            data.signature?.detected_type
            || "Unknown"
        ],

        [
            "MIME type",
            data.signature?.detected_mime
            || "Unknown"
        ],

        [
            "Size",
            formatBytes(
                data.overview?.size_bytes
            )
        ],

        [
            "Metadata fields",
            data.metadata?.field_count
            ?? 0
        ],

        [
            "Artefacts",
            data.artefacts?.total_found
            ?? 0
        ],

        [
            "Timeline events",
            data.timeline?.event_count
            ?? 0
        ],
    ].forEach(
        ([label, value]) => {

            addMetric(
                overview,
                label,
                value
            );
        }
    );

    renderTimelinePreview(
        data.timeline
        || {}
    );

    analysisResult.classList.remove(
        "hidden"
    );
}


/*
|--------------------------------------------------------------------------
| Timeline preview
|--------------------------------------------------------------------------
*/

function renderTimelinePreview(
    timeline
) {

    timelineBody.innerHTML =
        "";

    const events =
        timeline.events
        || [];

    const preview =
        events.slice(
            0,
            10
        );

    preview.forEach(
        event => {

            const row =
                document.createElement(
                    "tr"
                );

            appendCell(
                row,
                (
                    event.timestamp_utc
                    || event.timestamp_original
                    || "Unavailable"
                )
            );

            appendCell(
                row,
                (
                    event.label
                    || event.event_type
                    || "Timestamp"
                )
            );

            appendCell(
                row,
                formatScope(
                    event.scope
                )
            );

            appendCell(
                row,
                (
                    `${event.source_group
                        || event.source
                        || "Unknown"}:`
                    + `${event.source_field
                        || "unknown"}`
                )
            );

            timelineBody.appendChild(
                row
            );
        }
    );

    if (events.length > preview.length) {

        timelineNote.textContent =
            (
                `Showing ${preview.length} of ${events.length} events. `
                + "Use the Timeline CSV or full forensic report "
                + "for the complete timeline."
            );

    } else {

        timelineNote.textContent =
            (
                `${events.length} timeline event(s) recorded.`
            );
    }
}


/*
|--------------------------------------------------------------------------
| Report links
|--------------------------------------------------------------------------
*/

function configureReportLinks() {

    const encodedId =
        encodeURIComponent(
            evidenceId
        );

    forensicPdfLink.href =
        `/api/evidence/${encodedId}/report/pdf`;

    forensicJsonLink.href =
        `/api/evidence/${encodedId}/report/json`;

    timelineCsvLink.href =
        `/api/evidence/${encodedId}/report/timeline.csv`;

    artefactsCsvLink.href =
        `/api/evidence/${encodedId}/report/artefacts.csv`;

    forensicHtmlLink.href =
        `/api/evidence/${encodedId}/report/html`;
}


/*
|--------------------------------------------------------------------------
| Page errors
|--------------------------------------------------------------------------
*/

function showPageError(
    message
) {

    pageLoading.classList.add(
        "hidden"
    );

    workspace.classList.add(
        "hidden"
    );

    pageErrorMessage.textContent =
        message;

    pageError.classList.remove(
        "hidden"
    );
}


/*
|--------------------------------------------------------------------------
| API helpers
|--------------------------------------------------------------------------
*/

function collectorHeaders() {

    return {
        "X-Collector-Token":
            collectorToken,
    };
}


async function responseError(
    response
) {

    try {

        const data =
            await response.json();

        return (
            data.detail
            || "Request failed."
        );

    } catch {

        return "Request failed.";
    }
}


/*
|--------------------------------------------------------------------------
| UI helpers
|--------------------------------------------------------------------------
*/

function addProperty(
    container,
    name,
    value
) {

    const element =
        document.createElement(
            "div"
        );

    element.className =
        "property";

    const label =
        document.createElement(
            "span"
        );

    label.className =
        "property-name";

    label.textContent =
        name;

    const content =
        document.createElement(
            "span"
        );

    content.className =
        "property-value";

    content.textContent =
        value
        ?? "Unavailable";

    element.append(
        label,
        content
    );

    container.appendChild(
        element
    );
}


function addHashRow(
    container,
    name,
    value
) {

    const row =
        document.createElement(
            "div"
        );

    row.className =
        "hash-row";

    const label =
        document.createElement(
            "div"
        );

    label.className =
        "hash-name";

    label.textContent =
        name;

    const hash =
        document.createElement(
            "div"
        );

    hash.className =
        "hash-value";

    hash.textContent =
        value
        || "Unavailable";

    row.append(
        label,
        hash
    );

    container.appendChild(
        row
    );
}


function addMetric(
    container,
    label,
    value
) {

    const element =
        document.createElement(
            "div"
        );

    element.className =
        "metric";

    const name =
        document.createElement(
            "span"
        );

    name.className =
        "metric-label";

    name.textContent =
        label;

    const content =
        document.createElement(
            "span"
        );

    content.className =
        "metric-value";

    content.textContent =
        value
        ?? "Unavailable";

    element.append(
        name,
        content
    );

    container.appendChild(
        element
    );
}


function appendCell(
    row,
    value
) {

    const cell =
        document.createElement(
            "td"
        );

    cell.textContent =
        value
        ?? "Unavailable";

    row.appendChild(
        cell
    );
}


function formatScope(
    value
) {

    if (!value) {

        return "Unavailable";
    }

    return value
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


function formatBytes(
    bytes
) {

    if (
        bytes === null
        || bytes === undefined
    ) {

        return "Unavailable";
    }

    if (bytes === 0) {

        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    ];

    const index =
        Math.min(
            Math.floor(
                Math.log(bytes)
                / Math.log(1024)
            ),

            units.length - 1
        );

    return (
        (
            bytes
            / Math.pow(
                1024,
                index
            )
        ).toFixed(2)
        + " "
        + units[index]
    );
}


function formatTimestamp(
    value
) {

    if (!value) {

        return "Unavailable";
    }

    const parsed =
        new Date(
            value
        );

    if (
        Number.isNaN(
            parsed.getTime()
        )
    ) {

        return value;
    }

    return (
        parsed.toLocaleString()
        + " · "
        + value
    );
}


/*
|--------------------------------------------------------------------------
| Initialise
|--------------------------------------------------------------------------
*/

initialiseAnalysisPage();