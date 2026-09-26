const browseSourceButton = document.getElementById("browse-source-button");
const acquireButton = document.getElementById("acquire-button");

const caseReference = document.getElementById("case-reference");
const collectorName = document.getElementById("collector-name");
const evidenceDescription = document.getElementById("evidence-description");

const sourceEmpty = document.getElementById("source-empty");
const sourcePreview = document.getElementById("source-preview");
const sourcePath = document.getElementById("source-path");
const sourceProperties = document.getElementById("source-properties");

const acquisitionLoading = document.getElementById("acquisition-loading");
const acquisitionResult = document.getElementById("acquisition-result");
const acquisitionId = document.getElementById("acquisition-id");
const acquisitionBadge = document.getElementById("acquisition-badge");
const acquisitionIntegrity = document.getElementById("acquisition-integrity");
const acquisitionObservation = document.getElementById("acquisition-observation");

const acquisitionReportLink = document.getElementById("acquisition-report-link");
const acquisitionManifestLink = document.getElementById("acquisition-manifest-link");
const continueAnalysisLink = document.getElementById("continue-analysis-link");

let collectorToken = null;
let selectionId = null;
let currentEvidenceId = null;


/*
|--------------------------------------------------------------------------
| Collector session
|--------------------------------------------------------------------------
*/

async function initialiseCollector() {

    try {

        const response = await fetch(
            "/api/acquisition/session"
        );

        if (!response.ok) {

            throw new Error(
                "The local collector session could not be started."
            );
        }

        const data = await response.json();

        collectorToken = data.token;

        browseSourceButton.disabled = false;

    } catch (error) {

        browseSourceButton.disabled = true;

        alert(
            error.message
        );
    }
}


/*
|--------------------------------------------------------------------------
| Source selection
|--------------------------------------------------------------------------
*/

browseSourceButton.addEventListener(
    "click",
    async () => {

        if (!collectorToken) {
            return;
        }

        browseSourceButton.disabled = true;
        browseSourceButton.textContent = "Opening picker...";

        try {

            const response = await fetch(
                "/api/acquisition/select",
                {
                    method: "POST",
                    headers: collectorHeaders(),
                }
            );

            if (!response.ok) {

                throw new Error(
                    await responseError(
                        response
                    )
                );
            }

            const data = await response.json();

            if (data.cancelled) {
                return;
            }

            selectionId = data.selection_id;
            currentEvidenceId = null;

            renderSourcePreview(
                data.source
            );

            resetAcquisitionResult();
            updateAcquireButton();

        } catch (error) {

            alert(
                "Source selection failed: "
                + error.message
            );

        } finally {

            browseSourceButton.disabled = false;
            browseSourceButton.textContent = "Browse source evidence";
        }
    }
);


/*
|--------------------------------------------------------------------------
| Acquisition form
|--------------------------------------------------------------------------
*/

[
    caseReference,
    collectorName,
    evidenceDescription
].forEach(
    field => {

        field.addEventListener(
            "input",
            updateAcquireButton
        );
    }
);


function updateAcquireButton() {

    acquireButton.disabled = !(
        collectorToken
        && selectionId
        && caseReference.value.trim()
        && collectorName.value.trim()
        && evidenceDescription.value.trim()
    );
}


/*
|--------------------------------------------------------------------------
| Acquire evidence
|--------------------------------------------------------------------------
*/

acquireButton.addEventListener(
    "click",
    async () => {

        if (
            !collectorToken
            || !selectionId
        ) {
            return;
        }

        acquireButton.disabled = true;
        acquisitionLoading.classList.remove("hidden");
        acquisitionResult.classList.add("hidden");

        try {

            const response = await fetch(
                "/api/acquisition/acquire",
                {
                    method: "POST",

                    headers: {
                        ...collectorHeaders(),

                        "Content-Type":
                            "application/json",
                    },

                    body: JSON.stringify(
                        {
                            selection_id:
                                selectionId,

                            case_reference:
                                caseReference
                                    .value
                                    .trim(),

                            collector_name:
                                collectorName
                                    .value
                                    .trim(),

                            evidence_description:
                                evidenceDescription
                                    .value
                                    .trim(),
                        }
                    ),
                }
            );

            if (!response.ok) {

                throw new Error(
                    await responseError(
                        response
                    )
                );
            }

            const data = await response.json();

            currentEvidenceId = data.evidence_id;
            selectionId = null;

            renderAcquisition(
                data
            );

            acquisitionResult.classList.remove(
                "hidden"
            );

            acquisitionResult.scrollIntoView(
                {
                    behavior: "smooth",
                    block: "start",
                }
            );

        } catch (error) {

            alert(
                "Acquisition failed: "
                + error.message
            );

        } finally {

            acquisitionLoading.classList.add(
                "hidden"
            );

            updateAcquireButton();
        }
    }
);


/*
|--------------------------------------------------------------------------
| Render source preview
|--------------------------------------------------------------------------
*/

function renderSourcePreview(
    source
) {

    sourceEmpty.classList.add(
        "hidden"
    );

    sourcePreview.classList.remove(
        "hidden"
    );

    sourcePath.textContent =
        source.path
        || "Unavailable";

    sourceProperties.innerHTML =
        "";

    [
        [
            "Filename",
            source.filename
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
            "Creation basis",
            source.created_basis
            || "Unavailable"
        ],
    ].forEach(
        ([name, value]) => {

            addProperty(
                sourceProperties,
                name,
                value
            );
        }
    );
}


/*
|--------------------------------------------------------------------------
| Render acquisition result
|--------------------------------------------------------------------------
*/

function renderAcquisition(
    data
) {

    acquisitionId.textContent =
        "Evidence ID: "
        + data.evidence_id;

    const integrity =
        data.integrity
        || {};

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

    acquisitionIntegrity.innerHTML =
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
                acquisitionIntegrity,
                name,
                value
            );
        }
    );

    const changes =
        data.observable_metadata_changes
        || [];

    acquisitionObservation.textContent =
        changes.length
            ? (
                `${changes.length} source filesystem `
                + "metadata value(s) changed while "
                + "the logical acquisition was performed. "
                + "The changes are preserved in the manifest."
            )
            : (
                "No observable source filesystem metadata "
                + "changes were detected during acquisition. "
                + "The source content hash also remained unchanged."
            );

    configureResultLinks(
        data.evidence_id
    );
}


/*
|--------------------------------------------------------------------------
| Result links
|--------------------------------------------------------------------------
*/

function configureResultLinks(
    evidenceId
) {

    const encodedId =
        encodeURIComponent(
            evidenceId
        );

    acquisitionReportLink.href =
        `/api/acquisition/${encodedId}/report/pdf`;

    acquisitionManifestLink.href =
        `/api/acquisition/${encodedId}/manifest.json`;

    continueAnalysisLink.href =
        `/local-analysis?evidence_id=${encodedId}`;

    [
        acquisitionReportLink,
        acquisitionManifestLink,
        continueAnalysisLink
    ].forEach(
        link => {

            link.classList.remove(
                "disabled-link"
            );

            link.removeAttribute(
                "aria-disabled"
            );
        }
    );
}


function resetAcquisitionResult() {

    acquisitionResult.classList.add(
        "hidden"
    );

    acquisitionIntegrity.innerHTML =
        "";

    acquisitionObservation.textContent =
        "";

    [
        acquisitionReportLink,
        acquisitionManifestLink,
        continueAnalysisLink
    ].forEach(
        link => {

            link.href =
                "#";

            link.classList.add(
                "disabled-link"
            );

            link.setAttribute(
                "aria-disabled",
                "true"
            );
        }
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
| Prevent disabled links being followed
|--------------------------------------------------------------------------
*/

document.addEventListener(
    "click",
    event => {

        const link =
            event.target.closest(
                ".disabled-link"
            );

        if (link) {

            event.preventDefault();
        }
    }
);


/*
|--------------------------------------------------------------------------
| Initialise
|--------------------------------------------------------------------------
*/

initialiseCollector();