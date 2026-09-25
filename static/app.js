const fileInput =
    document.getElementById("file-input");

const dropZone =
    document.getElementById("drop-zone");

const analyseButton =
    document.getElementById("analyse-button");

const selectedFile =
    document.getElementById("selected-file");

const loading =
    document.getElementById("loading");

const results =
    document.getElementById("results");


let currentFile = null;


fileInput.addEventListener(
    "change",
    () => {
        if (fileInput.files.length) {
            setCurrentFile(fileInput.files[0]);
        }
    }
);


dropZone.addEventListener(
    "dragover",
    event => {
        event.preventDefault();

        dropZone.classList.add("dragging");
    }
);


dropZone.addEventListener(
    "dragleave",
    () => {
        dropZone.classList.remove("dragging");
    }
);


dropZone.addEventListener(
    "drop",
    event => {
        event.preventDefault();

        dropZone.classList.remove("dragging");

        if (event.dataTransfer.files.length) {
            setCurrentFile(
                event.dataTransfer.files[0]
            );
        }
    }
);


analyseButton.addEventListener(
    "click",
    analyseFile
);


function setCurrentFile(file) {
    currentFile = file;

    selectedFile.textContent =
        `${file.name} — ${formatBytes(file.size)}`;

    analyseButton.disabled = false;
}


async function analyseFile() {

    if (!currentFile) {
        return;
    }

    loading.classList.remove("hidden");
    results.classList.add("hidden");

    analyseButton.disabled = true;

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

        const response = await fetch(
            "/api/analyze",
            {
                method: "POST",
                body: form
            }
        );

        if (!response.ok) {

            const error = await response.json();

            throw new Error(
                error.detail || "Analysis failed."
            );
        }

        const data = await response.json();

        renderResults(data);

        results.classList.remove("hidden");

    } catch (error) {

        alert(
            `Analysis failed: ${error.message}`
        );

    } finally {

        loading.classList.add("hidden");

        analyseButton.disabled = false;
    }
}


function renderResults(data) {

    document.getElementById(
        "result-filename"
    ).textContent =
        data.overview.filename;

    document.getElementById(
        "analysis-time"
    ).textContent =
        `Analysed ${data.analysis.timestamp_utc}`;


    renderWarnings(data.warnings);

    renderOverview(data);

    renderSignature(data.signature);

    renderHashes(data.hashes);

    renderFilesystem(data.filesystem);

    renderMetadata(data.metadata);
}


function renderOverview(data) {

    const overview =
        document.getElementById(
            "overview-grid"
        );

    overview.innerHTML = "";

    addMetric(
        overview,
        "Filename",
        data.overview.filename
    );

    addMetric(
        overview,
        "Extension",
        data.overview.extension || "None"
    );

    addMetric(
        overview,
        "Detected Type",
        data.signature.detected_type
    );

    addMetric(
        overview,
        "MIME Type",
        data.signature.detected_mime
            || data.metadata.summary.mime_type
            || "Unknown"
    );

    addMetric(
        overview,
        "File Size",
        formatBytes(
            data.overview.size_bytes
        )
    );

    addMetric(
        overview,
        "Artefacts Extracted",
        data.analysis.artifact_count
    );
}


function addMetric(
    container,
    label,
    value
) {

    const metric =
        document.createElement("div");

    metric.className = "metric";

    const labelElement =
        document.createElement("span");

    labelElement.className =
        "metric-label";

    labelElement.textContent = label;


    const valueElement =
        document.createElement("span");

    valueElement.className =
        "metric-value";

    valueElement.textContent =
        value ?? "Unavailable";


    metric.append(
        labelElement,
        valueElement
    );

    container.appendChild(metric);
}


function renderSignature(signature) {

    const status =
        document.getElementById(
            "signature-status"
        );

    const content =
        document.getElementById(
            "signature-content"
        );

    content.innerHTML = "";

    status.className = "badge";


    if (
        signature.extension_matches === true
    ) {

        status.textContent =
            "SIGNATURE MATCH";

        status.classList.add("good");

    } else if (
        signature.extension_matches === false
    ) {

        status.textContent =
            "EXTENSION MISMATCH";

        status.classList.add("warning");

    } else {

        status.textContent =
            "UNDETERMINED";
    }


    addProperty(
        content,
        "Filename Extension",
        signature.extension
    );

    addProperty(
        content,
        "Detected Type",
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


function renderHashes(hashes) {

    const container =
        document.getElementById("hashes");

    container.innerHTML = "";

    [
        ["SHA-256", hashes.sha256],
        ["SHA-1", hashes.sha1],
        ["MD5", hashes.md5]
    ]
    .forEach(
        ([name, value]) => {

            const row =
                document.createElement("div");

            row.className = "hash-row";


            const nameElement =
                document.createElement("div");

            nameElement.className =
                "hash-name";

            nameElement.textContent = name;


            const valueElement =
                document.createElement("div");

            valueElement.className =
                "hash-value";

            valueElement.textContent =
                value;


            row.append(
                nameElement,
                valueElement
            );

            container.appendChild(row);
        }
    );
}


function renderFilesystem(filesystem) {

    document.getElementById(
        "filesystem-note"
    ).textContent =
        filesystem.warning;


    const container =
        document.getElementById(
            "filesystem"
        );

    container.innerHTML = "";


    addProperty(
        container,
        "Scope",
        filesystem.scope
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
        "Metadata Changed",
        filesystem.metadata_changed
    );
}


function addProperty(
    container,
    name,
    value
) {

    const element =
        document.createElement("div");

    element.className = "property";


    const nameElement =
        document.createElement("span");

    nameElement.className =
        "property-name";

    nameElement.textContent = name;


    const valueElement =
        document.createElement("span");

    valueElement.className =
        "property-value";

    valueElement.textContent =
        value ?? "Unavailable";


    element.append(
        nameElement,
        valueElement
    );

    container.appendChild(element);
}


function renderMetadata(metadata) {

    const count =
        document.getElementById(
            "metadata-count"
        );

    count.textContent =
        `${metadata.field_count} FIELDS`;


    const container =
        document.getElementById(
            "metadata"
        );

    container.innerHTML = "";


    if (metadata.status !== "ok") {

        const warning =
            document.createElement("div");

        warning.className =
            "warning-box";

        warning.textContent =
            metadata.error;

        container.appendChild(warning);

        return;
    }


    Object.entries(
        metadata.categories
    ).forEach(
        ([category, fields], index) => {

            const details =
                document.createElement(
                    "details"
                );

            details.className =
                "metadata-section";

            if (index === 0) {
                details.open = true;
            }


            const summary =
                document.createElement(
                    "summary"
                );

            summary.textContent =
                `${formatCategory(category)} (${fields.length})`;


            const table =
                document.createElement(
                    "table"
                );

            table.className =
                "metadata-table";


            fields.forEach(field => {

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
                    `${field.group}:${field.name}`;

                value.textContent =
                    formatMetadataValue(
                        field.value
                    );


                row.append(
                    key,
                    value
                );

                table.appendChild(row);
            });


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


function renderWarnings(warnings) {

    const container =
        document.getElementById(
            "warnings"
        );

    container.innerHTML = "";


    warnings.forEach(warning => {

        const element =
            document.createElement("div");

        element.className =
            "warning-box";

        element.textContent =
            warning.message;

        container.appendChild(element);
    });
}


function formatBytes(bytes) {

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

    const index = Math.floor(
        Math.log(bytes) /
        Math.log(1024)
    );

    return (
        `${(
            bytes /
            Math.pow(1024, index)
        ).toFixed(2)} ${units[index]}`
    );
}


function formatMetadataValue(value) {

    if (
        typeof value === "object"
        && value !== null
    ) {

        return JSON.stringify(
            value,
            null,
            2
        );
    }

    return String(value);
}


function formatCategory(category) {

    return category
        .replaceAll("_", " ")
        .replace(
            /\b\w/g,
            character =>
                character.toUpperCase()
        );
}