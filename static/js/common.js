window.ForensicUI = (() => {
    function formatBytes(bytes) {
        if (
            bytes === null
            || bytes === undefined
            || Number.isNaN(Number(bytes))
        ) {
            return "Unavailable";
        }

        const numericBytes = Number(bytes);

        if (numericBytes === 0) {
            return "0 B";
        }

        if (numericBytes < 0) {
            return "Unavailable";
        }

        const units = ["B", "KB", "MB", "GB", "TB"];
        const index = Math.floor(
            Math.log(numericBytes) / Math.log(1024)
        );
        const safeIndex = Math.max(
            0,
            Math.min(index, units.length - 1)
        );

        return `${(
            numericBytes / Math.pow(1024, safeIndex)
        ).toFixed(2)} ${units[safeIndex]}`;
    }

    function formatTimestamp(value) {
        if (!value) {
            return "Unavailable";
        }

        const parsed = new Date(value);

        if (Number.isNaN(parsed.getTime())) {
            return String(value);
        }

        return `${parsed.toLocaleString()} · ${value}`;
    }

    function formatCategory(value) {
        if (!value) {
            return "Other";
        }

        return String(value)
            .replaceAll("_", " ")
            .replace(/\b\w/g, character => character.toUpperCase());
    }

    function formatSimpleValue(value) {
        if (value === null || value === undefined) {
            return "Unavailable";
        }

        if (typeof value === "object") {
            return JSON.stringify(value);
        }

        return String(value);
    }

    function escapeHtml(value) {
        const element = document.createElement("div");
        element.textContent = value ?? "";
        return element.innerHTML;
    }

    function addMetric(container, label, value) {
        if (!container) {
            return;
        }

        const metric = document.createElement("div");
        metric.className = "metric";

        const labelElement = document.createElement("span");
        labelElement.className = "metric-label";
        labelElement.textContent = label;

        const valueElement = document.createElement("span");
        valueElement.className = "metric-value";
        valueElement.textContent = value ?? "Unavailable";

        metric.append(labelElement, valueElement);
        container.appendChild(metric);
    }

    function addProperty(container, name, value) {
        if (!container) {
            return;
        }

        const element = document.createElement("div");
        element.className = "property";

        const label = document.createElement("span");
        label.className = "property-name";
        label.textContent = name;

        const content = document.createElement("span");
        content.className = "property-value";
        content.textContent = value ?? "Unavailable";

        element.append(label, content);
        container.appendChild(element);
    }

    function addHashRow(container, name, value) {
        if (!container) {
            return;
        }

        const row = document.createElement("div");
        row.className = "hash-row";

        const label = document.createElement("div");
        label.className = "hash-name";
        label.textContent = name;

        const hash = document.createElement("div");
        hash.className = "hash-value";
        hash.textContent = value || "Unavailable";

        row.append(label, hash);
        container.appendChild(row);
    }

    async function responseError(response, fallback = "Request failed.") {
        try {
            const data = await response.json();
            return data.detail || fallback;
        } catch {
            return fallback;
        }
    }

    function setBadge(element, text, state = "neutral") {
        if (!element) {
            return;
        }

        element.className = "badge";

        if (["good", "warning", "danger"].includes(state)) {
            element.classList.add(state);
        }

        element.textContent = text;
    }

    function configureEvidenceReportLinks(evidenceId, mapping) {
        if (!evidenceId || !mapping) {
            return;
        }

        const encodedId = encodeURIComponent(evidenceId);

        Object.entries(mapping).forEach(([elementId, format]) => {
            const element = document.getElementById(elementId);

            if (!element) {
                return;
            }

            element.href = `/api/evidence/${encodedId}/report/${format}`;
            element.classList.remove("disabled-link");
            element.removeAttribute("aria-disabled");
        });
    }

    function makeUploadController({
        input,
        dropZone,
        selectedLabel,
        actionButton,
        onSelected,
    }) {
        let currentFile = null;

        function setFile(file) {
            currentFile = file || null;

            if (selectedLabel) {
                selectedLabel.textContent = currentFile
                    ? `${currentFile.name} — ${formatBytes(currentFile.size)}`
                    : "";
            }

            if (actionButton) {
                actionButton.disabled = !currentFile;
            }

            if (typeof onSelected === "function") {
                onSelected(currentFile);
            }
        }

        if (input) {
            input.addEventListener("change", () => {
                setFile(input.files?.[0] || null);
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

                const file = event.dataTransfer?.files?.[0] || null;
                setFile(file);
            });
        }

        return {
            getFile: () => currentFile,
            clear: () => {
                if (input) {
                    input.value = "";
                }
                setFile(null);
            },
            setFile,
        };
    }

    return {
        addHashRow,
        addMetric,
        addProperty,
        configureEvidenceReportLinks,
        escapeHtml,
        formatBytes,
        formatCategory,
        formatSimpleValue,
        formatTimestamp,
        makeUploadController,
        responseError,
        setBadge,
    };
})();
