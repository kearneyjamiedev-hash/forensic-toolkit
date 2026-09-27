const ui = window.ForensicUI;

const fileInput = document.getElementById("security-file-input");
const dropZone = document.getElementById("security-drop-zone");
const selectedFile = document.getElementById("security-selected-file");
const checkButton = document.getElementById("security-check-button");
const loading = document.getElementById("security-loading");
const results = document.getElementById("security-results");

const dispositionTitle = document.getElementById("security-disposition-title");
const dispositionSummary = document.getElementById("security-disposition-summary");
const dispositionBadge = document.getElementById("security-disposition-badge");
const filenameElement = document.getElementById("security-filename");
const checksContainer = document.getElementById("security-checks");
const findingsContainer = document.getElementById("security-findings");
const findingCount = document.getElementById("security-finding-count");
const overview = document.getElementById("security-overview");
const hashes = document.getElementById("security-hashes");

const uploader = ui.makeUploadController({
    input: fileInput,
    dropZone,
    selectedLabel: selectedFile,
    actionButton: checkButton,
    onSelected: () => {
        results.classList.add("hidden");
    },
});

checkButton.addEventListener("click", runSecurityCheck);

async function runSecurityCheck() {
    const file = uploader.getFile();

    if (!file) {
        return;
    }

    loading.classList.remove("hidden");
    results.classList.add("hidden");
    checkButton.disabled = true;
    checkButton.textContent = "Checking...";

    const form = new FormData();
    form.append("file", file);
    form.append(
        "browser_last_modified_ms",
        file.lastModified.toString()
    );

    try {
        const response = await fetch(
            "/api/security-check",
            {
                method: "POST",
                body: form,
            }
        );

        if (!response.ok) {
            throw new Error(
                await ui.responseError(
                    response,
                    "Security check failed."
                )
            );
        }

        const data = await response.json();
        renderSecurityResult(data);

        results.classList.remove("hidden");
        results.scrollIntoView({
            behavior: "smooth",
            block: "start",
        });

    } catch (error) {
        alert(`Security check failed: ${error.message}`);

    } finally {
        loading.classList.add("hidden");
        checkButton.disabled = false;
        checkButton.textContent = "Run security check";
    }
}

function renderSecurityResult(data) {
    const assessment = data.security_assessment;

    if (!assessment) {
        throw new Error(
            "The backend did not return a structured security assessment."
        );
    }

    filenameElement.textContent =
        data.overview?.filename || "Unknown file";

    dispositionTitle.textContent = assessment.title;
    dispositionSummary.textContent = assessment.summary;

    ui.setBadge(
        dispositionBadge,
        assessment.badge,
        assessment.state
    );

    renderChecks(assessment.checks || []);
    renderFindings(assessment.findings || []);
    renderOverview(data, assessment);
    renderHashes(data.hashes || {});

    ui.configureEvidenceReportLinks(
        data.evidence?.id,
        {
            "security-pdf-link": "pdf",
            "security-json-link": "json",
            "security-artefacts-link": "artefacts.csv",
        }
    );
}

function renderChecks(checks) {
    checksContainer.innerHTML = "";

    checks.forEach(check => {
        const item = document.createElement("div");
        item.className =
            `security-check-item ${check.state || "neutral"}`;

        const icon = document.createElement("span");
        icon.className = "security-check-icon";
        icon.textContent = {
            pass: "✓",
            review: "!",
            neutral: "·",
        }[check.state] || "·";

        const copy = document.createElement("div");
        const title = document.createElement("strong");
        const message = document.createElement("span");

        title.textContent = check.title;
        message.textContent = check.message;

        copy.append(title, message);
        item.append(icon, copy);
        checksContainer.appendChild(item);
    });
}

function renderFindings(findings) {
    findingsContainer.innerHTML = "";

    findingCount.textContent =
        `${findings.length} ${findings.length === 1 ? "finding" : "findings"}`;

    if (!findings.length) {
        const empty = document.createElement("div");
        empty.className = "security-empty-state";

        const title = document.createElement("strong");
        title.textContent = "No review findings were generated.";

        const message = document.createElement("span");
        message.textContent =
            "Continue to full forensic examination if you need a complete evidential view.";

        empty.append(title, message);
        findingsContainer.appendChild(empty);
        return;
    }

    findings.forEach(finding => {
        const item = document.createElement("article");
        item.className =
            `security-finding ${finding.severity || "info"}`;

        const heading = document.createElement("div");
        heading.className = "security-finding-heading";

        const title = document.createElement("strong");
        title.textContent = finding.title;

        const severity = document.createElement("span");
        severity.className =
            `security-severity ${finding.severity || "info"}`;
        severity.textContent = {
            high: "High attention",
            medium: "Review",
            low: "Context",
            info: "Information",
        }[finding.severity] || "Finding";

        const message = document.createElement("p");
        message.textContent = finding.message;

        const source = document.createElement("span");
        source.className = "security-finding-source";
        source.textContent = finding.source || "Analyzer";

        heading.append(title, severity);
        item.append(heading, message, source);
        findingsContainer.appendChild(item);
    });
}

function renderOverview(data, assessment) {
    overview.innerHTML = "";

    ui.addMetric(
        overview,
        "Detected type",
        data.signature?.detected_type || "Unknown"
    );

    ui.addMetric(
        overview,
        "MIME type",
        data.signature?.detected_mime || "Unknown"
    );

    ui.addMetric(
        overview,
        "Size",
        ui.formatBytes(data.overview?.size_bytes)
    );

    ui.addMetric(
        overview,
        "Artefacts",
        data.artefacts?.total_found ?? 0
    );

    ui.addMetric(
        overview,
        "Review findings",
        assessment.counts?.total ?? assessment.findings?.length ?? 0
    );

    ui.addMetric(
        overview,
        "Analysis mode",
        "Static"
    );
}

function renderHashes(hashData) {
    hashes.innerHTML = "";

    ui.addHashRow(
        hashes,
        "SHA-256",
        hashData.sha256
    );

    ui.addHashRow(
        hashes,
        "SHA-1",
        hashData.sha1
    );

    ui.addHashRow(
        hashes,
        "MD5",
        hashData.md5
    );
}
