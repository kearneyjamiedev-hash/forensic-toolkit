(() => {
    "use strict";

    const form = document.getElementById("case-create-form");
    const list = document.getElementById("case-list");
    const count = document.getElementById("case-count");
    const message = document.getElementById("case-form-message");
    const createButton = document.getElementById("create-case-button");

    function formatDate(value) {
        if (!value) return "Unknown";
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
    }

    async function errorMessage(response) {
        try {
            const data = await response.json();
            if (typeof data.detail === "string") return data.detail;
        } catch (_) {
            // Keep a safe generic fallback.
        }
        return `Request failed (${response.status}).`;
    }

    function renderCases(cases) {
        list.replaceChildren();
        count.textContent = `${cases.length} ${cases.length === 1 ? "case" : "cases"}`;

        if (!cases.length) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            empty.textContent = "No cases yet. Create the first investigation using the form.";
            list.appendChild(empty);
            return;
        }

        for (const item of cases) {
            const link = document.createElement("a");
            link.className = "case-card";
            link.href = `/case?id=${encodeURIComponent(item.case_id)}`;

            const top = document.createElement("div");
            top.className = "case-card-top";

            const ref = document.createElement("span");
            ref.className = "case-reference";
            ref.textContent = item.case_reference;

            const status = document.createElement("span");
            status.className = "case-status-badge";
            status.textContent = item.status;

            top.append(ref, status);

            const title = document.createElement("h4");
            title.textContent = item.title;

            const meta = document.createElement("div");
            meta.className = "case-card-meta";

            const examiner = document.createElement("span");
            examiner.textContent = `Examiner: ${item.examiner}`;

            const evidence = document.createElement("span");
            evidence.textContent = `Evidence: ${item.evidence_count}`;

            const updated = document.createElement("span");
            updated.textContent = `Updated: ${formatDate(item.updated_at_utc)}`;

            meta.append(examiner, evidence, updated);
            link.append(top, title, meta);
            list.appendChild(link);
        }
    }

    async function loadCases() {
        try {
            const response = await fetch("/api/cases", {
                headers: { "Accept": "application/json" },
            });

            if (!response.ok) throw new Error(await errorMessage(response));

            const data = await response.json();
            renderCases(Array.isArray(data.cases) ? data.cases : []);
        } catch (error) {
            list.replaceChildren();

            const failed = document.createElement("div");
            failed.className = "empty-state";
            failed.textContent = error instanceof Error
                ? error.message
                : "Cases could not be loaded.";

            list.appendChild(failed);
        }
    }

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        message.textContent = "";
        message.className = "case-message";
        createButton.disabled = true;

        const payload = {
            case_reference: document.getElementById("case-reference").value.trim(),
            title: document.getElementById("case-title").value.trim(),
            examiner: document.getElementById("case-examiner").value.trim(),
            description: document.getElementById("case-description").value.trim() || null,
        };

        try {
            const response = await fetch("/api/cases", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                body: JSON.stringify(payload),
            });

            if (!response.ok) throw new Error(await errorMessage(response));

            const created = await response.json();
            window.location.assign(`/case?id=${encodeURIComponent(created.case_id)}`);
        } catch (error) {
            message.className = "case-message case-message-error";
            message.textContent = error instanceof Error
                ? error.message
                : "Case could not be created.";

            createButton.disabled = false;
        }
    });

    loadCases();
})();
