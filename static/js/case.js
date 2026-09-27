(() => {

    "use strict";



    const caseId = new URLSearchParams(window.location.search).get("id");

    const workspace = document.getElementById("case-workspace");

    const errorBox = document.getElementById("case-error");

    const evidenceList = document.getElementById("case-evidence-list");

    const evidenceSelect = document.getElementById("available-evidence");

    const attachButton = document.getElementById("attach-evidence-button");

    const evidenceMessage = document.getElementById("case-evidence-message");

    const closeButton = document.getElementById("close-case-button");

    const caseStatusMessage = document.getElementById("case-status-message");



    const entryForm = document.getElementById("investigation-entry-form");

    const entryType = document.getElementById("entry-type");

    const entryExaminer = document.getElementById("entry-examiner");

    const entryEvidence = document.getElementById("entry-evidence");

    const entryContent = document.getElementById("entry-content");

    const entryFormMessage = document.getElementById("entry-form-message");

    const addEntryButton = document.getElementById("add-entry-button");



    const amendmentForm = document.getElementById("amendment-form");

    const amendmentTargetLabel = document.getElementById("amendment-target-label");

    const amendmentExaminer = document.getElementById("amendment-examiner");

    const amendmentEvidence = document.getElementById("amendment-evidence");

    const amendmentContent = document.getElementById("amendment-content");

    const amendmentMessage = document.getElementById("amendment-message");

    const cancelAmendmentButton = document.getElementById("cancel-amendment-button");

    const commitAmendmentButton = document.getElementById("commit-amendment-button");



    const investigationLog = document.getElementById("investigation-log");

    const entryCountLabel = document.getElementById("entry-count-label");

    const entryFilterType = document.getElementById("entry-filter-type");

    const entryFilterEvidence = document.getElementById("entry-filter-evidence");



    let currentCase = null;

    let availableEvidence = [];

    let investigationEntries = [];

    let amendmentTarget = null;



    function formatDate(value) {

        if (!value) return "—";

        const date = new Date(value);

        return Number.isNaN(date.getTime()) ? value : date.toLocaleString();

    }



    function shortHash(value) {

        if (!value) return "—";

        return value.length > 24 ? `${value.slice(0, 16)}…${value.slice(-8)}` : value;

    }



    function formatEntryType(value) {

        return String(value || "")

            .toLowerCase()

            .split("_")

            .filter(Boolean)

            .map((part) => part.charAt(0).toUpperCase() + part.slice(1))

            .join(" ");

    }



    function formatEntryNumber(value) {

        return `#${String(value || 0).padStart(4, "0")}`;

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



    function setMessage(element, message, kind = "") {

        element.textContent = message || "";

        element.className = "case-message";

        if (kind === "error") element.classList.add("case-message-error");

        if (kind === "success") element.classList.add("case-message-success");

    }



    function isCaseClosed() {

        return currentCase?.status === "CLOSED";

    }



    function renderCaseHeader(data) {

        document.getElementById("case-header-reference").textContent = data.case_reference;

        document.getElementById("case-header-status").textContent = data.status;

        document.getElementById("case-reference-label").textContent = data.case_reference;

        document.getElementById("case-title-display").textContent = data.title;

        document.getElementById("case-description-display").textContent = data.description || "No description supplied.";

        document.getElementById("case-status-display").textContent = data.status;

        document.getElementById("case-created-display").textContent = `Created ${formatDate(data.created_at_utc)}`;

        document.getElementById("case-evidence-count").textContent = String(data.evidence_count || 0);

        document.getElementById("case-entry-count").textContent = String(data.investigation_entry_count || 0);

        document.getElementById("case-examiner-display").textContent = data.examiner;

        document.getElementById("case-updated-display").textContent = formatDate(data.updated_at_utc);



        document.getElementById("overview-reference").textContent = data.case_reference;

        document.getElementById("overview-status").textContent = data.status;

        document.getElementById("overview-created").textContent = formatDate(data.created_at_utc);

        document.getElementById("overview-closed").textContent = formatDate(data.closed_at_utc);

        document.getElementById("overview-description").textContent = data.description || "No description supplied.";



        entryExaminer.value = entryExaminer.value || data.examiner || "";

        amendmentExaminer.value = amendmentExaminer.value || data.examiner || "";



        closeButton.hidden = data.status === "CLOSED";

        addEntryButton.disabled = data.status === "CLOSED";

        entryType.disabled = data.status === "CLOSED";

        entryExaminer.disabled = data.status === "CLOSED";

        entryEvidence.disabled = data.status === "CLOSED";

        entryContent.disabled = data.status === "CLOSED";



        if (data.status === "CLOSED") {

            setMessage(entryFormMessage, "This case is closed. New investigation entries are disabled; explicit corrections to existing entries remain available.");

        } else if (entryFormMessage.textContent.startsWith("This case is closed")) {

            setMessage(entryFormMessage, "");

        }

    }



    function renderEvidence(data) {

        evidenceList.replaceChildren();



        if (!data.evidence || !data.evidence.length) {

            const empty = document.createElement("div");

            empty.className = "empty-state";

            empty.textContent = "No evidence has been associated with this case yet.";

            evidenceList.appendChild(empty);

            return;

        }



        for (const item of data.evidence) {

            const card = document.createElement("article");

            card.className = "case-evidence-card";



            const heading = document.createElement("div");

            heading.className = "case-evidence-heading";



            const name = document.createElement("strong");

            name.textContent = item.original_filename;



            const id = document.createElement("span");

            id.textContent = item.evidence_id;



            heading.append(name, id);



            const fields = document.createElement("dl");

            fields.className = "case-evidence-fields";



            const values = [

                ["SHA-256", shortHash(item.original_sha256)],

                ["Detected type", item.detected_type || "Not recorded"],

                ["Integrity", item.integrity_status || "Not re-verified"],

                ["Findings", Number.isInteger(item.findings_count) ? String(item.findings_count) : "Not recorded"],

                ["Analysed", formatDate(item.analysis_timestamp_utc)],

                ["Added to case", formatDate(item.added_at_utc)],

            ];



            for (const [label, value] of values) {

                const wrapper = document.createElement("div");

                const dt = document.createElement("dt");

                const dd = document.createElement("dd");

                dt.textContent = label;

                dd.textContent = value;

                if (label === "SHA-256") dd.className = "code";

                wrapper.append(dt, dd);

                fields.appendChild(wrapper);

            }



            card.append(heading, fields);

            evidenceList.appendChild(card);

        }

    }



    function addEvidenceOptions(select, placeholderText) {

        select.replaceChildren();

        const placeholder = document.createElement("option");

        placeholder.value = "";

        placeholder.textContent = placeholderText;

        select.appendChild(placeholder);



        for (const item of currentCase?.evidence || []) {

            const option = document.createElement("option");

            option.value = item.evidence_id;

            option.textContent = `${item.original_filename} — ${item.evidence_id.slice(0, 8)}`;

            select.appendChild(option);

        }

    }



    function renderEvidenceSelectors() {

        addEvidenceOptions(entryEvidence, "No linked evidence");

        addEvidenceOptions(amendmentEvidence, "Use original entry link");

        addEvidenceOptions(entryFilterEvidence, "All evidence");

    }



    function renderAvailableEvidence() {

        evidenceSelect.replaceChildren();

        const linkedIds = new Set((currentCase?.evidence || []).map((item) => item.evidence_id));

        const choices = availableEvidence.filter((item) => !linkedIds.has(item.evidence_id));



        const placeholder = document.createElement("option");

        placeholder.value = "";

        placeholder.textContent = choices.length ? "Select analysed evidence…" : "No unlinked analysed evidence available";

        evidenceSelect.appendChild(placeholder);



        for (const item of choices) {

            const option = document.createElement("option");

            option.value = item.evidence_id;

            option.textContent = `${item.original_filename} — ${item.evidence_id.slice(0, 8)}`;

            evidenceSelect.appendChild(option);

        }



        evidenceSelect.disabled = choices.length === 0 || isCaseClosed();

        attachButton.disabled = true;



        if (isCaseClosed()) {

            setMessage(evidenceMessage, "This case is closed. Additional evidence cannot be associated with it.");

        }

    }



    function populateEntryTypeFilter() {

        const existing = new Set(Array.from(entryFilterType.options).map((option) => option.value));

        const values = [

            "OBSERVATION",

            "ACTION_TAKEN",

            "COMMAND_EXECUTED",

            "EVIDENCE_IDENTIFIED",

            "FINDING",

            "HYPOTHESIS",

            "VERIFICATION",

            "GENERAL_NOTE",

            "CORRECTION",

        ];

        for (const value of values) {

            if (existing.has(value)) continue;

            const option = document.createElement("option");

            option.value = value;

            option.textContent = formatEntryType(value);

            entryFilterType.appendChild(option);

        }

    }



    function visibleEntries() {

        const typeValue = entryFilterType.value;

        const evidenceValue = entryFilterEvidence.value;

        return investigationEntries.filter((entry) => {

            if (typeValue && entry.entry_type !== typeValue) return false;

            if (evidenceValue && entry.linked_evidence_id !== evidenceValue) return false;

            return true;

        });

    }



    function renderInvestigationLog() {

        investigationLog.replaceChildren();

        entryCountLabel.textContent = `${investigationEntries.length} ${investigationEntries.length === 1 ? "entry" : "entries"}`;



        const entries = visibleEntries();

        if (!entries.length) {

            const empty = document.createElement("div");

            empty.className = "empty-state";

            empty.textContent = investigationEntries.length

                ? "No investigation entries match the selected filters."

                : "No investigation entries have been committed to this case yet.";

            investigationLog.appendChild(empty);

            return;

        }



        for (const entry of entries) {

            const card = document.createElement("article");

            card.className = "case-log-entry";

            if (entry.entry_type === "CORRECTION") card.classList.add("case-log-entry-correction");



            const top = document.createElement("div");

            top.className = "case-log-entry-top";



            const heading = document.createElement("div");

            const type = document.createElement("span");

            type.className = "case-log-entry-type";

            type.textContent = formatEntryType(entry.entry_type);



            const number = document.createElement("strong");

            number.textContent = `Entry ${formatEntryNumber(entry.sequence_number)}`;

            heading.append(type, number);



            const timestamp = document.createElement("time");

            timestamp.textContent = formatDate(entry.created_at_utc);

            top.append(heading, timestamp);



            const content = document.createElement("p");

            content.className = "case-log-entry-content";

            content.textContent = entry.content;



            const meta = document.createElement("div");

            meta.className = "case-log-entry-meta";



            const examiner = document.createElement("span");

            examiner.textContent = `Examiner: ${entry.examiner}`;

            meta.appendChild(examiner);



            if (entry.linked_evidence_id) {

                const evidence = document.createElement("span");

                evidence.textContent = `Evidence: ${entry.linked_evidence_filename || entry.linked_evidence_id}`;

                meta.appendChild(evidence);

            }



            if (entry.parent_sequence_number) {

                const parent = document.createElement("span");

                parent.textContent = `Correction to ${formatEntryNumber(entry.parent_sequence_number)}`;

                meta.appendChild(parent);

            }



            const actions = document.createElement("div");

            actions.className = "case-log-entry-actions";

            const amendButton = document.createElement("button");

            amendButton.type = "button";

            amendButton.className = "secondary-button case-amend-button";

            amendButton.dataset.entryId = entry.entry_id;

            amendButton.textContent = "Add Correction";

            actions.appendChild(amendButton);



            card.append(top, content, meta, actions);

            investigationLog.appendChild(card);

        }

    }



    function openAmendment(entry) {

        amendmentTarget = entry;

        amendmentTargetLabel.textContent = `Entry ${formatEntryNumber(entry.sequence_number)} — ${formatEntryType(entry.entry_type)}`;

        amendmentExaminer.value = currentCase?.examiner || entry.examiner || "";

        amendmentEvidence.value = "";

        amendmentContent.value = "";

        setMessage(amendmentMessage, "");

        amendmentForm.hidden = false;

        amendmentContent.focus();

        amendmentForm.scrollIntoView({ behavior: "smooth", block: "nearest" });

    }



    function closeAmendment() {

        amendmentTarget = null;

        amendmentForm.hidden = true;

        amendmentContent.value = "";

        amendmentEvidence.value = "";

        setMessage(amendmentMessage, "");

    }



    async function fetchCase() {

        const response = await fetch(`/api/cases/${encodeURIComponent(caseId)}`, {

            headers: { "Accept": "application/json" },

        });

        if (!response.ok) throw new Error(await errorMessage(response));

        currentCase = await response.json();

    }



    async function fetchAvailableEvidence() {

        const response = await fetch("/api/cases/available-evidence", {

            headers: { "Accept": "application/json" },

        });

        if (!response.ok) throw new Error(await errorMessage(response));

        const data = await response.json();

        availableEvidence = Array.isArray(data.evidence) ? data.evidence : [];

    }



    async function fetchEntries() {

        const response = await fetch(`/api/cases/${encodeURIComponent(caseId)}/entries`, {

            headers: { "Accept": "application/json" },

        });

        if (!response.ok) throw new Error(await errorMessage(response));

        const data = await response.json();

        investigationEntries = Array.isArray(data.entries) ? data.entries : [];

    }



    function renderWorkspace() {

        renderCaseHeader(currentCase);

        renderEvidence(currentCase);

        renderAvailableEvidence();

        renderEvidenceSelectors();

        populateEntryTypeFilter();

        renderInvestigationLog();

        workspace.hidden = false;

    }



    async function refreshWorkspaceData() {

        await Promise.all([fetchCase(), fetchAvailableEvidence(), fetchEntries()]);

        renderWorkspace();

    }



    async function loadWorkspace() {

        if (!caseId) {

            errorBox.textContent = "No case ID was supplied.";

            errorBox.className = "case-message case-message-error";

            return;

        }



        try {

            await refreshWorkspaceData();

        } catch (error) {

            errorBox.textContent = error instanceof Error ? error.message : "Case workspace could not be loaded.";

            errorBox.className = "case-message case-message-error";

        }

    }



    document.querySelectorAll(".case-tab").forEach((tab) => {

        tab.addEventListener("click", () => {

            const target = tab.dataset.tab;

            document.querySelectorAll(".case-tab").forEach((candidate) => {

                const active = candidate === tab;

                candidate.classList.toggle("is-active", active);

                candidate.setAttribute("aria-selected", active ? "true" : "false");

            });

            document.querySelectorAll(".case-tab-panel").forEach((panel) => {

                panel.hidden = panel.dataset.panel !== target;

            });

        });

    });



    evidenceSelect.addEventListener("change", () => {

        attachButton.disabled = !evidenceSelect.value || isCaseClosed();

    });



    attachButton.addEventListener("click", async () => {

        const evidenceId = evidenceSelect.value;

        if (!evidenceId || !caseId || isCaseClosed()) return;



        attachButton.disabled = true;

        setMessage(evidenceMessage, "");



        try {

            const response = await fetch(`/api/cases/${encodeURIComponent(caseId)}/evidence`, {

                method: "POST",

                headers: {

                    "Content-Type": "application/json",

                    "Accept": "application/json",

                },

                body: JSON.stringify({ evidence_id: evidenceId }),

            });



            if (!response.ok) throw new Error(await errorMessage(response));

            const data = await response.json();

            await refreshWorkspaceData();

            setMessage(

                evidenceMessage,

                data.added ? "Evidence associated with this case." : "Evidence was already associated with this case.",

                "success",

            );

        } catch (error) {

            setMessage(evidenceMessage, error instanceof Error ? error.message : "Evidence could not be attached.", "error");

            attachButton.disabled = false;

        }

    });



    closeButton.addEventListener("click", async () => {

        if (!caseId || isCaseClosed()) return;

        if (!window.confirm("Close this case? New evidence and ordinary investigation entries will be disabled.")) return;



        closeButton.disabled = true;

        setMessage(caseStatusMessage, "");



        try {

            const response = await fetch(`/api/cases/${encodeURIComponent(caseId)}/close`, {

                method: "POST",

                headers: { "Accept": "application/json" },

            });

            if (!response.ok) throw new Error(await errorMessage(response));

            currentCase = await response.json();

            renderCaseHeader(currentCase);

            renderAvailableEvidence();

            setMessage(caseStatusMessage, "Case closed. Historical entries remain available for review and explicit correction.", "success");

        } catch (error) {

            closeButton.disabled = false;

            setMessage(caseStatusMessage, error instanceof Error ? error.message : "Case could not be closed.", "error");

        }

    });



    entryForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        if (!caseId || isCaseClosed()) return;



        addEntryButton.disabled = true;

        setMessage(entryFormMessage, "");



        const payload = {

            entry_type: entryType.value,

            content: entryContent.value.trim(),

            examiner: entryExaminer.value.trim(),

            linked_evidence_id: entryEvidence.value || null,

        };



        try {

            const response = await fetch(`/api/cases/${encodeURIComponent(caseId)}/entries`, {

                method: "POST",

                headers: {

                    "Content-Type": "application/json",

                    "Accept": "application/json",

                },

                body: JSON.stringify(payload),

            });

            if (!response.ok) throw new Error(await errorMessage(response));



            entryContent.value = "";

            entryEvidence.value = "";

            await refreshWorkspaceData();

            setMessage(entryFormMessage, "Investigation entry committed. The historical entry is read-only.", "success");

        } catch (error) {

            setMessage(entryFormMessage, error instanceof Error ? error.message : "Investigation entry could not be added.", "error");

        } finally {

            addEntryButton.disabled = isCaseClosed();

        }

    });



    investigationLog.addEventListener("click", (event) => {

        const button = event.target.closest(".case-amend-button");

        if (!button) return;

        const entry = investigationEntries.find((item) => item.entry_id === button.dataset.entryId);

        if (entry) openAmendment(entry);

    });



    cancelAmendmentButton.addEventListener("click", closeAmendment);



    amendmentForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        if (!caseId || !amendmentTarget) return;



        commitAmendmentButton.disabled = true;

        setMessage(amendmentMessage, "");



        const payload = {

            content: amendmentContent.value.trim(),

            examiner: amendmentExaminer.value.trim(),

            linked_evidence_id: amendmentEvidence.value || null,

        };



        try {

            const response = await fetch(

                `/api/cases/${encodeURIComponent(caseId)}/entries/${encodeURIComponent(amendmentTarget.entry_id)}/amendments`,

                {

                    method: "POST",

                    headers: {

                        "Content-Type": "application/json",

                        "Accept": "application/json",

                    },

                    body: JSON.stringify(payload),

                },

            );

            if (!response.ok) throw new Error(await errorMessage(response));



            await refreshWorkspaceData();

            closeAmendment();

        } catch (error) {

            setMessage(amendmentMessage, error instanceof Error ? error.message : "Correction could not be committed.", "error");

        } finally {

            commitAmendmentButton.disabled = false;

        }

    });



    entryFilterType.addEventListener("change", renderInvestigationLog);

    entryFilterEvidence.addEventListener("change", renderInvestigationLog);



    loadWorkspace();

})();
