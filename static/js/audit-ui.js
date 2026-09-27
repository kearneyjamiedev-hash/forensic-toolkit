(function () {
    "use strict";

    const EVENT_LABELS = {
        EVIDENCE_ACQUIRED: "Evidence acquired",
        ANALYSIS_STARTED: "Analysis started",
        ANALYSIS_COMPLETED: "Analysis completed",
        SECURITY_CHECK_COMPLETED: "Security check completed",
        EVIDENCE_VERIFIED: "Evidence verified",
        REPORT_GENERATED: "Report generated",
        INTEGRITY_FAILURE: "Integrity failure",
    };

    function humanEventType(value) {
        if (!value) return "Audit event";
        return EVENT_LABELS[value] || value
            .toLowerCase()
            .replaceAll("_", " ")
            .replace(/^./, char => char.toUpperCase());
    }

    function shortHash(value, length = 18) {
        if (!value) return "Unavailable";
        return value.length > length ? `${value.slice(0, length)}…` : value;
    }

    function formatTime(value) {
        if (!value) return "Unavailable";
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return value;
        return date.toLocaleString(undefined, {
            year: "numeric",
            month: "short",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        });
    }

    function eventClass(event) {
        if (event.event_type === "INTEGRITY_FAILURE" || event.outcome === "failed") {
            return "danger";
        }
        if (event.event_type === "REPORT_GENERATED") return "report";
        if (event.event_type === "EVIDENCE_ACQUIRED" || event.event_type === "EVIDENCE_VERIFIED") {
            return "verified";
        }
        return "normal";
    }

    function detailText(event) {
        const details = event.details || {};
        const parts = [];

        if (details.report_format) parts.push(`Report: ${details.report_format}`);
        if (details.analysis_scope) parts.push(`Scope: ${details.analysis_scope}`);
        if (details.disposition) parts.push(`Disposition: ${details.disposition}`);
        if (details.finding_count !== undefined) parts.push(`Findings: ${details.finding_count}`);
        if (details.artefact_count !== undefined) parts.push(`Artefacts: ${details.artefact_count}`);
        if (details.master_verified === true) parts.push("Master verified");
        if (details.working_verified === true) parts.push("Working copy verified");

        return parts.join(" · ");
    }

    function makeEvent(event) {
        const item = document.createElement("article");
        item.className = `audit-event ${eventClass(event)}`;

        const marker = document.createElement("div");
        marker.className = "audit-event-marker";

        const content = document.createElement("div");
        content.className = "audit-event-content";

        const heading = document.createElement("div");
        heading.className = "audit-event-heading";

        const title = document.createElement("strong");
        title.textContent = humanEventType(event.event_type);

        const time = document.createElement("span");
        time.textContent = formatTime(event.timestamp_utc);

        heading.append(title, time);
        content.appendChild(heading);

        const details = detailText(event);
        if (details) {
            const detail = document.createElement("p");
            detail.textContent = details;
            content.appendChild(detail);
        }

        const meta = document.createElement("div");
        meta.className = "audit-event-meta";

        if (event.actor) {
            const actor = document.createElement("span");
            actor.textContent = `Actor: ${event.actor}`;
            meta.appendChild(actor);
        }

        if (event.outcome) {
            const outcome = document.createElement("span");
            outcome.textContent = `Outcome: ${event.outcome}`;
            meta.appendChild(outcome);
        }

        content.appendChild(meta);
        item.append(marker, content);
        return item;
    }

    async function loadEvidenceAudit(evidenceId, root = document) {
        const panel = root.querySelector("[data-audit-evidence-panel]");
        if (!panel || !evidenceId) return;

        panel.classList.remove("hidden");

        const badge = panel.querySelector("[data-audit-chain-badge]");
        const metrics = panel.querySelector("[data-audit-metrics]");
        const eventsContainer = panel.querySelector("[data-audit-events]");
        const status = panel.querySelector("[data-audit-status]");
        const refresh = panel.querySelector("[data-audit-refresh]");

        panel.dataset.evidenceId = evidenceId;
        if (refresh) refresh.disabled = true;
        if (status) status.textContent = "Loading audit trail…";

        try {
            const response = await fetch(
                `/api/audit/evidence/${encodeURIComponent(evidenceId)}`
            );

            if (response.status === 404) {
                if (badge) {
                    badge.className = "badge";
                    badge.textContent = "No events yet";
                }
                if (metrics) metrics.innerHTML = "";
                if (eventsContainer) eventsContainer.innerHTML = "";
                if (status) status.textContent = "No audit events are recorded for this evidence item yet.";
                return;
            }

            if (!response.ok) {
                throw new Error("Audit trail could not be loaded.");
            }

            const data = await response.json();
            const chain = data.chain || {};
            const events = data.events || [];

            if (badge) {
                badge.className = `badge ${chain.verified ? "good" : "warning"}`;
                badge.textContent = chain.verified ? "Chain verified" : "Chain warning";
            }

            if (metrics) {
                metrics.innerHTML = "";
                const values = [
                    ["Events", data.event_count ?? events.length],
                    ["Evidence ID", evidenceId],
                    ["Head hash", shortHash(chain.head_hash, 22)],
                ];

                values.forEach(([label, value]) => {
                    const card = document.createElement("div");
                    card.className = "audit-metric";
                    const name = document.createElement("span");
                    name.textContent = label;
                    const val = document.createElement("strong");
                    val.textContent = value ?? "Unavailable";
                    if (label.includes("hash") || label.includes("ID")) val.title = String(value || "");
                    card.append(name, val);
                    metrics.appendChild(card);
                });
            }

            if (eventsContainer) {
                eventsContainer.innerHTML = "";
                [...events].reverse().slice(0, 8).forEach(event => {
                    eventsContainer.appendChild(makeEvent(event));
                });
            }

            if (status) {
                status.textContent = chain.verified
                    ? "The stored event chain verifies against its recorded hashes."
                    : (chain.reason || "The audit chain could not be verified.");
            }

        } catch (error) {
            if (badge) {
                badge.className = "badge warning";
                badge.textContent = "Unavailable";
            }
            if (status) status.textContent = error.message;

        } finally {
            if (refresh) refresh.disabled = false;
        }
    }

    document.addEventListener("click", event => {
        const button = event.target.closest("[data-audit-refresh]");
        if (!button) return;
        const panel = button.closest("[data-audit-evidence-panel]");
        if (panel?.dataset.evidenceId) {
            loadEvidenceAudit(panel.dataset.evidenceId, panel.parentElement || document);
        }
    });

    window.ForensicAudit = {
        loadEvidenceAudit,
        humanEventType,
        shortHash,
        formatTime,
        makeEvent,
    };
})();
