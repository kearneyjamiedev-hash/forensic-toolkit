const statusText = document.getElementById("dashboard-status-text");

async function loadHealth() {
    if (!statusText) return;
    try {
        const response = await fetch("/api/health");
        if (!response.ok) throw new Error();
        const data = await response.json();
        statusText.textContent = `Engine ready · v${data.version || "1.0.0"}`;
    } catch {
        statusText.textContent = "Local engine unavailable";
    }
}

loadHealth();
