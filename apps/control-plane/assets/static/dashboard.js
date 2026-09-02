const form = document.querySelector("#dashboard-session-form");
const input = document.querySelector("#dashboard-session-id");
const status = document.querySelector("#dashboard-status");
const view = document.querySelector("#dashboard-snapshot");

let socket;

function render(state) {
  view.textContent = JSON.stringify(state, null, 2);
}

async function openSession(sessionId) {
  socket?.close(1000, "session_changed");
  const buffered = [];
  const seen = new Set();
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  socket = new WebSocket(`${protocol}//${location.host}/api/v1/sessions/${encodeURIComponent(sessionId)}/stream`);
  socket.addEventListener("message", (message) => buffered.push(JSON.parse(String(message.data))));
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  const response = await fetch(`/api/v1/sessions/${encodeURIComponent(sessionId)}/snapshot`, { credentials: "same-origin", headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`snapshot_failed_${response.status}`);
  const state = await response.json();
  const apply = (batch) => {
    for (const event of batch?.events ?? []) {
      const key = `${event.eventId}:${event.revision}`;
      if (seen.has(key)) continue;
      seen.add(key);
      state.streamEvents ??= [];
      state.streamEvents.push(event);
    }
    render(state);
  };
  for (const batch of buffered.splice(0)) apply(batch);
  socket.addEventListener("message", (message) => apply(JSON.parse(String(message.data))));
  status.textContent = "Live. The authoritative snapshot was loaded before buffered stream events were applied.";
  render(state);
}

form?.addEventListener("submit", (event) => {
  event.preventDefault();
  status.textContent = "Connecting…";
  openSession(input.value.trim()).catch((error) => { status.textContent = `Unable to open Session: ${error.message}`; });
});
