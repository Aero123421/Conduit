(() => {
  let pending;
  const fromBase64url = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4)), (character) => character.charCodeAt(0));
  const toBase64url = (value) => { if (value === null) return null; const bytes = new Uint8Array(value); let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte); return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); };
  const csrf = () => document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("__Host-conduit_csrf="))?.slice("__Host-conduit_csrf=".length) ?? "";
  const json = async (path, init = {}) => { const response = await fetch(path, { credentials: "same-origin", ...init }); const value = response.status === 204 ? {} : await response.json(); if (!response.ok) throw new Error(value?.error?.message ?? "Device enrollment request failed"); return value; };
  const stepUp = async () => {
    const ceremony = await json("/api/v1/auth/step-up/options", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrf() }, body: "{}" });
    const publicKey = { ...ceremony.options, challenge: fromBase64url(ceremony.options.challenge), allowCredentials: (ceremony.options.allowCredentials ?? []).map((item) => ({ ...item, id: fromBase64url(item.id) })) };
    const credential = await navigator.credentials.get({ publicKey });
    if (!(credential instanceof PublicKeyCredential)) throw new Error("The browser did not return a passkey credential");
    const response = credential.response;
    await json("/api/v1/auth/step-up/verify", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrf() }, body: JSON.stringify({ challengeId: ceremony.challengeId, challenge: ceremony.options.challenge, response: { id: credential.id, rawId: toBase64url(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults(), response: { clientDataJSON: toBase64url(response.clientDataJSON), authenticatorData: toBase64url(response.authenticatorData), signature: toBase64url(response.signature), userHandle: toBase64url(response.userHandle) } } }) });
  };
  document.querySelector("#device-enrollment-lookup")?.addEventListener("submit", async (event) => {
    event.preventDefault(); const status = document.querySelector("#device-status");
    try { const code = document.querySelector("#device-user-code")?.value.trim().toUpperCase() ?? ""; pending = await json("/api/v1/device-enrollments/pending?userCode=" + encodeURIComponent(code)); document.querySelector("#device-hostname").textContent = pending.claims.hostnameLabel; document.querySelector("#device-platform").textContent = pending.claims.os + " / " + pending.claims.arch; document.querySelector("#device-node-version").textContent = pending.claims.nodeVersion + " (" + pending.claims.protocolVersion + ")"; document.querySelector("#device-fingerprint").textContent = pending.fingerprint; document.querySelector("#device-expires").textContent = pending.expiresAt; document.querySelector("#device-review").hidden = false; if (status) status.textContent = "Compare every value with the Node before deciding."; } catch (error) { if (status) status.textContent = error instanceof Error ? error.message : "Lookup failed"; }
  });
  const decide = async (decision) => { const status = document.querySelector("#device-status"); if (!pending) return; try { if (status) status.textContent = "Waiting for passkey verification…"; await stepUp(); await json("/api/v1/device-enrollments/" + encodeURIComponent(pending.enrollmentId) + "/decision", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrf() }, body: JSON.stringify({ decision }) }); document.querySelector("#device-review").hidden = true; if (status) status.textContent = decision === "approve" ? "Device approved. Return to the Node." : "Device denied."; } catch (error) { if (status) status.textContent = error instanceof Error ? error.message : "Decision failed"; } };
  document.querySelector("#device-approve")?.addEventListener("click", () => decide("approve"));
  document.querySelector("#device-deny")?.addEventListener("click", () => decide("deny"));
})();
